# Gateway HTTP API and run contract

This document describes the current `rustscript-agent-gateway` HTTP surface and
the run/event contract behind it. It replaces the earlier framework roadmap;
configuration, deployment, and tool ownership are covered by
[docs/configuration.md](../docs/configuration.md),
[docs/deployment.md](../docs/deployment.md), and the
[RSS tools design](../docs/superpowers/specs/2026-09-03-rss-tools-rust-capabilities-design.md).

**Implementation:** `src/gateway/api_server.rs` builds the Axum router,
`src/gateway/plugins.rs` and `src/gateway/workspaces.rs` serve the managed
routes, and `src/service.rs` owns admission, run lifecycle, and durable
terminal commits. No provider parser, agent loop, private host function, or
SQL statement lives in the gateway layer.

## Ownership boundary

| Layer | Owns |
| --- | --- |
| Gateway / API server | HTTP framing, authentication, admission, SSE delivery, request/response rendering |
| `AgentService` | run reservation, cancellation, terminal transitions, durable event sequencing, recovery |
| Agent RSS | provider mapping, conversation/tool loop, storage commands, tool dispatch, compaction, approval policy |
| Native capabilities | workspace confinement, process ownership, atomic file effects, execution tokens, deadlines |

The API server normalizes inbound requests into canonical run requests and
renders canonical events. Provider and tool behavior remains in RSS.

## Authentication and request limits

- When `RUSTSCRIPT_AGENT_BEARER_TOKEN` is configured, every route requires
  `Authorization: Bearer ***` (constant-time comparison).
- Without a configured token, the gateway only starts when
  `RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS=1`; anonymous access is for local testing.
- Managed workspace maintenance and plugin-control routes always require
  configured authentication; with anonymous mode they answer
  `403 managed_management_denied`.
- Request bodies are limited by `max_body_bytes` (4 MiB by default).
- Optional rate limiting (A7) charges one token per peer IP and, after a
  verified bearer, one per account. Exhaustion answers `429` with
  `Retry-After`.
- Errors use a single envelope: `{"error":{"code":"…","message":"…"}}`.
- SSE sends named events (`event: <event type>`) whose JSON data carries
  `event_id`, `seq`, `event`, `run_id`, `timestamp`, and the event payload
  fields.

## Routes

### Health, metrics, and model discovery

| Method and path | Behavior |
| --- | --- |
| `GET /health/detailed` | Liveness plus `active_agents`, `terminal_pending`, `agent`. For an RSS-selected source it also reports bounded `source` facts: `kind`, `hash`, `deprecated_override`. |
| `GET /metrics` | Prometheus text exposition of the bounded metrics registry; reads atomics only. |
| `GET /v1/models` | Returns the configured model id as an OpenAI-style model list. |

### Sessions and messages

| Method and path | Behavior |
| --- | --- |
| `GET /api/sessions` | Lists visible sessions. Query: `limit` (≤200), `offset`, `source`, `q`, `exclude_sources`, `include_children`. Subagent sessions are hidden unless `include_children` is set. Response includes `has_more`. |
| `POST /api/sessions` | Creates a session. Body: `id` or `session_id` (optional), `source`, `model`, `provider`, `system_prompt`, `title`. Defaults source to `yahu`; duplicate id answers `409 session_exists`. |
| `GET /api/sessions/{session_id}` | Returns the session view. |
| `PATCH /api/sessions/{session_id}` | Updates `title` and/or `end_reason`; an empty title is rejected. |
| `DELETE /api/sessions/{session_id}` | Deletes the session and cascades its runs and events. |
| `GET /api/sessions/{session_id}/messages` | Returns the durable message list. |
| `POST /api/sessions/{session_id}/chat` | Legacy completion path. Only available when a legacy agent source was installed by the legacy constructor; production source selection returns `501 agent_source_not_configured`. Use `POST /v1/runs` for coded-agent runs. |
| `POST /v1/sessions/{session_id}/workspace` | Binds a configured workspace selector to the session. Cannot change while the session has an active run (`409 active_run`). |
| `POST /v1/sessions/{session_id}/compact` | Runs an explicit compaction through `AgentService`. |

Session mutations are durable before they become visible in memory; a failed
storage commit leaves the previous in-memory state and answers
`503 persistence_unavailable`.

### Runs

| Method and path | Behavior |
| --- | --- |
| `POST /v1/runs` | Admits and starts a run. Body fields: `input`, `session_id`, `model`, `provider`, `parent_run_id`, `instructions`, `workspace`, `conversation_history`, `graph_id`, `workspace_branch`, plus flattened `options`. `Idempotency-Key` is an optional header. Answers `202` with `run_id`, `status`, and the captured run projection. |
| `GET /v1/runs/{run_id}/events` | SSE replay and live stream. `after_seq` is an exclusive cursor; a cursor older than retained history answers `409 event_cursor_too_old` with `earliest_seq`. The stream ends after the terminal event; a lagging subscriber receives a terminal `error` event with `code=event_lagged`. |
| `POST /v1/runs/{run_id}/stop` | Requests cooperative cancellation and returns `run_id` plus the current status. |
| `GET /v1/runs/{run_id}/approvals` | Lists pending approvals for the run. Requires configured bearer authentication. |
| `POST /v1/runs/{run_id}/approvals/{approval_id}` | Resolves a pending approval with `{"decision":"approved"|"denied"}`. Requires configured bearer authentication. |
| `GET /v1/runs/{run_id}/effects` | Lists the managed-effect ledger entries visible to this run. Requires configured bearer authentication. |

Admission is atomic: capacity, session, run ID, cancellation, and delivery
state are reserved together. Rejections leave no session or run behind and
answer typed errors such as `429 run_limit_reached`, `404 parent_run_not_found`,
`404 session_not_found`, `409 idempotency_key_reused`,
`422 plugin_graph_pin_required`, `409 plugin_graph_revoked`, or
`422 plugin_artifact_unavailable`.

Run cancellation is cooperative: stop, deadline, parent stop, gateway
shutdown, and client-disconnect policy share the same run token. A deadline
expiry commits one `run.cancelled` terminal; a worker that exits
without a terminal commits `run.failed` exactly once.

### Canonical events

Script-visible events (emitted through `stream::emit` and validated by
`src/events.rs`):

```text
model.started      model.delta        model.completed
tool.requested     approval.required  approval.resolved
tool.started       tool.output        tool.completed    tool.failed
compact.started    compact.completed
subagent.started   subagent.completed
```

Service-owned events that scripts cannot emit:

```text
run.started   run.completed   run.cancelled   run.failed   message.delta
```

Every event receives a per-run monotonic `seq` and is durable before live
delivery. Delivery is at-least-once; replay by `after_seq` is exact for the
retained history. The frozen canonical event IDs make provider and tool steps
replayable without repeating effects.

### Jobs and subagents

| Method and path | Behavior |
| --- | --- |
| `GET /api/jobs` | Lists jobs; `include_disabled` includes paused jobs. |
| `POST /api/jobs` | Creates a job record. Body: `id`/`job_id`, `name`, `schedule`, `prompt`, `deliver`, `skills`, `repeat`, `enabled`. |
| `GET/PATCH/DELETE /api/jobs/{job_id}` | Reads, updates, or deletes one job. |
| `GET /api/jobs/{job_id}/output/latest` | Returns the latest stored output. |
| `POST /api/jobs/{job_id}/pause` / `resume` | Sets the durable `enabled` flag. |
| `POST /api/subagents/{subagent_id}/interrupt` | Requests stop for an active subagent run; unknown ids answer `404 subagent_not_found`. |

There is no job scheduler and no `POST /api/jobs/{job_id}/run` route. Job
records, pause/resume, and latest output exist; scheduled execution is out of
scope. Parallel tool calls and subagent execution are also not implemented.

### Managed workspaces

All routes require configured bearer authentication and a managed workspace
configuration:

| Method and path | Behavior |
| --- | --- |
| `POST /v1/workspaces/{workspace_id}/checkpoints` | Creates a checkpoint of the managed workspace head. |
| `POST /v1/workspaces/{workspace_id}/restore` | Restores a checkpoint into a new branch. |
| `POST /v1/workspaces/{workspace_id}/branches` | Creates or selects a branch, optionally from a checkpoint. |
| `POST /v1/workspaces/{workspace_id}/publish` | Publishes a branch to the managed workspace head with expected-head CAS. |

Managed runs require an absolute persistent state database and an explicitly
configured workspace source; the private object root is derived beside the
database. See [docs/configuration.md](../docs/configuration.md).

### Plugin control

All routes require configured bearer authentication and a configured plugin
control source root; otherwise they answer `403 plugin_control_unconfigured`:

| Method and path | Behavior |
| --- | --- |
| `POST /v1/plugins/install` | Installs a controlled plugin package and returns the immutable revision. |
| `POST /v1/plugin-graphs/resolve` | Resolves a graph lock and diff without activating it. |
| `POST /v1/plugin-graphs/{graph_id}/prepare` | Compiles and validates the graph. |
| `GET /v1/plugin-graphs/{graph_id}` | Returns graph nodes, edges, contracts, permissions, and error chains. |
| `POST /v1/plugin-activations` | Activates a prepared graph with `expected_generation`. |
| `POST /v1/plugin-activations/{activation_id}/rollback` | Creates a new activation pointing at a retained graph. |

Graph ids, activation ids, and paths are opaque handles, not authority. A run
token cannot activate a plugin; install/activation use the host
`InstallAuthorization` and workspace/owner checks.

## Durable delivery and recovery

- Run identity, event sequence, and terminal state are committed through the
  RSS storage worker; the API never publishes an event before its durable
  append.
- Restart recovery converts every non-terminal run to `failed` with
  `error_code=gateway_restart`, appends one `run.failed` event, expires pending
  approvals, and fails every pending compaction. No prior side effect is
  replayed automatically.
- Exactly-once delivery to an external receiver is impossible; subscribers
  may observe the same durable event more than once and must reconnect with
  `after_seq` for a gap-free replay.
