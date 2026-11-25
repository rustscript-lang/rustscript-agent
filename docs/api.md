# HTTP API

The production router is defined in [`src/gateway/api_server.rs`](../src/gateway/api_server.rs). This reference lists only routes registered there; request and response details remain governed by the typed handlers and tests.

## Common behavior

- The configured request-body limit applies to the complete router.
- When bearer authentication is configured, send `Authorization: Bearer <token>` on every route. Optional rate limiting runs first per peer IP and then per verified account.
- Anonymous mode can expose ordinary routes, but managed-workspace maintenance, run-effect queries, and plugin control still require configured authentication. Plugin control additionally requires trusted host-side control configuration.
- Errors use `{"error":{"code":"...","message":"..."}}`, with route-specific status codes.
- Mutating session/job handlers and run admission commit durable state before publishing it in memory.

See [Configuration](configuration.md) for authentication, body, rate, and lifecycle bounds.

## Health and discovery

| Method | Path | Semantics |
| --- | --- | --- |
| `GET` | `/health/detailed` | Liveness plus active-run and pending-terminal gauges; includes bounded source metadata when available. |
| `GET` | `/metrics` | Prometheus text from the bounded in-memory registry; no storage query. |
| `GET` | `/v1/models` | Returns the configured model/provider identity. |

## Sessions

| Method | Path | Semantics |
| --- | --- | --- |
| `GET`, `POST` | `/api/sessions` | List or create sessions. Listing supports bounded pagination and source/search filters. |
| `GET`, `PATCH`, `DELETE` | `/api/sessions/{session_id}` | Read, update title/end reason, or delete a session. |
| `GET` | `/api/sessions/{session_id}/messages` | Return the session's canonical message history. |
| `POST` | `/v1/sessions/{session_id}/workspace` | Bind a validated workspace; rejected while the session has an active run. |
| `POST` | `/v1/sessions/{session_id}/compact` | Run the durable compaction lifecycle for the session. |
| `POST` | `/api/sessions/{session_id}/chat` | Legacy synchronous chat path. Source-selected production gateway constructors leave it unconfigured and return `501 agent_source_not_configured`; normal coded-agent execution uses `POST /v1/runs`. |

## Runs, events, effects, and approvals

| Method | Path | Semantics |
| --- | --- | --- |
| `POST` | `/v1/runs` | Atomically admit a run and return `202`. Optional `Idempotency-Key` replay returns the original run; reuse with different canonical input returns a conflict. |
| `GET` | `/v1/runs/{run_id}/events` | SSE replay followed by live events. `after_seq` resumes after a cursor; a cursor older than retained history returns `409 event_cursor_too_old`. |
| `POST` | `/v1/runs/{run_id}/stop` | Request cooperative cancellation. The durable run stays `running` until one terminal transition commits. |
| `GET` | `/v1/runs/{run_id}/effects` | Authenticated, read-only, cursor-paginated managed-effect summaries. It accepts `after_effect_id` and a bounded `limit`. |
| `GET` | `/v1/runs/{run_id}/approvals` | List pending approvals for an active run; requires bearer authentication. |
| `POST` | `/v1/runs/{run_id}/approvals/{approval_id}` | Resolve one pending approval with `{"decision":"approved"}` or `{"decision":"denied"}`. Resolution is owner-bound and one-time. |

Run admission freezes provider/tool/workspace/graph state before returning. A fresh admission starts one worker; an idempotent replay does not start another. Events and messages are durable before SSE broadcast. Delivery is at-least-once, so clients should deduplicate by durable event identity and resume by sequence.

## Managed workspaces

These routes require persistent managed-workspace configuration and authenticated native authority. The path workspace ID must equal the typed body workspace ID.

| Method | Path | Semantics |
| --- | --- | --- |
| `POST` | `/v1/workspaces/{workspace_id}/checkpoints` | Freeze a checkpoint; returns `201`, or `202` when submission succeeded but the final receipt is unknown. |
| `POST` | `/v1/workspaces/{workspace_id}/restore` | Restore a checkpoint and atomically admit a new run; returns `202` and starts the restored worker. |
| `POST` | `/v1/workspaces/{workspace_id}/branches` | Create a branch from authorized managed state; returns `201`. |
| `POST` | `/v1/workspaces/{workspace_id}/publish` | Publish a managed branch; returns `200`, or `202` for a submitted-unknown outcome. |

The typed request/receipt families and failure mapping are implemented in [`src/gateway/workspaces.rs`](../src/gateway/workspaces.rs).

## Plugin graphs

Plugin routes require a verified bearer plus trusted host-side `InstallAuthorization`; request JSON cannot supply install authority.

| Method | Path | Semantics |
| --- | --- | --- |
| `POST` | `/v1/plugins/install` | Validate and install an immutable plugin package capture. |
| `POST` | `/v1/plugin-graphs/resolve` | Resolve installed packages into a closed graph lock. |
| `POST` | `/v1/plugin-graphs/{graph_id}/prepare` | Compile and validate the stored graph without activating it. |
| `GET` | `/v1/plugin-graphs/{graph_id}` | Read the stored graph/control view. |
| `POST` | `/v1/plugin-activations` | Activate a prepared graph through the generationed control store. |
| `POST` | `/v1/plugin-activations/{activation_id}/rollback` | Roll back through activation history with conflict checks. |

Handlers and authorization are in [`src/gateway/plugins.rs`](../src/gateway/plugins.rs); durable locks, refs, activation generations, history, retention, and revocation are in [`src/plugins/control_store.rs`](../src/plugins/control_store.rs).

## Jobs and subagent compatibility

| Method | Path | Semantics |
| --- | --- | --- |
| `GET`, `POST` | `/api/jobs` | List or create durable job records. |
| `GET`, `PATCH`, `DELETE` | `/api/jobs/{job_id}` | Read, update, or delete a job record. |
| `GET` | `/api/jobs/{job_id}/output/latest` | Return the stored latest output, if any. |
| `POST` | `/api/jobs/{job_id}/pause` | Set the job record disabled. |
| `POST` | `/api/jobs/{job_id}/resume` | Set the job record enabled. |
| `POST` | `/api/subagents/{subagent_id}/interrupt` | Route an interrupt to the run handle with that ID. |

Job CRUD does not schedule or execute jobs. There is no `/api/jobs/{job_id}/run` route. Parallel tool dispatch and subagent fan-out are not implemented; see [Status](status.md).
