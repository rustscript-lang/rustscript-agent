# Status and maturity

This matrix describes the current source checkout. It does not claim a published release, live-provider availability, or final composed-candidate acceptance. The project is pre-v1, and absent routes or adapters are listed explicitly.

## Runtime and gateway

| Area | Status |
| --- | --- |
| Single-run runner (`rustscript-agent --script … --allow-host …`) | Implemented for synchronous script execution. HTTP remains deny-by-default; the runner exposes host allowlisting but no port flag. |
| Gateway sessions, messages, run admission, SSE events, stop, compaction, and subagent interrupt compatibility | Implemented. The current router is summarized in [API](api.md). |
| Durable SQLite sessions/messages/runs/events/jobs/approvals/compactions/idempotency | Implemented with RSS storage commands, bounded loading, migrations, and restart recovery. In-memory mode remains available and loses state on restart. |
| Atomic admission snapshot | Implemented: one permit/deadline spans preparation; relevant state is revalidated before durable commit and in-memory publication. |
| Terminal reliability | Implemented with durable-before-live publication, bounded terminal retries, observable `terminal_pending`, and restart repair. External event delivery remains at-least-once. |
| API hardening | Implemented: body bounds, optional bounded per-IP/per-account rate limiting, constant-time bearer comparison, and configurable last-subscriber disconnect policy. Rate limiting is disabled by default. |
| Observability | Implemented: bounded metrics registry, `GET /metrics` protected when bearer authentication is configured and exposed in supported anonymous mode, detailed health, and terminal tracing events. The binaries currently install no tracing subscriber, so stderr remains the packaged log surface. |
| Telegram gateway | Implemented: native rustls Bot API transport, deny-by-default account/chat/user allowlists, durable delivery cursors, bounded retries, first-boot drain, approvals, and bounded shutdown drain. |
| TLS listener | Not implemented. The gateway serves HTTP; terminate TLS at a reverse proxy. |
| Graceful signals | `SIGINT` is handled. `SIGTERM` is not caught; the documented systemd unit uses `KillSignal=SIGINT`. |

## Agent policy and providers

| Area | Status |
| --- | --- |
| Bundled RSS coding loop | Implemented through `rss/agent/main.rss`, with frozen coding prompt, provider turns, serial tool continuation, and durable compaction policy. |
| Gateway entry selection | A present `config.yaml` `agent.source` is authoritative. A missing config falls back to `RUSTSCRIPT_AGENT_SOURCE`, then deprecated `RUSTSCRIPT_AGENT_SCRIPT`, then `bundled:coding`; invalid present config fails closed. |
| Legacy chat completion path (`/api/sessions/{id}/chat`) | Legacy-constructor-only; production gateway selection via `RUSTSCRIPT_AGENT_SOURCE`, legacy `RUSTSCRIPT_AGENT_SCRIPT`, or bundled `bundled:coding` returns `501 agent_source_not_configured`. Normal coded-agent runs use `POST /v1/runs`. |
| `config::load_snapshot` bridge | Implemented in the production auth host and fixture host. Bounded config/auth loading, sanitized public config, opaque credential IDs, and native secret custody are present. |
| OpenAI Chat Completions (`openai`, `openai_chat`, or default) | Buffered and streaming source paths exist through opaque native credential transport. This is source status, not live-provider validation. |
| Codex Responses (`openai-codex` / `codex-responses`) | Access-only source path is present. Full refresh/lifecycle support is not claimed. |
| Generic custom Responses adapter | Not implemented; explicit selection returns typed `not_implemented` and sends no request. |
| Anthropic Messages | Not implemented; the adapter remains a typed `not_implemented` stub. |
| Package-level end-to-end config/auth/provider acceptance | Open. Final composed-candidate acceptance and remote delivery remain open. |

## Tools, approvals, and authority

| Area | Status |
| --- | --- |
| Built-in coding tools | Implemented for `read_file`, `search_files`, `write_file`, `patch`, `terminal`, and `process`, dispatched serially through RSS. |
| Filesystem/process confinement | Implemented with canonical workspace roots, token-scoped capability owners, direct `argv` execution, output bounds, cancellation, and owned-child cleanup. This is application confinement, not an OS sandbox. |
| Guardian review | Implemented in RSS with validated `allow`, `deny`, and `needs_user` outcomes and fail-closed malformed/unavailable handling. |
| Human approvals | Implemented with durable pending rows, HTTP and Telegram resolution, owner checks, expiry, one-time decisions, and one terminal tool result. |
| Managed workspace effects | Implemented for synchronous filesystem/process tool flows using private immutable trees, prepared receipts, durable commit/readback, conflict handling, and explicit publication. External process effects are recorded as outside-tree and are not rolled back. |
| Checkpoint, restore, branch, publish, and effect queries | Implemented behind authenticated native workspace authority and persistent state. Submitted-unknown outcomes remain fenced for reconciliation. |
| Parallel tool calls | Not implemented; rejected as `unsupported_parallel`. |
| Parallel subagents/fan-out | Not implemented and excluded from the current milestone. The interrupt compatibility route only cancels a run handle by ID. |
| General-purpose harness beyond the implemented tool approval/pinned-tool paths | Excluded from the current product claim. |

## Plugin graphs and state

| Area | Status |
| --- | --- |
| Plugin package install and graph resolution | Implemented for trusted host-controlled source roots, bounded manifests/schemas, immutable captures, publisher authorization, and closed graph locks. |
| Prepare, activate, inspect, and rollback routes | Implemented behind bearer verification plus host-side plugin-control authorization. A bearer alone does not grant install authority. |
| Admission graph pin | Implemented: the native admission transaction captures graph ID, activation generation, package refs, callable, registry identity, workspace, and durable ref. Caller JSON cannot mint the execution binding. |
| Hot activation | Implemented for new admissions. Existing runs retain their original graph; replay uses the original pin instead of the current activation. |
| Revocation and missing artifacts | Fail closed with typed graph/pin/artifact errors. Historical builtin captures can remain retained without becoming executable defaults. |
| Plugin state roots and migrations | Implemented for declared supported state/topology paths with revisioned roots, writer fences, checkpoints, and bounded collection. Unsupported topology/state combinations are rejected. |

## Jobs, release, and exclusions

| Area | Status |
| --- | --- |
| Job records | CRUD, pause/resume, and latest-output routes are implemented. |
| Scheduled/durable job execution | **Not implemented.** There is no scheduler and no `POST /api/jobs/{id}/run` route. |
| Published package/release | No release claim. The crate is `0.1.0` and depends on unreleased `pd-vm`/`pd-host-function` at pinned Core revision `11c9ee908a29365bd02573311f56e9308eb7dbe6`; deployments are source builds of pinned commits. |
| Full CI | Configured for format, clippy with warnings denied, and `cargo test --locked --all-features --all-targets` on Rust 1.99. See [Development](development.md). |

The detailed configuration surface is canonical in [Configuration](configuration.md), operational constraints in [Deployment](deployment.md), and ownership/replay invariants in [Architecture](architecture.md).
