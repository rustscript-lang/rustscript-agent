# Standalone RustScript Agent Yahu Hermes API Server Roadmap

**Goal:** Make the standalone `rustscript-agent` project a long-lived RustScript agent gateway that Yahu can use as a Hermes API Server target for every Hermes route Yahu currently calls, while preserving those routes' HTTP contracts, response envelopes, error/status behavior, SSE event ordering, authentication, session semantics, run controls, and jobs API. OpenAI-compatible proxy/conversion APIs are outside this roadmap.

**Architecture:** The standalone `rustscript-agent` project owns the listener, bearer authentication, CORS/body limits, durable session/run/job records, lifecycle cancellation, and connection cleanup. It uses `pd-edge` for edge/runtime integration and RustScript for RSS execution. A route selects an RSS entry module; the RSS module owns agent behavior: prompt composition, provider HTTP exchanges, provider-SSE parsing, tool loop, agent-visible event construction, and final payload content. Matching Hermes wire shapes does **not** mean forwarding a request to an upstream Hermes or model API: the standalone project executes the configured local RustScript agent directly.

**Tech stack:** standalone Axum/Tokio HTTP gateway; `pd-edge` edge/runtime and HTTP ABI (`http::request::*`, `http::exchange::*`, `http::response::*`); RustScript RSS modules and `pd-vm`; SQLite durable state; SSE; WebSocket only where a client contract actually needs it.

---

## 1. Evidence and compatibility rule

### Audited sources

| Source | Revision inspected | Evidence used |
|---|---:|---|
| [fffonion/yahu](https://github.com/fffonion/yahu) | `b0613da0860f5da0c38cfdb702d80b1d1b426ec6` | `src/backend/mod.rs`, `proxy.rs`, `sessions.rs`, `models.rs`, `subagents.rs`, `frontend/src/App.tsx`, and `frontend/src/chatRequest.ts` |
| Hermes Agent | local `78a343169cba2127a33cd0671a15c9250f19eba4` | `gateway/platforms/api_server.py` route table and handlers |
| Hermes API Server docs | same local checkout | `website/docs/user-guide/features/api-server.md` |

### Compatibility definition

For a route marked **Yahu-required**, standalone gateway must match the current Hermes API Server in all observable dimensions:

1. HTTP method, URL, auth requirement, and relevant headers.
2. JSON field names, wrapper object names, status codes, and error codes.
3. Request-field acceptance, including tolerated fields Yahu already sends.
4. Session identity, title, lineage, transcript, and provider/model-selection behavior.
5. SSE framing (`data: <JSON>\n\n`), event names, event field names, terminal events, keepalives, and cancellation behavior.
6. Response ordering and idempotent retry behavior under a client reconnect.

A compatibility test talks to Hermes and standalone gateway using the same fixture and asserts the documented contract. It must never route standalone gateway through Hermes as a compatibility implementation.

### Important Yahu boundary

Yahu has two different integration styles:

| Kind | Examples | Roadmap treatment |
|---|---|---|
| Hermes API Server client | `/v1/runs`, `/api/sessions`, `/api/jobs`, `/v1/models`, `/health/detailed` | **Hermes-compatible API surface.** Required for Yahu to point its `HERMES_API_URL` at standalone gateway. |
| Local host utility | workspace browser/editor, memory file editor, terminal WebSocket, skill-file editor, image cache/gallery, image watcher, update binary, local `state.db` insights | **Not an existing Hermes API Server contract.** It needs a separately versioned standalone gateway management/UI API or a Yahu sidecar. Do not label these endpoints as Hermes-compatible. |

The current Yahu `/hermes/{*path}` route is a same-origin authenticated relay to its configured API server. standalone gateway must replace the destination behind that relay; Yahu itself need not become a provider proxy.

## 2. Complete inventory of Yahu's current Hermes API dependencies

### 2.1 Required in the first compatibility milestone

| Hermes route | Yahu caller | Yahu-visible contract that standalone gateway must preserve |
|---|---|---|
| `GET /health/detailed` | `src/backend/proxy.rs` | Authenticated readiness body includes numeric `active_agents`; Yahu uses it with latest session activity to decide whether an externally started turn is still active. |
| `GET /v1/models` | `src/backend/models.rs` | Bearer-protected model listing consumed by Yahu's model selector/cache. Preserve the Hermes `object: "list"`, `data` form and advertised agent/profile model entries. |
| `GET /api/sessions` | `src/backend/sessions.rs`, `subagents.rs` | `object`, `data`, `limit`, `offset`, `has_more`; accept `limit`, `offset`, `source`, and `include_children`. Yahu additionally sends `q` and `exclude_sources`; current Hermes source tolerates them and Yahu filters client-side. standalone gateway must retain that tolerance. |
| `POST /api/sessions` | `frontend/src/App.tsx` | Accept optional `id`/`session_id`, `source`, `model`, `system_prompt`, `title`; return `201`, `object: "hermes.session"`, and `session`. Yahu reads `session`, `data`, then bare body as fallbacks. |
| `GET /api/sessions/{session_id}` | Yahu session detail, subagent projection | Return `object: "hermes.session"` and `session`, including message count, title, model/provider/source and lineage metadata that Yahu renders. |
| `PATCH /api/sessions/{session_id}` | Yahu lineage-title editor | Accept only Hermes fields `title` and `end_reason`; enforce identical title-conflict / `invalid_title` behavior. |
| `DELETE /api/sessions/{session_id}` | Yahu new-draft cleanup and context menu | Return `object: "hermes.session.deleted"`, `id`, `deleted`. |
| `GET /api/sessions/{session_id}/messages` | Yahu transcript, live-watch, and subagent views | Return `object: "list"`, resolved `session_id`, and message `data` with IDs, role, content, tool calls, tool name, timestamps, reasoning, token count, and finish reason when available. Hermes currently returns the whole transcript; Yahu performs its own windowing. |
| `POST /api/sessions/{session_id}/chat` | Yahu `/steer` while a turn is active | Accept `input`, `model`, optional `provider`, `reasoning_effort`/`model_options`, and `instructions`/`system_message`; return `object: "hermes.session.chat.completion"`, `session_id`, assistant `message`, and `usage`. |
| `POST /v1/runs` | Yahu normal streamed chat | Accept `input`, `session_id`, `conversation_history`, `instructions`, `model`, `provider`, `reasoning_effort`/`model_options`, `skip_memory`, and `disabled_toolsets`; return `202` with `run_id` and `status: "started"`. |
| `GET /v1/runs/{run_id}/events` | Yahu normal streamed chat | `text/event-stream`; source events must reach Yahu as `message.delta`, `tool.started`, `tool.completed`, `tool.failed`, `approval.request`, `run.completed`, `run.cancelled`, or `run.failed`. Each JSON event carries `event`, `run_id`, and timestamp; terminal event carries output/usage or error. Keepalive comments prevent idle disconnects. |
| `POST /v1/runs/{run_id}/stop` | Yahu stop button | Return `{ "run_id": ..., "status": "stopping" }` while cancellation is pending; the SSE subsequently terminates with `run.cancelled`. |
| `POST /api/subagents/{subagent_id}/interrupt` | `frontend/src/subagentProgress.ts` | Return `202`, `object: "hermes.subagent.interrupt"`, `subagent_id`, `status: "interrupt_requested"`, or Hermes-shaped `404 subagent_not_found`. |
| `GET /api/jobs` | Yahu cron page | Honor `include_disabled`; Hermes returns `{ "jobs": [...] }`, which Yahu also accepts as `data`. |
| `POST /api/jobs` | Yahu cron create | Accept at least `name`, `schedule`, `prompt`, `deliver`, `skills`, and `repeat`; return `{ "job": ... }`. |
| `GET /api/jobs/{job_id}` | Generic Yahu relay/future use | Return `{ "job": ... }` or `404`. |
| `GET /api/jobs/{job_id}/output/latest` | Yahu cron detail | Return `{ "output": ... }`, including `null` when no output exists. |
| `PATCH /api/jobs/{job_id}` | Yahu cron editor | Preserve Hermes allowed-field validation and return `{ "job": ... }`. |
| `DELETE /api/jobs/{job_id}` | Yahu cron delete | Return `{ "ok": true }`. |
| `POST /api/jobs/{job_id}/pause` | Yahu cron editor | Return `{ "job": ... }`. |
| `POST /api/jobs/{job_id}/resume` | Yahu cron editor | Return `{ "job": ... }`. |
| `POST /api/jobs/{job_id}/run` | Yahu manual run | Trigger asynchronous execution and return `{ "job": ... }`; output remains available through `output/latest`. |

### 2.2 Current Yahu capability gaps that are not Hermes API routes

These capabilities are currently implemented by Yahu reading/writing its configured host filesystem, calling its own shell process, or reading SQLite directly. They cannot truthfully be claimed as API Server compatibility because Hermes' `/v1/capabilities` currently advertises `admin_config_rw: false` and `memory_write_api: false`.

| Yahu capability | Current Yahu implementation | standalone gateway roadmap requirement |
|---|---|---|
| Workspace browse, preview, edit, rename, delete, download | `/workspace/*` handlers operate in a configured filesystem root | Build a separately versioned management API only after explicit filesystem host capabilities and per-root policy exist. |
| Skill list/tree/read/write/toggle/delete/backup/rollback | Direct `~/.hermes/skills` file operations | Build a management API with profile scoping, atomic writes, audit records, and path containment. Keep it distinct from read-only Hermes `/v1/skills`. |
| Memory read/write | Direct `memories/MEMORY.md` and `USER.md` reads/writes | Add an explicit memory-store capability and management contract; do not expose arbitrary files. |
| Interactive terminal | Yahu-owned `/terminal/ws` spawning a local PTY | A separate high-risk terminal session service with WebSocket origin checks, user approval, quotas, terminal lifecycle, and audited command access. This requires an explicit host-capability decision; it is outside the initial HTTP-only agent host scope. |
| Session watch / subagent WebSocket projection | Yahu polls Hermes sessions/messages and derives UI state | Expose native run/session subscriptions only after the core REST/SSE contracts pass. Do not derive UI state from hidden local databases. |
| Insights | Direct `state.db` reads plus model-price lookups | Add read-only metrics/usage API over the standalone gateway durable store; do not export raw database files. |
| Image gallery, metadata, file watcher, HEIC generation | Direct image-cache filesystem access and local image conversion | Add a media-library service with permitted roots, signed downloads, bounded generation jobs, and SSE change notifications. |
| Hermes/Yahu update action | Locally replaces the binary | Keep outside the agent public API; use an operator-only deployment workflow. |

### 2.3 Hermes routes explicitly outside the Yahu implementation scope

The preceding table is the complete implementation target for the current Yahu API call graph. The following Hermes routes are deliberately not part of this work because Yahu does not currently call them and the gateway must not become a compatibility proxy/conversion layer:

| Route | Required behavior |
|---|---|
| `GET /health` and `GET /v1/health` | Not required by the current Yahu caller set; expose only if a later UI contract adopts them. |
| `GET /v1/capabilities` | Not required for the first Yahu target; never advertise unimplemented routes. |
| `GET /v1/skills` and `GET /v1/toolsets` | Yahu currently obtains these through local management paths, not its Hermes API calls. |
| `POST /v1/chat/completions` | Explicitly excluded; no OpenAI-compatible request/response conversion. |
| `POST /v1/responses`, `GET`/`DELETE /v1/responses/{response_id}` | Explicitly excluded; no Responses compatibility surface. |
| `POST /api/sessions/{session_id}/fork` and `POST /api/sessions/{session_id}/chat/stream` | Not in Yahu's current API call graph; add only with a separately audited Yahu requirement. |
| `GET /v1/runs/{run_id}`, `POST /v1/runs/{run_id}/approval` | Not in Yahu's current API call graph; current scope covers the run event and stop paths Yahu calls. |
| `POST /api/platforms/{platform}/events`, `POST /api/cron/fire` | Separate signed connector contracts, not current Yahu API dependencies. |

## 3. Contract decisions required before implementation

1. **The compatibility baseline is current Hermes behavior for Yahu-required routes, not Yahu's local adapters.** Where Yahu sends extra query parameters, standalone gateway must tolerate them in the same way Hermes does. Where Yahu adds a local view or SSE projection, that remains Yahu behavior until standalone gateway ships a separately specified native UI API.
2. **Provider/model request overrides:** preserve Hermes precedence: session override, configured route alias, explicit model/provider, then server default. Preserve conflict rejection rather than silently combining a route's credentials with another provider.
3. **The external agent API must always require bearer authentication.** Match `Authorization: Bearer <key>`, require a non-placeholder secret, enforce explicit CORS allowlists, and keep the public liveness route deliberately minimal.
4. **Long-term-memory continuity:** support `X-Hermes-Session-Id`, `X-Hermes-Session-Key`, header validation (256-char/control-character restrictions), response echoing, and profile/tenant isolation before claiming multi-user parity.
5. **No native provider proxy:** source modules call providers through standalone gateway's policy-constrained `http::exchange::*` ABI and parse each provider's response/SSE. The API layer never forwards an unexamined body to an arbitrary provider URL.
6. **No fake streaming:** `http::response::stream::start/write/finish` sends each RSS-generated SSE frame immediately. Use the existing `http::exchange::body::next_chunk` path for provider stream consumption. Full-response buffering is not sufficient for stream conformance.
7. **Script field discrepancy must be resolved by a pinned fixture.** Current Yahu sends `script` on `POST /api/jobs`; the inspected Hermes `_handle_create_job` reads name/schedule/prompt/deliver/skills/repeat but does not pass `script` to `_cron_create`. Preserve the pinned Hermes behavior in the initial conformance suite and record an upstream Hermes change before extending the compatibility fixture. Do not silently invent a different response contract.

## 4. Implementation roadmap

### Milestone 0: Freeze the Hermes/Yahu contract as executable fixtures

**Objective:** Turn current source behavior into a versioned compatibility suite before adding handlers.

**Files:**
- Create: `rustscript-agent/tests/hermes_api_contract/fixtures/`
- Create: `rustscript-agent/tests/hermes_api_contract/mod.rs`
- Create: `rustscript-agent/tests/hermes_api_contract/yahu_required.rs`
- Create: `rustscript-agent/tests/hermes_api_contract/hermes_documented.rs`
- Create: `rustscript-agent/docs/hermes-api-compatibility.md`

**Steps:**
1. Encode the current route table from Hermes `ApiServerAdapter._http_route_table()` as the reference inventory.
2. Add golden request/response fixtures for every row in section 2.1, including unauthenticated `401`, malformed JSON `400`, unknown resource `404`, bad title `400 invalid_title`, and concurrent-run limit `429` where applicable.
3. Record exact SSE frame sequences for: successful run with text deltas, tool activity, approval wait/resolve, cancellation, and failure. Assert events are JSON under `data:` frames and that terminal events arrive before stream close.
4. Add an end-to-end Yahu smoke fixture that starts a standalone gateway test listener, configures Yahu's `HERMES_API_URL` to it, and exercises session create → run → SSE → stop, cron CRUD, model discovery, transcript retrieval, and subagent interrupt.
5. Add an explicit fixture manifest field for the audited Hermes/Yahu revisions. Updating it must require an intentional compatibility review.

**Acceptance:** A missing, renamed, or behaviorally incompatible Yahu-required endpoint fails CI with the route and fixture name.

### Milestone 1: Establish the API-server security and route substrate

**Objective:** Provide one standalone gateway listener with the same external protection and lifecycle baseline as Hermes.

**Files:**
- Create: `rustscript-agent/src/runtime/agent_gateway/mod.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/config.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/auth.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/router.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/errors.rs`
- Create: `rustscript-agent/src/bin/pd-edge-agent-gateway.rs`
- Test: `rustscript-agent/tests/hermes_api_contract/security.rs`

**Steps:**
1. Add a dedicated agent listener; retain the existing proxy data plane and admin/program-upload plane as independent services.
2. Implement bearer auth, strong-secret startup refusal, narrow CORS allowlist, preflight handling, request-size limits, `X-Content-Type-Options`, and `Referrer-Policy`.
3. Implement profile/tenant routing and `X-Hermes-Session-Id` / `X-Hermes-Session-Key` parsing before a request reaches an RSS entry.
4. Implement an error builder that produces the pinned Hermes error envelope and does not leak provider credentials, filesystem paths, raw commands, or host errors.
5. Register exact route/method pairs from the fixture manifest. Unknown routes must be `404`; unsupported methods must match framework/contract behavior.

**Acceptance:** Security fixtures pass with direct HTTP calls; no route can reach an agent entry without successful authentication except the explicitly public health route.

### Milestone 2: Implement durable session resources and transcript APIs

**Objective:** Replace Yahu's required session APIs without requiring Yahu to read standalone gateway's internal database.

**Files:**
- Create: `rustscript-agent/src/runtime/agent_gateway/session_store.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/session_api.rs`
- Create: `rustscript-agent/migrations/agent_gateway_sessions.sql`
- Create: `rustscript-agent/examples/agent_gateway/session_api.rss`
- Test: `rustscript-agent/tests/hermes_api_contract/sessions.rs`

**Steps:**
1. Create SQLite records for session metadata, message records, lineage, per-session model selection, stable memory key, and public session projections. Do not serialize a VM, callable, socket, or provider client.
2. Implement exact `GET`/`POST /api/sessions`, `GET`/`PATCH`/`DELETE /api/sessions/{id}`, `GET .../messages`, and `POST .../fork` contracts.
3. Preserve Hermes title sanitization/uniqueness, source validation, session-ID restrictions, lineage semantics, and response wrappers.
4. Store all agent-visible turns and tool records needed for transcript restoration, including reasoning/tool metadata allowed by the public projection.
5. Have `session_api.rss` construct source-owned agent messages while native code persists the resulting event/transcript records.

**Acceptance:** The session section of the contract suite passes, including fork, title conflict, pagination fields, direct message reads, and Yahu session-list/detail flows.

### Milestone 3: Build the run event loop and exact RSS-to-SSE stream bridge

**Objective:** Support Yahu's main chat path and Hermes run control without a response-conversion proxy.

**Files:**
- Create: `rustscript-agent/src/runtime/agent_gateway/run_store.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/run_scheduler.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/run_api.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/sse.rs`
- Create: `rustscript-agent/examples/agent_gateway/run_agent.rss`
- Create: `rustscript-agent/examples/agent_gateway/provider_sse.rss`
- Test: `rustscript-agent/tests/hermes_api_contract/runs.rs`
- Test: `rustscript-agent/tests/hermes_api_contract/runs_sse.rs`

**Steps:**
1. Add a bounded mailbox keyed by `(tenant, profile, session_id)`: same-session turns serialize, unrelated sessions may proceed concurrently, duplicate client idempotency keys resolve to one logical run.
2. Implement `POST /v1/runs`, `GET /v1/runs/{id}`, `GET /v1/runs/{id}/events`, and `POST /v1/runs/{id}/stop` with durable run status and short-lived, reconnect-safe transport buffers.
3. Pass a real standalone gateway request/response context into `run_agent.rss`. RSS uses `http::exchange::*` for provider calls, `body::next_chunk` for provider SSE, and `http::response::stream::*` for direct response streams where applicable.
4. Define a small RSS event helper that writes the exact Hermes `data: { ... }\n\n` contract. The helper owns event body construction; native code carries typed lifecycle records and handles backpressure/disconnect cleanup.
5. Wire deadline, client disconnect, explicit stop, shutdown drain, and approval wait states into the VM cancellation path. A stop must never claim completion before the running worker actually exits.
6. Add per-run redaction before event persistence/egress and monotonic sequence numbers for internal replay; never expose raw host errors.

**Acceptance:** The Yahu stream path receives `message.delta` and terminal `run.completed`; stop produces `stopping` then `run.cancelled`; tool and failure fixtures preserve the pinned event fields/order.

### Milestone 4: Implement synchronous session-chat and approval semantics

**Objective:** Complete the Yahu steering path and the Hermes human-in-the-loop contract.

**Files:**
- Modify: `rustscript-agent/src/runtime/agent_gateway/run_api.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/approval.rs`
- Create: `rustscript-agent/examples/agent_gateway/session_chat.rss`
- Test: `rustscript-agent/tests/hermes_api_contract/session_chat.rs`
- Test: `rustscript-agent/tests/hermes_api_contract/approval.rs`

**Steps:**
1. Implement `POST /api/sessions/{id}/chat` and `/chat/stream` over the same scheduler and persisted session history.
2. Preserve `input`, `instructions`/`system_message`, model/provider/options, session key headers, response headers, and Hermes response/SSE envelopes.
3. Add run-scoped approval records and `POST /v1/runs/{id}/approval`; accept `once`, `session`, `always`, `deny` plus documented aliases and resolve-all flags.
4. Keep approval identity distinct per run even when two runs intentionally share a conversation/session key.
5. Ensure RSS is suspended/resumed through a typed host capability; RSS never gains a bypass around the gateway approval decision.

**Acceptance:** Yahu `/steer` succeeds against standalone gateway; approval wait/resume fixtures and session stream fixtures pass.

### Milestone 5: Implement jobs/cron API parity

**Objective:** Make Yahu's cron UI work through standalone gateway's authenticated API instead of local scheduler files.

**Files:**
- Create: `rustscript-agent/src/runtime/agent_gateway/job_store.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/job_scheduler.rs`
- Create: `rustscript-agent/src/runtime/agent_gateway/jobs_api.rs`
- Create: `rustscript-agent/examples/agent_gateway/cron_job.rss`
- Test: `rustscript-agent/tests/hermes_api_contract/jobs.rs`

**Steps:**
1. Implement every Yahu-required jobs route in section 2.1, exact job wrappers, disabled filtering, latest-output retrieval, async manual trigger, pause/resume, and deletion cancellation.
2. Validate allowed patch fields against the frozen Hermes fixture, with atomic schedule/job updates and durable output records.
3. Execute each scheduled turn using a fresh source entry/session and record delivery state, matching Hermes's fresh-run behavior.
4. Keep job execution/client delivery asynchronous from the HTTP request; return the Hermes-compatible job record immediately.
5. Add a separate signed cron-fire ingress only if the selected deployment includes a managed cron provider.

**Acceptance:** Yahu create/edit/pause/resume/run/delete/output flows pass against standalone gateway, including the pinned `script`-field fixture.

### Milestone 6: Add Yahu-equivalent management/UI capabilities separately

**Objective:** Replace Yahu's local-only functions without conflating them with Hermes API compatibility.

**Files:**
- Create: `rustscript-agent/src/runtime/management_api/mod.rs`
- Create: `rustscript-agent/src/runtime/management_api/workspace.rs`
- Create: `rustscript-agent/src/runtime/management_api/skills.rs`
- Create: `rustscript-agent/src/runtime/management_api/memory.rs`
- Create: `rustscript-agent/src/runtime/management_api/media.rs`
- Create: `rustscript-agent/src/runtime/management_api/terminal.rs`
- Create: `rustscript-agent/docs/management-api-security.md`
- Test: `rustscript-agent/tests/management_api/`

**Steps:**
1. Publish a versioned `/management/v1/*` service under separate admin credentials/scopes; it is not mounted in the agent API listener by default.
2. Add filesystem-root allowlists, canonical-path containment, atomic writes, audit rows, file-size/type caps, optimistic revision checks, and per-operation authorization.
3. Build terminal WebSocket support only after terminal host operations have explicit user-approved design and live integration tests; no simulated PTY state.
4. Add media/library watchers and insights projections over authorized storage, not direct raw-database export.
5. Update Yahu only after each native management endpoint has an end-to-end browser test and a privilege-boundary test.

**Acceptance:** Yahu-equivalent UI features work without mounting standalone gateway internal paths or state databases into the browser-facing process.

## 5. Verification and release gates

1. `cargo test -p pd-edge --test hermes_api_contract` executes the source-derived API matrix.
2. SSE integration tests use a real listener and a real RSS provider-SSE fixture. They verify immediate downstream frames, keepalives, tool events, terminal event, disconnect, reconnect, stop, and approval.
3. A Yahu smoke test runs the published Yahu binary/source against standalone gateway only. It must not reach a Hermes endpoint during the test.
4. Security tests verify missing/invalid bearer keys, CORS denial, session-key validation, ID/path injection rejection, output redaction, and authorization isolation.
5. The published route inventory must be generated from the enabled implementation set and compared to the tested Yahu-required route matrix.
6. Run `git diff --check` and the plan's route-inventory consistency test after any roadmap update.

## 6. Explicit non-goals for the first delivery

- No HTTP request forwarding from standalone gateway to a Hermes instance.
- No provider URL supplied by an untrusted API request.
- No broad filesystem, shell, memory-file, or image-cache access on the public agent API listener.
- No claim that Yahu's local management routes are part of Hermes API Server compatibility.
- No `/v1/chat/completions`, `/v1/responses`, or any other OpenAI-compatible proxy/conversion endpoint.
- No static capability declaration ahead of an executable Yahu-required route conformance test.
