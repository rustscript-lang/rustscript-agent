# RustScript Agent Framework Implementation Plan

**Goal:** Build a standalone RustScript-driven agent framework with API Server and Telegram gateways, durable sessions, provider adapters, tool policy, compaction, and subagent orchestration.

**Architecture:** Native Rust owns configuration, secrets, platform I/O, service lifecycle, event delivery, and composition of generic RustScript capabilities. RSS owns agent policy: provider protocol mapping, conversation/tool loop, SQL/schema, approvals, compaction, and subagent policy. Each run invokes an exported RSS `run(context)` function and consumes a Rust-like stream of `Event` items followed by one `Complete` item or typed error. Core VM/compiler/runtime work is tracked only in the `rustscript` repository and enters this plan as an external contract gate.

**Tech Stack:** Rust 2024, Axum/Tokio, RustScript RSS programs, SQLite through generic `sqlite::*`, API Server HTTP/SSE, Telegram Bot API.

**Status:** Canonical agent-framework roadmap

---

## 1. Ownership boundary

| Layer | Owns | Excludes |
| --- | --- | --- |
| `rustscript-agent` native Rust | configuration, credentials, canonical domain envelopes, AgentService, run admission, platform adapters, event delivery, RSS program loading, capability-profile composition | private host functions, provider protocol parsers, hard-coded agent loop, direct SQL execution |
| Agent RSS | provider request/response mapping, conversation/tool loop, storage schema and SQL, tool registry, approval policy, compaction, subagent policy | raw threads, Tokio handles, direct descriptors, unrestricted network/files/process/database access |
| API Server / Telegram | normalize inbound platform data and render canonical events | provider calls, tool dispatch, storage rules, duplicate agent loops |
| `rustscript` external dependency | generic VM/compiler/runtime contracts | agent/provider/platform policy |

Repository invariant: `rustscript-agent` contains no `#[pd_host_function]` definition and no direct `rusqlite` execution path. Generic capability implementation belongs to `rustscript`; this roadmap does not prescribe its internal VM design.

## 2. External core contract gates

Agent milestones may consume these contracts after their owning `rustscript` plans meet target criteria:

| Contract | Owning core plan |
| --- | --- |
| Static callable identity and capability binding | `rustscript/plans/2026-08-09_static-builtin-id.md`, `2026-08-09_capability-profile-host-binding.md` |
| Exported invocation item stream and typed errors | `rustscript/plans/2026-08-09_run-outcome-event-error-contract.md` |
| Resource/operation/cancellation lifecycle | `rustscript/plans/2026-08-09_unified-host-lifecycle.md` |
| HTTP transport | `rustscript/plans/2026-08-09_http-transport-security-executor.md` |
| Reliable RSS module composition | `rustscript/plans/2026-08-09_nested-module-correctness.md` |
| Generic SQLite/filesystem/patch/process/task capabilities | Separate implementation-independent core capability plans when scheduled |

The agent repository does not duplicate any missing core capability as a private native shortcut.

## 3. Scope boundary and product boundary

### v1 platforms

- API Server with native session/run/event routes.
- OpenAI-compatible Chat Completions, streaming and non-streaming.
- Telegram polling with DM, group mention/reply, and forum-topic session mapping.

### v1 provider protocols

- OpenAI Chat Completions.
- OpenAI Responses.
- Anthropic Messages.
- Profiles for OpenRouter, DeepSeek, OpenCode Zen, OpenCode Go, and explicit custom endpoints.

Profiles supply endpoint/auth/model capability metadata. Protocol parsing remains in three shared RSS adapters.

### v1 tools

- file read/write/search;
- atomic patch;
- bounded foreground terminal;
- approvals;
- parallel independent tool calls;
- isolated subagents.

### Explicit exclusions

- TUI;
- durable cron/jobs;
- browser automation, MCP, media generation, or home automation;
- distributed scheduling;
- private agent/provider/Telegram host builtins;
- pd-edge as a runtime dependency;
- compatibility aliases for prototype `PD_EDGE_*` configuration names.

## 4. Canonical contracts

### 4.1 Inbound envelope

```text
platform
account_id
chat_id
thread_id?
user_id
message_id
session_hint?
content
attachments
command?
reply_to?
received_at
metadata
```

Default session identity derives from `(profile, platform, account_id, chat_id, thread_id)`.

### 4.2 Agent run context

```text
run_id
session_id
parent_run_id?
platform
input
messages
system_prompt
model
provider
provider_options
tool_schemas
limits
metadata
```

The context enters RSS as the sole argument to the exported `run(context)` callable. Ambient runtime input, JSON wrapper builtins, and source-string input injection are prohibited.

### 4.3 Canonical events

```text
run.started
model.started
model.delta
model.completed
tool.requested
approval.required
approval.resolved
tool.started
tool.output
tool.completed
compact.started
compact.completed
subagent.started
subagent.completed
run.completed
run.cancelled
run.failed
```

AgentService attaches run identity, timestamp, monotonic per-run sequence, typed payload, and parent identity where applicable when it consumes each core `Event(Value)` item. Core does not assign durable event identity or sequence.

### 4.4 Canonical provider model

RSS adapters map between provider wire formats and:

```text
LlmRequest
LlmEvent
LlmResponse
ProviderError
Usage
ToolCall
```

Unsupported model capabilities produce typed request/configuration errors. Unknown provider fields remain under explicit raw/provider-options fields.

### 4.5 Tool and approval contract

Each RSS tool descriptor contains name, description, JSON schema, toolset, risk class, dispatch function, and mapped generic capability. Native capability policy remains a hard upper bound. RSS approval policy can narrow access and pause/resume runs but cannot widen native roots, process, network, or database policy.

## 5. Target repository layout

```text
src/
  config.rs
  domain.rs
  events.rs
  service.rs
  runtime/
    rss_runner.rs
    capability_profiles.rs
    approval_bridge.rs
    delivery.rs
  gateway/
    api_server.rs
    api_openai.rs
    telegram.rs
    telegram_render.rs
    platform.rs
rss/
  agent/
  storage/
  harness/
  llm/
  providers/
migrations/
tests/
  contract/
  providers/
  harness/
  storage/
  runtime/
  gateways/
```

Shared domain/event contracts are integration-owned. Platform modules consume AgentService and cannot call providers or tools directly.

## 6. Implementation route

### Milestone A0: Freeze agent contracts and split the monolith

**Files:**
- Create: `src/config.rs`, `src/domain.rs`, `src/events.rs`, `src/service.rs`
- Split: `src/gateway.rs` into `src/gateway/**`
- Add: executable JSON fixtures under `tests/fixtures/`

**Criteria:** Existing gateway behavior remains passing; domain/event/provider/tool/storage command fixtures are validated; no private host function or direct SQL path is added.

### Milestone A1: Correct run lifecycle and live event service

Implement `plans/2026-08-09_agent-run-lifecycle-events.md`.

**Criteria:** structured run context reaches exported `run(context)` as an ordinary argument; the core stream yields zero or more `Event` items followed by one `Complete` item or typed error; AgentService owns sequencing, persistence, and delivery; cancellation and timeout are authoritative; admission is atomic.

### Milestone A2: Durable RSS-owned state

Implement `plans/2026-08-09_agent-durable-state.md`.

**Criteria:** sessions/messages/runs/events/approvals/compactions/parent links are transactional and recoverable through RSS storage commands.

### Milestone A3: Provider protocol adapters

**Files:**
- Create: `rss/llm/openai_chat.rss`
- Create: `rss/llm/openai_responses.rss`
- Create: `rss/llm/anthropic_messages.rss`
- Create profile modules under `rss/providers/`
- Add transcript fixtures and malformed/error/cancellation tests

**Criteria:** shared adapters handle non-stream/stream text, tool calls, usage, reasoning fields, provider errors, and cancellation; profiles reuse adapters without copied parsers.

### Milestone A4: Harness and approvals

**Files:**
- Create: `rss/harness/registry.rss`, `file.rss`, `patch.rss`, `terminal.rss`, `approval.rss`
- Create: `src/runtime/approval_bridge.rs`

**Criteria:** model schemas map to bounded generic capabilities; auto/manual/never/all approval modes pass; hard-deny policy remains native; pause/resume is durable.

**Status (2026-08-15):** Implemented as a single commit — see
`plans/2026-08-15_a4-harness-approvals.md`. `registry/file/patch/approval.rss`,
`approval_bridge.rs`, and focused harness/approval suites are green. The
bounded-foreground-terminal **timeout and command-args (argv) boundaries are a
CORE_BLOCKER** on the pinned core `fd4b570`: the generic `io::popen` has no
per-invocation timeout and only a shell-string form. `terminal.rss` reports a
typed `capability_unavailable` instead of fabricating bounded execution.

### Milestone A5: RSS agent loop and compaction

**Files:**
- Create: `rss/agent/main.rss`, `compact.rss`
- Add loop/compaction fixtures

**Criteria:** RSS completes model→tool→result→final rounds, enforces maximum turns/retry policy, emits canonical events, compacts complete historical prefixes without splitting tool pairs, and rolls back failed compaction.

### Milestone A6: Parallel tools and subagents

**Files:**
- Create: `rss/agent/parallel.rss`, `subagents.rss`
- Extend storage parent/child links and event fan-in

**Criteria:** bounded concurrency, ordered results, race/fail-fast semantics, depth/fanout budgets, parent cancellation, isolated child state, and no post-terminal side effects.

### Milestone A7: API Server

**Files:**
- Implement: `src/gateway/api_server.rs`, `api_openai.rs`

**Criteria:** auth, body/rate/idempotency limits, native run/session/event routes, OpenAI Chat Completions stream/non-stream, tool-call deltas, usage, approval resolution, and client-disconnect policy pass contract tests.

**Status (2026-08-16, branch `feat/agent-a7-api`):** the A7 REST/SSE dependency
wiring is implemented on top of the A5 production serial loop
(`e70db495bdf07593346f09ede250a7a4ce28bde5`):

- Run status (`GET /v1/runs/{run_id}`) and run list (`GET /v1/runs`) read the
  DURABLE store (`run.get` / `run.list`); the in-memory `started` placeholder
  is never a status source, so a run that never started can never be reported
  as started. The list supports `limit`/`offset`/`session_id`/`status` with
  bounded pagination (offset + limit ≤ 512 — the storage program's row page;
  a larger window is rejected typed, never silently truncated). The storage
  `run.list` filter was made optional for `session_id` (mirroring the existing
  optional `status` filter) so the unfiltered list stays a single bounded
  query.
- Approval resolution (`POST /v1/runs/{run_id}/approvals/{approval_id}/approve`
  and `/deny`) is wired to `AgentService::resolve_run_approval_for` (the
  shared exact-once core of `resolve_run_approval`): the resolution is keyed
  by run + approval id (a mismatch is a typed 409 and never consumes the
  park), the caller's `actor`/`reason` are recorded on the durable row, and
  the typed outcomes surface exactly-once (`approved`/`denied` 200,
  `already_resolved` 409, `no_pending_approval` 409, `expired` 200, storage
  failures 503) without string matching.
- Session compact (`POST /api/sessions/{session_id}/compact`) is an accurate
  typed unavailable (`501 compaction_unavailable`): compaction is driven by
  the serial agent loop INSIDE a run (the A5 `compact` decision — the loop
  plans a pair-preserving prefix with `compact.rss` and the service executes
  the planned commands while the run is durably `compacting`); there is no
  standalone session compaction entry, and the route never fakes success.
- Security boundaries: the new routes sit under the existing bearer-auth +
  per-IP/per-account rate-limit middleware, answer the canonical error
  envelope, and reject malformed bodies/query strings before any service
  work.
- OpenAI Chat Completions (`POST /v1/chat/completions`, stream false/true)
  is implemented (`src/gateway/api_openai.rs`, `tests/api_openai_tests.rs`):
  the route ONLY normalizes OpenAI inbound into the canonical
  AgentService/session/run contract and renders canonical durable/live
  events as OpenAI outbound responses — no provider wire parsing, no
  provider-adapter bypass, everything through the A5 production loop.
  Buffered requests wait for the durable terminal and return the official
  `chat.completion` shape (content, finish_reason, usage; `tool_calls`
  only from the FINAL provider round's `tool.started` events — the A5
  loop executes every tool round internally, so internal rounds never
  leak as client tool_calls); streaming emits SSE `data: {...}\n\n`
  chunks with per-turn BOUNDED buffering (the buffer is dropped when the
  round advances and flushed only when the terminal confirms the final
  response), an optional usage chunk (`stream_options.include_usage`), a
  typed error chunk on failure/cancellation (the SAME type derivation as
  the buffered 502/500 contract), a keep-alive heartbeat, and `[DONE]`
  last, with each chunk carrying the durable event sequence as the SSE
  `id` (Last-Event visibility), the bounded `x-request-id` header, and
  the configured client-disconnect policy applied through the subscriber
  guard. A `Lagged` live receiver recovers through the DURABLE catch-up
  (every event was persisted before publish — no silent loss).
  Per-request overrides (model/messages/system/user/assistant/tool/
  tool-result, tools/tool_choice, stream, stream_options.include_usage,
  bounded temperature [0,2]/top_p [0,1]/max_tokens/max_completion_tokens/
  user — the official OpenAI sampling ranges) enter the loop ONLY through
  the TYPED run context `request` map (`AdmitRunRequest::request_overrides`
  → `context["request"]`, consumed by the loop's `build_request`); the
  provider/profile, credentials, base_url, and allowlists stay
  gateway-config-owned (`reserved_field` rejection for any client
  attempt, `unknown_field`/`unsupported_field` for everything else — the
  explicit unknown-field policy, with every client parse failure mapping
  to the same 400 typed contract). The normalized conversation history is
  persisted INSIDE the `admission.create` transaction (session + messages
  + run + idempotency commit atomically), so a failed admission leaves no
  partial/orphan session and a replayed `Idempotency-Key` never creates
  a new one; a replayed admission NEVER spawns a second worker (provider
  calls and tool side effects stay exact-once) — the response attaches to
  the existing run's history/live stream instead. The route reuses the
  bearer / rate / body / idempotency (`Idempotency-Key`, request hash
  includes the bounded `user` metadata) guards, adds a bounded
  `x-request-id`, and is covered by 23 real-HTTP fixtures against the real
  router + real SQLite + real A5 loop + scripted provider (buffered text,
  model override, streamed text with usage, buffered/streamed tool rounds
  with real tool execution and exact-once provider call counts, typed
  provider error, stop-cancel, disconnect policy,
  malformed/unknown/reserved/oversize/auth/rate/idempotency incl. 409/429
  and mid-failure session counts, in-flight + concurrent same-key replay
  (one session, one worker), stream Lagged durable catch-up, SSE
  x-request-id, stream error type consistency, first-chunk role, tool-role
  array content preservation, official sampling ranges, multi-turn
  canonical message normalization). The canonical `model.completed`
  events now carry provider usage/stop_reason, `tool.started` carries the
  typed arguments, and the durable `run.completed` terminal persists the
  FINAL round's real usage and finish_reason (never fabricated zeros for
  reported usage).
- Follow-up (2026-08-16, branch `feat/agent-a7-openai-api`): the stream
  contract is explicit about the first chunk and overflow. The assistant
  role is carried by EXACTLY the first flushed delta/tool chunk and never
  repeated (pure-renderer unit tests assert the full chunk stream). The
  per-round TEXT buffer (4096 deltas / 256 KiB) and TOOL buffer (64 calls)
  overflow separately: text overflow falls back to the AUTHORITATIVE
  terminal text (lossless, buffered tool chunks preserved), while tool
  overflow ends the stream with the typed `stream_buffer_overflow` error
  chunk + `[DONE]` — never a silently truncated tool list. `tools: []` is
  an EXPLICIT client disable (the captured provider wire carries no tools),
  while OMITTING `tools` selects the registry's bounded tools.
  `max_events_per_run` defaults to 8192 (covering the 4096-delta + 64-tool
  stream bounds plus terminal events), the storage replay page cap is 16384
  (`event_replay_limits`; list-style queries keep the 512-row cap), and the
  janitor reclaims TERMINAL runs older than `durable_run_retention`
  (default 86400 s) through the typed `runs.prune_terminal` command
  (cascading events/retention/idempotency/links/approvals/compactions/
  usage/recovery); active, pending, and `terminal_pending` runs are never
  matched, so restart replay and the terminal retry loop stay intact. A
  terminal commit closes the run's broadcast sender, so a subscriber
  joining after the terminal replays history and ends immediately instead
  of waiting on the janitor TTL. The durable replay pages forward
  (`after_seq` cursor) so a terminal beyond the first page is still
  observed within the bounded wait, and the durable catch-up pages the same
  way. Coverage: 23 real-HTTP fixtures (was 22), 4 pure-renderer stream
  unit tests, the sender-close integration test, and the
  `runs.prune_terminal` storage test.

### Milestone A8: Telegram

**Files:**
- Implement: `src/gateway/telegram.rs`, `telegram_render.rs`

**Criteria:** deny-by-default allowlists, DM/group/topic mapping, deduplication, `/new`, `/stop`, `/compact`, `/status`, approvals, chunk/edit delivery, rate-limit retry, and restart behavior pass fixture tests.

### Milestone A9: Hardening and v1

**Criteria:** fault injection, cancellation races, storage migration/recovery, provider conformance, platform end-to-end tests, metrics/tracing, configuration reference, deployment guide, and release artifacts complete. No placeholder route is advertised.

## 7. Target criteria

- A Telegram message and an API request use the same AgentService/session/run model.
- A complete provider/tool loop is visible in RSS source.
- Native Rust contains no provider parser, agent loop, private host function, or SQL statement.
- Structured input fields are passed through the exported RSS entry argument and are preserved or rejected explicitly.
- Events are ordered, live, durable, replayable, and bounded.
- Parent cancellation reaches all child runs and active capabilities.
- Restart converts interrupted runs to a documented terminal state and retains replay history.
- No unbounded queue, event list, output buffer, provider request, or child fanout remains.
- API/Telegram adapters do not duplicate agent/provider/tool logic.

## 8. Verification matrix

```bash
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

Required suites cover contract fixtures, provider transcripts, harness policy, run lifecycle, durable state, API Server, Telegram, cancellation races, and restart recovery. Live paid APIs and real Telegram credentials are excluded from required CI.
