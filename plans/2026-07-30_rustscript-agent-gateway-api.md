# RustScript Agent Framework Implementation Plan

**Goal:** Build a standalone RustScript-driven agent framework with API Server and Telegram gateways, durable sessions, provider adapters, tool policy, compaction, and subagent orchestration.

**Architecture:** Native Rust owns configuration, secrets, platform I/O, service lifecycle, event delivery, and composition of generic RustScript capabilities. RSS owns agent policy: provider protocol mapping, conversation/tool loop, SQL/schema, approvals, compaction, and subagent policy. Core VM/compiler/runtime work is tracked only in the `rustscript` repository and enters this plan as an external contract gate.

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
| Structured run result, live events, typed errors | `rustscript/plans/2026-08-09_run-outcome-event-error-contract.md` |
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

The context enters RSS as a structured runtime value. Source-string input injection is prohibited.

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

Every event carries run identity, timestamp, monotonic per-run sequence, typed payload, and parent identity where applicable.

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

**Criteria:** structured run context reaches RSS, result/event channels remain separate, cancellation and timeout are authoritative, admission is atomic, and events are available during execution.

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
- Structured input fields are preserved or rejected explicitly.
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
