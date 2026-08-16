# rustscript-agent

A small independent runner for agents written in RustScript (`.rss`). The runner owns only program loading, HTTP policy configuration, host binding, and the VM `Waiting` → resume driver. Provider protocol, prompt state, turn limits, tool-call handling, and final output remain in the RustScript source.

## Run

```bash
cargo run --release -- \
  --script examples/http_get.rss \
  --allow-host api.example.com
```

The HTTP host is deny-by-default. Every destination must be explicitly allowlisted (hosts **and** ports; see [Configuration](docs/configuration.md)). The runner enables the RustScript `http-client` feature and does not provide an upstream agent or model adapter.

## Library API

```rust
use rustscript_agent::{AgentConfig, AgentRunner};

let runner = AgentRunner::from_file(
    "agent.rss",
    AgentConfig::for_hosts(["api.example.com"]),
)?;
let result = runner.run()?;
```

The current scope is intentionally synchronous at the Rust API boundary: a pending HTTP host operation is driven internally through the VM's blocking wait/resume path. A future gateway can expose the same VM lifecycle asynchronously without moving agent behavior into Rust.

## Hermes-compatible gateway

The gateway is part of this independent repository. It uses the RustScript `pd-vm` crate for RSS execution and does not depend on the `pd-edge` gateway runtime.

```bash
RUSTSCRIPT_AGENT_SCRIPT=examples/http_get.rss \
RUSTSCRIPT_AGENT_ALLOW_HOSTS=api.example.com \
RUSTSCRIPT_AGENT_ALLOW_PORTS=443 \
RUSTSCRIPT_AGENT_BEARER_TOKEN='<secret>' \
RUSTSCRIPT_AGENT_STATE_DB=/var/lib/rustscript-agent/state.db \
cargo run --release --bin rustscript-agent-gateway
```

Full environment-variable reference: [docs/configuration.md](docs/configuration.md).
Deployment, systemd/container examples, shutdown and backup: [docs/deployment.md](docs/deployment.md).

## Status

This repository is **not v1-complete**. The table states the current
revision's real status; blocked or excluded items are explicit, and no
placeholder route is advertised.

| Area | Status |
| --- | --- |
| Single-run runner (`rustscript-agent --script … --allow-host …`) | Implemented |
| Gateway HTTP API: sessions, runs (create/get/list/stop), SSE events, approval approve/deny, jobs CRUD, subagent interrupt | Implemented (see [plans/2026-07-30_rustscript-agent-gateway-api.md](plans/2026-07-30_rustscript-agent-gateway-api.md)); run status/list read the DURABLE store (`run.get`/`run.list`), never the in-memory placeholder |
| Session compact route (`POST /api/sessions/{id}/compact`) | Implemented as **accurate typed unavailable** (`501 compaction_unavailable`): compaction is driven by the serial agent loop inside a run (A5 `compact` decision); no standalone session compaction entry exists, and the route never fakes success |
| Durable SQLite state: sessions/messages/runs/events/jobs/approvals/compactions, restart recovery | Implemented |
| Legacy chat completion path (`/api/sessions/{id}/chat`) | Implemented; requires `RUSTSCRIPT_AGENT_SCRIPT`, otherwise answers `501 agent_source_not_configured` |
| API hardening (A7): bounded per-peer-IP/per-account rate limiting, client-disconnect policy | Implemented (disabled by default; see [docs/configuration.md](docs/configuration.md)) |
| Observability (A9): bounded metrics registry, `GET /metrics`, structured terminal tracing | Implemented (see [docs/deployment.md](docs/deployment.md)) |
| Provider protocol adapters (OpenAI Chat/Responses, Anthropic Messages, provider profiles) | **Partial — OpenAI Chat, OpenAI Responses, and Anthropic Messages are production**. OpenAI Chat (buffered+streaming) and Anthropic Messages (buffered+streaming) implement the full `/v1/messages` and chat-completions wire contract: text/tool calls/usage/reasoning, standard-shape and marker-preservation guards, structured provider errors, stream error events, cancellation, and EOF fail-closed. OpenAI Responses (buffered+streaming) implements the `/responses` wire contract with the same guards. See [plans/2026-08-13_a3-provider-core-blocker.md](plans/2026-08-13_a3-provider-core-blocker.md). |
| RSS serial loop + durable compaction policies (A5) | Implemented and wired into the gateway: `rss/agent/main.rss` + `rss/agent/compact.rss` run through `AgentGatewayState::with_default_agent_program*` (the built-in default agent), driving model→tool→result rounds, durable approvals with exact-once wait/resume, and durable compaction. See [plans/2026-08-15_a5-production-serial-loop.md](plans/2026-08-15_a5-production-serial-loop.md). |
| Harness and approval machinery (A4) | Implemented: `registry/file/patch/approval.rss` + `src/runtime/approval_bridge.rs` with durable exact-once approvals; the bounded foreground terminal remains a typed `capability_unavailable` core gap. See [plans/2026-08-15_a4-harness-approvals.md](plans/2026-08-15_a4-harness-approvals.md). |
| Parallel tools and subagents (A6) | Typed non-executable handoff (the serial loop folds `parallel.handoff`/`subagent.handoff` into a typed terminal until the A7 run-admission interface wires the native supervisor) |
| Scheduled / durable job execution | **Not implemented (explicitly excluded)**. Job CRUD, pause/resume, and latest-output routes exist, but there is no scheduler; `POST /api/jobs/{id}/run` is intentionally absent and answers `404`. |
| Telegram gateway (A8) | **Implemented**: native Bot API transport (https/rustls), deny-by-default account/chat/user allowlists, durable delivery cursors (at-least-once), bounded 429/5xx/401 retries, fail-closed first-boot drain, bounded shutdown drain, and the A5 wiring — `/run` (real admission with a durable run-id echo; bare `/run` is a usage error), `/stop` (typed cancel, parked approvals cancelled immediately), `/status` (durable state), `/new` (session reset), `/compact` (typed availability), and `/approve`/`/deny` (durable approval resolution gated on the run's durable origin actor — foreign/non-owner/owner-less ids are byte-identical to unknown ids, the actor/reason persisted). See [docs/deployment.md](docs/deployment.md). |

Current lifecycle/reliability behavior is covered by the integration
suites in `tests/` (admission, bounded delivery, terminal-commit retries,
restart recovery, storage stalls); CI runs them with
`cargo test --locked --all-features --all-targets`.
