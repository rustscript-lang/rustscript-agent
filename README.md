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
| Gateway HTTP API: sessions, runs, SSE events, stop, jobs CRUD, subagent interrupt | Implemented (see [plans/2026-07-30_rustscript-agent-gateway-api.md](plans/2026-07-30_rustscript-agent-gateway-api.md)) |
| Durable SQLite state: sessions/messages/runs/events/jobs/approvals/compactions, restart recovery | Implemented |
| Legacy chat completion path (`/api/sessions/{id}/chat`) | Implemented; requires `RUSTSCRIPT_AGENT_SCRIPT`, otherwise answers `501 agent_source_not_configured` |
| API hardening (A7): bounded per-peer-IP/per-account rate limiting, client-disconnect policy | Implemented (disabled by default; see [docs/configuration.md](docs/configuration.md)) |
| Observability (A9): bounded metrics registry, `GET /metrics`, structured terminal tracing | Implemented (see [docs/deployment.md](docs/deployment.md)) |
| Provider protocol adapters (OpenAI Chat/Responses, Anthropic Messages, provider profiles) | **Partial — OpenAI Chat and Anthropic Messages are production**. OpenAI Chat (buffered+streaming) and Anthropic Messages (buffered+streaming) implement the full `/v1/messages` and chat-completions wire contract: text/tool calls/usage/reasoning, standard-shape and marker-preservation guards, structured provider errors, stream error events, cancellation, and EOF fail-closed. OpenAI Responses remains a typed `not_implemented` stub. See [plans/2026-08-13_a3-provider-core-blocker.md](plans/2026-08-13_a3-provider-core-blocker.md). |
| RSS serial loop + durable compaction policies (A5) | **Policies implemented and tested** (`rss/agent/main.rss`, `rss/agent/compact.rss` with executable suites); the production entry is **not wired** into the gateway/service yet (blocked by A3/A4). See [plans/2026-08-13_a5-scope-split.md](plans/2026-08-13_a5-scope-split.md). |
| Harness and approval machinery (A4) | Not implemented (excluded from the current milestone scope); approval **repository** CRUD exists, there is no approval flow driving runs |
| Parallel tools and subagents (A6) | Not implemented (excluded from the current milestone scope) |
| Scheduled / durable job execution | **Not implemented (explicitly excluded)**. Job CRUD, pause/resume, and latest-output routes exist, but there is no scheduler; `POST /api/jobs/{id}/run` is intentionally absent and answers `404`. |
| Telegram gateway (A8) | **Implemented**: native Bot API transport (https/rustls), deny-by-default account/chat/user allowlists, durable delivery cursors (at-least-once), bounded 429/5xx/401 retries, fail-closed first-boot drain, bounded shutdown drain. See [docs/deployment.md](docs/deployment.md). |

Current lifecycle/reliability behavior is covered by the integration
suites in `tests/` (admission, bounded delivery, terminal-commit retries,
restart recovery, storage stalls); CI runs them with
`cargo test --locked --all-features --all-targets`.
