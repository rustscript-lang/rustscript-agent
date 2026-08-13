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
| Provider protocol adapters (OpenAI Chat/Responses, Anthropic Messages, provider profiles) | **Partial — blocked by core (A3)**. Wire building, standard-shape guard, marker-preservation, and structured provider errors are green; buffered response parsing, streaming, and the Responses/Anthropic adapters stay typed `not_implemented` stubs until core compiler defects are fixed. See [plans/2026-08-13_a3-provider-core-blocker.md](plans/2026-08-13_a3-provider-core-blocker.md). |
| RSS agent loop + compaction (A5) | **Not implemented — blocked**. Requires the A3 core contract gates; no `rss/agent/` source exists in this revision. |
| Harness and approvals (A4) | Not implemented (excluded from the current milestone scope) |
| Parallel tools and subagents (A6) | Not implemented (excluded from the current milestone scope) |
| Scheduled / durable job execution | **Not implemented (explicitly excluded)**. Job CRUD, pause/resume, and latest-output routes exist, but there is no scheduler; `POST /api/jobs/{id}/run` is intentionally absent and answers `404`. |
| Telegram gateway (A8) | Not implemented |

Current lifecycle/reliability behavior is covered by the integration
suites in `tests/` (admission, bounded delivery, terminal-commit retries,
restart recovery, storage stalls); CI runs them with
`cargo test --locked --all-features --all-targets`.
