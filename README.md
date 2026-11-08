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
RUSTSCRIPT_AGENT_SOURCE=bundled:coding \
RUSTSCRIPT_AGENT_ALLOW_HOSTS=api.example.com \
RUSTSCRIPT_AGENT_ALLOW_PORTS=443 \
RUSTSCRIPT_AGENT_BEARER_TOKEN='<secret>' \
RUSTSCRIPT_AGENT_STATE_DB=/var/lib/rustscript-agent/state.db \
cargo run --release --bin rustscript-agent-gateway
```

A present `config.yaml` `agent.source` is the authoritative agent source; a
present-but-invalid config source fails closed with no environment fallback.
Only when the config is missing does the gateway fall back to
`RUSTSCRIPT_AGENT_SOURCE`, then the deprecated `RUSTSCRIPT_AGENT_SCRIPT`, then
the bundled coding entry. A valid source is `bundled:coding`, or `file:` plus
an absolute path. Full environment-variable reference:
[docs/configuration.md](docs/configuration.md).
Deployment, systemd/container examples, shutdown and backup: [docs/deployment.md](docs/deployment.md).

## Status

This repository is **not v1-complete**. The table describes code in this
source checkout; it does not claim a published release, live-provider
availability, or final composed-candidate acceptance. Blocked or excluded
items are explicit, and no placeholder route is advertised.

| Area | Status |
| --- | --- |
| Single-run runner (`rustscript-agent --script … --allow-host …`) | Implemented |
| Gateway HTTP API: sessions, runs, SSE events, stop, jobs CRUD, subagent interrupt | Implemented (see [plans/2026-07-30_rustscript-agent-gateway-api.md](plans/2026-07-30_rustscript-agent-gateway-api.md)) |
| Durable SQLite state: sessions/messages/runs/events/jobs/approvals/compactions, restart recovery | Implemented |
| Gateway entry selection | A present `config.yaml` `agent.source` is authoritative; a missing config falls back to `RUSTSCRIPT_AGENT_SOURCE`, then the deprecated `RUSTSCRIPT_AGENT_SCRIPT`, then bundled `bundled:coding`. |
| Legacy chat completion path (`/api/sessions/{id}/chat`) | Legacy-constructor-only; production gateway selection via `RUSTSCRIPT_AGENT_SOURCE`, legacy `RUSTSCRIPT_AGENT_SCRIPT`, or bundled `bundled:coding` returns `501 agent_source_not_configured`. Normal coded-agent runs use `POST /v1/runs`. |
| OpenAI Chat Completions (`openai`, `openai_chat`, or default) | Current source has buffered and streaming requests through the opaque native credential transport; this is source status, not live-provider validation. |
| Codex Responses (`openai-codex` / `codex-responses`) | Access-only source path is present. Full refresh/lifecycle support is not claimed here. |
| Generic custom Responses adapter (explicit adapter selection) | Not implemented; returns typed `not_implemented` and sends no request. |
| Anthropic Messages | Not implemented; remains a typed `not_implemented` stub. |
| API hardening (A7): bounded per-peer-IP/per-account rate limiting, client-disconnect policy | Implemented (disabled by default; see [docs/configuration.md](docs/configuration.md)) |
| Observability (A9): bounded metrics registry, `GET /metrics`, structured terminal tracing | Implemented (see [docs/deployment.md](docs/deployment.md)) |
| RSS coding loop + durable compaction policies (A5) | The gateway's bundled coding entry runs through the agent worker; compaction policies remain implemented and tested (`rss/agent/compact.rss`). |
| RSS coding tools + workspace-confined loop | Implemented for the library worker: `read_file`, `search_files`, `write_file`, `patch`, `terminal`, `process` run serially through `rss/tools/dispatch.rss`. Local E2E: `cargo test --test coding_agent_e2e_tests` and `cargo test --test coding_agent_edge_e2e_tests`. See [docs/configuration.md](docs/configuration.md). Parallel tools remain excluded (A6). |
| Approval execution chain (A4) | Implemented for tool dispatch: durable approval records, `ask` policy for write/process, HTTP and Telegram approve/reject, one typed terminal result. A general-purpose harness layer beyond tool approval remains excluded. |
| Parallel tools and subagents (A6) | Not implemented (excluded from the current milestone scope) |
| Scheduled / durable job execution | **Not implemented (explicitly excluded)**. Job CRUD, pause/resume, and latest-output routes exist, but there is no scheduler; `POST /api/jobs/{id}/run` is intentionally absent and answers `404`. |
| Telegram gateway (A8) | **Implemented**: native Bot API transport (https/rustls), deny-by-default account/chat/user allowlists, durable delivery cursors (at-least-once), bounded 429/5xx/401 retries, fail-closed first-boot drain, bounded shutdown drain. See [docs/deployment.md](docs/deployment.md). |

The bounded `config.yaml` / `auth.yaml` loaders and production
`config::load_snapshot` bridge exist. Package-level end-to-end config/auth/provider
acceptance, final composed-candidate acceptance, and remote delivery remain
open.

Current lifecycle/reliability behavior is covered by the integration
suites in `tests/` (admission, bounded delivery, terminal-commit retries,
restart recovery, storage stalls, coding-agent E2E). CI runs them with
`cargo test --locked --all-features --all-targets`. The main coding
workflow E2E is `cargo test --test coding_agent_e2e_tests`. Cancellation
and output-limit edges are `cargo test --test coding_agent_edge_e2e_tests`.
