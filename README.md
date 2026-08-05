# rustscript-agent

A small independent runner for agents written in RustScript (`.rss`). The runner owns only program loading, HTTP policy configuration, host binding, and the VM `Waiting` → resume driver. Provider protocol, prompt state, turn limits, tool-call handling, and final output remain in the RustScript source.

## Run

```bash
cargo run --release -- \
  --script examples/http_get.rss \
  --allow-host api.example.com
```

The HTTP host is deny-by-default. Every destination must be explicitly allowlisted. The runner enables the RustScript `http-client` feature and does not provide an upstream agent or model adapter.

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

The gateway is part of this independent repository. It uses the `pd-edge` library crate for edge/runtime integration and the RustScript `pd-vm` crate for RSS execution; `pd-edge` does not contain the gateway business layer.

```bash
PD_EDGE_AGENT_SCRIPT=examples/http_get.rss \
PD_EDGE_AGENT_ALLOW_HOSTS=api.example.com \
cargo run --release --bin rustscript-agent-gateway
```

Optional configuration includes `PD_EDGE_AGENT_STATE_DB`, `PD_EDGE_AGENT_BEARER_TOKEN`, `PD_EDGE_AGENT_GATEWAY_ADDR`, `PD_EDGE_AGENT_ALLOW_SCHEMES`, and `PD_EDGE_AGENT_ALLOW_PORTS`.
