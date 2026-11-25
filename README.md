# rustscript-agent

`rustscript-agent` is a standalone agent runtime with **agent policy in RustScript and authority/durability in Rust**. RSS programs own the model loop, provider adaptation, tool routing, approval policy, and compaction decisions; the Rust host owns admission, capabilities, durable state, effect commits, and transport.

## Core properties

- **Script-owned behavior:** the bundled coding loop, provider dispatch, Guardian review, and tool registry live under [`rss/`](rss/).
- **Typed host boundary:** named host shapes preserve `Unit`, `Option<T>`, and `Result<T, E>` semantics instead of inferring variants from JSON nulls.
- **Atomic admission:** each run freezes its session context, provider profile, tool registry, workspace authority, limits, prompt, deadline, and plugin graph before execution.
- **Durable lifecycle:** SQLite-backed sessions, messages, runs, events, approvals, graph pins, and effect receipts support restart repair and replay without reissuing completed work.
- **Reviewed effects:** tool calls pass through prepare, Guardian or user review, native execution, and durable commit; managed workspace mutations use private trees and explicit publication.
- **Fail-closed authority:** HTTP, filesystem, process, credential, workspace, and plugin-control capabilities are bounded and deny by default unless the native host grants them.

## Quick start

Start the gateway with the immutable bundled coding entry:

```bash
RUSTSCRIPT_AGENT_SOURCE=bundled:coding \
RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS=1 \
cargo run --release --bin rustscript-agent-gateway
```

Anonymous mode is for local evaluation. Production deployments should configure bearer authentication, persistent state, provider credentials, and network allowlists; see [Configuration](docs/configuration.md) and [Deployment](docs/deployment.md).

The request path is compact:

```text
HTTP / Telegram
  -> Rust admission snapshot and durable run
  -> RSS provider + agent + Guardian policy
  -> Rust capability/effect boundary
  -> durable messages, events, receipts, and publications
```

## Documentation

- [Architecture](docs/architecture.md) — RSS/native ownership, typed boundaries, lifecycle, effects, replay, and capability fences
- [HTTP API](docs/api.md) — implemented route families and lifecycle semantics
- [Configuration](docs/configuration.md) — canonical environment, embedding, capability, and provider settings
- [Deployment](docs/deployment.md) — source builds, state, operations, shutdown, backup, systemd, and containers
- [Development](docs/development.md) — repository layout, focused tests, CI, RSS corpus, and fixture conventions
- [Status](docs/status.md) — detailed capability and maturity matrix, including explicit exclusions

## Build and test

The repository uses Rust 1.99 in CI and pins RustScript Core at `11c9ee908a29365bd02573311f56e9308eb7dbe6`.

```bash
cargo +1.99.1 build --locked
cargo +1.99.1 test --locked --all-features --test docs_contract_tests
cargo +1.99.1 test --locked --all-features --all-targets
cargo +1.99.1 fmt --all -- --check
```

## Current maturity

The gateway, durable run lifecycle, serial coding tools, approvals, managed effects, plugin graph pinning, and Telegram transport are implemented in the current source tree. The project remains pre-v1: provider coverage is uneven, scheduled execution and parallel tools/subagents are excluded, and final remote-provider acceptance remains open. See the [status matrix](docs/status.md).

## Related projects

- [RustScript Core](https://github.com/rustscript-lang/rustscript) — language, compiler, VM, and host SDK
- [RustScript specification](https://github.com/rustscript-lang/spec) — language specification
- [pd-edge](https://github.com/rustscript-lang/pd-edge) — RustScript edge runtime and ABI
- [pd-controller](https://github.com/rustscript-lang/pd-controller) — control plane for RustScript edge deployments
- [RustScript Playground](https://github.com/rustscript-lang/playground) — browser playground
- [RustScript website and documentation](https://github.com/rustscript-lang/website)
