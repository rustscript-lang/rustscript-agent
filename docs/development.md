# Development

## Repository layout

| Path | Purpose |
| --- | --- |
| [`src/service.rs`](../src/service.rs) and [`src/service/`](../src/service/) | Atomic admission, run lifecycle, approvals, compaction, managed completion, and plugin administration. |
| [`src/gateway/`](../src/gateway/) | Axum API, Telegram adapter, workspace/plugin/effect routes, and RSS-backed persistence worker. |
| [`src/runtime/`](../src/runtime/) | RSS compilation/execution, closed bundles, typed host catalog, adapters, cancellation, and delivery. |
| [`src/capabilities/`](../src/capabilities/) | Token lifecycle and confined filesystem, process, and artifact capabilities. |
| [`src/effects/`](../src/effects/) | Managed workspace object store, effect journal, checkpoints, publications, authority, and restart fences. |
| [`src/plugins/`](../src/plugins/) | Manifest/schema validation, immutable packages, graph resolution/preparation, activation state, and run pins. |
| [`rss/`](../rss/) | Bundled agent, provider, auth, tool, configuration, and storage policy. |
| [`tests/`](../tests/) | Integration roots, shared support, fixtures, and consolidated case modules. |
| [`schemas/`](../schemas/) | Plugin manifest/lock/state contracts and canonical generated snapshots. |
| [`docs/`](.) | Product, architecture, API, configuration, deployment, development, and maturity references. |

## Toolchain and scratch space

CI selects Rust `1.99`; this checkout is verified with `1.99.1`. Keep Cargo locked to the manifest/lockfile pin.

Integration fixtures require runner-owned scratch directories outside the checkout. CI creates one root and exports all three supported aliases:

```bash
export RUSTSCRIPT_AGENT_TEST_TMP=/absolute/private/scratch
export RUSTSCRIPT_AGENT_TEST_TMPDIR="$RUSTSCRIPT_AGENT_TEST_TMP"
export TEST_TMPDIR="$RUSTSCRIPT_AGENT_TEST_TMP"
```

Tests create unique private children below that root. They must not write generated state into the repository.

## Focused tests

Run the narrow owner first and confirm the filter executes at least one test:

```bash
# Documentation/configuration/deployment drift and links
cargo +1.99.1 test --locked --all-features --test docs_contract_tests

# Every bundled RSS source
cargo +1.99.1 test --locked --all-features --test rss_corpus_compile_tests

# Router and gateway contracts
cargo +1.99.1 test --locked --all-features --test gateway_contract_tests

# Coding loop and cancellation/output edges
cargo +1.99.1 test --locked --all-features --test coding_agent_e2e_tests
cargo +1.99.1 test --locked --all-features --test coding_agent_edge_e2e_tests

# Managed effect commit/recovery and plugin pinning
cargo +1.99.1 test --locked --all-features --test effect_commit_recovery_tests
cargo +1.99.1 test --locked --all-features --test tools_pin_production_ab
```

For an individual case, keep the integration target explicit:

```bash
cargo +1.99.1 test --locked --all-features \
  --test docs_contract_tests relative_markdown_links_resolve -- --exact
```

## Full CI gates

The canonical workflow is [`.github/workflows/ci.yml`](../.github/workflows/ci.yml):

```bash
cargo +1.99.1 fmt --all -- --check
cargo +1.99.1 clippy --locked --all-features --all-targets -- -D warnings
cargo +1.99.1 test --locked --all-features --all-targets
git diff --check
```

CI also requires the tracked and untracked working tree to remain clean after the gates.

## Bundled RSS corpus

[`tests/rss_corpus_compile_tests.rs`](../tests/rss_corpus_compile_tests.rs) discovers sources programmatically instead of freezing a count. At this revision it finds **88** bundled sources: **87** under `rss/` and **1** under `examples/`.

With `config-fixture`, all 88 compile through their real host catalogs. Without it, only the exact historical fixture entries `rss/auth/oauth_flow.rss`, `rss/auth/store_entry.rss`, and `rss/auth/config_entry.rss` are reported as unavailable; every other discovered source compiles against the production agent catalog. Production modules, libraries without a run export, and new files are all included automatically.

Recheck the inventory before editing a count:

```bash
python3 -c 'from pathlib import Path; print(sum(1 for d in ("rss", "examples") for _ in Path(d).rglob("*.rss")))'
```

## Consolidated integration roots

Cargo treats each top-level `tests/*.rs` file as a separate integration binary. The current tree has **63** such roots. Related cases are consolidated below those roots with `#[path = "..."] mod ...;`; for example:

- [`tests/docs_contract_tests.rs`](../tests/docs_contract_tests.rs) owns documentation, domain, and contract cases from `tests/cases/`;
- [`tests/gateway_contract_tests.rs`](../tests/gateway_contract_tests.rs) owns gateway/API case modules;
- [`tests/effect_commit_recovery_tests.rs`](../tests/effect_commit_recovery_tests.rs) owns the effect recovery matrices;
- larger reusable fixtures live in [`tests/support/`](../tests/support/) rather than becoming independent Cargo targets.

At this revision, `tests/cases/` contains **86** Rust case modules. Recheck both inventories programmatically before documenting a changed count:

```bash
python3 -c 'from pathlib import Path; print("roots", len(list(Path("tests").glob("*.rs")))); print("cases", len(list(Path("tests/cases").glob("*.rs"))))'
```

When adding a case, attach it to the narrowest existing root. Add a new top-level root only when it needs a distinct feature gate, binary environment, or isolation boundary.

## Fixture timing conventions

Compilation, process startup, and the behavior under test have different clocks:

- Start a **setup/readiness budget** before cold compilation or gateway startup. Shared gateway bounds live in [`tests/support/gateway_ready.rs`](../tests/support/gateway_ready.rs).
- Start the operation's own deadline only after its readiness marker or required setup has completed. Do not make a short authority/deadline assertion pay for unrelated cold compilation.
- Use one absolute deadline per phase and pass it through nested waits; do not reset the clock on every poll.
- On timeout, report whether the child exited, readiness was missing, or the operation exceeded its own bound. Preserve those as separate failures.
- Timing-sensitive targets should run alone at their normal within-target concurrency when qualifying them; cross-target pressure is a separate stress run.

Exact-child fixtures should use an owned marker containing the exact test name, parent PID, and nonce, then invoke the current test executable with `--exact`. Require the child exit code, `running 1 test`, the named test result, and the final libtest summary before accepting the result. [`tests/plugin_store_recovery_tests.rs`](../tests/plugin_store_recovery_tests.rs) contains this pattern.

## Child ownership and cleanup

A fixture that spawns a process owns cleanup on success, error, panic, and timeout:

- [`tests/support/owned_child.rs`](../tests/support/owned_child.rs) kills and waits for synchronous children and can isolate a Linux process group.
- [`tests/support/owned_async_child.rs`](../tests/support/owned_async_child.rs) enables Tokio `kill_on_drop`, then synchronously reaps as a last resort.
- Drain stdout and stderr concurrently with bounded capture so a full pipe cannot deadlock the child or consume unbounded memory.
- On observer failure, request cancellation or release test gates first, then kill/reap and join owned workers before propagating the assertion.
- Never leave a background child, process group, paused gate, or immutable test tree for a later case to clean up.

These conventions are part of fixture correctness: a passing assertion with an unreaped child or a reset deadline does not qualify the lifecycle being tested.
