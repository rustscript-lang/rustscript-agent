# A4 Harness and Durable Approvals — Implementation Status and CORE_BLOCKER

Date: 2026-08-15
Branch: `feat/agent-a4-harness`
Base: `300114df834685ce0a102daa1aae5a882a6aed7a`
Core pin: `fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e` (unchanged)

## 1. Scope delivered (single A4 commit)

The A4 milestone in `plans/2026-07-30_rustscript-agent-gateway-api.md` §6 is
delivered as a **single coherent commit**. It maps model tool schemas to
bounded generic capabilities, composes the A2 approvals storage into a durable
native approval bridge, and keeps the native hard-deny authoritative.

### Files

| File | Purpose |
|---|---|
| `rss/harness/registry.rss` | Tool registry: maps `file.read`, `file.write`, `patch.apply`, `terminal.run` model schemas to bounded generic capabilities (`io.file` / `io.process`) and their native risk class. Pure policy; no I/O. |
| `rss/harness/file.rss` | Bounded `file.read` / `file.write` via generic `io::*`. Native root/symlink/traversal safety, write gate, and byte limits come from the configured `IoPolicy`. |
| `rss/harness/patch.rss` | Bounded `patch.apply`: literal-context replacement with typed `context_not_found` failure that leaves the file unchanged. Native root/write/byte bounds enforced by `IoPolicy`. |
| `rss/harness/terminal.rss` | Bounded foreground terminal policy. Because the generic process capability is blocked (see §3), it returns a typed `capability_unavailable` (`process_timeout_unavailable`) rather than fabricating bounded execution. |
| `rss/harness/approval.rss` | Approval policy: `auto`/`manual`/`never`/`all` modes, with a `native_hard_deny` input that cannot be widened by any mode. |
| `src/runtime/approval_bridge.rs` | Native durable approval bridge composing the A2 storage program. Persists pending, exactly-once resume after approval, typed terminal on deny/expire, native hard-deny. No direct SQL; no private host function. |
| `tests/harness_tests.rs` | 13 focused harness suites (registry, file, patch, approval modes + native hard-deny, terminal blocker). |
| `tests/approval_bridge_tests.rs` | 6 durable approval-bridge suites over real SQLite (exactly-once, deny terminal, expire sweep, native deny, orphan rejection). |
| Native wiring | `AgentConfig.io: IoPolicy`, `AgentGatewayConfig.io: IoPolicy`, `configure_io` in the runner, `io::*` allowed in the restricted registry, `docs/configuration.md` documents the new `io` field. |

### Native wiring (generic capability only)

`src/runtime/rss_runner.rs` now:
- carries an `IoPolicy` on `AgentConfig` (and `AgentGatewayConfig`);
- calls `vm.configure_io(...)` in `prepare_vm`;
- allows the generic `io::open`, `io::read_all`, `io::read_line`, `io::write`,
  `io::flush`, `io::close`, `io::exists`, `io::popen` builtins in the
  restricted registry.

No `#[pd_host_function]`, no direct file/process implementation, no direct
SQL, and no agent-private builtin was added. Native Rust composes the generic
core `io::*` capability and configures roots/write/process/byte bounds; RSS
policy can only narrow them.

## 2. Confirmed generic capability surface at core `fd4b570`

The pinned core exposes the generic **filesystem and process** capability via
namespaced `io::*` builtins with a configurable `IoPolicy`:

- `IoPolicy { allowed_roots, allow_write, allow_process, max_read_bytes,
  max_write_bytes }`
- path authorization canonicalizes the target (and its parent for
  not-yet-existing files) and requires `canonical.starts_with(root)`, which
  closes symlink and `..` traversal escapes;
- `io::open` rejects writes unless `allow_write`, and mode gates read/write;
- `io::read_all` / `io::read_line` / `io::write` enforce `max_read_bytes` /
  `max_write_bytes`;
- `io::popen` requires `allow_process` (native hard deny by default);
- the async bridge (already implemented in `rss_runner.rs`) drives the io
  futures; reachability confirmed with a minimal compile/run repro before
  implementation.

`file.rss` and `patch.rss` therefore get native root / size / output /
symlink-traversal safety for free from `IoPolicy`; a write outside the root
terminates the run with a typed `InvocationError::Capability`, never a partial
read or a fabricated success.

## 3. CORE_BLOCKER — bounded foreground terminal

The A4 requirement that `terminal` must enforce a **timeout** and **command
arguments (argv)** safety boundary is **not satisfiable** by the generic
process capability at the pinned core:

| Boundary | Generic `io::*` at `fd4b570` |
|---|---|
| root / write / output / size | native `IoPolicy` (roots, `allow_write`, byte caps) |
| process gate | native `allow_process` (hard deny by default) |
| **timeout** | **absent** — `io::popen(command, mode)` has no per-invocation timeout; only a 1 s *cleanup* wait exists on close |
| **command args (argv)** | **absent** — `io::popen` accepts only a shell string (`sh -c`), not a structured argv array |

`terminal.rss` therefore returns a typed `capability_unavailable` /
`process_timeout_unavailable` decision for every foreground command and never
claims a bound the generic capability cannot enforce. This is an honest
reflection of the boundary, not a placeholder or a fabricated success.

### Precise missing symbols / feature

- Missing: a generic process-execution builtin with an explicit per-invocation
  timeout parameter, e.g. `io::popen` extended to
  `io::popen(command: string, mode: string, timeout_ms: int, argv: array)` (or
  a separate `io::run(argv: array, timeout_ms: int, output_max_bytes: int)`).
- Missing: `IoPolicy` / process capability enforcement of `timeout_ms` and a
  structured argv array (the current host spawns a shell string via `sh -c`).

### Minimal repro

`tests/harness_tests.rs::terminal_without_timeout_is_blocked_with_typed_unavailable`
demonstrates the current behavior (typed `capability_unavailable`). To see the
capability gap in the core directly:

```rust
// configure_io with allow_process: true; call:
//   io::popen("sleep 3600", "r") then io::read_all(handle)
// -> blocks until the process exits; there is no timeout argument and no
//    argv array to bound the call.
```

### Suggested core contract

A generic process capability, parallel to how `IoPolicy` already bounds file
roots/writes/bytes, that takes an argv array and a `timeout_ms` and enforces
both natively (killing the process group on timeout, capping stdout by
`max_read_bytes`). RSS `terminal.rss` would then map the model command+args to
this bounded capability and enforce `root`-style allowlists; the native
`allow_process` gate remains the hard upper bound.

Until that core contract exists, the agent does **not** add a private process
builtin or a direct process implementation as a substitute.

## 4. Criteria matrix

| Criterion | Status |
|---|---|
| model schemas map to bounded generic capabilities | GREEN (registry.rss + file/patch via `io::*`) |
| auto/manual/never/all approval modes pass | GREEN (approval.rss, 5 suites) |
| hard-deny policy remains native | GREEN (native `IoPolicy` + `approval_bridge::NativeDenyPolicy`; cannot be widened by mode) |
| pause/resume is durable | GREEN (approval_bridge over real A2 storage: persisted pending, exactly-once resume, typed terminal on deny/expire) |
| file/patch root, size, output, symlink/traversal safety | GREEN (native `IoPolicy`) |
| terminal timeout + command-args boundaries | **BLOCKED** (core process capability, §3) |

## 5. Verification

```bash
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/a4-target
export TMPDIR=/mnt/TEMP/rustscript/a4-tmp
cargo test --locked --test harness_tests          # 13 passed
cargo test --locked --test approval_bridge_tests  # 6 passed
cargo test --locked --workspace --all-targets     # regression gate
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

Not pushed; no provider adapters, A6, or A5 production loop touched. A4 plan
status updated only within this scope.
