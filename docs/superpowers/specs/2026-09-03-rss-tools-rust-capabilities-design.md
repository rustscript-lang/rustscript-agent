# RSS tools and Rust capability boundary

**Status:** current design

**Repository:** `rustscript-agent`

This document describes the boundary between agent-visible tools and native
capabilities as implemented in this revision. It supersedes the migration
plan that introduced the split; the source tree, not this document, is the
authority for exact function names.

## 1. Design constraint

Every tool visible to a model is an RSS-owned component.

RSS owns:

- the public tool name and description;
- the JSON Schema presented to the provider;
- registry order and enablement;
- argument validation and defaults;
- dispatch by public tool name;
- tool-specific algorithms and result formatting;
- tool-specific error mapping;
- composition of one or more native capabilities.

Rust owns only generic capabilities and runtime invariants that cannot safely
depend on script cooperation.

Rust must not contain:

- a built-in list of model-visible tool names;
- model-visible tool descriptions or JSON Schemas;
- an enum with public-tool variants;
- dispatch branches keyed by public tool names;
- tool-specific argument parsing or response formatting.

Adding a model-visible tool normally requires an RSS change and tests, with no
Rust registry change.

## 2. Current layout

RSS tool modules:

```text
rss/tools/
├── types.rss
├── registry.rss
├── validate.rss
├── dispatch.rss
├── read_file.rss
├── search_files.rss
├── write_file.rss
├── patch.rss
├── terminal.rss
└── process.rss
```

Each tool also has a thin entry module (`read_file_entry.rss`,
`search_files_entry.rss`, and so on) that adapts the host invocation context.
The public descriptor, validation, execution, and result semantics stay in the
main module.

Native capability modules:

```text
src/capabilities/
├── mod.rs
├── types.rs
├── host.rs
├── lifecycle.rs
├── filesystem.rs
├── confined_io.rs
├── process.rs
├── artifacts.rs
└── hash.rs
```

`src/runtime/agent_host.rs` registers the tool-lifecycle functions
`agent_runtime::tool_prepare` and `agent_runtime::tool_commit`; their host-map
adapters live in `src/capabilities/host.rs`.

`src/registry.rs` contains the structural `ToolRegistrySnapshot`: it bounds,
validates, and freezes the descriptors exported by RSS. Its identity is used
for consistency checks, not authorization.

## 3. RSS module contracts

Each public tool module exports `descriptor()` and the shared `invoke()`
entry. The file tools additionally export `validate(arguments)` and
`execute(context, arguments)`; `terminal` and `process` keep validation and
execution internal to the module because their action handling is
config-bound.

`descriptor()` returns the canonical provider-facing structure:

```json
{
  "name": "read_file",
  "description": "...",
  "input_schema": {},
  "risk_class": "read",
  "toolset": "coding"
}
```

`validate()` returns a typed RSS result and performs no native effects.
`execute()` calls generic capabilities using the execution token supplied by
the lifecycle layer and returns the canonical tool result. `invoke()` is the
shared entry used by the dispatch table.

`registry.rss` orders enabled descriptors, canonicalizes the descriptor array
for identity, and exports:

```text
pub fn descriptors(config: map) -> array
pub fn identity(config: map) -> map
pub fn find(name: string, config: map) -> map
```

`dispatch.rss` performs lookup, validation, lifecycle preparation, execution,
and final commit. The current route table is a name-to-RSS-callable map
covering the six built-in tools; `dispatch`, `invoke_prepared`, and the
pre-approval check share that table. A registry hit with no route fails closed
before any native prepare or effect.

Built-in public tools and arguments:

```text
read_file(path, offset?, limit?)
search_files(pattern, path?, target?, file_glob?, limit?, offset?)
write_file(path, content)
patch(path, old_string, new_string, replace_all?)
terminal(argv, cwd?, timeout_ms?, max_output_bytes?, stdin?)
process(action, process_id, data?, timeout_ms?, offset?, limit?)
```

Every tool result uses the common envelope:

```json
{
  "ok": true,
  "content": "model-visible text",
  "data": {},
  "error": null,
  "truncated": false,
  "artifacts": []
}
```

A failed call returns `ok=false` with at least `error.code` and
`error.message`. Model-visible output and durable event payloads obey byte
limits; oversized output is stored in the bounded artifact store and exposed
through opaque artifact ids. `terminal` accepts an argv array, never a shell
command string.

## 4. Capability names

RSS composes native primitives through the `cap::*` namespace. Current
primitives include:

```text
cap::fs_metadata(execution_token, path)
cap::fs_read_range(execution_token, path, offset, limit)
cap::fs_list(execution_token, path, cursor, limit)
cap::fs_write_atomic(execution_token, path, expected_hash, bytes)
cap::process_spawn(execution_token, argv, cwd, env_names, limits)
cap::process_poll(execution_token, process_handle, cursor, limit)
cap::process_log(execution_token, process_handle, cursor, limit)
cap::process_write(execution_token, process_handle, bytes)
cap::process_kill(execution_token, process_handle)
cap::process_close(execution_token, process_handle)
cap::artifact_put_result(execution_token, bytes, metadata)
cap::clock_monotonic_ms()
```

These names describe native primitives and are never presented to a model.
Public tool descriptors never reuse these capability schemas.

## 5. Execution lifecycle

### 5.1 Preparation

RSS receives one provider tool call and validates it against the RSS
descriptor. It then calls:

```text
agent_runtime::tool_prepare(metadata) -> map
```

Metadata contains the run ID, call ID, opaque public tool name, canonical
argument identity, descriptor/registry identity, RSS risk classification, and
a bounded sanitized summary. Rust treats the name as opaque data.
`tool_prepare` checks run/parent activity, durable replay, run and tool-call
limits, approval policy, and then commits `tool.started` before issuing a
scoped execution token.

Return shape:

```json
{"kind": "execute", "execution_token": "opaque", "deadline_ms": 0}
```

or a durable replay envelope carrying the committed result.

### 5.2 Capability use

Each execution token is bound to profile/session/run/call identity, the frozen
workspace capability, an absolute deadline and cancellation token, the
approved risk ceiling, output/artifact budgets, process ownership, and a
lifecycle generation. A token cannot be reused by another call or after
terminal commit. Native capability functions validate the token before every
effect. RSS cannot mint or modify one.

One tool may invoke multiple capabilities; `patch`, for example, performs a
bounded read, an RSS transformation, and an atomic compare-and-write.

### 5.3 Completion

RSS normalizes and bounds the result, then calls:

```text
agent_runtime::tool_commit(execution_token, result) -> map
```

Rust validates token ownership, commits the durable tool result and terminal
tool event, closes the execution token, and returns the committed envelope.

If RSS terminates with an open token, cleanup marks the execution interrupted,
cancels owned processes, and prevents token reuse. Recovery never repeats an
execution that has a canonical durable terminal result.

## 6. Registry snapshot and provider contract

The bundled registry is loaded by compiling and running
`rss/tools/registry.rss` with `{"kind":"descriptors","config":{}}`. The
returned descriptor array is structurally bounded, canonicalized, given an
identity, and retained as the native `ToolRegistry`. At run admission the
current snapshot is cloned into the run context as the frozen
provider-facing registry snapshot.

Rust verifies generic limits for count, names, description bytes, schema
bytes/depth, and duplicate names. It does not supply built-in names,
descriptions, or schemas.

The frozen snapshot is sent to every provider request for that run. Resume
recompiles or reloads the same RSS source and verifies registry identity
before continuing. A changed registry requires a new run.

## 7. Approval boundary

RSS assigns the requested risk class in each descriptor. Rust policy maps the
frozen descriptor identity and risk class to allow/ask/deny. Approval records
bind run/call ID, registry identity, canonical argument identity, requested
risk class, and expiry.

RSS cannot lower risk after approval: `tool_prepare` compares requested
metadata with the frozen descriptor, and a capability checks that its native
operation does not exceed the approved ceiling. A read-approved token cannot
call a write or process capability.

The `ask` flow is durable: before `tool.started` or a native effect, the
gateway records an `approval.request` row; approve/reject is exposed through
HTTP and Telegram; the same durable tool call resumes after approval with
revalidation of name, arguments, and parent. Rejection, expiry, stop, and
restart produce one typed terminal tool result with no native effect.

## 8. Failure and recovery behavior

- Invalid RSS arguments fail before `tool_prepare`; no durable started state
  or native effect occurs.
- A failed durable started commit returns a terminal dispatch error and no
  execution token.
- A capability error is converted by the RSS tool module into its public
  error contract, then committed once.
- A failed result commit after a native effect closes the execution token and
  fails the run; the capability is not repeated in-process.
- Restart inspects durable lifecycle state. Completed, failed, and interrupted
  results replay. An execution left open at process death becomes interrupted
  through recovery policy and does not automatically repeat mutating effects.
- Process handles are run/call-owned and are cancelled during stop, deadline,
  source failure, or gateway recovery.

## 9. Security properties

- Workspace authority originates in Rust admission, never in RSS strings.
- Every path capability resolves beneath the frozen root and resists symlink
  replacement.
- Every process starts in an authorized cwd with a bounded environment,
  duration, and output.
- RSS receives opaque handles and tokens only.
- RSS cannot call capabilities before durable preparation or after completion.
- Capability errors expose bounded neutral messages and no host absolute paths
  outside the workspace.
- Tool output and artifacts pass through the existing secret redaction and
  byte caps before persistence or publication.
- Production host catalogs omit unrestricted pd-vm file and process APIs that
  bypass execution-token checks.

## 10. Verification anchors

The boundary is exercised by the RSS tool registry and dispatch suites
(`tests/rss_tool_registry_tests.rs`, `tests/rss_tool_dispatch_tests.rs`),
capability lifecycle tests (`tests/capability_lifecycle_tests.rs`,
`tests/capability_tests.rs`), process/pinned-tool tests
(`tests/rss_process_tool_tests.rs`, `tests/tools_pin_*`), and the real
coding-agent loop (`tests/coding_agent_e2e_tests.rs`,
`tests/coding_agent_edge_e2e_tests.rs`). Architecture tests assert that Rust
production source contains no built-in public tool registry or name-keyed
dispatch.
