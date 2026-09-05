# RSS Tools and Rust Capabilities Design

**Status:** Approved

**Repository:** `rustscript-agent`

**Purpose:** Move every agent-facing tool definition and behavior into RustScript source while retaining security, resource ownership, cancellation, approval, and durable lifecycle enforcement in generic Rust capabilities.

## 1. Design constraint

Every tool visible to a model is an RSS-owned component.

RSS owns:

- public tool name and description;
- JSON Schema presented to the provider;
- registry order and enablement;
- argument validation and defaults;
- dispatch by public tool name;
- tool-specific algorithms and result formatting;
- tool-specific error mapping;
- composition of one or more native capabilities.

Rust owns only generic capabilities and runtime invariants that cannot safely depend on script cooperation.

Rust must not contain:

- a built-in list of model-visible tool names;
- model-visible tool descriptions or JSON Schemas;
- an enum with variants such as `ReadFile`, `Patch`, or `Terminal`;
- dispatch branches keyed by public tool names;
- tool-specific argument parsing or response formatting.

This boundary applies to current tools and future tools. Adding a model-visible tool must normally require an RSS change and tests, with no Rust registry change.

## 2. Current mismatch

The current implementation places the six public tools in `src/tools/*`:

- `registry.rs` owns the built-in ordering, schemas, risk classes and native executor mapping;
- `dispatch.rs` validates public arguments, selects `NativeToolExecutor`, manages execution and shapes `ToolResult`;
- `files.rs`, `terminal.rs` and `process.rs` contain model-visible behavior;
- `rss/agent/main.rss` delegates each call to `agent::tool_dispatch`.

That structure makes RSS the loop coordinator while Rust remains the actual tool platform. It prevents tool behavior from being authored, replaced and distributed as RSS modules.

## 3. Target module layout

### 3.1 RSS-owned tools

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

Each public tool module exports:

```text
pub fn descriptor() -> map
pub fn validate(arguments: map) -> map
pub fn execute(context: map, arguments: map) -> map
```

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

`validate()` returns a typed RSS result and cannot perform native effects.

`execute()` calls generic capabilities using the execution token supplied by the lifecycle layer and returns the canonical RSS `ToolResult` map.

`registry.rss` explicitly orders enabled descriptors. It canonicalizes the descriptor array before hashing and exports:

```text
pub fn descriptors(config: map) -> array
pub fn identity(config: map) -> map
pub fn find(name: string, config: map) -> map
```

`dispatch.rss` performs lookup, validation, lifecycle preparation, execution and final commit.

### 3.2 Generic Rust capabilities

Replace tool-domain Rust modules with:

```text
src/capabilities/
├── mod.rs
├── filesystem.rs
├── process.rs
├── lifecycle.rs
├── artifacts.rs
├── host.rs
└── types.rs
```

The capability layer may know operation names such as `fs_read_range`, `fs_write_atomic`, `process_spawn` and `process_poll`. These names describe native primitives and are never presented to a model.

Capability APIs are registered under namespaces separate from the agent tools:

```text
cap::fs_metadata(execution_token, path)
cap::fs_read_range(execution_token, path, offset, limit)
cap::fs_list(execution_token, path, cursor, limit)
cap::fs_write_atomic(execution_token, path, expected_hash, bytes)
cap::process_spawn(execution_token, argv, cwd, env_names, limits)
cap::process_poll(execution_token, process_handle, cursor, limit)
cap::process_write(execution_token, process_handle, bytes)
cap::process_kill(execution_token, process_handle)
cap::artifact_put(execution_token, bytes, metadata)
```

The exact host schema uses typed maps/resources supported by pd-vm. Public model tool descriptors never reuse these capability schemas.

## 4. Execution lifecycle

### 4.1 Preparation

RSS receives one provider tool call and validates it against the RSS descriptor. It then calls:

```text
agent_runtime::tool_prepare(metadata) -> map
```

Metadata contains:

- run ID;
- call ID;
- opaque public tool name;
- canonical argument digest;
- descriptor/registry identity;
- RSS risk classification;
- bounded sanitized summary.

Rust treats the name as opaque data. `tool_prepare` performs generic checks:

1. run and parent are active;
2. call ID/name match the durable assistant parent;
3. canonical terminal result is replayed when present;
4. run/tool-call limits permit another call;
5. approval policy permits execution;
6. `tool.started` is committed durably before capability access;
7. a scoped execution token is issued.

Return shape:

```json
{
  "kind": "execute",
  "execution_token": "opaque",
  "deadline_ms": 0
}
```

or:

```json
{
  "kind": "replay",
  "result": {}
}
```

### 4.2 Capability use

Each execution token is bound to:

- profile/session/run/call identity;
- frozen workspace directory capability;
- absolute deadline and cancellation token;
- approved risk ceiling;
- output/artifact budgets;
- process ownership;
- lifecycle generation.

A token cannot be reused by another call or after terminal commit. Native capability functions validate the token before every effect. RSS cannot mint or modify one.

One tool may invoke multiple capabilities. This supports RSS implementations such as `patch`: bounded read, RSS transformation, atomic compare-and-write.

### 4.3 Completion

RSS normalizes and bounds the result, then calls:

```text
agent_runtime::tool_commit(execution_token, result) -> map
```

Rust validates token ownership, commits the durable tool result and terminal tool event, closes the execution token, and returns the committed envelope.

If RSS terminates or panics with an open token, RAII cleanup marks the execution interrupted, cancels owned processes and prevents token reuse. Recovery never repeats an execution that has a canonical durable terminal result.

## 5. Tool algorithms in RSS

### 5.1 `read_file`

RSS validates path, offset and limit; it calls bounded read capability and adds line numbers and pagination metadata. Rust performs path confinement and byte I/O only.

### 5.2 `search_files`

RSS owns glob/regex options, pagination, ordering and output formatting. Rust exposes bounded directory iteration and bounded file reads. If performance later requires a native search iterator, it must remain a generic workspace search capability with no model-facing schema or formatting.

### 5.3 `write_file`

RSS validates input, reads current metadata/hash when needed and requests atomic replacement. Rust enforces root confinement, expected-hash compare, file mode policy and atomic write mechanics.

### 5.4 `patch`

RSS parses replacement/patch input, computes candidate content, checks uniqueness and formats a diff preview/result. Rust only supplies bounded read and atomic compare-and-write. No patch grammar or fuzzy-match strategy remains in Rust.

### 5.5 `terminal`

RSS validates command, cwd and user-facing options, then maps them to `cap::process_spawn`. Rust owns process-group creation, environment allowlist, cwd capability, time/output limits and cancellation.

### 5.6 `process`

RSS maps public actions to process capability operations and formats logs/status. Rust owns opaque process resources, authorization, bounded buffers, stdin/kill mechanics and cleanup.

## 6. Registry snapshot and provider contract

At run admission, Rust invokes the exported RSS registry function using the admitted agent source and non-secret tool policy. The returned descriptor array is:

1. structurally bounded by Rust;
2. canonicalized deterministically;
3. hashed;
4. stored in the run context as the frozen provider-facing registry snapshot.

Rust verifies generic limits for count, names, description bytes, schema bytes/depth and duplicate names. It does not supply built-in names, descriptions or schemas.

The frozen snapshot is sent to every provider request for that run. Resume recompiles/loads the same RSS source and verifies registry identity before continuing. A changed registry requires a new run or an explicit migration contract.

## 7. Approval boundary

RSS assigns the requested risk class in each descriptor. Rust policy maps the frozen descriptor identity and risk class to allow/ask/deny.

Approval records bind:

- run/call ID;
- registry identity;
- canonical argument digest;
- requested risk class;
- expiry.

RSS cannot lower risk after approval because `tool_prepare` compares the requested metadata with the frozen descriptor. A capability also checks that its native operation does not exceed the approved ceiling. For example, a read-approved token cannot call a write or process capability.

## 8. Failure and recovery behavior

- Invalid RSS arguments fail before `tool_prepare`; no durable started state or native effect occurs.
- A failed durable started commit returns a terminal dispatch error and no execution token.
- A capability error is converted by the RSS tool module into its public error contract, then committed once.
- A failed result commit after a native effect closes the execution token and fails the run; the capability is not repeated in-process.
- Restart inspects durable lifecycle state. Completed/failed/interrupted results replay. An execution left open at process death becomes interrupted through recovery policy and does not automatically repeat mutating effects.
- Process handles are run/call-owned and are cancelled during stop, deadline, source failure or gateway recovery.

## 9. Security properties

- Workspace authority originates in Rust admission, never in RSS strings.
- Every path capability resolves beneath the frozen root and resists symlink replacement.
- Every process starts in an authorized cwd with bounded environment, duration and output.
- RSS receives opaque handles/tokens only.
- RSS cannot call capabilities before durable preparation or after completion.
- Capability errors expose bounded neutral messages and no host absolute paths outside the workspace.
- Tool output/artifacts pass through existing secret redaction and byte caps before persistence/publication.
- Generic pd-vm host APIs that bypass these checks are omitted from the production agent catalog.

## 10. Migration sequence

1. Add RSS tool contract tests and generic capability interfaces while retaining old dispatch behind a test-only comparison path.
2. Move registry descriptors, ordering, schema validation and fingerprint source into RSS.
3. Implement lifecycle execution tokens and capability risk classes.
4. Migrate read-only file tools and compare exact fixture envelopes.
5. Migrate write/patch tools with atomic compare-and-write tests.
6. Migrate terminal/process tools with process ownership and restart tests.
7. Switch `rss/agent/main.rss` from `agent::tool_dispatch` to `tools::dispatch`.
8. Remove `NativeToolExecutor`, built-in registry entries and public tool-name branches from Rust.
9. Rename surviving generic modules from `tools` to `capabilities`.
10. Run full agent, gateway, Telegram, debug and release gates.

No compatibility shim remains in production after migration. Durable data compatibility is preserved because public tool names, call IDs, result roles and event contracts remain unchanged.

## 11. Test contract

### RSS tests

- descriptors and schemas for all six tools;
- deterministic registry identity;
- validation defaults and failures;
- dispatch routing;
- exact result envelopes;
- patch/search algorithms;
- terminal/process action mapping;
- provider tool-call to tool-result loop.

### Rust capability tests

- token ownership and single-close behavior;
- workspace confinement and symlink races;
- atomic compare-and-write;
- process group cancellation and output caps;
- approval ceiling enforcement;
- durable-before-effect preparation;
- replay and interrupted recovery;
- panic/unwind cleanup.

### Architecture tests

- Rust production source contains no built-in public tool registry.
- `src/capabilities` contains no public tool description/schema fixtures.
- `rss/tools` contains all model-visible descriptors.
- adding a fixture-only RSS tool requires no Rust enum/dispatch edit.
- production host catalog excludes unrestricted pd-vm file/process APIs.

### End-to-end tests

- real RSS agent loop executes every tool through generic capabilities;
- gateway restart replays canonical tool results without duplicate effects;
- stop/deadline cancels open process capabilities;
- approval blocks capabilities before effect;
- toolset snapshot remains identical across reopen;
- Telegram/API output remains compatible.

## 12. Acceptance criteria

1. Every model-visible tool is defined and implemented in `rss/tools`.
2. `rss/agent/main.rss` contains no call to `agent::tool_dispatch`.
3. Rust has no `NativeToolExecutor` or built-in public tool order.
4. Rust exposes generic capabilities and durable lifecycle functions only.
5. Workspace, process, approval, output and cancellation safeguards remain native and mandatory.
6. Existing public tool names and durable message/event contracts remain compatible.
7. A new RSS-only tool can be registered without editing Rust dispatch code.
8. Full locked debug and release suites pass from the final migration commit.
