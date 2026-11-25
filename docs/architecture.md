# Architecture

`rustscript-agent` splits control policy from host authority: RustScript (`.rss`) decides what the agent should do, while Rust decides what the process is permitted to do and when state becomes durable.

## Responsibility split

| RustScript owns | Rust owns |
| --- | --- |
| Agent loop, provider selection and protocol adaptation | HTTP/Telegram ingress, request normalization, authentication, and rate limits |
| Prompt/message shaping, turn limits, compaction policy, and tool dispatch | Atomic admission, deadlines, cancellation, capacity, and run sequencing |
| Guardian review policy and `allow` / `deny` / `needs_user` decisions | Capability issuance, user-approval handoff, filesystem/process confinement, and secret custody |
| Declarative storage commands and plugin manifests | SQLite worker, durable-before-visible publication, graph capture/pinning, effect journal, and restart repair |

The owning implementations are the bundled [`rss/agent`](../rss/agent/), [`rss/llm`](../rss/llm/), [`rss/tools`](../rss/tools/), and [`rss/storage`](../rss/storage/) modules on the policy side, and [`AgentService`](../src/service.rs), the [gateway](../src/gateway/), [capabilities](../src/capabilities/), [effects](../src/effects/), and [plugins](../src/plugins/) on the native side. The storage SQL is expressed in RSS, but Rust controls the worker, transaction boundary, sequencing, and in-memory publication.

## Typed host boundary

The public host catalog uses descriptor-owned named structs rather than untyped maps for closed shapes. [`src/runtime/host_types.rs`](../src/runtime/host_types.rs) declares fixed provider, capability, process, approval, tool, and plugin-state envelopes. Open provider/plugin JSON crosses as bounded serialized text and is audited in [`src/runtime/host_compose.rs`](../src/runtime/host_compose.rs).

The boundary preserves three distinct concepts:

- `Unit` represents an operation with no value.
- `Option<T>` uses the core's explicit tagged carrier; `None`, `Some(())`, and nested options remain distinct.
- `Result<T, E>` is validated as its declared carrier and is not reconstructed from a null or an ad hoc `{ok: ...}` map.

[`src/runtime/host_shapes.rs`](../src/runtime/host_shapes.rs) converts only schema-owned legacy nullable leaves and delegates final validation to the VM. Ambiguous nulls, duplicate wrapping, invalid resource handles, and undeclared dynamic returns fail closed. Typed-boundary regressions are exercised by [`tests/native_callback_result_composite_rss_tests.rs`](../tests/native_callback_result_composite_rss_tests.rs), [`tests/rss_tools_contract_tests.rs`](../tests/rss_tools_contract_tests.rs), and the host-catalog audits in [`src/runtime/host_compose.rs`](../src/runtime/host_compose.rs).

## Admission snapshot and run lifecycle

`POST /v1/runs` enters [`AgentService::admit_external_with_workspace_selector`](../src/service.rs). Admission uses one capacity permit and one absolute cancellation deadline across every preparation attempt. Slow prompt, workspace, storage, and plugin preparation runs outside the global commit gate. The commit phase then revalidates the relevant inputs and atomically publishes the durable admission plus its in-memory handle.

The frozen admission context includes:

- session history and parent run;
- model and provider profile;
- tool registry and run limits;
- canonical workspace binding and native workspace authority;
- coding prompt and project guidance;
- active or checkpoint-selected plugin graph, package refs, and callable capture;
- deadline, cancellation token, and idempotency identity.

A rejected admission leaves no partial session, message, run, event, pin, or live permit. The implementation and contention/deadline regressions live in [`src/service.rs`](../src/service.rs), [`tests/run_lifecycle_tests.rs`](../tests/run_lifecycle_tests.rs), and [`tests/provider_durable_replay_loop_tests.rs`](../tests/provider_durable_replay_loop_tests.rs).

After admission, the worker drives the exported RSS `run(context)` stream. Rust commits `run.started`, provider/tool lifecycle events, and exactly one terminal transition. Stop, deadline, disconnect, and gateway halt request typed cancellation; a run remains durably `running` until the terminal commit succeeds. Live SSE delivery follows durable state and is at-least-once.

## Durable session, run, and event state

With `RUSTSCRIPT_AGENT_STATE_DB`, [`GatewayPersistence`](../src/gateway/store.rs) serializes SQLite commands through the compiled [`rss/storage/main.rss`](../rss/storage/main.rss) program. Durable state covers sessions, messages, runs, events, jobs, approvals, compactions, idempotency receipts, plugin locks/activations/refs, plugin state, and managed-effect records.

Writes are durable before they become visible in the in-memory store or live event stream. Event IDs and message IDs are stable for provider turns and tool calls, while per-run sequence numbers define replay order. Terminal commits retry within bounded limits; an uncommitted terminal remains observable as `terminal_pending` instead of being reported as complete.

The store migrates and repairs interrupted rows before rebuilding memory. Loading is cursor-paginated with row and byte bounds rather than a single unbounded query. See [`src/gateway/store.rs`](../src/gateway/store.rs), [`rss/storage/load.rss`](../rss/storage/load.rss), and [`tests/storage_tests.rs`](../tests/storage_tests.rs).

## Effect prepare, review, commit, and rollback

Tool execution has a native lifecycle rather than a direct guest-to-OS call:

1. **Prepare:** validate the frozen registry identity, owner, risk, arguments, deadline, cancellation, graph pin, and workspace head; issue an opaque execution token or return an existing durable replay.
2. **Review:** apply configured read/write/process policy. Guardian evaluates a bounded action preview. A decision may allow, deny, or request a user decision.
3. **Execute:** a token-scoped host performs the confined filesystem/process/artifact operation. RSS never receives raw native authority.
4. **Commit:** persist canonical tool events, the result message, effect receipt, and any managed tree publication before broadcasting them.
5. **Rollback or fence:** abandon uncommitted private state when absence is proven. An indeterminate commit keeps the owner/fence for reconciliation rather than guessing that the effect failed.

The generic token lifecycle is in [`src/capabilities/lifecycle.rs`](../src/capabilities/lifecycle.rs). Managed tree preparation and native authority are in [`src/effects/broker.rs`](../src/effects/broker.rs); durable event/result composition is in [`src/service/managed_effects.rs`](../src/service/managed_effects.rs). Managed rollback covers private workspace state. Process or other effects outside the tree are explicitly recorded as not reverted; no general rollback of external systems is claimed.

## Guardian and user handoff

[`rss/agent/guardian.rss`](../rss/agent/guardian.rss) owns the review decision schema and fail-closed policy. Its valid outcomes are:

- `allow`: execute under the already prepared native scope;
- `deny`: persist refusal and do not execute;
- `needs_user`: publish one durable pending approval for the original run and suspend that call.

The HTTP approval routes and Telegram buttons resolve only the pending durable row. Resolution does not mint a broader grant, and replay cannot reuse a one-time decision for another call. Malformed or unavailable Guardian output fails closed. The handoff is covered by [`tests/guardian_sandbox_policy_tests.rs`](../tests/guardian_sandbox_policy_tests.rs) and [`tests/provider_durable_replay_loop_tests.rs`](../tests/provider_durable_replay_loop_tests.rs).

## Plugin graph pinning

Plugin administration installs immutable package captures, resolves a closed graph, prepares it, and moves a generationed activation pointer. A new run does not execute from caller-provided `graph_id` data: native admission reads the active/checkpoint graph, validates its lock and package refs, captures the callable, and commits the graph ID, activation generation, and ref with the run.

A replay returns the original pin without consulting a newer activation. Existing runs therefore retain their admitted graph across a hot cut; revocation and missing artifacts fail closed. The control metadata is in [`src/plugins/control_store.rs`](../src/plugins/control_store.rs), and the admission/recovery invariant is implemented in [`src/plugins/pin.rs`](../src/plugins/pin.rs) and tested by [`tests/tools_pin_production_ab.rs`](../tests/tools_pin_production_ab.rs).

## Restart and replay

Restart processing distinguishes completed work from work whose outcome is unknown:

- completed provider steps replay their durable response without another provider call;
- retry-safe pending provider requests may retry the same logical turn;
- unsafe or effectful pending provider requests become typed interruptions;
- committed tool results replay without running the tool or incrementing metrics again;
- open capability tokens and owned children are interrupted and cleaned up;
- interrupted runs receive one terminal repair, and pending compactions are failed;
- managed branches derive writer ownership from bounded durable history and remain unresolved if the proof is incomplete.

See [`src/durable_provider.rs`](../src/durable_provider.rs), the recovery paths in [`src/service.rs`](../src/service.rs), [`src/gateway/store.rs`](../src/gateway/store.rs), and managed restart derivation in [`src/effects/broker.rs`](../src/effects/broker.rs). Restart and lost-ack scenarios are covered by [`tests/provider_durable_replay_loop_tests.rs`](../tests/provider_durable_replay_loop_tests.rs), [`tests/effect_commit_recovery_tests.rs`](../tests/effect_commit_recovery_tests.rs), and [`tests/plugin_store_recovery_tests.rs`](../tests/plugin_store_recovery_tests.rs).

## Capability boundaries

Authority is native, scoped, and revocable:

- HTTP is deny-by-default for schemes, hosts, ports, redirects, sizes, timeouts, and private addresses.
- File tools resolve beneath the admitted canonical workspace; managed mode writes private object trees instead of the source directory.
- Process tools execute `argv` directly, bind child handles to one run/token generation, meter output, and clean up owned children on cancellation or shutdown.
- Provider credentials remain opaque native resources; sanitized metadata can cross into RSS, raw secrets cannot.
- Plugin management requires both verified bearer ingress and a trusted host-side install authorization.
- Checkpoint, restore, branch, publish, and effect-query operations require native workspace authority and persistent state.

The concrete limits are canonical in [Configuration](configuration.md). Security boundaries are also exercised by [`tests/capability_tests.rs`](../tests/capability_tests.rs), [`tests/effect_workspace_tests.rs`](../tests/effect_workspace_tests.rs), [`tests/native_auth_contract_tests.rs`](../tests/native_auth_contract_tests.rs), and [`tests/plugin_admin_api_tests.rs`](../tests/plugin_admin_api_tests.rs).
