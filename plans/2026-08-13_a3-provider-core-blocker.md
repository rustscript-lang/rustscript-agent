# A3 Provider Adapter Core Blocker

Date: 2026-08-13
Branch: `scope/agent-a3`
Core checkout: `/mnt/TEMP/rustscript/agent-roadmap/rustscript` at `plan/callable-stream-integration` (06b37fd)

## Status

A3 "shared adapters handle non-stream/stream text, tool calls, usage, reasoning
fields, provider errors, and cancellation; profiles reuse adapters without
copied parsers" is **partially blocked** by a core compiler defect. One test
suite (`openai_chat_provider_error_is_structured`) is green; the remaining
non-stream suites and all streaming work are `#[ignore]`d until the core is
fixed (see `tests/provider_tests.rs` module doc).

## Symptom

With the production adapter module layout (`rss/llm/openai_chat.rss`: multiple
map parameters, cross-module accessor results, same-module helpers, struct
types), the VM fails calls at runtime with

```
Invocation(Vm(TypeMismatch("callable argument schema")))
Invocation(Vm(TypeMismatch("callable return schema")))
Invocation(Vm(TypeMismatch("string")))
```

even though every runtime value is correctly typed. The guard lives in
`rustscript/src/vm/mod.rs::enter_script_frame` (~line 1205): it compares each
operand against the compiler-emitted `TypeSchema::Callable` prototype schema.
The emitted schemas are corrupted (wrong parameter shapes/counts, wrong
return schemas) for a subset of call sites in non-root modules.

## Verified, avoidable trigger (already worked around in the adapter)

In a function with **two map parameters**, string-reading fields of the
**first** map parameter and passing the **second** map onward to another
script function corrupts the callee's prototype schema. Reading the *second*
map parameter instead is safe.

Repro: `hop4_m2.rss` fails; `hop13_m2.rss` (identical except the read moves
to the second map parameter) passes.
Repro files: `/mnt/TEMP/rustscript/scratch-a3/repro/hop4_m2.rss`,
`hop13_m2.rss` (plus `chain_m1.rss` accessor module and `hop*_root.rss`
drivers).

Workaround applied: `openai_chat_complete_dispatch(request, profile)` and
`openai_chat_stream_dispatch(request, profile)` read profile fields from the
**second** map parameter. See the comment in `rss/llm/openai_chat.rss`.

## Verified, non-avoidable trigger (blocks the parse path)

Calling a script function with an **array value produced by a cross-module
accessor** (`types::request_array(...)` and friends) corrupts the callee's
schema. Inline arguments, typed element annotations (`array<map>`,
`array<string>`), intermediate locals, and same-module materialization
helpers all fail identically. The corruption is module-layout dependent: the
identical call works in small modules and fails in the full adapter module,
so no source restructuring in this repository can reliably avoid it.

Minimal repro (fails):

```rss
// root_splice.rss — run with the driver in tests (see commands below)
use self::chain_m1 as types;

pub fn run(context: map) -> map {
    let request: map = context["request"];
    let tools: array = types::request_array(request, "tools");
    let body: string = splice("{}", tools);
    { kind: "ok", body: body }
}

fn splice(body: string, tools: array) -> string {
    body
}
```

`root_splice2.rss` (same call with a literal `[]` argument) passes, which
isolates the trigger to the cross-module array value.

Additional compile-time limitations of the same revision (worked around in
the adapter source):

- Annotated `let` statements whose initializer type the checker cannot prove
  (`json::encode` results, literals inside branches, same-module helpers) are
  rejected when placed inside expression-if branches
  (`json_enc_e.rss`, `letif_a.rss`) or in the branch of a **tail**
  expression-if (`tailif_m2.rss`). Statement-if bodies are fine.
- `bytes::to_utf8` requires a concretely typed argument; annotate the body
  local as `bytes` first (`bytes_b.rss` fails, `bytes_a.rss` passes).

## Exact commands

```bash
# Core blocker repro (runtime): compile + run root_splice.rss through the agent runner
cd /mnt/TEMP/rustscript/agent-roadmap/a3
CARGO_TARGET_DIR=/mnt/TEMP/rustscript/agent-roadmap/target-a3 \
  cargo test --test blocker_repro7_tmp -- --nocapture   # (temp driver, deleted before commit)
# Expect:
#   ROOTSPLICE root_splice:   Err(Invocation(Vm(TypeMismatch("callable return schema"))))
#   ROOTSPLICE root_splice2:  Ok(...)   # literal-array control passes
#
# Full adapter flow: the four ignored suites fail at runtime with the same family:
cargo test --test provider_tests -- --ignored
```

The repro sources live under `/mnt/TEMP/rustscript/scratch-a3/repro/`
(`chain_m1.rss` provides the accessor module; `hop*`, `fullchain*`,
`splice*`, `tailif*`, `letif*`, `bytes_*`, `json_enc_*` cover each trigger).

## Core unblock conditions

A fix in `rustscript` (outside this repository's scope) must make the
emitted `TypeSchema::Callable` for every script prototype match the declared
parameter/return types regardless of call-site inference in non-root
modules. Concretely:

1. Calls inside statement-if bodies in imported modules must not corrupt
   callee schemas (currently `TypeMismatch("callable argument schema")`).
2. Array-typed values returned by host/cross-module calls must not corrupt
   the callee's return schema (`TypeMismatch("callable return schema")`).
3. Annotated lets inside expression-if branches must resolve to their
   declared schema (strict-typing rejection).

## What is committed and green

- `rss/llm/types.rss` — canonical contract (request accessors, response/error
  builders, call results).
- `rss/llm/openai_chat.rss` — buffered adapter: wire building, tool-schema
  splicing, response/error parsing (compiles; structured provider-error
  mapping verified end to end by the green suite).
- `rss/llm/harness.rss` — test dispatch entry (no protocol logic).
- `rss/providers/*.rss` — OpenRouter, DeepSeek, OpenCode Zen, OpenCode Go,
  custom profiles reusing the shared adapter (no copied parsers).
- `tests/provider_tests.rs` — fixture server infrastructure, canonical
  request/profile construction, 1 green suite, 7 documented ignored suites.
- `tests/fixtures/providers/**` — transcripts for chat buffered/stream,
  responses, anthropic, and error/malformed payloads.
- `src/runtime/rss_runner.rs` — restricted registry now exposes
  `bytes::from_utf8`/`bytes::to_utf8` and `http::client::sse`; the
  `configure_http` result is propagated; stream polling holds a Tokio
  context (from the earlier session's uncommitted work).

## Still open when the core clears

- Buffered response parsing suites (text/usage/reasoning, tool calls,
  malformed payload, invalid JSON).
- `openai_chat_stream` implementation (`http::client::sse` chunk
  aggregation) plus its text/usage, tool-call chunk aggregation, and typed
  cancellation suites.
- `openai_responses` and `anthropic_messages` adapters (currently typed
  `not_implemented` stubs) with their buffered/streaming transcripts.
