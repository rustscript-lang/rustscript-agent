# A3 Provider Adapter Core Blocker

Date: 2026-08-13 (updated 2026-08-13 after agent-side review pass)
Branch: `scope/agent-a3`
Core checkout: `/mnt/TEMP/rustscript/agent-roadmap/rustscript` at `plan/callable-stream-integration` (06b37fd)

## Status

A3 "shared adapters handle non-stream/stream text, tool calls, usage, reasoning
fields, provider errors, and cancellation; profiles reuse adapters without
copied parsers" is **partially blocked** by core compiler defects. Two suites
are green (`openai_chat_provider_error_is_structured` and the P1 wire-format
guard `openai_chat_wire_format_is_standard`); the remaining non-stream suites
and all streaming work are `#[ignore]`d until the core is fixed (see
`tests/provider_tests.rs` module doc).

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

## Verified, avoidable trigger (worked around in the adapter)

In a function with **two map parameters**, string-reading fields of the
**first** map parameter and passing the **second** map onward to another
script function corrupts the callee's prototype schema. Reading the *second*
map parameter instead is safe.

Repro: `hop4_m2.rss` fails; `hop13_m2.rss` (identical except the read moves
to the second map parameter) passes.
Repro files: `tests/fixtures/core-repros/hop4_m2.rss`, `hop13_m2.rss` (plus
`chain_m1.rss` accessor module and `hop*_root.rss` drivers).

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
    let body: string = splice("{", tools);
    { kind: "ok", body: body }
}

fn splice(body: string, tools: array) -> string {
    body
}
```

`root_splice2.rss` (same call with a literal `[]` argument) passes, which
isolates the trigger to the cross-module array value.

## Verified stream blocker (closure capture, independent of layout)

The pure-text stream path (`http::client::sse` callback aggregating text
deltas, usage, `[DONE]`) cannot be expressed in this core revision: the
frontend availability pass rejects closures that **assign to a captured
local** (`local 'state' was moved earlier; use 'state.copy()' ...`), because
any assignment inside a closure body forces `CaptureBindingMode::Move` for
the captured slot. This is a compile-time rejection, independent of module
layout — even a root-module probe fails identically. There is no shared
accumulator mechanism left for the callback, so `openai_chat_stream` stays a
typed `not_implemented` stub and `http::client::sse` is **not exposed** in
the restricted registry (it has no consumer). The core test suite proves the
SSE transport itself works; only the script-side aggregation pattern is
unavailable.

## Additional compile-time limitations of the same revision (worked around in the adapter source)

- Annotated `let` statements whose initializer type the checker cannot prove
  (`json::encode` results, literals inside branches, same-module helpers) are
  rejected when placed inside expression-if branches
  (`tests/fixtures/core-repros/json_enc_e.rss`, `letif_a.rss`) or in the
  branch of a tail expression-if (`tailif_m2.rss`). Statement-if bodies are
  fine.
- `bytes::to_utf8` requires a concretely typed argument; annotate the body
  local as `bytes` first.

## Green survival call sites (verified end to end)

The following paths run green on the current core HEAD with the production
adapter module, so any future core fix must keep them working:

- Wire building: `chat_build_wire` → `chat_build_messages` /
  `chat_append_message_by_role` / `chat_append_user_message` /
  `chat_append_assistant_message` / `chat_build_tools`, including
  cross-module accessor calls inside `while` bodies, expression-if dispatch
  branches, struct literals, `json::encode` at function top level, and the
  tool-schema / user-parts string splices (`chat_splice_tool_schemas`,
  `chat_splice_user_parts`).
- Standard wire shape (P1): user messages emit `content` as a parts array via
  marker splice (`__RSS_USER_PARTS_<i>__`), tool/assistant messages carry
  plain strings, `tool_choice` is omitted when empty. Verified by
  `openai_chat_wire_format_is_standard` on the 400-error path (wire is built
  and recorded before error parsing, so the assertion is independent of the
  blocked response-parse path).
- Structured provider errors: `chat_parse_error` / `chat_error_payload`
  (status/type/code/param/message/request_id mapping) — verified end to end
  by `openai_chat_provider_error_is_structured`.
- Content parsing helper `chat_message_text` accepts both a plain string and
  an array of `{type, text}` / `{type, output_text}` parts (used by
  `chat_parse_message`; the surrounding parse path remains blocked).

## Exact commands

```bash
# Core blocker repro (runtime): compile + run the committed repro set
cd /mnt/TEMP/rustscript/agent-roadmap/a3
CARGO_TARGET_DIR=/mnt/TEMP/rustscript/agent-roadmap/target-a3 \
  cargo test --test core_repro_driver -- --ignored --nocapture
# Expect: 7 passed; root_splice/hop4 fail with typed TypeMismatch,
#         root_splice2/hop13 pass as controls, compile-time repros rejected.
#
# Full adapter flow: the ignored suites fail at runtime with the same family:
cargo test --test provider_tests -- --ignored
```

The repro sources live in `tests/fixtures/core-repros/` (`chain_m1.rss`
provides the accessor module; `hop*`, `root_splice*`, `tailif*`, `letif*`,
`json_enc_e` cover each trigger) and are independently runnable through
`tests/core_repro_driver.rs` (ignored by default, documented in its header).

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
4. Closures must be allowed to assign to captured locals without forcing
   `Move` on the source (or an equivalent shared-accumulator mechanism must
   exist), to unblock the SSE callback aggregation pattern.

## What is committed and green

- `rss/llm/types.rss` — canonical contract (request accessors, response/error
  builders, call results).
- `rss/llm/openai_chat.rss` — buffered adapter: standard wire building
  (user content parts array, tool/assistant string content, omitted empty
  `tool_choice`, tool-schema and user-parts splices), response/error parsing,
  content string+parts compatibility; streaming stays a typed
  `not_implemented` stub (see stream blocker above).
- `rss/llm/harness.rss` — test dispatch entry (no protocol logic).
- `rss/providers/*.rss` — OpenRouter, DeepSeek, OpenCode Zen, OpenCode Go,
  custom profiles reusing the shared adapter (no copied parsers).
- `tests/provider_tests.rs` — fixture server infrastructure, canonical
  request/profile construction, 2 green suites (provider error + P1 wire
  format), 11 documented ignored suites (buffered parse, streaming, and
  blocked references for the openai_responses/anthropic fixtures).
- `tests/fixtures/providers/**` — transcripts for chat buffered/stream,
  responses (data-only SSE), anthropic, and error/malformed payloads.
- `tests/fixtures/core-repros/` + `tests/core_repro_driver.rs` — committed,
  independently runnable minimal repro set for the core blocker.
- `src/runtime/rss_runner.rs` — restricted registry exposes only consumed
  capabilities: JSON, stream emit, `bytes::to_utf8`, SQLite, and
  `http::client::request`. `bytes::from_utf8` and `http::client::sse` were
  removed (no RSS consumer; see stream blocker).

## Still open when the core clears

- Buffered response parsing suites (text/usage/reasoning, tool calls,
  malformed payload, invalid JSON).
- `openai_chat_stream` implementation (`http::client::sse` chunk
  aggregation) plus its text/usage, tool-call chunk aggregation, and typed
  cancellation suites.
- `openai_responses` and `anthropic_messages` adapters (currently typed
  `not_implemented` stubs) with their buffered/streaming transcripts.
