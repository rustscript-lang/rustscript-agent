# A3 Provider Adapter Core Blocker

Date: 2026-08-13 (re-evaluated 2026-08-15 after consuming the final core revision)
Implementation: merged into `master` at `946e307`; A3 consume commit updates the dependency pin
Core dependency: `https://github.com/rustscript-lang/rustscript.git` at full revision `fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e`

Core implementation plan:
[`2026-08-14_a3-rustscript-core-unblock.md`](2026-08-14_a3-rustscript-core-unblock.md)

## Status

The 2026-08-15 consume pinned the final core revision `fd4b570…` (B1–B4
plus the callable-streaming base plus the §11a parameter-liveness fix). The
four A3 core blockers are fixed at the repro level and the residual
slot-aliasing defect is cleared: `tests/core_repro_driver.rs` runs by
default with every probe positive (including the converted five-parameter
caller probe), the dependency pin is canonical HTTPS Git with no path
dependency, the streaming adapter (`openai_chat_stream`) is implemented
with `http::client::sse` exposed in the restricted registry, and the eight
OpenAI Chat provider suites run by default and pass against the recorded
wire fixtures (buffered, stream aggregation, cancellation, and the
EOF-without-`[DONE]` fail-closed guard). No schema
guard is bypassed and no fixture is weakened.

A3 "shared adapters handle non-stream/stream text, tool calls, usage, reasoning
fields, provider errors, and cancellation; profiles reuse adapters without
copied parsers" is **implemented**. The four Responses/Anthropic suites remain
placeholder `#[ignore]`d (adapter work, unrelated to core). Four suites
are green (`openai_chat_provider_error_is_structured`, the P1 wire-format
guard `openai_chat_wire_format_is_standard`, and the two marker-splice
preservation guards `openai_chat_wire_preserves_marker_like_user_text` /
`openai_chat_wire_preserves_marker_like_tool_schema`); the eight OpenAI
Chat buffered/stream/cancellation suites run by default and pass at
`fd4b570…`, including the EOF-without-`[DONE]` fail-closed guard (see
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
`rustscript/src/vm/mod.rs::enter_script_frame` (line 1205 at the pinned
revision): it compares each operand against the compiler-emitted
`TypeSchema::Callable` prototype schema. The emitted schemas are corrupted
(wrong parameter shapes/counts, wrong return schemas) for a subset of call
sites in non-root modules.

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
helpers all fail identically. The corruption is not a function of module size
or layout: it reproduces in a minimal ROOT module probe exactly as in the
full adapter module, so no source restructuring in this repository can
reliably avoid it.

Minimal repro (fails; byte-identical to `tests/fixtures/core-repros/root_splice.rss`):

```rss
// ROOT module: same (string, array) function.
use json;
use bytes;
use http;
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

## Verified stream blocker (closure capture, independent of layout)

The pure-text stream path (`http::client::sse` callback aggregating text
deltas, usage, `[DONE]`) cannot be expressed in this core revision. The
frontend availability pass computes each closure's capture mode by scanning
the closure body with context `CaptureBindingMode::Move`
(`rustscript/src/compiler/lifetime/availability/captures.rs::closure_capture_mode_for_slot`):
any by-value use of a captured local inside the body forces the source slot
to `Move`, so the local is marked moved and any later use outside the closure
is rejected at compile time with

```
local 'state' was moved earlier; use 'state.copy()' to copy it before moving
```

(`rustscript/src/compiler/lifetime/availability.rs::require_local_not_moved`,
`E_LOCAL_MOVED`). Note the mechanism precisely: closure bodies are single
expressions in this core revision (a `{ ... }` after `|params|` parses as a
brace literal, and statement blocks are not supported inside closures), so an
assignment statement is not even expressible — the by-value read of the
accumulator inside the callback is the move that forces the source out of the
enclosing scope. There is therefore no shared-accumulator mechanism left for
the callback: `openai_chat_stream` stays a typed `not_implemented` stub and
`http::client::sse` is **not exposed** in the restricted registry (it has no
consumer). The core test suite proves the SSE transport itself works; only
the script-side aggregation pattern is unavailable.

Committed root-module probe (fails with the exact error above):
`tests/fixtures/core-repros/closure_assign_root.rss`, plus the read-only
control `closure_read_root.rss` (reads through `state.copy()` — the exact
remedy the error message suggests — and passes). Driven by
`tests/core_repro_driver.rs` (the negative control runs by default).

## Additional compile-time limitations of the same revision (worked around in the adapter source)

- Annotated `let` statements whose initializer type the checker cannot prove
  (`json::encode` results, literals inside branches, same-module helpers) are
  rejected when placed inside the branches of a **tail-position
  expression-if** — an expression-if that is the function's final expression
  (`tests/fixtures/core-repros/json_enc_e.rss`, `letif_a.rss`,
  `tailif_m2.rss`; all three are tail-position). The identical annotated let
  in a NON-tail expression-if branch (value bound to a local) resolves
  correctly — verified with scratch probes against the pinned core. The
  rejection is emitted by
  `rustscript/src/compiler/pipeline.rs::enforce_strict_rustscript_type_resolution`
  (`local '<name>' does not resolve to a concrete compile-time type in
  RustScript`). Statement-if bodies are fine.
- `bytes::to_utf8` requires a concretely typed argument; annotate the body
  local as `bytes` first.

## Core source anchors (pinned revision 06b37fd)

- `rustscript/src/vm/mod.rs::enter_script_frame` — runtime callable
  argument-schema guard (`TypeMismatch("callable argument schema")`, line
  1205 at the pinned revision).
- `rustscript/src/compiler/lifetime/availability/captures.rs::closure_capture_mode_for_slot`
  (line 167) — closure capture-mode scan with `Move` context; and
  `apply_capture_binding_effect` (line 116) — marks the source local moved.
- `rustscript/src/compiler/lifetime/availability.rs::require_local_not_moved`
  (line 965) — emits `local '<name>' was moved earlier; use '<name>.copy()'
  ...` (`E_LOCAL_MOVED`).
- `rustscript/src/compiler/pipeline.rs::enforce_strict_rustscript_type_resolution`
  (line 530) — emits `... does not resolve to a concrete compile-time type
  in RustScript`.
- `rustscript/src/compiler/typing/validate.rs::validate_json_schema` (line
  343) — `json::encode` rejects generic maps ("requires object/struct-shaped
  data"), which forces the marker-splice wire mechanism (see P3 marker note
  below).
- `rustscript/src/builtins/runtime/core.rs::builtin_string_replace_literal_impl`
  (line 819) — `string_replace_literal` replaces ALL occurrences
  (`str::replace`), which is what makes the splice markers collision-prone
  and required the per-tool indexed markers.

## Unblock conditions (also see the P3 marker note below)

A fix in `rustscript` (outside this repository's scope) must make the
emitted `TypeSchema::Callable` for every script prototype match the declared
parameter/return types regardless of call-site inference in non-root
modules. Concretely:

1. Calls inside statement-if bodies in imported modules must not corrupt
   callee schemas (currently `TypeMismatch("callable argument schema")`).
2. Array-typed values returned by host/cross-module calls must not corrupt
   the callee's return schema (`TypeMismatch("callable return schema")`).
3. Annotated lets inside tail-position expression-if branches must resolve to
   their declared schema (strict-typing rejection).
4. Closures must be allowed to by-value-capture (or mutably borrow) locals
   without forcing `Move` on the source — or an equivalent shared-accumulator
   mechanism must exist — to unblock the SSE callback aggregation pattern.

## P3: marker-splice collision surface (open, documented)

The standard wire shape is built by splicing raw JSON into the encoded body
through literal markers (`__RSS_USER_PARTS_<i>__` per user message,
`__RSS_TOOL_SCHEMA_<i>__` per tool). A collision-free structured build is
blocked by the core: `json::encode` accepts only struct-shaped values
(`validate_json_schema` rejects generic maps), tool schemas arrive as raw
strings that must be embedded unquoted, and no random source exists in the
restricted registry. Two guards keep the risk bounded and tested:

- **User text** — a collision requires a user text part that is EXACTLY
  `__RSS_USER_PARTS_<j>__` for a LATER user message index `j` (the splice
  accumulates across passes, so an earlier-spliced parts array containing the
  exact quoted marker of a later message would be replaced again). Marker
  prefixes, embedded occurrences, and suffixed forms pass through
  byte-identical — proven by
  `openai_chat_wire_preserves_marker_like_user_text`.
- **Tool schemas** — a collision requires a tool schema whose JSON text
  contains the exact quoted marker `"__RSS_TOOL_SCHEMA_<j>__"` of a later
  tool. Embedded occurrences pass through byte-identical — proven by
  `openai_chat_wire_preserves_marker_like_tool_schema`. The shared unindexed
  marker of the previous revision was a REAL multi-tool bug (every tool's
  schema collapsed to the first tool's, since `string_replace_literal`
  replaces all occurrences); it is fixed by per-tool indexed markers and the
  test now asserts both tools' schemas independently.

Neither trigger is reachable from ordinary user text or schemas; both require
deliberately crafting the exact full marker string, and the fix is a core
capability (randomized markers or structured JSON building), out of this
repository's scope.

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
  plain strings, empty `tool_choice` is OMITTED from the body entirely (the
  struct encoder drops null optional fields; OpenAI treats an absent
  tool_choice as the default `auto`). Verified by
  `openai_chat_wire_format_is_standard` on the 400-error path (wire is built
  and recorded before error parsing, so the assertion is independent of the
  blocked response-parse path). The guard asserts the key's ABSENCE on the
  parsed map plus a literal body check — indexing a missing key reads as
  `null` in serde_json, which would mask a regression that re-emits
  `"tool_choice":null` or an empty string.
- Marker-splice preservation (P3 guards): marker-like fragments in user text
  and tool schemas survive the splice byte-identical
  (`openai_chat_wire_preserves_marker_like_user_text` /
  `openai_chat_wire_preserves_marker_like_tool_schema`); the tool schema
  markers are per-tool indexed (`__RSS_TOOL_SCHEMA_<i>__`) so multi-tool
  requests splice each schema into its own placeholder.
- Structured provider errors: `chat_parse_error` / `chat_error_payload`
  (status/type/code/param/message/request_id mapping) — verified end to end
  by `openai_chat_provider_error_is_structured`.
- Content parsing helper `chat_message_text` accepts both a plain string and
  an array of `{type, text}` / `{type, output_text}` parts (used by
  `chat_parse_message`; the surrounding parse path remains blocked).

## Exact commands

```bash
# Core blocker repro set at the pinned revision: runs by default as the
# B1–B4 regression guard.
cd /home/wow/rustscript/rustscript-agent
cargo test --test core_repro_driver
# Expect: 11 passed, 0 ignored. root_splice/hop4/tailif/json_enc_e/letif_a
# pass (B1/B2 fixed), closure_assign still rejected (preserved move
# semantics), and BOTH param_aliasing probes pass (five-parameter caller
# converted from the residual-defect failure assertion to positive at
# fd4b570; two-parameter control unchanged).
#
# Full adapter flow: 12 passed, 4 ignored (stub-only placeholders):
cargo test --test provider_tests
cargo test --test provider_tests -- --ignored   # 4 placeholders pass asserting not_implemented
```

The repro sources live in `tests/fixtures/core-repros/` (`chain_m1.rss`
provides the accessor module; `hop*`, `root_splice*`, `tailif*`, `letif*`,
`json_enc_e`, `closure_assign_root`, `closure_read_root` cover each trigger;
`param_aliasing*` cover the former residual defect) and are independently
runnable through `tests/core_repro_driver.rs` (runs by default; both
`param_aliasing_*` probes are positive assertions at `fd4b570…`).

## What is committed and green

- `rss/llm/types.rss` — canonical contract (request accessors, response/error
  builders, call results).
- `rss/llm/openai_chat.rss` — buffered adapter: standard wire building
  (user content parts array, tool/assistant string content, empty
  `tool_choice` omitted, per-tool indexed tool-schema and user-parts
  splices), response/error parsing, content string+parts compatibility;
  streaming (`openai_chat_stream`) is implemented with an
  `http::client::sse` shared-accumulator closure and passes the stream
  suites at `fd4b570…`.
- `rss/llm/harness.rss` — test dispatch entry (no protocol logic).
- `rss/providers/*.rss` — OpenRouter, DeepSeek, OpenCode Zen, OpenCode Go,
  custom profiles reusing the shared adapter (no copied parsers).
- `tests/provider_tests.rs` — fixture server infrastructure, canonical
  request/profile construction, 12 green suites (provider error, P1 wire
  format, the two marker-preservation guards, and the eight OpenAI Chat
  buffered/stream/cancellation suites including the EOF-without-`[DONE]`
  fail-closed guard), 4 documented ignored
  placeholder-reference suites for the openai_responses/anthropic fixtures.
- `tests/fixtures/providers/**` — transcripts for chat buffered/stream,
  responses (event-typed SSE: `event:` lines matching `data.type` with a
  final `data: [DONE]`), anthropic, and error/malformed payloads.
- `tests/fixtures/core-repros/` + `tests/core_repro_driver.rs` — committed,
  independently runnable repro set for the B1–B4 fixes (positive) plus the
  fd4b570 probe pair (`param_aliasing_*`) and its two-parameter control,
  all positive and run by default.
- `src/runtime/rss_runner.rs` — restricted registry exposes only consumed
  capabilities: JSON, stream emit, `bytes::to_utf8`, SQLite,
  `http::client::request`, and `http::client::sse` (consumed by the
  streaming adapter since core revision fd4b570).

## Still open

- Nothing: the eight OpenAI Chat suites run by default and pass at
  `fd4b570…` (the residual slot-aliasing defect is fixed in core; repro and
  fix record: unblock plan §11a).
- `openai_responses` and `anthropic_messages` adapters (currently typed
  `not_implemented` stubs) with their buffered/streaming transcripts — pure
  agent work, unrelated to the core defect.
  `not_implemented` stubs) with their buffered/streaming transcripts.
