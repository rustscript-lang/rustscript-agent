# Real provider tool-loop repair and E2E acceptance

**Goal:** A real authenticated production AgentService must independently write, read, compile and test a Rust CLI, then deliver a business final answer.

**Architecture:** Preserve pure transport SSE framing, authenticated sanitization, and RSS protocol ownership. Keep workspace-relative native capability contracts. Persist side-effect-free validation failures before durable context reconstruction; never manufacture a successful tool result or grant execution authority during rejection recording.

**Tech Stack:** Rust, RSS, production bundled Main/Guardian, native Responses transport, SDK-owned private SQLite, rustc.

## Existing evidence and scope
- Base HEAD: 2f9678be44448fa5a28d3870c7eda63c7abd1573; preserve the existing uncommitted SSE layering fix.
- The previous real run emitted terminal cwd=absolute workspace root and invalid_cwd. Its next search_files(path=".") returned before tool_prepare, and the following durable context lost that local failure result. The persisted assistant function call consequently lacked its matching output. Treat the remote responses_error cause as unconfirmed until deterministic wire validation and/or live evidence establish it.
- No parallel investigation or delegated implementation. No credential contents in logs, no manual database access, no external side effects beyond the explicitly authorized provider/tool test.

## Acceptance matrix
1. SSE/security: existing deep metadata regression, complete recorded-stream replay, fragmented framing, 64/65 public depth boundary, unchanged credential depth=8, duplicate-key/invalid UTF-8/secret filtering/cancellation/byte bounds and layering guards.
2. Tool contract: the frozen coding execution contract explains workspace-relative paths, empty cwd/search path for workspace root, no implicit shell, and empty process environment. Native absolute/traversal/symlink denial tests remain intact.
3. Deterministic production integration: real bundled RSS + canonical registry + native authenticated fixture transport + private SDK SQLite. Deliberate pre-prepare validation error must be followed by exactly one matching function_call_output containing its error, then successful write/read/process calls, default ASK Guardian reviews, and business final answer. Check every wire call/output pair; check restored SQLite messages through public SDK only. No fake tool executor.
4. Rejection safety controls: no successful local result is persisted as an unstarted effect; wrong parent/name/run rejected; started-but-uncommitted effects cannot be recast as validation errors; repeated refresh is idempotent; persistence failure stops follow-up; cancellation/deadline remains enforced. Preserve retention and replay contracts.
5. Real live E2E (explicit opt-in, ignored in ordinary CI): fresh empty workspace, native existing cached-access importer, real Responses-only transport, production SQLite and bundled Main/Guardian. Agent must create main.rs using write_file/patch, read it via read_file, invoke rustc via terminal, execute >=3 unit tests, and execute CLI cases `2 3 -1`=>4, empty=>0, invalid=>nonzero. Require run.completed, no terminal run failure, matched successful tool results, a final business message after the final tool result, and actual build/test exit statuses. Preserve recovered transient model failures separately; they must not be hidden or accepted as completed responses. Guardian text alone cannot satisfy final-answer acceptance. Harness must not write/repair solution files.
6. Independent artifact acceptance: retain generated main.rs/binaries/tool evidence, recompile source independently and repeat tests/CLI checks; this supplements and never substitutes for the Agent's own tool execution.
7. Cleanup: private auth/home/SDK state removed, worker/child cleanup verified, no secrets persisted in public evidence. Keep source/prompt/program/log artifacts only. No retry-to-green; preserve each failed attempt with its source state and repair cause.

## Implementation order and gates
- Freeze current source and reproduce missing-output failure with a deterministic transport that validates the actual outgoing Responses input.
- Add minimal rejection-persistence and model-visible contract fixes, with RED/GREEN regression evidence. Fix only issues demonstrated by these gates or subsequent real execution.
- Keep the real Rust-program test permanently as an explicit opt-in test with a caller-assigned evidence/project root and strict completion assertions.
- Run focused tests (fixture feature) then related Debug/Release suites, fmt and Clippy including lib test code. Preserve actual Cargo JSON executable/features/profile binding and inner exit codes under the existing slot-1 target.
- Run authorized real E2E once on the corrected candidate; if it finds a distinct defect, retain failure, diagnose, add regression, fix and execute a new distinctly recorded candidate. Do not accept mocks or no-run builds as live success.
- Record final executed matrix and any remaining failed acceptance criterion here. Completion requires the live generated Rust artifact and independent verification, not unit-test totals alone.

## Final execution record

### Corrections
- Keep pure SSE framing in `src/transport/sse.rs`, authenticated record sanitization in `src/auth/authenticated_stream.rs`, and Responses semantics in RSS.
- Keep credential JSON depth 8 / body 64 KiB. Public SSE JSON depth is 64; access/provider streaming has an independent 8 MiB total, while each line/data/output record remains capped at 64 KiB. Native and authenticated wrappers both enforce the selected total. Retarget stream overflow fixtures to the explicit stream total, and separately prove the default credential I/O context remains 64 KiB.
- Persist only failed, unstarted tool observations before durable context reload. Check parent/run/name and absence of started effects under the commit gate; never issue a token here. Preserve idempotence, cancellation, and fail-closed persistence.
- Responses function outputs preserve failure code/message and successful structured result metadata, including process exit codes. Legacy content-only outputs retain their existing shape.
- Explain workspace-relative paths, empty root path, nonempty search patterns and empty process environment in the coding execution contract. Keep the canonical six-tool descriptors and schemas unchanged.
- Mark only explicit native transport failures without cancel/deadline/revocation as retryable through the existing finite retry path. Keep the original run deadline and retry budget. Previously completed tools are not re-executed.
- Native HTTP body diagnostics expose fixed categories only, never raw exception/body/header strings.

### Executed acceptance
Evidence root: `/mnt/TEMP/workspace/rustscript-agent/tmp/workspace-session-binding-10-959a765d/complete-real-e2e-repair`.
- Real RED/GREEN records: `red-continuation` -> corrected production loop; `red-transient` -> existing finite retry integration; `red-stream-total-v2` -> bounded stream/credential separation; `red-process-output` -> preservation of process status. Compile/setup failures are retained separately and do not count as behavioral RED.
- `related-release-v4` and `related-debug`: 11 selected test targets each; 657 passed, 0 failed, 9 ignored in each profile, inner Cargo RC 0. The expected nested FIFO failure is excluded from outer totals. Cargo JSON profiles/executable paths/features are independently bound in `parent-related-ledgers.json`.
- `fmt-check`: RC 0; after test-harness cleanup `clippy-v2` checks all features/all targets with `-D warnings`, RC 0, no warning/error diagnostic. Final formatting checked again at handoff.
- Final source live acceptance `final-live`: RC 0, 98.83 s; 23 real Responses POSTs (11 business, 12 Guardian), 9 actual tool calls with 9 matched completed outputs, no tool failure and exactly one run.completed. The Agent created and read `main.rs`, compiled `sum_tests` and `sum_cli`, ran 5 passing unit tests, checked 4/0/invalid-exit cases, and supplied a business final answer after all tool results. No harness-authored solution.
- `final-live/independent/verification.json`: independent fresh compilation of the generated source and execution of 5 tests, CLI output 4, empty output 0, invalid exit 1, all verified.
- `final-live/parent-verification.json`: public SDK evidence, matched tool-call IDs, private auth/store cleanup, and exact final source snapshot. Private home and SDK artifacts are removed; generated source/binaries and safe public evidence are retained.

### Remaining external condition and preserved failures
Several earlier live candidates failed and remain archived. Native diagnostic runs measured TLS peer closure without close_notify before a complete Responses terminal event. The final accepted run recovered six transport failures using the existing bounded retry path. This does not establish who closed the connection and does not promise that an upstream outage can never exhaust retries. Truncated responses remain failures; no partial tool call is executed. No TLS validation, workspace confinement or approval restriction was disabled.

### Repeatable real-test command
Set a fresh absolute caller-owned evidence directory, a private HOME, and all project fixture/TMP aliases under assigned scratch; reuse the approved Cargo target. The existing native helper imports cached access without exposing it to the model or logs. Ordinary CI never reads the real credential source.

```sh
RUSTSCRIPT_AGENT_ALLOW_CODEX_ACCESS_LIVE_E2E=1 \
RUSTSCRIPT_AGENT_LIVE_EVIDENCE_ROOT=/absolute/assigned/fresh-evidence \
cargo test --locked --release --features config-fixture \
  --test codex_access_live_e2e_tests \
  live_rust_program::real_rust_program_multi_turn_tool_e2e \
  -- --exact --ignored --nocapture
```

Accept only actual RC 0 plus the persisted tool/program/final-response assertions. No-run compilation, a Guardian assessment, or a successful raw model response alone cannot satisfy this test.
