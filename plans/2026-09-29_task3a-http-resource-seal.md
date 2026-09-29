# Task 3A — HTTP/SSE resource migration seal

Status: accepted on 2026-09-29. Task 4 and later production-auth work remain pending.

## Frozen revisions

- Agent baseline: `b7e7c000e4546b966fa2c04e54214e2b24dc4407`.
- Reviewed and fully tested Agent code: `a6ebc43e3bc6f788399f16de6bc64ba27d0449e5`.
- Published Core revision used by both `pd-vm` and `pd-host-function`: `d9387f98df78dd88d2d1c04eebac4415f844efaf`.
- The commit containing this seal adds verification documents only; the code revision above is the test anchor.

## Accepted boundary

The OpenAI Chat RSS adapter, HTTP example, embedded RSS fixtures and restricted registry use the published resource API. Requests are mutable resources configured through `BorrowMut` calls and consumed by `TakeOwned` client operations. Responses, headers and SSE summaries use keyed resources and typed accessors. No compatibility overload reconstructs the removed HTTP map transport.

The published Core catalog is authoritative: `on_event` accepts four strings and returns `bool`; `on_open` receives `(status, headers, url)` and returns `bool`. Summary headers are obtained through `http::sse_summary::headers`, then read using `http::headers` accessors. These signatures supersede the provisional callback and summary-accessor shapes in the earlier plan.

RSS retains provider parsing, `[DONE]` stop, fail-closed EOF without `[DONE]`, usage and tool-call aggregation. Authorization boundaries remain restricted, including the missing-real-HTTP-import binding negative and denied ambient IO. This compatibility seal does not satisfy the later `C-MIGRATION` gate or authorize production raw provider credentials in RSS.

## Verification

All commands below completed successfully on the tested code revision:

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-features --all-targets
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace --all-features --all-targets -- --test-threads=1
```

The final serial test command exited 0: **38 targets, 969 passed, 0 failed, 10 existing ignored tests**. All 35 declared integration-test targets are present in the result. No `#[ignore]` annotations were added or removed by this migration. Nested subprocess test summaries are excluded from the aggregate; each target's final summary is counted once.

Machine-readable per-target results: [Task 3A results](verification/2026-09-29_task3a-results.json).

Relevant coverage includes HTTP API migration (8 tests), dependency pin guards (4), gateway (64), lifecycle (34), runner (33), and compilation of the bundled 49-file RSS corpus. Streaming provider checks cover text/usage, tool deltas, cancellation and EOF without a terminator.

The plan's `provider_tests streaming` filter matches no registered tests; the actual streaming tests use `stream`. `metrics_tests http` also matches none, so the entire metrics target was run. The final full command covers both complete targets.

## Review and regression evidence

Independent final review of the baseline through `94faccc03168f456baf37665686ec929f953d575` found no runtime blocker and one ownership-test defect. Commit `a6ebc43e3bc6f788399f16de6bc64ba27d0449e5` closes that finding: the same mutable header operation compiles before sending, and its post-send negative must report `local 'request' was moved earlier`. The stricter assertion first failed on the old fixture's unrelated borrow-mode error, then passed after the fixture correction. Scoped independent re-review accepted the fix and its helper changes. Reviewers did not run Cargo; execution evidence is from the integration worktree.

The gate also required two test-harness corrections. The held HTTP fixture can be released before a connection arrives, has bounded waits, and the timeout test explicitly checks arrival while retaining its three-second response bound. The cumulative-deadline test retains its 400ms admission budget and 250ms queue delay, uses the existing preparation observer to exhaust the original budget, and verifies unchanged absolute deadline, zero provider calls, typed cancellation and cleanup.

An earlier default-parallel run failed `process_write_to_exited_child_is_stdin_closed`; twelve isolated repetitions passed, and the final required serial gate passed it. This seal does not claim that the parallel timing observation has been eliminated.
