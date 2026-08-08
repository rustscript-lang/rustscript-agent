# Agent Durable State and Recovery Plan

**Goal:** Replace full-snapshot persistence with transactional RSS-owned storage for sessions, messages, runs, events, approvals, compactions, idempotency, and parent/child links.

**Architecture:** A dedicated storage service submits typed commands to RSS storage programs backed by generic `sqlite::*`. Mutations commit durably before in-memory publication. Events append incrementally with monotonic sequence and bounded retention metadata; restart recovery is explicit and replayable.

**Tech Stack:** RustScript RSS modules, generic SQLite host capability, Rust storage service/actor, migration and restart tests.

---

## Independence and dependency

- Independent of provider adapters and platform rendering.
- Depends on reliable nested RSS composition and generic SQLite capability.
- Integrates with the run-lifecycle event service through typed append/replay commands.

## Scope boundary

### In scope

- Normalized agent schema and migrations.
- Typed storage command contract.
- Incremental durable mutation and rollback semantics.
- Event retention/replay cursors and restart recovery.
- Idempotency and parent/child links.
- Removal of full serialized snapshot replacement and direct native SQL.

### Out of scope

- VM/SQLite internal implementation.
- Jobs/cron execution.
- Provider cache implementation beyond schema hooks.
- Cross-machine replication.
- Compatibility migration from unreleased prototype snapshots unless an explicit release artifact requires it.

## Target schema

```text
schema_migrations
sessions
messages
runs
run_events
approvals
compactions
provider_usage
child_run_links
idempotency_keys
delivery_cursors
```

Every table has explicit keys, timestamps, bounded payload fields, and foreign-key behavior. Run event identity is `(run_id, seq)`.

## Implementation route

### Milestone 1: Freeze typed storage commands

**Files:**
- Modify/create: `rss/storage/main.rss`
- Create/refine: `rss/storage/schema.rss`, `sessions.rss`, `messages.rss`, `runs.rss`, `events.rss`, `approvals.rss`, `compactions.rss`
- Add JSON fixtures under `tests/fixtures/`

Define request/response/error shapes for:

- migration/status;
- session/message create/read/update;
- run reserve/start/terminal transition;
- event append/page/replay bounds;
- approval create/resolve;
- compaction checkpoint transaction;
- idempotency claim/complete/conflict;
- parent/child link create/query;
- restart recovery.

Unknown commands/fields return typed errors.

### Milestone 2: Build normalized migrations

**Files:**
- Create: `migrations/` or migration RSS modules
- Add migration tests

1. Create schema v1 with foreign keys and indexes.
2. Make each migration transactional and idempotent.
3. Test a fresh database and upgrade from every released schema version.
4. Do not preserve unreleased full-snapshot format unless explicitly selected as a fixture.

### Milestone 3: Replace snapshot save/load with a storage service

**Files:**
- Replace/refine: `src/gateway_store.rs` as `src/storage.rs` or `src/storage/**`
- Modify: `src/service.rs`, gateway handlers

1. Remove `delete all + insert entire state` persistence.
2. Submit one typed command per domain mutation to a dedicated storage worker/actor.
3. Execute storage work off async request threads.
4. Commit durable state before publishing in-memory/cache/event changes.
5. On failure, return an error with no visible partial mutation.
6. Remove native SQL strings and direct `rusqlite` dependency.

### Milestone 4: Correct event sequence and retention

1. Allocate sequence transactionally per run.
2. Allow retained history to begin at `first_seq > 1`.
3. Validate adjacency from the stored first sequence, not from one.
4. Persist retention floor/high-water metadata.
5. Return `cursor_too_old` with the oldest available sequence.
6. Append terminal recovery events using `last_seq + 1`, never retained length.
7. Keep payload/event count/age limits configurable.

### Milestone 5: Add restart recovery

1. On startup, migrate schema and load only required active indexes/caches.
2. Convert active/admitted/running runs to the documented terminal restart state in one transaction.
3. Append one recovery terminal event per interrupted run.
4. Preserve replayable prior events and parent/child links.
5. Resume no prior side effect automatically.
6. Rebuild delivery cursors and idempotency state deterministically.

### Milestone 6: Scale and failure tests

**Files:**
- Modify: `tests/storage_tests.rs`
- Modify: `tests/gateway_tests.rs`

Required cases:

- more than 1,024 total records without a snapshot ceiling;
- more than 240 events, retention, restart, and replay;
- first retained sequence greater than one;
- append/terminal transaction failure with no in-memory divergence;
- concurrent idempotency claims;
- duplicate event sequence rejection;
- interrupted migration rollback;
- restart recovery exactly once;
- parent/child query and cancellation state;
- bounded page sizes and payload limits.

### Milestone 7: Verification

```bash
cargo fmt --all -- --check
cargo test --locked --test storage_tests
cargo test --locked --test gateway_tests
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

## Target criteria

- No full-state snapshot replacement remains.
- No fixed 1,019-record effective gateway ceiling remains.
- Failed persistence leaves no visible in-memory mutation.
- Event retention survives restart when the first retained sequence exceeds one.
- Replay reports precise oldest/high-water cursors.
- Interrupted runs receive one durable terminal recovery transition/event.
- Native Rust contains no SQL statement or direct SQLite execution.
- Storage work does not block Tokio request threads.
- Migrations, idempotency, retention, and recovery are covered by executable tests.
