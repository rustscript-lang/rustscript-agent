# Changelog

All notable changes to `rustscript-agent` source releases are documented here.

## [0.1.0] - 2026-11-26

The v0.1.0 GitHub source release is the first release of the standalone
RustScript agent runtime.

### Shipped capabilities

- Script-owned agent policy: the bundled RustScript corpus implements the coding loop, provider dispatch, tool routing, Guardian review, and compaction decisions behind typed native host contracts.
- Two source-built binaries: the synchronous `rustscript-agent` runner and the `rustscript-agent-gateway` HTTP/Telegram service.
- Atomic run admission and a durable SQLite lifecycle for sessions, messages, runs, events, approvals, compactions, plugin graph pins, managed effects, and restart repair.
- Serial coding tools for file inspection, file mutation, and bounded process execution, with fail-closed capability checks plus Guardian or user approval.
- Managed workspace checkpoint, restore, branch, publication, and effect-query flows, together with versioned plugin graph capture, activation, rollback, and state handling.
- Buffered and streaming OpenAI Chat source paths, an access-only Codex Responses source path, durable SSE delivery, and a Telegram adapter with bounded retries and approval controls.

### Current limits

The `v0.1.0` tag is source-only: no `rustscript-agent` crates.io package or
prebuilt binaries are published, and this release does not claim that
RustScript Core crates are published. Build the tagged agent commit with its
committed lockfile; Cargo must fetch the pinned RustScript Core Git revision
`11c9ee908a29365bd02573311f56e9308eb7dbe6`.

- Confined read/list filesystem inspection requires Unix. Confined mutation and publication currently require Linux because atomic publication uses Linux `renameat2`. On other Unix targets, confined mutation paths return `unsupported_platform`; non-Unix confined filesystem paths remain unsupported. This platform boundary does not classify unrelated runtime or gateway components as platform-limited.
- Scheduled durable job execution is not implemented. Job record CRUD does not schedule or execute jobs.
- Tool calls are serial. Parallel tool dispatch and subagent fan-out are not implemented.
- The generic custom Responses adapter and Anthropic Messages adapter remain typed `not_implemented` paths. Provider coverage is uneven, and final composed-candidate/live-provider acceptance remains open.
- The gateway has no native TLS listener, catches `SIGINT` but not `SIGTERM`, and provides application-level confinement rather than an OS sandbox.
