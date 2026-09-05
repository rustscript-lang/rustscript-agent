# rustscript-agent configuration reference

This document is the canonical configuration reference for this revision of
`rustscript-agent`. It lists **only** configuration that exists in this
revision: every environment variable the binaries read, every native
`AgentGatewayConfig` field, and the capability-policy defaults the gateway
passes through to the `pd-vm` core. Reserved-but-unimplemented configuration
is called out explicitly in [Reserved configuration](#reserved-configuration)
and must not be treated as real.

A drift guard (`tests/docs_consistency_tests.rs`) compares this document
against `src/` in both directions: a variable that the binaries read but this
document misses, or a variable this document advertises that no binary reads,
fails the test suite.

## Configuration sources

| Source | Owns | Read by |
| --- | --- | --- |
| Environment variables (`RUSTSCRIPT_AGENT_*`) | gateway process | `rustscript-agent-gateway` binary (`src/bin/rustscript-agent-gateway.rs`) |
| CLI arguments (`--script`, `--allow-host`) | one run | `rustscript-agent` binary (`src/bin/rustscript-agent.rs`) |
| Native `AgentGatewayConfig` fields | embedding code | library API; the gateway binary maps a fixed subset from environment variables |

RSS programs never read ambient configuration: all bounds reach the VM
through validated native configuration (`AgentConfig`/`HttpConfig`/
`SqlitePolicy`), and the storage program receives its per-command limits
through the typed command envelope.

## Environment variables (gateway binary)

Every `RUSTSCRIPT_AGENT_*` variable has a deprecated prototype alias
`PD_EDGE_AGENT_*`. When the primary variable is unset, the legacy name is
read and a deprecation warning is printed to stderr; the primary name always
wins. The aliases are scheduled for removal before v1 — do not rely on them.

| Variable | Deprecated alias | Type | Default | Bounds / notes |
| --- | --- | --- | --- | --- |
| `RUSTSCRIPT_AGENT_GATEWAY_ADDR` | `PD_EDGE_AGENT_GATEWAY_ADDR` | string (`SocketAddr`) | `127.0.0.1:8090` | Bind address. An unparsable value fails startup. |
| `RUSTSCRIPT_AGENT_BEARER_TOKEN` | `PD_EDGE_AGENT_BEARER_TOKEN` | string (secret) | unset | Required unless `RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS=1`. A blank value is rejected. Compared in constant time against the token carried in the `Authorization: Bearer ***` header. Treat as a secret; see [Secrets](#secrets). |
| `RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS` | `PD_EDGE_AGENT_ALLOW_ANONYMOUS` | flag | unset | Only the exact value `1` enables anonymous access. Local testing only. |
| `RUSTSCRIPT_AGENT_ALLOW_HOSTS` | `PD_EDGE_AGENT_ALLOW_HOSTS` | comma-separated list | empty (deny all) | Every HTTP(S)/WS(S) destination host must be allowlisted. Empty list denies all hosts. |
| `RUSTSCRIPT_AGENT_ALLOW_SCHEMES` | `PD_EDGE_AGENT_ALLOW_SCHEMES` | comma-separated list | `https,wss` | Replaces the default scheme set when set. |
| `RUSTSCRIPT_AGENT_ALLOW_PORTS` | `PD_EDGE_AGENT_ALLOW_PORTS` | comma-separated list of `u16` | empty (deny all) | When set it must contain at least one valid port and no empty entries; otherwise startup fails. Empty list denies all ports — with the default configuration no request can be made, so production deployments must list the ports scripts may reach (for example `443`). |
| `RUSTSCRIPT_AGENT_ALLOW_PRIVATE_IPS` | `PD_EDGE_AGENT_ALLOW_PRIVATE_IPS` | flag | unset (`false`) | Only the exact value `1` allows destinations on private/loopback IP ranges. |
| `RUSTSCRIPT_AGENT_SCRIPT` | `PD_EDGE_AGENT_SCRIPT` | filesystem path | unset | Path to the RSS agent source. Read and compiled at startup; sources over 1 MiB (`MAX_AGENT_SOURCE_BYTES`) or that fail to compile reject startup. |
| `RUSTSCRIPT_AGENT_STATE_DB` | `PD_EDGE_AGENT_STATE_DB` | filesystem path | unset (in-memory) | SQLite state file (sessions, messages, runs, events, jobs, approvals, compactions). Without it the gateway runs in-memory only and state is lost on restart. See `docs/deployment.md`. |
| Rate limiting (A7) |
| `RUSTSCRIPT_AGENT_RATE_LIMIT_ENABLED` | `PD_EDGE_AGENT_RATE_LIMIT_ENABLED` | flag | `0` (disabled) | Only the exact values `0`/`1` are accepted; anything else fails startup. When enabled, every API request consumes one per-peer-IP token and verified requests additionally consume one per-account token. |
| `RUSTSCRIPT_AGENT_RATE_LIMIT_IP_BURST` | `PD_EDGE_AGENT_RATE_LIMIT_IP_BURST` | integer `u32` | `60` | Tokens available per window for one peer IP. Must be positive and at most 1 000 000. |
| `RUSTSCRIPT_AGENT_RATE_LIMIT_ACCOUNT_BURST` | `PD_EDGE_AGENT_RATE_LIMIT_ACCOUNT_BURST` | integer `u32` | `120` | Tokens available per window for one verified bearer account. Must be positive and at most 1 000 000. |
| `RUSTSCRIPT_AGENT_RATE_LIMIT_WINDOW_MS` | `PD_EDGE_AGENT_RATE_LIMIT_WINDOW_MS` | integer milliseconds | `60000` | Refill window shared by both dimensions. Must be positive and at most 86 400 000 ms (24 h). |
| `RUSTSCRIPT_AGENT_RATE_LIMIT_MAX_BUCKETS` | `PD_EDGE_AGENT_RATE_LIMIT_MAX_BUCKETS` | integer `usize` | `10000` | Upper bound on tracked buckets (per-IP and per-account combined); at the bound the stalest bucket is evicted, so memory is bounded. |
| `RUSTSCRIPT_AGENT_CLIENT_DISCONNECT_POLICY` | `PD_EDGE_AGENT_CLIENT_DISCONNECT_POLICY` | enum | `keep-running` | `keep-running`: the run survives every subscriber disconnect and events stay replayable by cursor. `cancel-on-disconnect`: the run is cancelled with the typed `client_disconnect` reason when the LAST subscriber disconnects while it is still active. Unknown spellings fail startup. |
| Telegram adapter (A8) |
| `RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN` | `PD_EDGE_AGENT_TELEGRAM_BOT_TOKEN` | string (secret) | unset (adapter disabled) | Bot API token. When set, the Telegram poller starts alongside the API server; a blank value fails startup. Never logged; see [Secrets](#secrets). |
| `RUSTSCRIPT_AGENT_TELEGRAM_API_BASE` | `PD_EDGE_AGENT_TELEGRAM_API_BASE` | URL | `https://api.telegram.org` | Bot API base. Must be a bare origin: `https` only (an `http` base is rejected unless the host is localhost AND `RUSTSCRIPT_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST=1`), no credentials, query, fragment, or path. |
| `RUSTSCRIPT_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST` | `PD_EDGE_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST` | flag | unset (`false`) | Only the exact value `1` allows an `http` api_base for a localhost host (test fixtures and local development; the token must never travel in cleartext). |
| `RUSTSCRIPT_AGENT_TELEGRAM_DROP_PENDING_UPDATES` | `PD_EDGE_AGENT_TELEGRAM_DROP_PENDING_UPDATES` | flag | `1` (drop) | Safe first-boot default: updates queued while the bot was offline are drained and dropped before polling starts (fail-closed). Only the exact value `0` keeps them for processing. |
| `RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_ACCOUNTS` | `PD_EDGE_AGENT_TELEGRAM_ALLOWED_ACCOUNTS` | comma-separated list | empty (deny all) | Allowed bot account usernames (case-insensitive). Empty list denies every account. |
| `RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_CHATS` | `PD_EDGE_AGENT_TELEGRAM_ALLOWED_CHATS` | comma-separated list of `i64` | empty (deny all) | Allowed chat ids (negative ids are groups/supergroups). Empty list denies all chats; a non-integer entry fails startup. |
| `RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_USERS` | `PD_EDGE_AGENT_TELEGRAM_ALLOWED_USERS` | comma-separated list of `i64` | empty (deny all) | Allowed sender user ids. Empty list denies all users; a non-integer entry fails startup. |
| `RUSTSCRIPT_AGENT_TELEGRAM_POLL_TIMEOUT_SECS` | `PD_EDGE_AGENT_TELEGRAM_POLL_TIMEOUT_SECS` | integer seconds | `30` | `getUpdates` long-poll timeout. A non-integer value fails startup. |

Example (all variables with their deprecated aliases):

```bash
RUSTSCRIPT_AGENT_GATEWAY_ADDR=127.0.0.1:8090 \
RUSTSCRIPT_AGENT_BEARER_TOKEN=[REDACTED] \
RUSTSCRIPT_AGENT_ALLOW_HOSTS=api.example.com \
RUSTSCRIPT_AGENT_ALLOW_PORTS=443 \
RUSTSCRIPT_AGENT_SCRIPT=examples/http_get.rss \
RUSTSCRIPT_AGENT_STATE_DB=/var/lib/rustscript-agent/state.db \
cargo run --release --bin rustscript-agent-gateway
```

## CLI arguments (runner binary)

`rustscript-agent` is the single-run runner: it compiles one script and
drives its exported `run(context)` to completion with no gateway.

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `--script PATH` | path | required | RSS source file (≤ 1 MiB). |
| `--allow-host HOST` | string, repeatable | required | Host allowlist entry; at least one is required. Hosts are lowercased. |
| `--help` / `-h` | flag | — | Prints usage. |

The runner enforces the same deny-by-default HTTP policy as the gateway:
with only hosts allowlisted, script HTTP requests still need the port
allowlist (see above), which the runner currently does not expose — requests
over non-listed ports fail inside the VM.

## Native `AgentGatewayConfig` fields (library API)

`AgentGatewayConfig` (`src/config.rs`) is validated before use:
`AgentGatewayState::new`/`with_*` reject any configuration with a zero
lifecycle bound. The gateway binary exposes only the environment variables
above; every other field is set by embedding code.

| Field | Type | Default | Validation |
| --- | --- | --- | --- |
| `model` | `String` | `"local-agent"` | — |
| `provider` | `Option<String>` | `Some("local-agent")` | — |
| `agent_name` | `String` | `"local-rss-agent"` | Reported by `/health/detailed`. |
| `bearer_token` | `Option<String>` | `None` | Blank tokens rejected by the binary. |
| `max_body_bytes` | `usize` | 4 MiB | Must be positive. HTTP request body limit (`DefaultBodyLimit`). |
| `max_concurrent_runs` | `usize` | 8 | Must be positive. Admission limit; excess admissions answer `429 run_limit_reached`. |
| `run_timeout` | `Duration` | 900 s | Must be positive. Per-run wall-clock deadline; expiry cancels with `Deadline` and answers `504 agent_timeout` on the legacy chat path. |
| `event_channel_capacity` | `usize` | 64 | Must be positive. Bounded per-run event channel. |
| `broadcast_capacity` | `usize` | 64 | Must be positive. SSE broadcast channel capacity. |
| `max_events_per_run` | `usize` | 240 | Must be positive. Retained event history bound per run. |
| `max_event_bytes` | `usize` | 32 KiB | Must be positive. Per-event payload bound. |
| `terminal_run_ttl` | `Duration` | 60 s | Must be positive. Retention of terminal run handles before release. |
| `cancellation_grace` | `Duration` | 5 s | Must be positive. Bounded wait after a deadline before the worker is abandoned. |
| `janitor_interval` | `Duration` | 5 s | Must be positive. Terminal-commit retry / pending-terminal cadence. |
| `terminal_commit_retry_window` | `Duration` | 300 s | Must be positive. Bounded window during which a failed terminal commit is retried. |
| `terminal_persist_retries` | `usize` | 3 | —. Additional immediate retries before a terminal is parked as pending. |
| `terminal_persist_retry_delay` | `Duration` | 25 ms | Must be positive. Backoff between immediate terminal-persist retries. |
| `rate_limit` | `RateLimitConfig` | disabled; `ip_burst = 60`, `account_burst = 120`, `window = 60 s`, `max_buckets = 10 000` | Validated by `RateLimitConfig::validate` (bursts ≤ 1 000 000, window ≤ 86 400 s, buckets ≤ 1 000 000). Bounded in-memory token buckets keyed by peer IP and verified bearer account; see `RUSTSCRIPT_AGENT_RATE_LIMIT_*` above. |
| `client_disconnect_policy` | `ClientDisconnectPolicy` | `keep-running` | `keep-running` (default) or `cancel-on-disconnect`; see `RUSTSCRIPT_AGENT_CLIENT_DISCONNECT_POLICY` above. |
| `sse_keepalive_interval` | `Duration` | 10 s | Must be positive. SSE keep-alive interval; also the upper bound on client-disconnect detection (the next keep-alive write fails, the SSE body is dropped, and the subscriber drop guard fires). |
| `telegram` | `Option<TelegramConfig>` | `None` (disabled) | When present, the gateway starts the Telegram poller alongside the API server on the same service/store. Validated by `TelegramConfig::validate` (non-blank token, bare-origin https api_base, positive bounds, allowlists may stay empty — deny-by-default). See the `RUSTSCRIPT_AGENT_TELEGRAM_*` variables and `docs/deployment.md`. |
| `http` | `HttpConfig` | core defaults (below) | Validated by the core (`HttpConfig::validate`). |
| `sqlite` | `SqlitePolicy` | core defaults, `max_statements = 1024` | — |
| `fuel` | `Option<u64>` | `Some(10_000_000)` | VM fuel budget; `None` disables the fuel cap. |

`RateLimitConfig` bounds: `enabled` (master switch), `ip_burst`, `account_burst`,
`window`, `max_buckets`. `TelegramConfig` bounds: `bot_token` (redacted in
every Debug/log surface), `api_base`, `allow_insecure_localhost`, `poll_timeout`,
`poll_interval`, `max_429_retries`, `max_429_backoff`, `max_5xx_retries`,
`max_edit_interval`, `max_response_body_bytes`, `new_wait_timeout`,
`drop_pending_updates`, `unauthorized_failure_bound`, `dedup_capacity`,
`allowed_accounts`, `allowed_chats`, `allowed_users`.

## HTTP capability policy (core `HttpConfig` defaults)

The gateway passes `HttpConfig` through to the `pd-vm` HTTP host unchanged.
Defaults come from the pinned core revision; the policy is deny-by-default:
**hosts and ports must both be allowlisted before any request can be made.**

| Field | Default |
| --- | --- |
| `allowed_schemes` | `https`, `wss` |
| `allowed_hosts` | empty (deny all) |
| `allowed_ports` | empty (deny all) |
| `max_redirects` | 5 |
| `max_request_body_bytes` | 1 MiB |
| `max_response_body_bytes` | 8 MiB |
| `connect_timeout` | 10 s |
| `request_timeout` | 30 s |
| `allow_private_ips` | `false` |
| `max_stream_item_bytes` | 1 MiB |
| `max_stream_total_bytes` | 64 MiB |
| `max_sse_line_bytes` | 64 KiB |
| `max_websocket_frame_bytes` | 1 MiB |
| `max_websocket_send_bytes` | 1 MiB |
| `max_stream_duration` | 5 min |
| `stream_idle_timeout` | 30 s |
| `websocket_close_timeout` | 5 s |

## SQLite policy (core `SqlitePolicy` defaults)

| Field | Default |
| --- | --- |
| `database_root` | `None` (the gateway storage worker sets it to the state DB's parent directory) |
| `allow_unsafe_sql` | `false` |
| `limits.max_connections` | 16 (the gateway storage worker opens 1) |
| `limits.max_statements` | 128 (the gateway default config raises this to 1024; the storage worker runs 64) |
| `limits.max_rows` | 1 000 |
| `limits.max_columns` | 128 |
| `limits.max_result_bytes` | 4 MiB |
| `limits.max_statement_bytes` | 1 MiB |
| `limits.max_parameters` | 128 |
| `limits.max_parameter_bytes` | 1 MiB |
| `limits.max_pending_operations` | 32 |
| `limits.max_transaction_ms` | 5 000 |
| `limits.busy_timeout_ms` | 5 000 |

The storage worker (`src/gateway/store.rs`) runs every command through the
RSS storage program (`rss/storage/main.rss`) on a dedicated thread with a
single connection and these per-command limits: `busy_timeout_ms = 5000`,
`max_connections = 1`, `max_statements = 64`, `max_transaction_ms = 5000`,
plus the configured `max_events_per_run` / `max_rows` / `max_result_bytes`
page bounds.

## RSS source and run bounds

| Constant | Value | Notes |
| --- | --- | --- |
| `MAX_AGENT_SOURCE_BYTES` | 1 MiB | Agent sources (and the storage program) over this bound are rejected at load/compile time. |
| `RUN_EPOCH_DEADLINE_TICKS` | 1 000 000 000 | Epoch budget granted to one cancellable run; the cancellation watcher jumps the epoch past it. |
| `RUN_EPOCH_CHECK_INTERVAL` | 1 000 | Interpreter operations between epoch checks on cancellable runs. |

## Coding tools and serial loop

The library `AgentService` worker compiles bundled `rss/agent/main.rss` and
drives a **serial** RSS `tools::dispatch` loop over the generic capability
host (`agent::provider_call`, filesystem/process/artifact adapters). This is
not an OpenAI-compatible inference path.

Built-in RSS registry tools, in registry order:

| Name | Toolset | Risk | Notes |
| --- | --- | --- | --- |
| `read_file` | coding | read | Bounded workspace file read. |
| `search_files` | coding | read | Bounded workspace search. |
| `write_file` | coding | write | Write complete workspace file contents. |
| `patch` | coding | write | Minimal unique-string replacement. |
| `terminal` | process | process | Direct `argv` execution; no shell command string. |
| `process` | process | process | Background/control sibling of `terminal`. |

Parallel tool calls are rejected (`unsupported_parallel`). Subagents and A6
parallel fan-out are out of scope.

## Workspace guidance, priority, and budgets

Admission freezes one coding system prompt from the run workspace. Root-level
guidance files are read in this priority, highest first: `AGENTS.md`,
`CLAUDE.md`, `.cursorrules`. Default `CodingPromptBudgets` are 16 KiB total
prompt, 8 KiB combined guidance, and 4 KiB per guidance file. Each admitted
file is length-prefixed as untrusted content so project bytes cannot forge
later contract sections. The frozen prompt is reused as the sole system
message on every subsequent provider request for that run.

## Provider profiles

`ProviderProfile` is a validated, secret-safe snapshot retained on
`AgentService`. Built-in names map protocol labels only (`local-agent` →
`local-agent`, `openai` / `openai-compatible` → `openai-chat-completions`).
Options are request-shaping controls (`profile`, `protocol`,
`reasoning_effort`, `base_url`, sampling numbers). Credential-bearing keys,
headers, and unsafe URLs are rejected rather than redacted. Profiles do not
grant network access; HTTP remains deny-by-default unless hosts **and** ports
are allowlisted.

## Run limits, deadline, and cancellation

`RunLimits` (`max_turns`, `max_tool_calls`, `max_tool_output_bytes`,
`workspace_root`) are captured at admission. `workspace_root` must be an
absolute existing directory and is canonicalized. `AgentGatewayConfig.run_timeout`
is the per-run wall-clock deadline; it is not reset per provider or tool
call. `stop` requests cooperative cancellation once: the provider call, RSS
run, and native process/terminal children share the run token.
`cancellation_grace` bounds how long the worker waits after a deadline before
the thread is abandoned. Client-disconnect policy is independent
(`keep-running` by default).

## Durable replay

`DurableProviderHost` is the production provider seam. Before each fresh inner
call it commits a sanitized `model.requested` boundary (`retry_safe` plus a
`sha256:` fingerprint; never `request`/`messages`/`prompt`/`provider_options`/
`api_key`/`headers`/`body`). Completed canonical provider steps
(`model.completed` plus the assistant message) replay on restart without an
inner call or a second `turns` increment. Pending retry-safe requests retry the
same logical turn and do not synthesize an assistant/tool parent. Pending
requests that are not retry-safe, lack a fingerprint, leak secret keys, or
already have a later tool effect fail closed (`interrupted_provider`) with no
provider or tool effect.

Native dispatch is durable-first. Assistant `tool_call` parents and user
`tool_result` messages carry `parent_message_id` and monotonic `ordinal`
values. A missing or name-mismatched parent fails closed (`missing_tool_parent`)
and does not run the executor. Replaying an already durable `ToolResult` does
not re-account metrics.

Exactly-once delivery to an external receiver is impossible: event delivery is
at-least-once. Durable replay guarantees the agent does not duplicate tool
effects or provider-step rows; subscribers may observe the same durable event
more than once.

## Coding metrics

Five saturating coding-agent counters are recorded without prompts, paths, or
raw outputs:

| Metric | Prometheus name | Counted when |
| --- | --- | --- |
| `model_calls` | `agent_model_calls_total` | Each actual `AgentProviderHost::call` |
| `tool_calls` | `agent_tool_calls_total` | Each freshly executed or failed tool dispatch |
| `tool_failures` | `agent_tool_failures_total` | Canonical `ToolResult.ok == false` |
| `turns` | `agent_turns_total` | Successful `ok: true` provider envelopes |
| `truncations` | `agent_truncations_total` | Typed `truncated` on a model envelope or tool result |

## Security confinement

Coding file tools and `terminal`/`process` are confined to the admitted
`workspace_root`. `terminal` executes `argv` directly; a `command` shell
string is rejected (`invalid_argv`). Default HTTP policy denies all hosts and
ports. The coding loop E2E uses `ScriptedProvider` as model transport and the
`local-agent` profile so it cannot fall through to an OpenAI-compatible
network adapter.

## Local coding-agent E2E

The main real coding workflow is covered by:

```bash
cargo test --test coding_agent_e2e_tests
```

Stop-during-terminal cancellation and bounded output-limit overflow are
covered by:

```bash
cargo test --test coding_agent_edge_e2e_tests
```

The main suite generates a temporary git workspace, drives the production
`AgentService` worker and bundled RSS loop, and asserts a real `read_file` →
`patch` → `terminal` argv test run. The edge suite asserts stop-during-terminal
child cleanup, exact tool lifecycle, durable parent/name/ordinal chaining,
truncated overflow artifacts, that reopening a completed run is a no-op, and
pending provider-turn restart: retry-safe replay/retry, completed-step replay
fidelity, unsafe fail-closed, and no duplicate tool effect or metric count.

## Secrets

- `RUSTSCRIPT_AGENT_BEARER_TOKEN` and `RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN`
  are the two secrets in this revision. All examples in this document show
  them as `[REDACTED]`; they must never be passed through process arguments
  or committed to repositories.
- The binaries never echo either secret: the bearer token is compared in
  constant time and the Telegram token is redacted in every Debug/log
  surface. Store them in an environment file or secret manager with
  restrictive permissions (see `docs/deployment.md`).

## Reserved configuration

The following configuration does **not** exist in this revision. It is
listed only to reserve the namespace and to make the roadmap explicit; no
binary reads these names and setting them has no effect.

- **A4 harness/approval machinery (排除)** and **A6 parallel tools /
  subagents (排除)** are out of scope for this repository's current
  milestones and define no configuration. The approval repository CRUD
  (`approval.request`/`get`/`resolve`/`expire` storage commands) exists, but
  there is no approval flow driving runs.
- A job **scheduler** is not implemented: job CRUD/pause/resume/latest-output
  routes exist, but scheduled execution defines no configuration.
