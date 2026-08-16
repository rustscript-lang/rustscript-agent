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
| Production serial loop (A5) |
| `RUSTSCRIPT_AGENT_PROVIDER_BASE_URL` | `PD_EDGE_AGENT_PROVIDER_BASE_URL` | URL | unset | Provider endpoint base for the built-in serial loop. Direct adapters (`openai_chat`, `openai_responses`, `anthropic_messages`) require it; profile modules merge it as an override. |
| `RUSTSCRIPT_AGENT_PROVIDER_API_KEY` | `PD_EDGE_AGENT_PROVIDER_API_KEY` | string (secret) | unset | Provider API key for the built-in serial loop. Never logged; see [Secrets](#secrets). |
| `RUSTSCRIPT_AGENT_PROVIDER_MODEL` | `PD_EDGE_AGENT_PROVIDER_MODEL` | string | unset | Model override merged into the provider options of the built-in serial loop. |
| `RUSTSCRIPT_AGENT_MAX_TURNS` | `PD_EDGE_AGENT_MAX_TURNS` | integer `usize` | `8` | Bounded serial-loop turns (a tool round consumes one turn); a runaway tool loop terminates at this bound. |
| `RUSTSCRIPT_AGENT_MAX_RETRIES` | `PD_EDGE_AGENT_MAX_RETRIES` | integer `usize` | `2` | Provider retries allowed per turn before the typed `max_retries_exceeded` terminal. |
| `RUSTSCRIPT_AGENT_APPROVAL_MODE` | `PD_EDGE_AGENT_APPROVAL_MODE` | enum | `auto` | Approval mode fed to the A4 approval policy: `auto`, `manual`, `never`, or `all`. Anything else fails startup validation. |
| `RUSTSCRIPT_AGENT_APPROVAL_TIMEOUT_SECS` | `PD_EDGE_AGENT_APPROVAL_TIMEOUT_SECS` | integer seconds | `600` | Lifetime of a pending approval; the janitor sweep resumes the parked run with a typed expired tool result after it. |
| `RUSTSCRIPT_AGENT_MAX_CONTEXT_MESSAGES` | `PD_EDGE_AGENT_MAX_CONTEXT_MESSAGES` | integer `usize` | `64` | Durable-history compaction window; when the session history exceeds it the loop plans and the service executes a compaction. `0` disables the gate. |
| `RUSTSCRIPT_AGENT_RETAINED_TAIL` | `PD_EDGE_AGENT_RETAINED_TAIL` | integer `usize` | `8` | Retained tail after a compaction (never marked, stays in context). |
| `RUSTSCRIPT_AGENT_STREAM` | `PD_EDGE_AGENT_STREAM` | flag | `1` | Stream transport flag passed to the provider adapters (`1` uses the SSE transport, `0` buffered). Only the exact values `0`/`1` are accepted. |
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
| `provider_options` | `serde_json::Value` | `{}` | Canonical provider options for the built-in serial loop (`base_url`, `api_key`, `model`, ...). Direct adapters require `base_url`; profile modules merge these as overrides. See `RUSTSCRIPT_AGENT_PROVIDER_*` above. |
| `max_turns` | `usize` | 8 | Bounded serial-loop turns; a runaway tool loop terminates at this bound. See `RUSTSCRIPT_AGENT_MAX_TURNS`. |
| `max_retries` | `usize` | 2 | Provider retries per turn before the typed `max_retries_exceeded` terminal. See `RUSTSCRIPT_AGENT_MAX_RETRIES`. |
| `base_retry_delay_ms` | `u64` | 1000 | Exponential backoff base for provider retries. |
| `max_retry_delay_ms` | `u64` | 30000 | Exponential backoff cap for provider retries. |
| `approval_mode` | `String` | `"auto"` | One of `auto`/`manual`/`never`/`all`; anything else fails validation. Fed to the A4 approval policy. See `RUSTSCRIPT_AGENT_APPROVAL_MODE`. |
| `approval_timeout` | `Duration` | 600 s | Must be positive. Lifetime of a pending approval; the janitor sweep resumes the parked run with a typed expired tool result after it. See `RUSTSCRIPT_AGENT_APPROVAL_TIMEOUT_SECS`. |
| `max_context_messages` | `usize` | 64 | Durable-history compaction window; `0` disables the gate. See `RUSTSCRIPT_AGENT_MAX_CONTEXT_MESSAGES`. |
| `retained_tail` | `usize` | 8 | Retained tail after a compaction. See `RUSTSCRIPT_AGENT_RETAINED_TAIL`. |
| `stream` | `bool` | `true` | Stream transport flag passed to the provider adapters. See `RUSTSCRIPT_AGENT_STREAM`. |
| `parallel` | `bool` | `false` | Parallel orchestration requested (A6 handoff; typed non-executable until the A7 run-admission interface wires the native supervisor). |
| `task` | `bool` | `false` | Task/subagent delegation requested (A6 handoff; typed non-executable). |
| `agent_name` | `String` | `"local-rss-agent"` | Reported by `/health/detailed`. |
| `bearer_token` | `Option<String>` | `None` | Blank tokens rejected by the binary. |
| `max_body_bytes` | `usize` | 4 MiB | Must be positive. HTTP request body limit (`DefaultBodyLimit`). |
| `max_concurrent_runs` | `usize` | 8 | Must be positive. Admission limit; excess admissions answer `429 run_limit_reached`. |
| `run_timeout` | `Duration` | 900 s | Must be positive. Per-run wall-clock deadline; expiry cancels with `Deadline` and answers `504 agent_timeout` on the legacy chat path. |
| `event_channel_capacity` | `usize` | 64 | Must be positive. Bounded per-run event channel. |
| `broadcast_capacity` | `usize` | 64 | Must be positive. SSE broadcast channel capacity. |
| `max_events_per_run` | `usize` | 8192 | Must be positive. Retained event history bound per run. Covers the SSE stream bounds (4096 buffered deltas + 64 tool chunks + terminal events) so a `Lagged` live receiver can always catch up through the durable replay. |
| `max_event_bytes` | `usize` | 32 KiB | Must be positive. Per-event payload bound. |
| `terminal_run_ttl` | `Duration` | 60 s | Must be positive. Retention of terminal run handles before release. |
| `durable_run_retention` | `Duration` | 86400 s | Must be positive. Durable retention of TERMINAL runs (completed/failed/cancelled): the janitor deletes terminal runs older than this window (and their events/retention/idempotency records) through the typed `runs.prune_terminal` RSS command. Active, pending, and `terminal_pending` runs are never matched, so restart replay and the terminal retry loop stay intact. |
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
| `io` | `IoPolicy` | fully-restricted (no roots, no write, no process) | Native hard upper bound for the bounded harness tools (`file`/`patch`/`terminal`): `allowed_roots`, `allow_write`, `allow_process`, `max_read_bytes`, `max_write_bytes`. RSS policy can only narrow this, never widen it. |
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
| `max_response_body_bytes` | 1 MiB |
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

The built-in RSS programs (the serial agent loop `rss/agent/main.rss` and
the A2 storage program `rss/storage/main.rss`) are compiled from the crate's
source tree at construction. A deployment without the source tree must ship
them (or set `RUSTSCRIPT_STORAGE_PROGRAM` to an absolute storage-program
path); a missing storage program is a typed construction error that fails
startup cleanly — never a panic. This variable is read by the library (not
by the binaries), so it is not part of the canonical env table above.

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

## OpenAI compatibility notes

- On `/v1/chat/completions`, omitted `tools` and `tools: []` both mean no
  tools. Only an explicitly non-empty declaration is sent to the provider;
  the legacy and Telegram routes retain their registry policy.
- `max_completion_tokens` and `max_tokens` are preserved as separate
  request fields. Profiles may set `max_tokens_field` for legacy adapters.
- Streaming uses canonical chunk ids in `seq:subindex` form. Send the last
  received id in `Last-Event-ID` to resume at the next chunk. Terminal output
  is loaded from the durable RSS message reference, so event/replay payload
  bounds do not shorten the returned bounded output.
- OpenAI middleware failures share the `{error:{message,type,code,request_id}}`
  envelope and the `x-request-id` header. Bearer scheme matching is ASCII
  case-insensitive.
