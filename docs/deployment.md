# rustscript-agent deployment guide

This guide covers running the `rustscript-agent-gateway` binary (and the
single-run `rustscript-agent` binary) outside a development checkout. It
states current behavior only; anything marked *not implemented* must not be
treated as available.

## 1. Delivery constraint: the core dependency is not released

`rustscript-agent` depends on the RustScript VM through a **path
dependency** (`pd-vm = { path = "../rustscript", ... }` in `Cargo.toml`).
Consequences, stated plainly:

- A build requires a checkout of `rustscript-lang/rustscript` next to this
  repository (the agent repo at `<root>/rustscript-agent`, the core repo at
  `<root>/rustscript`), at a revision whose `pd-vm` 0.1.0 matches this
  repository's `Cargo.lock`.
- The lockfile in this revision was generated against core revision
  `06b37fd155be2b81ba4b41dbb6514e7b283f4f10` (branch
  `plan/callable-stream-integration`). `cargo build/test --locked` fails if
  the checked-out core revision no longer matches.
- **There is no crates.io release of this crate, and none can be made until
  the core (`pd-vm`, `pd-host-function`, and their dependency edges) is
  merged and published and the path dependency is replaced by a version
  dependency.** CI pins the same core revision for exactly this reason.
- Deployments therefore run from a source build of a pinned agent commit
  plus a pinned core commit; record both revisions together in the
  deployment manifest. Do not claim a "release" for a build of this branch.

## 2. Build

```bash
# sibling checkouts required (see section 1)
git clone https://github.com/rustscript-lang/rustscript-agent.git
git clone https://github.com/rustscript-lang/rustscript.git
cd rustscript-agent
git checkout <pinned agent revision>
cd ../rustscript && git checkout 06b37fd155be2b81ba4b41dbb6514e7b283f4f10 && cd ../rustscript-agent
cargo build --release --locked
```

Artifacts: `target/release/rustscript-agent` (single-run runner) and
`target/release/rustscript-agent-gateway` (HTTP gateway). There are no other
binaries.

## 3. Starting the gateway

The gateway is configured entirely by environment variables (see
`docs/configuration.md`). Minimal production-style start:

```bash
export RUSTSCRIPT_AGENT_GATEWAY_ADDR=127.0.0.1:8090
export RUSTSCRIPT_AGENT_BEARER_TOKEN='<secret>'      # see section 9
export RUSTSCRIPT_AGENT_ALLOW_HOSTS=api.example.com
export RUSTSCRIPT_AGENT_ALLOW_PORTS=443
export RUSTSCRIPT_AGENT_SCRIPT=/etc/rustscript-agent/agent.rss
export RUSTSCRIPT_AGENT_STATE_DB=/var/lib/rustscript-agent/state.db
# Optional (A7): bounded rate limiting and the client-disconnect policy.
export RUSTSCRIPT_AGENT_RATE_LIMIT_ENABLED=1
export RUSTSCRIPT_AGENT_CLIENT_DISCONNECT_POLICY=keep-running
# Optional (A8): Telegram adapter; without a token the adapter stays off.
export RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN='<secret>'   # see section 9
exec ./target/release/rustscript-agent-gateway
```

Startup failure modes (all exit non-zero before serving):

- unparsable `RUSTSCRIPT_AGENT_GATEWAY_ADDR`;
- missing or blank `RUSTSCRIPT_AGENT_BEARER_TOKEN` (unless
  `RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS=1`);
- `RUSTSCRIPT_AGENT_ALLOW_PORTS` with an empty entry or no valid ports;
- `RUSTSCRIPT_AGENT_RATE_LIMIT_*` values outside their validated bounds
  (bursts above 1 000 000, a window above 86 400 000 ms, or a non-`0`/`1`
  `RUSTSCRIPT_AGENT_RATE_LIMIT_ENABLED`);
- `RUSTSCRIPT_AGENT_CLIENT_DISCONNECT_POLICY` with an unknown spelling;
- a blank `RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN` or an invalid
  `RUSTSCRIPT_AGENT_TELEGRAM_API_BASE` (non-https remote origin, embedded
  credentials, query, fragment, or path);
- unreadable `RUSTSCRIPT_AGENT_SCRIPT` or a source over 1 MiB / failing to
  compile;
- an unwritable or invalid `RUSTSCRIPT_AGENT_STATE_DB` path.

The legacy `PD_EDGE_AGENT_*` aliases still work but print a deprecation
warning; they are scheduled for removal before v1.

## 4. SQLite state

- `RUSTSCRIPT_AGENT_STATE_DB` names the state file. The parent directory
  must exist and be writable by the gateway user; it is the SQLite
  `database_root` for the RSS storage program.
- The file is opened with `read_write_create` mode through the core SQLite
  host with a 5 000 ms busy timeout; the core does not enable WAL, so the
  default rollback-journal behavior applies.
- **One gateway process per state file.** The storage worker owns a single
  connection and SQLite serializes writers; a second gateway on the same
  file contends for the writer slot and fails with `SQLITE_BUSY` once the
  5 000 ms busy timeout is exhausted. The gateway is not designed for
  multi-process access to one state file; use one file per instance.
- Without `RUSTSCRIPT_AGENT_STATE_DB` the gateway runs fully in memory:
  sessions, runs, jobs, and events are lost on restart.

## 5. Network and capability policy

- The HTTP policy is deny-by-default and enforced by the `pd-vm` core at
  request time: every destination host **and** port must be allowlisted
  (`RUSTSCRIPT_AGENT_ALLOW_HOSTS`, `RUSTSCRIPT_AGENT_ALLOW_PORTS`), schemes
  default to `https,wss`, and private/loopback IP destinations are rejected
  unless `RUSTSCRIPT_AGENT_ALLOW_PRIVATE_IPS=1`. With the default
  configuration no script can make any HTTP request at all.
- The gateway's own listener binds per `RUSTSCRIPT_AGENT_GATEWAY_ADDR`
  (default `127.0.0.1:8090`). TLS is not implemented; terminate TLS in a
  reverse proxy in front of the gateway.
- Requests are authorized with an `Authorization: Bearer ***` header
  (constant-time token comparison) when a token is configured; every route
  — including `/health/detailed` and `/metrics` — sits behind the
  middleware. Admission is additionally bounded by `max_concurrent_runs`
  (native config, 8 by default) and the body limit (4 MiB by default).
- **Rate limiting (A7)** is implemented and disabled by default
  (`RUSTSCRIPT_AGENT_RATE_LIMIT_ENABLED=1` turns it on): one bounded
  token-bucket per peer IP and one per verified bearer account, both
  refilling over one window; an exhausted bucket answers `429` with a
  `Retry-After` header. Failed authentication never charges an account
  bucket. The limiter is middleware on the API router only — the Telegram
  adapter's Bot API outbound traffic is never rate-limited by it.
  Budget your metrics scraper accordingly: `/metrics` counts against the
  peer-IP budget like every other route, and there is no private
  exemption.
- Run execution is bounded: `run_timeout` (default 900 s), fuel
  (10 000 000 default), per-run event caps (`max_events_per_run` 240,
  `max_event_bytes` 32 KiB), and a 5 s cancellation grace.
- **Client-disconnect policy (A7)**: `keep-running` (default) survives any
  subscriber disconnect and events stay replayable through the `after_seq`
  cursor; `cancel-on-disconnect` cancels the run with the typed
  `client_disconnect` reason only when the LAST subscriber disconnects
  while the run is still active (multi-subscriber and reconnect races can
  never cancel while one subscriber remains).

## 6. Health and readiness

| Endpoint | Meaning |
| --- | --- |
| `GET /health/detailed` | Liveness + minimal readiness: `{"status":"ok","active_agents":N,"terminal_pending":N,"agent":"local-rss-agent"}`. `terminal_pending` reports runs whose terminal commit is awaiting the bounded durable retry (observable instead of a silent leak). |
| `GET /metrics` | Prometheus text exposition of the bounded metrics registry (admissions, active runs, terminals, storage ops, SSE subscribers, run durations). Reads atomics only — the scrape never blocks on the store. Requires the bearer token when one is configured and counts against the per-IP rate-limit budget. |
| `GET /v1/models` | Returns the configured model id; doubles as a plain reachability probe. |

Both require the bearer token when one is configured. A healthy process is
one that answers; `terminal_pending > 0` is not a crash condition but
indicates the storage side was recently unavailable. Metrics and health
share one atomic snapshot, so the two endpoints can never disagree.

## 7. Shutdown

- The gateway handles Ctrl-C (`SIGINT`) through `tokio::signal::ctrl_c`
  with a bounded, ordered drain:
  1. **Stop admission**: new runs answer the typed `gateway_halting`
     rejection (HTTP 503), so no new work can start.
  2. **Stop Telegram** (when enabled): the poller stops, the final
     getUpdates offset is persisted, and the join is bounded at 60 s. The
     reconnect task can never spawn a second adapter mid-shutdown.
  3. **Cancel active runs** with the typed `resource-closed` reason;
     workers exit within their configured bounds and commit their typed
     terminal transitions.
  4. **Close the storage worker** deterministically: queued commands fail
     fast with a typed `storage_unavailable` error instead of hanging.
  The process then exits.
- `SIGTERM` is **not** caught by the current binary. Under systemd, set
  `KillSignal=SIGINT` so the graceful path runs; a plain `SIGTERM` kills the
  process immediately. SQLite recovers the file on next start (journal
  rollback), but in-flight in-memory run state is lost.
- An interrupted process is repaired on restart: interrupted runs are
  converted to a documented terminal state during load, exactly once, and
  pending terminal commits are retried within `terminal_commit_retry_window`
  (default 300 s). Every pending compaction is failed by restart recovery
  (any pending row after a restart is an interrupted leftover), so a crash
  between the run terminal commit and `compaction.fail` can never leave a
  session stuck.

## 8. Telegram adapter deployment (A8)

The Telegram adapter shares the same `AgentService` and SQLite store as the
API server; it is enabled by setting `RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN`.

- **Transport**: Bot API calls go out over **https** through a rustls TLS
  connector. The api_base must be a bare origin — no credentials, query,
  fragment, or path (the token is embedded in the request URL by the Bot
  API protocol, so anything else could smuggle it). An `http` base is
  rejected unless the host is localhost AND
  `RUSTSCRIPT_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST=1` (test fixtures
  only). The adapter's outbound traffic is **not** affected by the API
  rate limiter.
- **Allowlists are deny-by-default**: `allowed_accounts` (bot account
  usernames), `allowed_chats`, and `allowed_users` all start empty and an
  empty list denies everything. Configure all three before enabling the
  token in production; a denied sender gets a plain "not allowed" reply.
- **Retries are bounded**: 429 answers sleep `retry_after` (capped at
  `max_429_backoff`, 30 s by default) for at most 3 rounds; 5xx answers use
  capped exponential backoff for at most 3 rounds; an unauthorized failure
  bound (3 by default) parks the adapter in a degraded state instead of
  hammering the API with an invalid token.
- **First boot is fail-closed**: by default updates queued while the bot
  was offline are drained and **dropped** before polling starts
  (`RUSTSCRIPT_AGENT_TELEGRAM_DROP_PENDING_UPDATES=0` opts into processing
  them). Delivery of run events is at-least-once through durable delivery
  cursors: a message may be delivered twice after a crash, never silently
  lost.
- **Degraded startup never kills the API**: if `getMe`/network fails at
  startup, the adapter retries in the background with bounded backoff (3
  attempts) and is then disabled for the process; the API server keeps
  serving. The reconnect task is also cancelled by the graceful shutdown
  path (section 7).
- **Shutdown drains**: on SIGINT the poller stops, the final getUpdates
  offset is persisted, and the join is bounded (section 7).

## 9. Backup and recovery

- Stop the gateway (graceful shutdown, section 7), then copy the state file.
  Because WAL is not enabled, a single-file copy taken while the gateway is
  stopped is a consistent snapshot; remove any stale `state.db-journal`
  leftovers only after a clean shutdown.
- Restore: place the copy at the configured path and start the gateway.
- There is no online backup tooling and no migration runner in this
  revision; schema changes are applied by the RSS storage program at open
  time (see `rss/storage/schema.rss`).

## 10. Secrets and logging

- Secrets: `RUSTSCRIPT_AGENT_BEARER_TOKEN` and
  `RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN`. Deliver them via an environment
  file with mode `0600` owned by the service user (section 11), or injected
  secrets, never via command-line arguments or image build args. Neither
  secret is ever logged: the bearer token is compared in constant time and
  the Telegram token is redacted in every Debug/log surface.
- Logging: the binaries write startup/halt messages to **stderr** via
  `eprintln!`. `tracing` events exist in library code but the binaries
  install **no tracing subscriber**, so `RUST_LOG` has no effect today and
  no structured log output is produced. **Observability (A9) is
  implemented**: a bounded metrics registry (fixed label sets — no
  run/session/token/model high-cardinality labels) is scraped at
  `GET /metrics` in Prometheus text format, and `/health/detailed` reads
  the same atomic snapshot. Capture stderr with your supervisor and rotate
  it.

## 11. systemd unit

```ini
# /etc/systemd/system/rustscript-agent-gateway.service
[Unit]
Description=RustScript agent gateway
After=network-online.target

[Service]
User=rustscript-agent
Group=rustscript-agent
ExecStart=/opt/rustscript-agent/bin/rustscript-agent-gateway
EnvironmentFile=/etc/rustscript-agent/gateway.env
# The binary handles SIGINT gracefully; SIGTERM would kill it immediately.
KillSignal=SIGINT
TimeoutStopSec=30
Restart=on-failure
RestartSec=2
# State and source live under /var/lib; the service user must own them.
StateDirectory=rustscript-agent
ReadWritePaths=/var/lib/rustscript-agent

[Install]
WantedBy=multi-user.target
```

`/etc/rustscript-agent/gateway.env` (mode `0600`):

```bash
RUSTSCRIPT_AGENT_GATEWAY_ADDR=127.0.0.1:8090
RUSTSCRIPT_AGENT_BEARER_TOKEN=[REDACTED]
RUSTSCRIPT_AGENT_ALLOW_HOSTS=api.example.com
RUSTSCRIPT_AGENT_ALLOW_PORTS=443
RUSTSCRIPT_AGENT_SCRIPT=/var/lib/rustscript-agent/agent.rss
RUSTSCRIPT_AGENT_STATE_DB=/var/lib/rustscript-agent/state.db
```

## 12. Container example

```dockerfile
# Build stage: requires the pinned core checkout next to the agent repo.
FROM rust:1-slim AS build
WORKDIR /src
COPY rustscript-agent/ ./rustscript-agent/
COPY rustscript/ ./rustscript/
RUN cd rustscript-agent && cargo build --release --locked --bin rustscript-agent-gateway

FROM debian:bookworm-slim
RUN useradd --system --home /var/lib/rustscript-agent rustscript-agent
COPY --from=build /src/rustscript-agent/target/release/rustscript-agent-gateway /usr/local/bin/
USER rustscript-agent
EXPOSE 8090
# Secrets via --env-file or an orchestrator secret, never baked into the image.
ENTRYPOINT ["/usr/local/bin/rustscript-agent-gateway"]
```

Mount the state directory (`/var/lib/rustscript-agent`) as a volume; keep
the state file exclusive to one replica (section 4). TLS and health-check
paths are the same as sections 5–6.

## 13. Single-run runner

`rustscript-agent --script agent.rss --allow-host api.example.com` compiles
and runs one script to completion and prints the `Complete` value. It is
synchronous and holds no state; it is suitable for cron-style invocation,
not for serving. Note that the runner exposes no port allowlist, so script
HTTP requests over non-default policy ports fail inside the VM (section 5).
