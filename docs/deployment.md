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
exec ./target/release/rustscript-agent-gateway
```

Startup failure modes (all exit non-zero before serving):

- unparsable `RUSTSCRIPT_AGENT_GATEWAY_ADDR`;
- missing or blank `RUSTSCRIPT_AGENT_BEARER_TOKEN` (unless
  `RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS=1`);
- `RUSTSCRIPT_AGENT_ALLOW_PORTS` with an empty entry or no valid ports;
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
  connection and SQLite serializes writers; running two gateways on the same
  file causes lock contention and undefined behavior. Use one file per
  instance.
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
- Requests are authorized with `Authorization: Bearer <token>` (constant
  time) when a token is configured; every route — including
  `/health/detailed` — sits behind the middleware. Rate limiting is **not
  implemented**; admission is bounded by `max_concurrent_runs`
  (native config, 8 by default) and the body limit (4 MiB by default).
- Run execution is bounded: `run_timeout` (default 900 s), fuel
  (10 000 000 default), per-run event caps (`max_events_per_run` 240,
  `max_event_bytes` 32 KiB), and a 5 s cancellation grace.

## 6. Health and readiness

| Endpoint | Meaning |
| --- | --- |
| `GET /health/detailed` | Liveness + minimal readiness: `{"status":"ok","active_agents":N,"terminal_pending":N,"agent":"local-rss-agent"}`. `terminal_pending` reports runs whose terminal commit is awaiting the bounded durable retry (observable instead of a silent leak). |
| `GET /v1/models` | Returns the configured model id; doubles as a plain reachability probe. |

Both require the bearer token when one is configured. A healthy process is
one that answers; `terminal_pending > 0` is not a crash condition but
indicates the storage side was recently unavailable.

## 7. Shutdown

- The gateway handles Ctrl-C (`SIGINT`) through `tokio::signal::ctrl_c`:
  active runs are cancelled with the typed `resource-closed` reason, workers
  exit within their configured bounds, and the process then exits.
- `SIGTERM` is **not** caught by the current binary. Under systemd, set
  `KillSignal=SIGINT` so the graceful path runs; a plain `SIGTERM` kills the
  process immediately. SQLite recovers the file on next start (journal
  rollback), but in-flight in-memory run state is lost.
- An interrupted process is repaired on restart: interrupted runs are
  converted to a documented terminal state during load, exactly once, and
  pending terminal commits are retried within `terminal_commit_retry_window`
  (default 300 s).

## 8. Backup and recovery

- Stop the gateway (graceful shutdown, section 7), then copy the state file.
  Because WAL is not enabled, a single-file copy taken while the gateway is
  stopped is a consistent snapshot; remove any stale `state.db-journal`
  leftovers only after a clean shutdown.
- Restore: place the copy at the configured path and start the gateway.
- There is no online backup tooling and no migration runner in this
  revision; schema changes are applied by the RSS storage program at open
  time (see `rss/storage/schema.rss`).

## 9. Secrets and logging

- Secrets: only `RUSTSCRIPT_AGENT_BEARER_TOKEN`. Deliver it via an
  environment file with mode `0600` owned by the service user (section 10),
  or an injected secret, never via command-line arguments or image build
  args. The token is never logged by the binaries.
- Logging: the binaries write startup/halt messages to **stderr** via
  `eprintln!`. `tracing` events exist in library code but the binaries
  install **no tracing subscriber**, so `RUST_LOG` has no effect today and
  no structured log output is produced. Metrics/tracing integration is not
  implemented. Capture stderr with your supervisor and rotate it.

## 10. systemd unit

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

## 11. Container example

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

## 12. Single-run runner

`rustscript-agent --script agent.rss --allow-host api.example.com` compiles
and runs one script to completion and prints the `Complete` value. It is
synchronous and holds no state; it is suitable for cron-style invocation,
not for serving. Note that the runner exposes no port allowlist, so script
HTTP requests over non-default policy ports fail inside the VM (section 5).
