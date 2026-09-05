# Production Agent Authentication and Usability Implementation Plan

**Goal:** 将当前已通过 E2E 的 serial coding-agent engine 变成可直接配置真实模型、选择项目、安全运行并可长期恢复的 gateway/CLI agent。

**Architecture:** 所有 model-visible tools 的名称、描述、JSON Schema、验证、dispatch、算法和结果整形由 `rss/tools/*` 实现；Rust 只提供 workspace-confined filesystem/process、artifact、approval、deadline/cancellation 和 durable lifecycle 等通用 capabilities。随后引入版本化 `config.yaml` 与独立的 `auth.yaml`。`config.yaml` 只保存 provider、model、OAuth 公共端点、workspace、agent policy 等非敏感配置；`auth.yaml` 只保存命名 credential 及 token 生命周期状态。Rust 层在 `rustscript-agent` 仓库内实现通用 OAuth、PKCE、token refresh、安全文件存储和 RSS host bridge；RustScript 层实现 OpenAI Codex 特有的 device-login 状态机。运行时通过 config 中的 credential 引用读取短期 access token，凭据绝不进入 SQLite run context、durable messages、events、metrics 或日志。

**Tech Stack:** Rust 2024、Tokio、Axum/Hyper/Rustls、Serde YAML、RustScript/pd-vm host API、OAuth 2.0 Authorization Code + PKCE、refresh-token grant、OpenAI Codex device authorization、SQLite durable agent state。

---

## 1. Scope and completion boundary

本计划包含当前 agent 从“library/E2E 可运行”到“用户可配置并部署”的完整收尾路线：

1. 将现有 native model-facing tools 迁移为 RSS tools + Rust generic capabilities。
2. `config.yaml` / `auth.yaml` 双层配置。
3. Rust 通用 OAuth library 与 RSS host functions。
4. RSS Codex device login。
5. 通用 browser OAuth flow，包含 PKCE、loopback callback、headless/manual fallback 与 refresh。
6. 真实 provider runtime 接入，先闭合 OpenAI Codex。
7. bundled coding agent 默认入口。
8. 显式 workspace 选择与 session 绑定。
9. write/process approval 执行链。
10. 自动/手动 compaction。
11. master 集成、部署与发布验收。

以下能力继续后置，不阻塞本计划完成：parallel tool calls、subagents、durable scheduler、多 gateway 共享同一 SQLite、OpenAI Responses/Anthropic 的全部 provider 覆盖。

## 1A. RSS tool ownership and Rust capability boundary

The approved design is specified in `docs/superpowers/specs/2026-09-03-rss-tools-rust-capabilities-design.md` and is a prerequisite for every later task in this plan.

Target RSS layout:

```text
rss/tools/
├── types.rss
├── registry.rss
├── validate.rss
├── dispatch.rss
├── read_file.rss
├── search_files.rss
├── write_file.rss
├── patch.rss
├── terminal.rss
└── process.rss
```

RSS owns all provider-visible descriptors, schemas, validation, dispatch, tool-specific algorithms, error mapping and output formatting. `rss/agent/main.rss` calls `tools::dispatch` directly.

Target Rust layout:

```text
src/capabilities/
├── mod.rs
├── types.rs
├── filesystem.rs
├── process.rs
├── artifacts.rs
├── lifecycle.rs
└── host.rs
```

Rust owns only generic security/resource boundaries: frozen workspace capabilities, atomic file operations, process ownership, deadline/cancellation, output/artifact caps, approval ceilings and durable tool lifecycle. Rust treats the public tool name as opaque metadata. Production Rust code must contain no built-in public tool order, public descriptor/schema fixtures, `NativeToolExecutor`, or dispatch branches keyed by `read_file`, `search_files`, `write_file`, `patch`, `terminal` or `process`.

The generic lifecycle contract is:

```text
agent_runtime::tool_prepare(metadata) -> execute token | durable replay
cap::* (execution_token, ...) -> bounded native capability result
agent_runtime::tool_commit(execution_token, result) -> committed envelope
```

`tool_prepare` commits durable started state before issuing a capability token. Every capability validates run/call ownership, risk ceiling, workspace, deadline and cancellation. RSS cannot mint, modify or reuse execution tokens. `tool_commit` durably closes the call. Open tokens are interrupted and their owned processes are cancelled during stop, deadline, source failure or recovery.

## 2. Configuration ownership

### 2.1 File locations

默认 home：

```text
~/.rustscript-agent/
├── config.yaml
├── auth.yaml
├── auth.yaml.lock
└── state.db
```

允许 `RUSTSCRIPT_AGENT_HOME` 覆盖整个 home，便于测试、容器与多实例隔离。不得分别用环境变量覆盖 token、refresh token 或 OAuth endpoint。

### 2.2 `config.yaml`: only non-secret behavior

Proposed v1 shape:

```yaml
version: 1

agent:
  source: bundled:coding
  max_turns: 64
  max_tool_calls: 128
  max_tool_output_bytes: 1048576

model:
  provider: openai-codex
  model: gpt-5-codex

providers:
  openai-codex:
    protocol: codex-responses
    base_url: https://chatgpt.com/backend-api/codex
    auth: codex-primary
    oauth:
      flow: codex-device
      issuer: https://auth.openai.com
      client_id: app_EMoamEEZ73f0CkXaXp7hrann
      device_user_code_path: /api/accounts/deviceauth/usercode
      device_poll_path: /api/accounts/deviceauth/token
      authorization_path: /codex/device
      token_endpoint: https://auth.openai.com/oauth/token
      redirect_uri: https://auth.openai.com/deviceauth/callback
      refresh_skew_seconds: 120

workspaces:
  allowed_roots:
    - /home/user/src
  default: /home/user/src/project

approvals:
  read: allow
  write: ask
  process: ask

compaction:
  enabled: true
  max_context_messages: 120
  retained_tail: 32
```

Rules:

- `config.yaml` schema rejects `access_token`, `refresh_token`, `id_token`, `api_key`, `authorization`, `cookie`, `password`, arbitrary headers and similarly credential-bearing keys at every nesting level.
- Provider endpoint must be HTTPS, except explicit loopback HTTP callback URLs generated by the local OAuth listener.
- Provider host/port enters an OAuth/provider-specific allowlist; RSS source cannot substitute a different authority.
- `auth` is a credential ID reference only.
- Unknown root/provider/auth keys fail startup with path-qualified errors.
- Deprecated environment aliases may be read-only migration inputs for one release, but the canonical source is YAML.

### 2.3 `auth.yaml`: only credentials and token lifecycle state

Proposed v1 shape:

```yaml
version: 1
credentials:
  codex-primary:
    provider: openai-codex
    kind: oauth
    source: codex-device
    token_type: Bearer
    access_token: "..."
    refresh_token: "..."
    expires_at_ms: 1788440000000
    scopes: []
    account_id: acct_...
    generation: 4
    status: active
    last_refresh_at_ms: 1788436400000
```

Rules:

- `auth.yaml` rejects model IDs, base URLs, workspace paths, timeout policy and other behavior configuration.
- Persist only fields required for runtime and refresh. Device code, user code, authorization code, PKCE verifier, PKCE state, request bodies and transient errors never enter this file.
- `id_token` is omitted unless a provider requires it for future runtime behavior. The initial Codex path does not persist it.
- `account_id` is derived from the validated access-token JWT claim `https://api.openai.com/auth.chatgpt_account_id`; it is metadata, never trusted as authorization by itself.
- Refresh-token rotation increments `generation`. Writers must compare the generation observed before the network call and re-read under the auth lock before commit.
- Terminal refresh errors set `status: reauth_required` without deleting the last token pair. Transient network/5xx/429 errors leave credential state active and return a retryable typed error.

### 2.4 File security and concurrency

- Create home directory with Unix mode `0700`; create `auth.yaml`, lock and replacement files with `0600`.
- Reject symlink auth files and unsafe parent traversal; use no-follow/openat-style checks where supported.
- Read file through a bounded byte cap before parsing YAML.
- Save using same-directory exclusive temporary file, flush, fsync, atomic rename and parent-directory fsync.
- Protect read-modify-write using an in-process mutex plus cross-process lock.
- Never serialize auth structs through `Debug`; implement redacted summaries.
- Windows tests verify atomic replacement and best available ACL/file handling without claiming POSIX mode guarantees.
- Corrupt YAML is moved or copied to a timestamped `.corrupt` artifact only after a bounded read; startup/login returns a typed error and never silently starts from an empty credential set.

## 3. Rust OAuth boundary

All new OAuth code lives in this repository. No OAuth type, host function or provider special case is added to `pd-vm` or any other RustScript core crate.

### 3.1 Library modules

Create:

```text
src/auth/mod.rs
src/auth/config.rs
src/auth/store.rs
src/auth/oauth.rs
src/auth/host.rs
src/auth/pkce.rs
src/auth/token.rs
```

Core public types:

```rust
pub struct AuthStore;
pub struct CredentialId(String);
pub struct OAuthProviderConfig;
pub struct OAuthTokenSet;
pub struct OAuthClient;
pub struct OAuthSession;
pub enum OAuthFlowKind { AuthorizationCodePkce, DeviceCode }
pub enum AuthStatus { Active, ReauthRequired, Disabled }
pub enum OAuthErrorCode;
```

`OAuthClient` receives an injected clock, HTTP transport, browser opener and loopback listener factory so tests never contact live providers.

### 3.2 Generic native operations

Expose library functions and matching RSS host functions under an `oauth::` namespace:

```text
oauth::request(auth_id, operation, payload) -> typed response
oauth::save_tokens(auth_id, token_response) -> credential metadata
oauth::access_token(auth_id) -> short-lived access envelope
oauth::status(auth_id) -> redacted metadata
oauth::delete(auth_id) -> typed result
```

`operation` is a symbolic operation configured by Rust (`device_start`, `device_poll`, `token_exchange`, `refresh`). RSS cannot pass an arbitrary URL, HTTP method or Authorization header. Rust resolves endpoint, method, body encoding, timeout and allowed authority from `config.yaml`.

`oauth::request` returns bounded provider data:

```json
{
  "ok": true,
  "status": 200,
  "body": {},
  "retry_after_ms": null
}
```

The host enforces:

- HTTPS remote endpoint and configured authority.
- bounded response body, JSON depth/key/string limits and deadline.
- cancellation propagated from the owning CLI/run.
- redaction of token-shaped response fields in logs and errors.
- no durable event publication for raw OAuth payloads.

`oauth::save_tokens` accepts a provider response only from the active in-memory OAuth session. It validates access token, optional refresh rotation, token type and expiry before calling `AuthStore`.

`oauth::access_token` returns only access token, token type, expiry and derived account ID to the ephemeral provider invocation. It never returns refresh token to RSS.

### 3.3 Generic authorization-code OAuth flow

Rust implements a reusable Authorization Code + PKCE S256 flow:

1. Generate cryptographically random verifier and state.
2. Build authorization URL from the selected provider config.
3. Bind a random loopback port on `127.0.0.1` and accept one bounded callback.
4. Open the browser when available.
5. Validate exact state and single-use callback session.
6. Exchange code using form encoding and the configured token endpoint.
7. Persist validated tokens through `AuthStore`.
8. On SSH/headless systems, print the URL and accept a pasted callback URL/code through the CLI without weakening state/PKCE checks.
9. Cancel and remove all transient state on timeout, Ctrl-C or callback error.

Generic flow configuration supports provider-specific scopes and additional public authorization parameters through a strict allowlist. Client secrets are outside the initial public-client scope.

### 3.4 Generic refresh flow

Rust owns token refresh for every OAuth provider:

1. Read credential and generation.
2. If access token remains valid beyond `refresh_skew_seconds`, return it.
3. Serialize refresh per credential ID; re-read after acquiring the lock.
4. POST `grant_type=refresh_token` with client ID and current refresh token.
5. Require a new access token.
6. Preserve old refresh token if the response omits one; atomically replace it when rotated.
7. Update absolute expiry from `expires_in`, with bounded clock-skew handling.
8. Classify `invalid_grant`, `invalid_token`, HTTP 401/403 and consumed refresh token as `reauth_required`.
9. Classify 429 using `Retry-After`; keep existing credential active and expose a retryable/quota error.
10. Treat transport timeout and 5xx as retryable; never overwrite a valid credential with a partial response.

Two gateway processes racing a single-use refresh token converge through the auth file lock and generation check. The later process adopts the newer generation rather than replaying the old refresh token.

## 4. RSS Codex device login

Create:

```text
rss/auth/codex_device.rss
rss/auth/types.rss
```

The Codex-specific state machine remains in RSS and uses only the generic Rust host functions.

### 4.1 State sequence

1. Call `oauth::request(auth_id, "device_start", {client_id})`.
2. Parse `user_code`, `device_auth_id` and `interval`; reject missing/wrong-type/oversized fields.
3. Emit a sanitized CLI instruction containing `https://auth.openai.com/codex/device` and the user code. The device auth ID remains internal.
4. Poll `device_poll` with `{device_auth_id, user_code}` until authorization, cancellation or a 15-minute absolute deadline.
5. Treat HTTP 403/404 as pending for this provider.
6. Honor configured minimum interval and bounded 429 `Retry-After`; no tight polling.
7. Parse `authorization_code` and `code_verifier` from the successful poll response.
8. Call `token_exchange` using authorization-code grant, configured redirect URI and verifier.
9. Call `oauth::save_tokens`; report only redacted credential metadata.
10. Clear all transient values before return on success, rejection, cancellation or timeout.

### 4.2 Required RSS tests

Use a fake native OAuth host and fixture responses to cover:

- happy path and exact operation order.
- pending 403/404 followed by success.
- 429 backoff and absolute deadline.
- cancellation during wait.
- malformed start, poll and exchange responses.
- exchange with missing access token.
- refresh token present/absent in initial exchange.
- no raw token/device auth ID in events, snapshots or rendered output.
- no direct `http::*` call and no hard-coded credential persistence in the RSS module.

## 5. CLI auth and config UX

Refactor the current single-purpose argument parser without breaking legacy invocation.

Commands:

```text
rustscript-agent auth login openai-codex
rustscript-agent auth login <provider>
rustscript-agent auth status [provider]
rustscript-agent auth logout <credential-id>
rustscript-agent config path
rustscript-agent config check
rustscript-agent run --script ...
```

Legacy `rustscript-agent --script ...` remains an alias for `run` during migration.

Files likely to change:

```text
src/bin/rustscript-agent.rs
src/bin/rustscript-agent-gateway.rs
src/config.rs
src/lib.rs
```

CLI acceptance criteria:

- Login writes only `auth.yaml`; provider/model selection writes only `config.yaml`.
- Status output never prints token prefixes or lengths.
- Logout removes one named credential atomically and leaves unrelated credentials unchanged.
- `config check` validates config/auth references and reports missing, disabled or reauth-required credentials without printing secrets.
- Device login works over SSH without trying to bind a publicly reachable callback.
- Ctrl-C exits with a typed cancellation and leaves no partial credential entry.

## 6. Runtime provider integration

### 6.1 Credential resolution

At run admission, freeze only the credential ID and provider configuration hash. Immediately before each real provider request:

1. Resolve the named credential through `AuthManager`.
2. Refresh when required.
3. Construct an ephemeral provider transport profile.
4. Invoke the RSS provider adapter.
5. Drop the token-bearing profile after the call.

Do not put access/refresh tokens in:

- `RunContext` or its SQLite JSON.
- provider fingerprint input.
- `model.requested` / `model.completed` event payloads.
- assistant/tool messages.
- metrics labels.
- artifact files.
- panic/error strings.

The durable provider fingerprint uses model, protocol, sanitized provider options and canonical messages. Credential ID and token generation are excluded so a refresh does not change logical request identity.

### 6.2 Codex Responses transport

Implement the Codex inference path required by the new login:

```text
rss/llm/openai_responses.rss
rss/llm/harness.rss
src/runtime/rss_runner.rs
```

Required request behavior:

- Base URL defaults to `https://chatgpt.com/backend-api/codex` from config.
- Transport uses the Responses protocol expected by the Codex backend.
- Rust derives `ChatGPT-Account-ID` from the access-token JWT claim and exposes it only to the ephemeral adapter profile.
- Set the Codex-compatible `originator` and `User-Agent` headers from trusted native configuration, never from user/RSS payload.
- Authorization header is built at the final transport boundary.
- 401 triggers one refresh-and-retry for the same logical provider step; no duplicate `model.requested` row or turn count.
- 429/quota remains distinct from expired authentication.
- Streaming and cancellation preserve the existing durable provider contract.

Tests use a local TLS/HTTP fixture or injected transport; no live OpenAI call belongs in CI.

## 7. Bundled coding agent default

Change gateway startup so a production binary can run without a source checkout:

- Embed `rss/agent/main.rss` and its imports at build time or package them as verified resources beside the binary.
- `agent.source: bundled:coding` is the default.
- `agent.source: file:/absolute/path.rss` enables custom source after size/hash/compile validation.
- Keep `RUSTSCRIPT_AGENT_SCRIPT` as a deprecated migration override only.
- Compile the selected source at startup and expose its hash in redacted health metadata.
- Startup fails before binding when the source or provider/auth reference is invalid.

Tests prove the installed binary can start from a directory containing no repository source files.

## 8. Explicit workspace selection

Add config and API fields for workspace selection:

- `workspaces.allowed_roots` defines canonical permitted roots.
- `workspaces.default` is optional and must lie under an allowed root.
- `POST /api/runs` accepts a workspace path or configured workspace name.
- Telegram session commands can select/status a workspace; the selected canonical path is durably attached to the session.
- Admission resolves the path once, opens the directory capability and freezes it into `RunLimits`.
- Symlink replacement after admission cannot escape the opened root.
- A request cannot select process cwd implicitly when no default is configured.

Existing file/process confinement tests become parameterized across default, named, denied, symlink and reopen cases.

## 9. Approval execution chain

Wire existing approval persistence into the serial tool dispatcher:

1. `read_file` and `search_files` follow configured read policy.
2. `write_file` and `patch` default to `ask`.
3. `terminal` and `process` default to `ask`.
4. Before `tool.started` or native effect, persist `approval.requested` with canonical call hash and expiry.
5. Expose approve/reject through HTTP and Telegram.
6. Resume the same durable tool call after approval; revalidation must detect changed name/arguments/parent.
7. Rejection, expiry, stop and restart produce one typed terminal tool result with no native effect.
8. Approval records contain sanitized summaries, never complete file contents, command output or credentials.

The durable replay rule remains: an already completed/failed/interrupted canonical result bypasses both approval and native effect.

## 10. Production compaction

Wire `rss/agent/compact.rss` into `AgentService`:

- Trigger before a provider request when configured message/token bounds are crossed.
- Expose explicit HTTP and Telegram compaction actions.
- Preserve tool-call/tool-result pairs and the durable generation contract.
- A compaction failure leaves original history readable and fails or continues according to explicit policy.
- Restart resumes or fails pending compaction exactly once.
- The next provider request uses the committed summary plus retained tail.

Tests run a long real coding loop across compaction and reopen, asserting no lost parent chain and bounded provider context.

## 11. Task sequence and TDD gates

The RSS-tool migration is the first implementation phase. Tasks 1–13 remain blocked until Tasks 0A–0F pass their gates.

### Task 0A: Define RSS tool contracts and registry

**Files:** create `rss/tools/types.rss`, `rss/tools/registry.rss`, `rss/tools/validate.rss`; add `tests/rss_tool_registry_tests.rs`.

**RED:** fixture tests for exact descriptors, deterministic ordering/identity, duplicate names, schema bounds, enablement and an extra fixture-only RSS tool that requires no Rust enum change.

**GREEN:** RSS exports canonical descriptors and registry identity; Rust only performs generic structural bounds on the exported snapshot.

**Commit:** `feat(tools): define rss tool registry contracts`

### Task 0B: Add generic lifecycle execution tokens

**Files:** create `src/capabilities/types.rs`, `src/capabilities/lifecycle.rs`, `src/capabilities/host.rs`; modify `src/runtime/agent_host.rs`, `src/service.rs`; add `tests/capability_lifecycle_tests.rs`.

**RED:** durable-before-token, owner mismatch, replay, approval ceiling, deadline, cancellation, single-close, open-token recovery and panic cleanup tests.

**GREEN:** expose `agent_runtime::tool_prepare` and `agent_runtime::tool_commit`; public tool names remain opaque.

**Commit:** `feat(runtime): issue scoped tool capability tokens`

### Task 0C: Migrate read-only file tools to RSS

**Files:** create `src/capabilities/filesystem.rs`, `rss/tools/read_file.rss`, `rss/tools/search_files.rss`; modify `src/runtime/agent_host.rs`; add RSS/capability equivalence fixtures.

**RED:** exact old/new envelopes for pagination, line numbering, regex/glob behavior, ordering, invalid paths, symlink races, cancellation and output caps.

**GREEN:** RSS owns arguments, search/read algorithms and formatting; Rust exposes confined metadata/list/read-range primitives only.

**Commit:** `feat(tools): implement file reads in rss`

### Task 0D: Migrate mutating file tools to RSS

**Files:** create `rss/tools/write_file.rss`, `rss/tools/patch.rss`; extend `src/capabilities/filesystem.rs`; add atomic-write and patch fixture tests.

**RED:** exact write/patch envelopes, replacement uniqueness, patch grammar, expected-hash conflict, atomic replacement, file mode, symlink replacement, cancellation and interrupted recovery.

**GREEN:** RSS owns write/patch semantics and diff formatting; Rust exposes atomic compare-and-write and root confinement only.

**Commit:** `feat(tools): implement file mutation in rss`

### Task 0E: Migrate process tools to RSS

**Files:** create `src/capabilities/process.rs`, `rss/tools/terminal.rss`, `rss/tools/process.rss`; add process capability and RSS mapping tests.

**RED:** spawn/poll/log/stdin/kill, cwd, environment allowlist, process group, output cursor, deadline, cancellation, stop and reopen fixtures.

**GREEN:** RSS owns public terminal/process validation, actions and formatting; Rust owns opaque process resources and bounded native process operations.

**Commit:** `feat(tools): implement process tools in rss`

### Task 0F: Switch agent dispatch and remove native tool domain

**Files:** create `rss/tools/dispatch.rss`; modify `rss/agent/main.rss`, `src/runtime/agent_host.rs`, `src/service.rs`, `src/config.rs`, `src/lib.rs`; remove superseded `src/tools/*`; update all tool/agent/gateway E2E.

**RED:** architecture tests that fail while `agent::tool_dispatch`, `NativeToolExecutor`, built-in Rust tool order, public Rust descriptors or name-keyed Rust dispatch remain.

**GREEN:** `rss/agent/main.rss` calls `tools::dispatch`; surviving generic code lives under `src/capabilities`; existing durable message/event contracts remain compatible.

**Commit:** `refactor(tools): complete rss tool ownership`

### Task 1: Add config/auth schemas and path resolution

**Files:** create `src/config_file.rs`, `src/auth/config.rs`; modify `src/config.rs`, `src/lib.rs`; add `tests/config_file_tests.rs`.

**RED:** tests for missing files, strict key separation, home override, invalid auth reference, HTTPS policy and bounded YAML.

**GREEN:** minimal loaders and typed validation. No OAuth network code.

**Commit:** `feat(config): split runtime settings from auth state`

### Task 2: Build the secure auth store

**Files:** create `src/auth/store.rs`, `src/auth/token.rs`; add `tests/auth_store_tests.rs`.

**RED:** mode, symlink, corrupt file, atomic replacement, refresh rotation, generation conflict, multi-credential preservation and redacted Debug tests.

**GREEN:** bounded YAML store with locking and atomic persistence.

**Commit:** `feat(auth): add isolated credential store`

### Task 3: Implement generic OAuth + PKCE

**Files:** create `src/auth/oauth.rs`, `src/auth/pkce.rs`; add `tests/oauth_flow_tests.rs`.

**RED:** authorization URL, PKCE/state, loopback callback, manual callback, timeout, cancellation, malformed token response and refresh classification tests.

**GREEN:** transport-injected generic OAuth client and refresh manager.

**Commit:** `feat(auth): add generic oauth flows and refresh`

### Task 4: Expose OAuth host functions to RSS

**Files:** create `src/auth/host.rs`; modify `src/runtime/rss_runner.rs`, `src/runtime/mod.rs`; add `tests/oauth_host_tests.rs`.

**RED:** catalog/schema, operation allowlist, authority confinement, cancellation, response caps and secret-redaction tests.

**GREEN:** register `oauth::*` only in the agent/auth runner catalog. Core dependency remains unchanged.

**Commit:** `feat(auth): expose confined oauth host functions`

### Task 5: Implement Codex device login in RSS

**Files:** create `rss/auth/types.rss`, `rss/auth/codex_device.rss`; add `tests/codex_device_login_tests.rs` and fixtures.

**RED:** full state-machine fixture suite.

**GREEN:** RSS orchestration using symbolic native OAuth operations.

**Commit:** `feat(auth): implement codex device login in rss`

### Task 6: Add auth/config CLI

**Files:** modify `src/bin/rustscript-agent.rs`; optionally create `src/cli.rs`; add `tests/auth_cli_tests.rs`.

**RED:** subprocess tests with isolated home, headless flow, cancellation, status and logout.

**GREEN:** subcommands with legacy run compatibility.

**Commit:** `feat(cli): add auth and config commands`

### Task 7: Resolve and refresh credentials at provider call time

**Files:** modify `src/service.rs`, `src/runtime/rss_runner.rs`, `src/durable_provider.rs`, `src/config.rs`; add `tests/provider_auth_tests.rs`.

**RED:** expired token refresh, rotated refresh token, concurrent calls, 401 one-shot refresh, 429 classification, restart and no-secret durable-state tests.

**GREEN:** `AuthManager` integration preserving provider idempotency.

**Commit:** `feat(provider): resolve oauth credentials at runtime`

### Task 8: Complete Codex Responses inference

**Files:** modify `rss/llm/openai_responses.rss`, `rss/llm/harness.rss`, `src/runtime/rss_runner.rs`; extend `tests/provider_tests.rs`; add `tests/codex_agent_e2e_tests.rs`.

**RED:** wire/header/parser/stream/cancellation fixtures and a complete agent turn using fake Codex transport.

**GREEN:** real protocol adapter with native trusted headers.

**Commit:** `feat(provider): connect codex oauth to responses`

### Task 9: Make bundled coding agent the gateway default

**Files:** modify `src/bin/rustscript-agent-gateway.rs`, `src/service.rs`, `Cargo.toml`; add packaging/startup tests.

**RED:** binary starts outside checkout and invalid custom source fails before listen.

**GREEN:** bundled source/resource loading.

**Commit:** `feat(gateway): default to bundled coding agent`

### Task 10: Add explicit workspace config and session binding

**Files:** modify `src/config.rs`, `src/gateway/api_server.rs`, `src/gateway/telegram.rs`, `src/service.rs`; extend file/process/gateway tests.

**RED:** allowed/default/named/denied/reopen cases.

**GREEN:** canonical workspace capability frozen at admission.

**Commit:** `feat(workspace): bind sessions to allowed roots`

### Task 11: Wire approval decisions into execution

**Files:** modify `src/service.rs`, `src/capabilities/lifecycle.rs`, `rss/tools/dispatch.rss`, gateway/Telegram handlers and approval storage RSS; add approval E2E.

**RED:** no-effect-before-approval, reject/expire/stop/restart/replay cases, plus a risk-class downgrade attempt from RSS after approval.

**GREEN:** generic Rust lifecycle validates the frozen RSS descriptor and approval ceiling before issuing an execution token; RSS retains public tool dispatch ownership.

**Commit:** `feat(approval): gate mutating tool effects`

### Task 12: Wire production compaction

**Files:** modify `src/service.rs`, `rss/agent/main.rss`, gateway/Telegram handlers; extend compaction and agent-loop E2E.

**RED:** threshold, explicit request, crash/reopen and provider-context assertions.

**GREEN:** durable compaction before provider request.

**Commit:** `feat(agent): compact long running sessions`

### Task 13: Documentation, migration and release integration

**Files:** modify `README.md`, `docs/configuration.md`, `docs/deployment.md`; add YAML examples and migration tests.

Actions:

- Remove stale claims that OpenAI Chat remains core-blocked.
- Document current protocol matrix accurately.
- Migrate supported `RUSTSCRIPT_AGENT_*` behavior settings into `config.yaml`; keep only home/bootstrap migration inputs in environment.
- Document `auth.yaml` backup/restore and permission requirements without showing token examples that resemble real secrets.
- Merge the integration stack into `master` using repository history rules.
- Build source and packaged binaries from a clean checkout.

**Commit:** `docs(agent): document authenticated production setup`

## 12. Verification matrix

Every implementation task follows RED → GREEN → refactor. Final gates run serially with the project target-slot rules:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-features --all-targets
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace --all-features --all-targets -- --test-threads=1
cargo test --locked --workspace --all-features --all-targets --release -- --test-threads=1
```

Additional mandatory security gates:

- verify every model-visible tool descriptor, schema, validator, dispatcher and formatter is sourced from `rss/tools/*`.
- scan production Rust source for the removed `agent::tool_dispatch`, `NativeToolExecutor`, built-in public tool ordering and branches keyed by the six public tool names.
- register and execute a fixture-only RSS tool without changing any Rust enum or public-name dispatch table.
- verify production host catalogs omit unrestricted pd-vm filesystem/process APIs that bypass execution-token checks.
- crash before/after `tool_prepare`, each capability effect and `tool_commit`; verify durable-first ordering, interrupted recovery and no automatic repeat of mutating effects.
- scan persisted SQLite, YAML, event, message, artifact and log fixtures for exact synthetic access/refresh/device/code-verifier secrets.
- crash at every boundary: before auth write, after temp fsync, after rename, after refresh response, after durable provider request and before provider completion.
- concurrent process refresh using a one-use fake refresh token; assert one network refresh or generation adoption and one valid final credential.
- replay a completed provider/tool step after access-token rotation; assert no duplicate external effect.
- run CLI/gateway from a clean directory with only installed resources, `config.yaml` and `auth.yaml`.
- verify `auth.yaml` never appears in workspace tools, provider prompts or HTTP API responses.

## 13. Delivery contract

The finished system must satisfy all of these statements:

1. Every model-visible tool is defined and implemented in `rss/tools/*`.
2. RSS owns public tool schemas, validation, dispatch, algorithms and result formatting; Rust owns only generic confined capabilities and lifecycle enforcement.
3. Rust production code contains no `NativeToolExecutor`, built-in public tool list/schema or public-name dispatch branches.
4. `rss/agent/main.rss` calls RSS tool dispatch directly; `agent::tool_dispatch` is removed.
5. A new RSS-only tool can be registered and executed without editing Rust dispatch code.
6. A fresh user can create config, run Codex device login, select a workspace and start the bundled coding agent without editing RSS or injecting a test provider.
7. OAuth access tokens refresh automatically and atomically; refresh-token rotation survives concurrent gateway/CLI access.
8. `config.yaml` contains no credentials; `auth.yaml` contains no behavior policy.
9. Codex device-login policy is implemented in RSS; generic OAuth transport, PKCE, storage and refresh are implemented in Rust inside `rustscript-agent`.
10. No OAuth functionality is added to RustScript core.
11. Raw auth material is absent from durable agent state, events, metrics, logs, artifacts and error text.
12. Mutating tool effects respect workspace and approval policy.
13. Long sessions compact durably and reopen without losing tool parent relationships.
14. Full debug and release suites pass from the final integrated commit.

## 14. Main risks and chosen trade-offs

- **RSS tool logic still needs native safeguards:** every effect requires a Rust-issued execution token. Production host catalogs exclude unrestricted file/process APIs that could bypass workspace, approval, deadline or durable lifecycle checks.
- **Migration can change output contracts:** each tool migrates against exact old/new fixtures before old native dispatch is removed. Public tool names and durable message/event shapes remain compatible.
- **YAML contains plaintext tokens:** initial scope uses strict local-file protection and atomic writes. OS keychain integration may be added later behind the same `AuthStore` trait without changing RSS or provider contracts.
- **Codex device endpoints are provider-specific:** endpoint paths and response interpretation stay in RSS/config; Rust exports symbolic confined operations and generic token persistence.
- **Refresh tokens may rotate on every use:** per-credential serialization plus generation revalidation is mandatory from the first release.
- **Codex backend needs trusted headers:** account ID is derived natively from JWT; originator/User-Agent are trusted config constants and cannot come from a run request.
- **Multiple auth entries:** named credentials are supported now; automatic pool rotation remains outside this plan.
- **Environment migration:** behavior settings move to `config.yaml`; environment remains only for selecting the agent home during bootstrap and for temporary compatibility reads.
