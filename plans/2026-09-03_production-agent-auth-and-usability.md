# Production Agent Authentication and Usability Implementation Plan

**Goal:** 将当前已通过 E2E 的 serial coding-agent engine 变成可直接配置真实模型、选择项目、安全运行并可长期恢复的 gateway/CLI agent。

**Architecture:** RSS 是 agent 的业务行为主实现层：provider 选择与适配、认证与登录/refresh 编排、retry/polling、模型请求与响应整形、session/workspace policy、approval、compaction 以及用户可见业务错误均由 RSS/provider adapter 决定。RustScript agent 只提供必要的通用基础能力和安全执行边界，包括有界解析、typed structural schema、可信 authority enforcement、secret storage/transport、PKCE 原语、callback listener、CAS/锁、fsync、取消与资源上限。配置和凭据的 Rust 类型可继续声明结构字段；字段含义、默认策略和工作流决策交由 RSS 解释。

Rust 与 RSS 通过受限 host bridge 协作。provider/domain 映射由可信 policy 驱动，RSS 只能使用 policy 授权的 provider/authority，不能以请求参数替换 authority。原始 access/refresh token、authorization code、device auth ID、PKCE verifier 等保持 host-side opaque；RSS 只接收 bounded、sanitized provider data 与不可伪造的 opaque handles。现有公共工具、durable messages/events、CLI legacy invocation 和资源阈值保持兼容。

**Tech Stack:** Rust 2024、Tokio、Axum/Hyper/Rustls、Serde YAML、RustScript/pd-vm host API、OAuth 2.0 Authorization Code + PKCE、refresh-token grant、OpenAI Codex device authorization、SQLite durable agent state。

---

## 0. Mandatory RSS-first boundary for Task 1 and every later task

This section is normative. It takes precedence over conflicting language, file lists, examples, and implementation steps elsewhere in this plan. It applies retroactively to Task 1 and to all in-progress and future Task 2+ work.

- RSS is the primary implementation layer for agent business behavior: provider selection and adaptation, authentication/login/refresh workflow orchestration, retry and polling policy, model request/response shaping, session/workspace policy, approvals, compaction decisions, and user-facing business error mapping.
- Rust supplies only necessary generic foundational capabilities and their security enforcement: bounded parsing/typed transport, filesystem confinement and permissions, cross-process locking, atomic persistence, generation compare-and-swap, cryptographic/PKCE primitives, bounded HTTP transport, callback listener mechanics, clock/cancellation, and secret-handle access. Rust may enforce mandatory trust boundaries; it must not become a parallel business workflow engine.
- Provider-specific endpoints/defaults, protocol payload interpretation and workflow decisions belong in RSS/provider adapters. Trusted authority validation may remain a generic Rust mechanism driven by trusted policy/configuration, without granting RSS permission to substitute an unauthorized authority. Secrets must remain confined to host-side storage/transport and opaque handles; RSS-first does not permit exposing raw credentials to model context, durable events, or logs.
- Structural data declarations may remain in Rust when they define bounded YAML/JSON shapes, typed transport envelopes, persistence records, or capability handles. Rust loaders validate types, sizes, key separation, generic URL syntax and trusted authority constraints; RSS interprets provider fields, state labels, defaults, selection and business errors. Do not duplicate or relocate generic declarations solely to satisfy an ownership label.
- Task 1 schema/loaders and Task 2 secure storage are permissible Rust foundations only to the extent that they implement data integrity, resource bounds, persistence and capability enforcement. Provider business rules, provider-name branches, refresh timing, login decisions and business error mapping embedded in those modules require migration to RSS or a separately justified generic security contract.
- Every Task 1+ implementation and review must enumerate RSS-owned behavior, necessary Rust primitives, the host bridge contract, and real RSS entry-path verification. A Rust-heavy task file list is not permission to move business behavior into Rust. Amend conflicting later task instructions before their implementation is accepted.
- Every real provider/auth/runtime path must use the opaque-provider bridge described in section 1B. Existing RSS `api_key` maps and direct RSS `http::*` calls for provider authentication are migration blockers; they cannot be retained as a parallel path.
- Re-review the integrated Task 1 implementation, the current Task 2 scope, and every remaining task against this boundary. Earlier review results do not establish compliance with this clarified requirement. Block further integration of Task 1+ changes until the boundary review and any required corrections pass; preserve existing commits and work in progress.

### 0.1 Boundary review evidence and current acceptance status

The completed review is preserved at:

```text
/mnt/TEMP/workspace/rustscript-agent/tmp/prod-agent-rss-boundary-review-84988318/rss-first-boundary-review.md
```

It records:

- plan snapshot `9a5cf3a0ddcfb148228d72fffebae08a177c6f52`;
- integrated Task 1 commit `1c0b8dfd8aaac82552adf66cf0dee114f0af4e8f`;
- `passed=false` for both normative compliance and quality acceptance;
- Task 1 Rust-only loader/schema coverage with no real RSS entry or host-bridge verification;
- Codex-specific endpoint/default/authority logic in Rust and an existing RSS `api_key` flow that violates the opaque-credential boundary;
- Task 2–13 file lists and acceptance descriptions that did not consistently name RSS owners, bridge contracts or RSS entry tests.

The existing integration commit is retained. Task 1 acceptance is **reopened for the boundary address**. Task 2 acceptance is **unaccepted** until its interrupted snapshot has been reviewed and the revised boundary is verified.

### 0.2 Explicit staged correction order

The following stages are mandatory and intentionally separate foundation work from later provider/runtime behavior:

1. **Stage A — integrated Task 1 boundary address.** Address the existing Task 1 integration on top of `1c0b8df` without reverting it. Remove provider-name/default/business branches from the generic loader, keep structural schema/resource/security checks, and add a minimal real RSS config/auth entry plus a fixture host bridge. This entry exercises only structural snapshot and opaque-reference handling; it must not require Task 2 storage, OAuth networking, Codex login, or authenticated model runtime. Task 1 remains reopened until this focused gate passes.
2. **Stage B — interrupted Task 2 snapshot review.** Freeze and review the current interrupted Task 2 snapshot before any continuation. Verify its exact diff, file ownership, raw-secret flow, Rust provider semantics and test scope against section 0. Task 2 remains unaccepted during this review. After the review, continue only with generic store primitives, generation/CAS and the minimal RSS store entry; do not require future OAuth or provider-runtime functionality from this foundation step.
3. **Stage C — opaque-provider bridge migration.** Before accepting any authenticating runtime work in Task 7 or Task 8, migrate the existing RSS provider bridge (`rss/providers/profile.rss`, `rss/llm/types.rss`, `rss/llm/openai_chat.rss` and related provider adapters) from raw `api_key` maps to the section 1B opaque handle contract. Add negative secret-flow tests and remove direct provider Authorization assembly from RSS. Task 3–6 may build and exercise the new bridge with fake transports; no real authenticated provider runtime may proceed until Stage C passes.
4. **Stage D — later RSS-owned runtime behavior.** Continue provider runtime, Codex Responses, bundled source policy, workspace/session policy, approvals and compaction only after their individual RSS entry gates pass. Each stage may consume a prior generic primitive through the bridge, yet may not move its business policy into Rust for convenience.

---

## 1. Scope and completion boundary

本计划包含当前 agent 从“library/E2E 可运行”到“用户可配置并部署”的完整收尾路线：

1. 将现有 native model-facing tools 迁移为 RSS tools + Rust generic capabilities。
2. `config.yaml` / `auth.yaml` 双层配置；Rust 保留结构与安全校验，RSS 负责业务解释和默认策略。
3. Rust 通用安全、存储、PKCE、callback、bounded transport primitives 与 RSS host bridge。
4. RSS Codex device login。
5. RSS 编排通用 browser OAuth flow，包含 PKCE、loopback callback、headless/manual fallback 与 refresh；Rust 只提供原语、传输与 secret persistence。
6. 真实 provider runtime 接入，先闭合 OpenAI Codex，并先完成 opaque-provider bridge migration。
7. bundled coding agent 默认入口及 RSS source policy。
8. 显式 workspace 选择与 session 绑定。
9. write/process approval 执行链。
10. 自动/手动 compaction。
11. master 集成、部署与发布验收。

以下能力继续后置，不阻塞本计划完成：parallel tool calls、subagents、durable scheduler、多 gateway 共享同一 SQLite、OpenAI Responses/Anthropic 的全部 provider 覆盖。

### 1A. RSS tool ownership and Rust capability boundary

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

RSS owns all provider-visible descriptors, schemas, validation, dispatch, tool-specific algorithms, error mapping and output formatting. `rss/agent/main.rss` calls `tools::dispatch` directly. Entry modules may adapt host input into RSS types, while public semantics remain in RSS.

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

### 1B. Normative RSS ↔ Rust host bridge contract

This contract applies to config/auth, OAuth, provider runtime, workspace, approval and compaction. It is separate from business policy and must be usable by a minimal fixture host before the later features exist.

**Data classes:**

- **Structural values:** bounded typed maps/records for YAML, JSON, request envelopes and durable records. Rust may declare and validate these shapes; RSS assigns provider/business meaning.
- **Sanitized provider data:** status, bounded public headers, bounded non-secret body fields, retry timing, expiry numbers, public account metadata and typed error facts after secret fields are removed. RSS may interpret these values.
- **Opaque handles:** non-forgeable host-issued references tied to a credential, provider policy, callback session, generation, run or capability token. RSS may pass handles back to the host, yet cannot inspect, forge, duplicate or turn them into raw secret strings.

**Required calls and ownership:**

| Bridge call | RSS responsibility | Rust/host responsibility | Result visible to RSS |
|---|---|---|---|
| `config::load_snapshot(home)` | interpret provider/model/source/workspace/approval/compaction policy and defaults | bounded YAML, typed structural parse, key separation, home/path checks, generic URL and trusted-policy checks | sanitized config snapshot, credential IDs, trusted policy handles |
| `auth::load_metadata(credential_id)` | decide active/reauth/disabled meaning and next action | locked read, bounded parse and redacted metadata | provider ID, expiry, generation, status label, sanitized metadata; never raw token |
| `oauth::pkce_begin(policy_handle, public_intent)` | choose flow, scopes and provider parameters | random verifier/state, callback session and opaque verifier/state handles; trusted authority selection | authorization URL and opaque callback/verifier handles |
| `oauth::callback_wait(callback_handle)` | decide pending/success/cancel/timeout flow | single bounded loopback/manual callback, exact state and single-use checks, cancellation/deadline | sanitized result plus opaque authorization-code handle |
| `oauth::transport(request, credential_use)` | choose provider path, method, public payload, retry and interpretation | resolve authority/path from trusted policy, enforce HTTPS/allowlist/caps, inject secret at final transport boundary, redact | bounded sanitized response and opaque secret/result slots |
| `auth::save_if_generation(id, expected_generation, secret_slots, metadata)` | decide which provider fields constitute a token set and when to persist | validate slot provenance, lock, CAS, atomic replace, fsync and raw-token storage | redacted credential metadata or typed conflict/error |
| `workspace::open(selection, policy_handle)` | choose workspace name/path policy and user-facing errors | canonicalize/open confined directory and freeze capability | opaque workspace capability and canonical metadata |
| `lifecycle::prepare/commit(...)` and storage calls | choose business operation, summary and policy decision | durable-first records, risk ceilings, generation/recovery and native effect enforcement | typed committed/replayed result |

The provider request envelope is public and bounded:

```text
ProviderRequest {
    policy_handle: opaque trusted-provider policy handle,
    method: bounded public method,
    path: bounded provider path,
    public_headers: allowlisted non-secret headers,
    public_body: bounded typed/encoded provider payload,
    credential_use: none | opaque access handle | opaque refresh handle
}
```

RSS may choose a provider path and payload only through a policy handle obtained from trusted configuration. Rust resolves and enforces the authorized authority, optional path prefix and security-sensitive header policy; an RSS or user-supplied URL, `Host`, `Authorization`, cookie or authority cannot replace it. Provider/domain mapping is policy data, with no generic Rust switch from a provider name to a hard-coded domain.

The transport result is likewise bounded:

```text
SanitizedProviderResponse {
    status: bounded status,
    public_headers: allowlisted values,
    body_without_secret_fields: bounded structural data,
    retry_after_ms: bounded optional value,
    secret_slots: opaque handles tied to this request/session
}
```

Access tokens, refresh tokens, authorization codes, device auth IDs, PKCE verifiers and raw response fields remain host-side. RSS may inspect presence/type of sanitized fields and pass opaque slots to `auth::save_if_generation`; it never receives a token string. Rust adds `Authorization` only at the final transport boundary and never publishes it through events, messages, metrics, artifacts, logs or errors.

---

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

Proposed v1 shape. The values shown are public configuration data; omitted provider defaults and all selection decisions are supplied by RSS/provider adapters rather than by the generic Rust loader.

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
- Rust treats provider/model/source/workspace/approval/compaction fields as bounded structural data. RSS/provider adapters interpret their meaning, selection and defaults. Resource ceilings such as 64 turns, 128 tool calls and 1048576 output bytes remain enforced by Rust capabilities and may not be raised past the trusted ceiling.
- Provider-specific endpoint/path/flow fields are public structural values. RSS owns their interpretation and provider defaults. Rust performs generic URL syntax, size and scheme checks and verifies the resulting request against a trusted provider policy; it does not hard-code `openai-codex` field semantics.
- Provider endpoint must be HTTPS, except explicit loopback HTTP callback URLs generated by the local OAuth listener.
- Provider host/port/path enters an OAuth/provider-specific allowlist supplied by trusted policy. The mapping is data/configuration selected by the trusted host, not a provider-name branch in Rust. RSS cannot substitute a different authority.
- `auth` is a credential ID reference only. Generic reference existence and structural consistency may be checked by the host; provider matching and selection policy are RSS decisions.
- Unknown root/provider/auth keys fail startup with path-qualified errors.
- Deprecated environment aliases may be read-only migration inputs for one release, but the canonical source is YAML. Environment does not override token, refresh token or OAuth endpoint contents.

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

- Rust may retain typed persistence declarations for these fields and validate bounds, required storage shape and secret separation. RSS/provider adapters interpret `provider`, `kind`, `source`, `status`, scope meaning and lifecycle transitions.
- `auth.yaml` rejects model IDs, base URLs, workspace paths, timeout policy and other behavior configuration.
- Persist only fields required for runtime and refresh. Device code, user code, authorization code, PKCE verifier, PKCE state, request bodies and transient errors never enter this file.
- `id_token` is omitted unless a provider requires it for future runtime behavior. The initial Codex path does not persist it.
- `account_id` is optional sanitized provider metadata. If it must be derived from a token claim, derivation occurs host-side under an explicit trusted provider policy and only the validated non-secret metadata crosses the bridge; the generic auth store does not infer provider claim names. `account_id` is never trusted as authorization by itself.
- Refresh-token rotation increments `generation`. Writers must compare the generation observed before the network call and re-read under the auth lock before commit.
- Terminal refresh errors set `status: reauth_required` without deleting the last token pair. Transient network/5xx/429 errors leave credential state active and return a retryable typed error; RSS decides the business classification and user-facing action.

### 2.4 File security and concurrency

- Create home directory with Unix mode `0700`; create `auth.yaml`, lock and replacement files with `0600`.
- Reject symlink auth files and unsafe parent traversal; use no-follow/openat-style checks where supported.
- Read file through a bounded byte cap before parsing YAML.
- Save using same-directory exclusive temporary file, flush, fsync, atomic rename and parent-directory fsync.
- Protect read-modify-write using an in-process mutex plus cross-process lock.
- Never serialize auth structs through `Debug`; implement redacted summaries.
- Windows tests verify atomic replacement and best available ACL/file handling without claiming POSIX mode guarantees.
- Corrupt YAML is moved or copied to a timestamped `.corrupt` artifact only after a bounded read; startup/login returns a typed error and never silently starts from an empty credential set.
- Raw token bytes remain inside the host store and final transport boundary. The bridge exposes only opaque handles and sanitized metadata.

---

## 3. Rust security, storage, crypto and transport boundary

All new OAuth support lives in this repository. No OAuth type, host function or provider special case is added to `pd-vm` or any other RustScript core crate. Rust implements reusable primitives and security enforcement; RSS/provider adapters own flow orchestration and business interpretation.

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

Core public/structural types may include:

```rust
pub struct AuthStore;
pub struct CredentialId(String);
pub struct OAuthProviderConfig;       // bounded structural public config
pub struct OAuthTokenSet;              // host-side persistence representation
pub struct OpaqueCredentialHandle;
pub struct OpaqueSecretSlot;
pub struct OAuthTransport;
pub struct OAuthClient;              // injected bounded transport facade only
pub struct OAuthSession;             // host-side callback/session record only
pub struct SanitizedOAuthResponse;
pub enum OAuthFlowKind { AuthorizationCodePkce, DeviceCode } // structural tag only
pub enum AuthStatus { Active, ReauthRequired, Disabled }    // stored label; RSS interprets it
pub enum OAuthErrorCode;                                    // transport/security facts
```

`OAuthTransport` receives an injected clock, HTTP transport, browser opener and loopback listener factory so tests never contact live providers. It must not implement a provider login state machine, refresh scheduler, provider retry policy, provider-specific payload parser or provider-name-to-domain switch. Generic structural declarations remain in Rust where they describe persistence/transport records; their business meaning stays in RSS.

### 3.2 Generic native operations and bridge implementation

Expose library functions and matching RSS host functions under an `oauth::` namespace:

```text
config::load_snapshot() -> bounded structural config + trusted policy handles
oauth::load_metadata(auth_id) -> redacted credential metadata
oauth::pkce_begin(policy_handle, public_intent) -> authorization URL + opaque handles
oauth::callback_wait(callback_handle) -> sanitized callback result + opaque code handle
oauth::transport(provider_request, credential_use) -> SanitizedOAuthResponse
oauth::save_if_generation(auth_id, expected_generation, secret_slots, metadata) -> credential metadata
oauth::access_handle(auth_id) -> opaque access envelope
oauth::status(auth_id) -> redacted metadata
oauth::delete(auth_id) -> typed result
```

`provider_request` carries a bounded method/path/public body and an opaque trusted provider-policy handle. RSS owns the operation sequence and request payload semantics. Rust resolves the authorized authority and any allowed path/header policy from trusted configuration, enforces HTTPS/loopback rules, caps body/response sizes and rejects arbitrary URLs, methods outside the generic allowlist, `Authorization`, cookies and user-supplied security-sensitive headers. There are no Rust branches for `device_start`, `device_poll`, `token_exchange`, `refresh` or any other provider workflow operation.

The host enforces:

- HTTPS remote endpoint and configured trusted authority/path policy.
- bounded request/response body, JSON depth/key/string limits and deadline.
- cancellation propagated from the owning CLI/run.
- redaction of token-shaped response fields in logs and errors.
- no durable event publication for raw OAuth payloads.
- provenance and lifetime checks for every opaque handle/secret slot.

A token response is returned as sanitized public fields plus opaque secret slots. RSS may decide whether a response is a successful token set, which fields are required, how `expires_in` maps to policy, and what business error to show. `oauth::save_if_generation` accepts only slots from the active in-memory bridge session, checks their expected structural labels and generation, and persists their raw contents inside `AuthStore`; RSS never receives those contents.

`oauth::access_handle` returns only an opaque access handle and redacted metadata to RSS. The host uses the handle to assemble the Authorization header at the final transport boundary, then drops the token-bearing transport profile. A refresh handle follows the same path and is never convertible to an access-token string in RSS.

### 3.3 Generic authorization-code OAuth primitives

RSS/provider adapters implement the reusable Authorization Code + PKCE workflow using the bridge. Rust supplies the following primitives and security checks:

1. Generate cryptographically random verifier and state and retain them behind opaque handles.
2. Build/validate a bounded authorization URL from public parameters plus trusted provider policy; RSS chooses scopes and provider-specific public parameters.
3. Bind a random loopback port on `127.0.0.1` and accept one bounded callback.
4. Open the browser when available through the injected opener.
5. Validate exact state and single-use callback session in the host.
6. Exchange an opaque authorization-code handle through bounded transport with the opaque verifier; RSS owns the provider request sequence and response interpretation.
7. Persist validated token slots through `AuthStore` after RSS requests the save operation.
8. On SSH/headless systems, print the URL and accept a pasted callback URL/code through the CLI without weakening state/PKCE checks; the raw code remains host-side.
9. Cancel and remove all transient state on timeout, Ctrl-C or callback error.

Generic flow configuration supports provider-specific scopes and additional public authorization parameters through a strict allowlist. Client secrets are outside the initial public-client scope. RSS decides when to start, poll, exchange, retry or report; Rust enforces callback, PKCE, authority, size and cancellation boundaries.

### 3.4 Generic refresh primitives

RSS owns token refresh eligibility, timing, workflow, retry, status classification and user-facing policy for every provider. Rust supplies locked metadata/handle access, host-side refresh-token use, bounded transport and atomic persistence:

1. RSS reads metadata and decides whether the access token remains valid beyond configured `refresh_skew_seconds`; Rust returns only redacted metadata/opaque handles.
2. Rust serializes refresh per credential ID and re-reads after acquiring the lock.
3. RSS requests a refresh transport using an opaque refresh handle; Rust posts the generic `grant_type=refresh_token` form with the current raw refresh token only at the final host boundary.
4. RSS interprets the bounded response and decides whether a new access token is required; Rust enforces token-slot provenance and bounded fields.
5. RSS decides the expiry policy from sanitized `expires_in`; Rust applies bounded clock arithmetic and persists the selected metadata.
6. Rust preserves the old refresh token when the response omits one and atomically replaces it when a rotated opaque slot is supplied.
7. RSS classifies `invalid_grant`, `invalid_token`, HTTP 401/403 and provider-consumed refresh tokens as `reauth_required` according to provider policy.
8. RSS classifies 429 using bounded `Retry-After`; Rust preserves active credential state and returns a typed quota/transport fact.
9. RSS decides retry limits and backoff for timeout/5xx; Rust returns bounded typed transport errors and never overwrites a valid credential with a partial response.
10. Rust compares the observed generation before commit and re-reads under the auth lock. Two gateway processes racing a single-use refresh token converge on the newer generation; the later process adopts it rather than replaying the old refresh token.

This keeps CAS/locks/fsync and raw token persistence in Rust while keeping refresh workflow and policy in RSS.

---

## 4. RSS Codex device login

Create:

```text
rss/auth/codex_device.rss
rss/auth/types.rss
```

The Codex-specific state machine remains in RSS and uses only the generic bridge. Provider paths, payload interpretation, pending policy, interval and business error mapping remain in this adapter. Device auth ID, authorization code and PKCE verifier are host-side opaque values; the RSS state machine retains handles only.

### 4.1 State sequence

1. Obtain the trusted provider-policy handle and call the bridge with the public device-start payload containing `client_id`.
2. Parse bounded sanitized fields: `user_code`, `interval` and an opaque device-session handle. Reject missing, wrong-type or oversized fields.
3. Emit a sanitized CLI instruction containing `https://auth.openai.com/codex/device` and the user code. The device auth ID remains host-side and is never rendered.
4. Poll through the bridge with the opaque device-session handle and user code until authorization, cancellation or a 15-minute absolute deadline.
5. Treat HTTP 403/404 as pending for this provider.
6. Honor configured minimum interval and bounded 429 `Retry-After`; RSS prevents tight polling.
7. On success, receive opaque authorization-code and verifier handles plus sanitized response metadata.
8. Call the bridge for token exchange using those handles, the configured public redirect URI and RSS-selected provider payload.
9. Call `oauth::save_if_generation` with opaque secret slots; report only redacted credential metadata.
10. Clear all transient RSS handles and request state before return on success, rejection, cancellation or timeout; the host invalidates its corresponding handles.

### 4.2 Required RSS tests

Use a fake native OAuth host and fixture responses to cover:

- real `codex_device::login` RSS entry and exact bridge operation order.
- happy path and exact operation order.
- pending 403/404 followed by success.
- 429 backoff and absolute 15-minute deadline.
- cancellation during wait.
- malformed start, poll and exchange responses.
- exchange with missing access token slot.
- refresh token present/absent in initial exchange.
- no raw token/device auth ID/authorization code/verifier in events, snapshots or rendered output.
- no direct `http::*` call and no hard-coded credential persistence in the RSS module.

---

## 5. CLI auth and config UX

Refactor the current single-purpose argument parser without breaking legacy invocation. The Rust CLI remains a thin shell for argv, home, TTY/browser/cancellation and process exit mapping. RSS owns command meaning, provider selection, source/default policy, auth status interpretation, logout semantics and user-facing business errors.

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
rss/auth/commands.rss
rss/config/selection.rss
```

**RSS owner:** `rss/auth/commands.rss` dispatches command behavior and redacted output; `rss/config/selection.rss` interprets provider/model/source selection and defaults. These modules call the bridge and do not receive raw credentials.

**Necessary Rust primitives:** argv/path/home resolution, TTY/browser/manual callback plumbing, bounded output, cancellation/exit status, structural config loading and host-side auth persistence. Rust must not select a provider or decide a login/refresh business outcome.

**Bridge contract:** CLI passes a bounded command envelope and opaque IDs to RSS. RSS calls `config::load_snapshot`, `auth::load_metadata`, `oauth::*` and `auth::delete`; the host writes/removes raw credentials atomically and returns only sanitized metadata. `config check` may report missing/disabled/reauth-required labels from RSS interpretation while Rust enforces structural references and secret redaction.

CLI acceptance criteria:

- Login writes only `auth.yaml`; provider/model/source selection writes only `config.yaml`.
- Status output never prints token prefixes or lengths.
- Logout removes one named credential atomically and leaves unrelated credentials unchanged.
- `config check` validates config/auth references and reports missing, disabled or reauth-required credentials without printing secrets.
- Device login works over SSH without trying to bind a publicly reachable callback.
- Ctrl-C exits with a typed cancellation and leaves no partial credential entry.
- Subprocess tests invoke the real RSS command entry with an injected/fake host bridge; no live provider is required for the foundation gate.

---

## 6. Runtime provider integration

### 6.1 Credential resolution

At run admission, RSS freezes the selected provider, credential ID and provider configuration hash as non-secret logical inputs. Immediately before each real provider request:

1. RSS resolves provider/model selection and the named credential reference through the sanitized config/auth bridge.
2. RSS decides whether refresh is needed and, if so, runs the provider-specific refresh policy through `oauth::transport` and `auth::save_if_generation`.
3. The host returns an opaque access handle and sanitized provider metadata.
4. RSS/provider adapter builds the request body, path, public protocol headers and retry decision.
5. Rust validates the trusted provider policy, assembles the Authorization header at the final transport boundary, executes bounded transport and drops the token-bearing profile after the call.

There is no Rust `AuthManager` workflow deciding refresh or provider behavior. `src/service.rs` and `src/runtime/rss_runner.rs` only preserve generic admission, cancellation, durable redaction and bridge invocation boundaries.

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
rss/agent/provider_runtime.rss
src/runtime/rss_runner.rs
```

**RSS owner:** `rss/llm/openai_responses.rss` defines Codex request/response/stream shaping, provider parser, protocol header intent, provider error semantics and the one-shot retry decision. `rss/llm/harness.rss` and `rss/agent/provider_runtime.rss` drive the real RSS agent entry and durable turn policy.

**Necessary Rust primitives:** bounded request/response transport, cancellation, deadline, trusted authority/path policy, opaque credential use, final Authorization assembly, host-only sanitized metadata and durable event redaction. Rust does not parse Codex payload semantics or choose 401/429 retry behavior.

**Bridge contract:** RSS passes a policy handle, provider path, public request body and opaque access handle. Host returns a `SanitizedProviderResponse`; secret slots never enter RSS. If the Codex transport requires `ChatGPT-Account-ID`, host derives/validates it only under an explicit trusted provider policy and exposes sanitized account metadata. RSS may place that metadata in the provider request; user/run payloads cannot override trusted security-sensitive headers. `originator` and `User-Agent` are provider-specific header intent in RSS, while the host applies only policy-approved values and rejects arbitrary security-header overrides.

Required request behavior:

- Base URL defaults to `https://chatgpt.com/backend-api/codex` only in the RSS/provider policy or explicit public config; Rust does not inject a Codex default.
- Transport uses the Responses protocol expected by the Codex backend.
- Account metadata, when required, follows the sanitized host-only bridge contract above.
- Set Codex-compatible `originator` and `User-Agent` from trusted policy-approved values; never from user/RSS payload fields that bypass the policy.
- Authorization header is built at the final host transport boundary.
- RSS decides whether a 401 causes one refresh-and-retry for the same logical provider step; no duplicate `model.requested` row or turn count.
- RSS maps 429/quota distinctly from expired authentication.
- Streaming and cancellation preserve the existing durable provider contract.

Tests use a local TLS/HTTP fixture or injected transport through the bridge; no live OpenAI call belongs in CI. Acceptance requires a complete real RSS agent turn using the fake Codex transport after Stage C opaque-provider migration passes.

---

## 7. Bundled coding agent default

Change gateway startup so a production binary can run without a source checkout. RSS owns source selection/default policy and source-related business errors. Rust owns resource packaging, size/hash verification and the generic compile/startup gate.

- Embed `rss/agent/main.rss` and its imports at build time or package them as verified resources beside the binary.
- `agent.source: bundled:coding` is the RSS default policy; the Rust startup layer only supplies/validates the selected structural source descriptor.
- `agent.source: file:/absolute/path.rss` enables custom source after size/hash/compile validation.
- Keep `RUSTSCRIPT_AGENT_SCRIPT` as a deprecated migration override only.
- Compile the selected source at startup and expose its hash in redacted health metadata.
- Startup fails before binding when the source or provider/auth reference is invalid.

Files likely to change:

```text
rss/agent/source_policy.rss
rss/agent/main.rss
src/bin/rustscript-agent-gateway.rs
src/service.rs
Cargo.toml
```

**Bridge contract:** RSS returns a bounded source-selection decision and public source descriptor; Rust verifies embedded/file resource identity, size and compile boundary, then returns an opaque verified-source handle. RSS agent behavior executes from the verified handle. No Rust source-name switch may implement coding-agent policy.

Tests prove the installed binary can start from a directory containing no repository source files and that the real RSS entry is loaded. Invalid custom source fails before listen. The test must not require an authenticated provider call.

---

## 8. Explicit workspace selection

Add config and API fields for workspace selection. RSS owns workspace name/path selection, session binding policy, Telegram/API command meaning and user-facing errors. Rust owns canonicalization and the confined directory capability.

- `workspaces.allowed_roots` defines canonical permitted roots.
- `workspaces.default` is optional and must lie under an allowed root.
- `POST /api/runs` accepts a workspace path or configured workspace name.
- Telegram session commands can select/status a workspace; the selected canonical path is durably attached to the session.
- Admission resolves the path once, opens the directory capability and freezes it into `RunLimits`.
- Symlink replacement after admission cannot escape the opened root.
- A request cannot select process cwd implicitly when no default is configured.

Files likely to change:

```text
rss/agent/workspace.rss
rss/storage/admission.rss
src/config.rs
src/gateway/api_server.rs
src/gateway/telegram.rs
src/service.rs
```

**RSS owner:** `rss/agent/workspace.rss` maps configured/named selections to policy decisions and sanitized errors; `rss/storage/admission.rss` emits the durable admission command. Gateway/Telegram modules remain thin input/output adapters.

**Necessary Rust primitives:** canonicalize/open directory capability, root confinement, no-follow/symlink replacement resistance, admission freeze, durable session record and cancellation. Generic root/security validation remains host-side.

**Bridge contract:** RSS sends a bounded selection plus a trusted roots policy handle to `workspace::open`; Rust returns an opaque workspace capability and canonical non-secret metadata. RSS cannot supply a capability token or bypass allowed roots.

Existing file/process confinement tests become parameterized across default, named, denied, symlink and reopen cases. Add a real RSS session/admission entry test; it must use a fake host capability and must not require later provider runtime.

---

## 9. Approval execution chain

Wire existing approval persistence into the serial tool dispatcher. RSS owns approval policy, risk-class meaning, request/decision transitions, sanitized summaries and user-facing outcomes. Rust owns durable records, execution tokens, approval ceilings and effect revalidation.

1. `read_file` and `search_files` follow configured read policy.
2. `write_file` and `patch` default to `ask`.
3. `terminal` and `process` default to `ask`.
4. Before `tool.started` or native effect, persist `approval.requested` with canonical call hash and expiry.
5. Expose approve/reject through HTTP and Telegram.
6. Resume the same durable tool call after approval; revalidation must detect changed name/arguments/parent.
7. Rejection, expiry, stop and restart produce one typed terminal tool result with no native effect.
8. Approval records contain sanitized summaries, never complete file contents, command output or credentials.

Files likely to change:

```text
src/service.rs
src/capabilities/lifecycle.rs
rss/tools/dispatch.rss
rss/storage/approvals.rss
src/gateway/api_server.rs
src/gateway/telegram.rs
```

**Bridge contract:** RSS passes the canonical RSS descriptor, call hash, risk intent and sanitized summary to `lifecycle::tool_prepare`/approval storage. Rust validates the frozen descriptor/hash, workspace, deadline, cancellation and approval ceiling before issuing an execution token. RSS retains public tool dispatch ownership and cannot downgrade a risk class after approval.

The durable replay rule remains: an already completed/failed/interrupted canonical result bypasses both approval and native effect.

Acceptance requires a real RSS dispatch entry covering no-effect-before-approval, reject/expire/stop/restart/replay, and an RSS risk-class downgrade attempt. The fake host must prove generic lifecycle enforcement without requiring future provider functionality.

---

## 10. Production compaction

Wire `rss/agent/compact.rss` into `AgentService`. RSS owns threshold/trigger policy, pair preservation, summary construction, explicit actions and failure/continue policy. Rust/storage owns durable transaction, generation, recovery and cancellation primitives.

- Trigger before a provider request when configured message/token bounds are crossed.
- Expose explicit HTTP and Telegram compaction actions.
- Preserve tool-call/tool-result pairs and the durable generation contract.
- A compaction failure leaves original history readable and fails or continues according to explicit RSS policy.
- Restart resumes or fails pending compaction exactly once.
- The next provider request uses the committed summary plus retained tail.

Files likely to change:

```text
rss/agent/compact.rss
rss/agent/main.rss
rss/storage/compactions.rss
src/service.rs
src/gateway/api_server.rs
src/gateway/telegram.rs
```

**Bridge contract:** RSS emits typed storage commands and explicit compaction decisions; Rust/storage validates generation, durable ordering, recovery and cancellation, then returns committed state. Rust does not select the threshold, summary policy or business error mapping.

Tests run a long real RSS coding loop across compaction and reopen, asserting no lost parent chain and bounded provider context. Add a direct RSS compaction entry test for threshold, explicit request, crash/reopen and pair preservation. The existing `max_context_messages: 120` and `retained_tail: 32` behavior remains the compatibility baseline.

---

## 11. Task sequence and TDD gates

The RSS-tool migration is the first implementation phase. Tasks 1–13 remain blocked until Tasks 0A–0F pass their gates, then follow the staged correction order in section 0. Every Task 1–13 entry below names its RSS owner, necessary generic Rust primitives, bridge contract and real RSS entry acceptance. A foundation task must use a fixture host when later runtime functionality is unavailable.

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

### Task 1: Address the integrated config/auth boundary

**Status:** acceptance reopened for the boundary address. Existing integration `1c0b8dfd8aaac82552adf66cf0dee114f0af4e8f` remains in history and is not reverted. This task must pass Stage A before Task 2 continuation.

**Objective:** add bounded structural config/auth schemas and path resolution while proving that provider selection/default/business interpretation is RSS-owned and that the foundation can be exercised through a minimal RSS entry.

**RSS owner:** create `rss/config/entry.rss`. The entry reads a structural snapshot, exposes provider/model/source/workspace/auth references to later RSS policy, and preserves opaque credential references. It does not duplicate generic Rust structural declarations or implement OAuth, provider calls or full selection behavior yet; those remain later RSS tasks.

**Necessary Rust primitives:** create `src/config_file.rs`, `src/auth/config.rs`; modify `src/config.rs`, `src/lib.rs`; retain bounded YAML, typed structural fields, strict key separation, home/path resolution, generic HTTPS/loopback and trusted-authority enforcement. Remove Rust `openai-codex` authority mapping, Codex endpoint/default interpretation, `local-agent` special cases and business defaults. Keep generic reference integrity where it protects the structural boundary.

**Bridge contract:** `config::load_snapshot(home)` returns bounded public structural data, credential IDs and trusted provider-policy handles. The RSS entry may inspect sanitized fields and opaque references; it cannot receive token fields or choose an authority. A fixture host implements this contract without Task 2 store, OAuth transport or authenticated runtime.

**Files:**

```text
src/config_file.rs
src/auth/config.rs
src/config.rs
src/lib.rs
rss/config/entry.rss
tests/config_file_tests.rs
tests/config_rss_entry_tests.rs
```

**RED:** tests for missing files, strict key separation, home override, invalid auth reference, HTTPS policy and bounded YAML; provider-name authority/default absence; a real RSS config/auth entry reading fixture data; no raw-secret fields in the RSS snapshot.

**GREEN:** minimal loaders and typed validation. Rust retains structural data declarations and generic security checks only. No OAuth network code, provider selection engine, refresh policy or future runtime requirement is added.

**RSS entry acceptance:** invoke the real `rss/config/entry.rss` through the fixture host and assert the selected structural references, trusted policy handle, path-qualified errors and secret absence. This is a foundation-only gate and must pass without Task 2 storage, Task 3 PKCE, Codex login or a real provider.

**Commit:** `feat(config): split runtime settings from auth state`

### Task 2: Snapshot-review and build the secure auth store

**Status:** unaccepted. The interrupted Task 2 snapshot must be reviewed before continuation; no acceptance may be inferred from the existing integration commit.

**Objective:** provide host-side credential persistence and concurrency primitives while keeping token lifecycle meaning and refresh/reauth policy in RSS.

**Pre-continuation snapshot review:** capture the current Task 2 snapshot, inspect its exact file/diff scope and compare it with section 0. Check for provider-specific fields/branches, raw-token bridge exposure, Rust refresh decisions and missing RSS entry coverage. Classify and correct the snapshot before extending it. Do not require Task 3 OAuth or Task 7 provider runtime for this review.

**RSS owner:** create `rss/auth/store_entry.rss` (or extend the minimal auth entry from Task 1) to interpret status labels, rotation/reauth policy, save decisions and redacted user-facing outcomes. RSS passes opaque secret slots and expected generations only.

**Necessary Rust primitives:** create `src/auth/store.rs`, `src/auth/token.rs`; bounded auth YAML persistence, Unix `0700`/`0600`, Windows ACL best effort, no-follow/symlink checks, lock, atomic replacement, flush/fsync/rename/parent fsync, generation CAS, opaque secret-slot provenance and redacted `Debug`.

**Bridge contract:** `auth::load_metadata`, `auth::save_if_generation`, `auth::access_handle`, `auth::status` and `auth::delete` return only sanitized metadata/opaque handles. Raw token bytes remain inside the host store. The bridge accepts no raw token argument from RSS and does not decide whether a provider response means refresh success or reauth.

**Files:**

```text
src/auth/store.rs
src/auth/token.rs
rss/auth/store_entry.rss
tests/auth_store_tests.rs
tests/auth_store_rss_tests.rs
```

**RED:** mode, symlink, corrupt file, bounded-read corrupt recovery, atomic replacement, refresh rotation storage, generation conflict, multi-credential preservation and redacted Debug tests; concurrent writers; real RSS store-entry fixture with opaque handles and no raw-secret observation.

**GREEN:** bounded YAML store with locking and atomic persistence. Refresh-token rotation is a storage primitive; RSS later decides when to invoke it. Do not add provider endpoint logic, retry policy, OAuth network calls or provider status interpretation to Rust.

**RSS entry acceptance:** invoke the real RSS store entry with a fake host, cover corrupt/recovery, concurrent generation adoption and multi-credential preservation, and scan events/snapshots/output for raw synthetic secrets. This gate depends only on Task 1 structural data and the store bridge.

**Commit:** `feat(auth): add isolated credential store`

### Task 3: Implement generic OAuth/PKCE primitives for RSS orchestration

**Objective:** provide reusable crypto, callback, bounded transport and secret-persistence primitives without implementing a Rust OAuth workflow engine.

**RSS owner:** create `rss/auth/oauth_flow.rss` for generic authorization-code/device flow sequencing, refresh timing, retry/backoff and status/error policy. Provider adapters select scopes, public parameters and payload interpretation.

**Necessary Rust primitives:** create `src/auth/oauth.rs`, `src/auth/pkce.rs`; random S256 verifier/state, opaque callback/verifier handles, injected bounded HTTP, loopback listener, browser/manual callback plumbing, clock/deadline/cancellation, response caps and generic token-slot persistence.

**Bridge contract:** `oauth::pkce_begin`, `oauth::callback_wait`, `oauth::transport`, `auth::load_metadata` and `auth::save_if_generation` use the section 1B envelopes. Rust validates callback state, trusted authority, bounds and handle provenance; RSS chooses sequence, refresh timing, retry and business classification.

**Files:**

```text
src/auth/oauth.rs
src/auth/pkce.rs
rss/auth/oauth_flow.rss
tests/oauth_flow_tests.rs
tests/oauth_rss_entry_tests.rs
```

**RED:** authorization URL, PKCE/state, loopback callback, manual callback, timeout, cancellation, malformed token response and refresh classification tests, all through a fake transport/host; assert no raw code/token/verifier reaches RSS output.

**GREEN:** transport-injected generic primitives and host bridge. There is no Rust `OAuthSession` workflow state machine, refresh manager, provider retry policy or provider-specific parser.

**RSS entry acceptance:** run the real generic RSS auth entry with a fixture provider and fake host, cover browser/manual/callback/cancel/timeout plus sanitized response interpretation. No live provider call is permitted.

**Commit:** `feat(auth): add generic oauth flows and refresh`

### Task 4: Expose the confined OAuth host bridge

**Objective:** register generic host primitives for RSS without encoding Codex or any provider workflow in Rust.

**RSS owner:** create/extend `rss/auth/bridge_contract.rss` to construct bounded public provider requests, choose policy handles, interpret sanitized response facts and sequence bridge calls. Provider operation names and payload meanings remain RSS data/logic.

**Necessary Rust primitives:** create `src/auth/host.rs`; modify `src/runtime/rss_runner.rs`, `src/runtime/mod.rs`; register generic catalog entries for structural config, PKCE/callback, transport, metadata, opaque secret handles and CAS persistence. Enforce authority/capability checks, body/response caps, cancellation, timeout and redaction.

**Bridge contract:** `oauth::transport` accepts a trusted policy handle, bounded method/path/public body and optional opaque credential use. It rejects arbitrary URL/Authorization/cookie input, resolves authority from trusted policy and returns `SanitizedProviderResponse` plus opaque slots. `save_if_generation` verifies slot provenance. There are no symbolic Rust operations named after Codex device steps.

**Files:**

```text
src/auth/host.rs
src/runtime/rss_runner.rs
src/runtime/mod.rs
rss/auth/bridge_contract.rss
tests/oauth_host_tests.rs
tests/oauth_bridge_rss_tests.rs
```

**RED:** catalog/schema, operation allowlist, authority confinement, cancellation, response caps, secret-redaction, forged-handle and unauthorized-authority tests; real RSS bridge calls for every contract method.

**GREEN:** register `oauth::*` only in the agent/auth runner catalog. Core dependency remains unchanged; RSS owns all provider workflow semantics.

**RSS entry acceptance:** execute `rss/auth/bridge_contract.rss` through a fake transport, verify allowed policy authority, rejected replacement authority, bounded response and opaque secret slots, and scan that no raw token reaches RSS/events/logs.

**Commit:** `feat(auth): expose confined oauth host functions`

### Task 5: Implement Codex device login in RSS

**Objective:** implement the complete Codex device-login state machine in RSS using the generic bridge.

**RSS owner:** create `rss/auth/types.rss`, `rss/auth/codex_device.rss`; all Codex state transitions, `403/404` pending policy, interval/429 backoff, 15-minute deadline, payload interpretation, token-field requirements and user-facing errors.

**Necessary Rust primitives:** generic request/cancel/clock/deadline, trusted authority/path enforcement, opaque device/code/verifier handles, bounded response parsing, token-slot save and secret redaction. Rust does not select a Codex endpoint or interpret Codex response state.

**Bridge contract:** RSS supplies the trusted Codex policy handle and public payload/path; host retains device auth ID, authorization code and verifier, performs bounded transport and returns sanitized fields/opaque slots. `auth::save_if_generation` stores tokens without exposing them.

**Files:**

```text
rss/auth/types.rss
rss/auth/codex_device.rss
tests/codex_device_login_tests.rs
tests/codex_device_rss_entry_tests.rs
tests/fixtures/codex_device/*
```

**RED:** full state-machine fixture suite: happy path/order, pending 403/404, 429 backoff/deadline, cancellation, malformed start/poll/exchange, missing access-token slot, refresh-token present/absent and secret absence in all rendered/persisted outputs.

**GREEN:** RSS orchestration using symbolic generic bridge primitives and opaque handles. No direct `http::*`, raw credential map or provider state machine is added to Rust.

**RSS entry acceptance:** invoke `codex_device::login` as the real RSS entry with a fake host and assert exact calls, sanitized instruction, transient cleanup and no raw device/auth material in snapshots/events/output.

**Commit:** `feat(auth): implement codex device login in rss`

### Task 6: Add RSS-owned auth/config CLI

**Objective:** expose auth/config commands through a thin compatible CLI while keeping command semantics and provider/source selection in RSS.

**RSS owner:** `rss/auth/commands.rss` handles command meaning, login/status/logout policy, provider selection and redacted output; `rss/config/selection.rss` handles model/provider/source defaults and migration policy.

**Necessary Rust primitives:** modify `src/bin/rustscript-agent.rs`; optionally create `src/cli.rs`; retain argv parsing, isolated home, TTY/browser/manual callback, cancellation, subprocess exit mapping and structural config/auth access. No Rust provider/default decision tree.

**Bridge contract:** CLI forwards a bounded command envelope to the RSS entry. RSS calls the section 1B auth/config bridge. Host performs only atomic secret writes/deletes and returns sanitized metadata.

**Files:**

```text
src/bin/rustscript-agent.rs
rss/auth/commands.rss
rss/config/selection.rss
tests/auth_cli_tests.rs
tests/auth_cli_rss_entry_tests.rs
```

**RED:** subprocess tests with isolated home, headless flow, cancellation, status, logout, config check, legacy `--script` alias and no-secret output; provider selection/default cases go through RSS.

**GREEN:** compatible subcommands with RSS command dispatch and host-only credential persistence.

**RSS entry acceptance:** run the installed CLI against the real RSS command entry and fake auth host; verify login/status/logout/config outputs, file separation and cancellation without live provider access.

**Commit:** `feat(cli): add auth and config commands`

### Task 7: Migrate opaque provider bridge and resolve credentials at provider call time

**Gate:** Stage C must pass before any authenticated runtime request or Task 8 acceptance. The old RSS `api_key` path is removed before the first real provider invocation.

**Objective:** route provider calls through opaque credential/transport handles while RSS decides credential resolution, refresh, 401 one-shot retry, 429/quota mapping and idempotency.

**RSS owner:** create `rss/providers/opaque_bridge.rss` and `rss/agent/provider_runtime.rss`; migrate provider profile merge, provider adapter selection, credential decision, refresh workflow, retry/backoff and business errors into RSS. Remove raw `api_key` from provider maps and canonical LLM types.

**Necessary Rust primitives:** modify `src/service.rs`, `src/runtime/rss_runner.rs`, `src/durable_provider.rs`, `src/config.rs`; retain credential metadata/opaque handles, generation/CAS, ephemeral host transport profile, durable redaction, cancellation and final Authorization assembly. Rust contains no `AuthManager` workflow and no provider-name retry/refresh policy.

**Bridge contract:** RSS requests `auth::load_metadata`, chooses whether to refresh, obtains an opaque access/refresh handle, sends a public `ProviderRequest`, and interprets only `SanitizedProviderResponse`. Host policy resolves authority and injects Authorization; secret handles cannot be converted to strings. `rss/providers/profile.rss`, `rss/llm/types.rss`, `rss/llm/openai_chat.rss` and all related adapters use this contract.

**Files:**

```text
rss/providers/opaque_bridge.rss
rss/agent/provider_runtime.rss
rss/providers/profile.rss
rss/llm/types.rss
rss/llm/openai_chat.rss
src/service.rs
src/runtime/rss_runner.rs
src/durable_provider.rs
src/config.rs
tests/provider_auth_tests.rs
tests/provider_auth_rss_entry_tests.rs
tests/fixtures/provider_bridge/*
```

**RED:** expired-token refresh, rotated refresh token, concurrent calls, 401 one-shot refresh, 429 classification, restart, idempotent replay and no-secret durable-state tests; negative scan proving `api_key`/raw Authorization never enters RSS profile/request/event/log paths; old direct RSS HTTP path must fail the architecture gate.

**GREEN:** opaque provider bridge and RSS runtime orchestration preserving provider idempotency. Rust retains storage/transport enforcement only. Real authenticated runtime is still blocked until the negative bridge scan and fake provider entry pass.

**RSS entry acceptance:** run the real `rss/agent/main.rss` provider loop against a fake provider/host, assert refresh/401/429 decisions, generation adoption, no duplicate durable request and no raw credential in all durable surfaces. Verify Stage C migration before enabling live provider configuration.

**Commit:** `feat(provider): resolve oauth credentials at runtime`

### Task 8: Complete Codex Responses inference

**Gate:** Task 7 Stage C opaque-provider migration and fake authenticated RSS entry must pass first.

**Objective:** implement the real Codex Responses protocol adapter in RSS and connect it to the opaque provider bridge.

**RSS owner:** modify `rss/llm/openai_responses.rss`, `rss/llm/harness.rss`; extend RSS provider runtime with request/response/stream shaping, parser, provider header intent, error semantics, 401 retry decision and 429/quota mapping.

**Necessary Rust primitives:** modify `src/runtime/rss_runner.rs`; bounded transport/stream, cancellation, trusted policy/authority enforcement, final opaque Authorization assembly, sanitized account metadata and durable provider-step accounting.

**Bridge contract:** adapter receives a non-secret provider policy/profile plus opaque handle, sends bounded public body/path and receives sanitized response data. Host-only Codex account metadata may be returned only after trusted-policy validation. RSS cannot override authority or security-sensitive header values.

**Files:**

```text
rss/llm/openai_responses.rss
rss/llm/harness.rss
rss/agent/provider_runtime.rss
src/runtime/rss_runner.rs
tests/provider_tests.rs
tests/codex_agent_e2e_tests.rs
tests/codex_responses_rss_entry_tests.rs
```

**RED:** wire/header/parser/stream/cancellation fixtures, account-metadata sanitization, 401 one-shot retry, 429 distinction and a complete agent turn using fake Codex transport; assert no duplicate `model.requested`, turn count or secret durable field.

**GREEN:** real RSS protocol adapter with native trusted transport/headers and preserved streaming/durable contract. Rust does not parse Codex business payloads or decide retries.

**RSS entry acceptance:** execute a complete `rss/agent/main.rss` turn through `openai_responses` with fake TLS/HTTP transport, including tool call/result continuation, cancellation and retry. No live OpenAI call belongs in CI.

**Commit:** `feat(provider): connect codex oauth to responses`

### Task 9: Make bundled coding agent the gateway default

**Objective:** package and start the RSS coding agent outside a source checkout while leaving source/default policy in RSS.

**RSS owner:** create/modify `rss/agent/source_policy.rss`, `rss/agent/main.rss`; decide `bundled:coding`, custom file source, deprecated environment migration and source-related business errors.

**Necessary Rust primitives:** modify `src/bin/rustscript-agent-gateway.rs`, `src/service.rs`, `Cargo.toml`; embed/package verified resources, enforce size/hash/compile boundary, expose redacted hash health metadata and fail before listen on invalid resources.

**Bridge contract:** RSS returns a bounded source descriptor; Rust returns an opaque verified-resource handle after generic checks. Gateway does not select provider behavior or source policy in Rust.

**Files:**

```text
rss/agent/source_policy.rss
rss/agent/main.rss
src/bin/rustscript-agent-gateway.rs
src/service.rs
Cargo.toml
tests/packaging_startup_tests.rs
tests/bundled_agent_rss_entry_tests.rs
```

**RED:** binary starts outside checkout, invalid custom source fails before listen, source hash is redacted metadata and the real RSS entry executes with an injected/fake provider.

**GREEN:** bundled source/resource loading with legacy `RUSTSCRIPT_AGENT_SCRIPT` migration behavior.

**RSS entry acceptance:** run the installed binary from a directory with no repository source files and invoke the bundled RSS entry. This gate may use fake provider/auth data; it must prove resource loading without demanding a new provider feature.

**Commit:** `feat(gateway): default to bundled coding agent`

### Task 10: Add RSS-owned workspace config and session binding

**Objective:** bind each run/session to an explicitly selected confined workspace while keeping selection policy in RSS.

**RSS owner:** create/modify `rss/agent/workspace.rss`, `rss/storage/admission.rss`; decide default/named/denied selection, session commands, canonical-path user errors and admission policy.

**Necessary Rust primitives:** modify `src/config.rs`, `src/gateway/api_server.rs`, `src/gateway/telegram.rs`, `src/service.rs`; canonicalize/open directory capability, trusted roots, no-follow/symlink replacement resistance, admission freeze, durable session binding and cancellation.

**Bridge contract:** gateway/Telegram forwards bounded external input to RSS. RSS calls `workspace::open(selection, policy_handle)` and receives an opaque capability plus canonical non-secret metadata. Rust rejects out-of-policy roots independently of RSS.

**Files:**

```text
rss/agent/workspace.rss
rss/storage/admission.rss
src/config.rs
src/gateway/api_server.rs
src/gateway/telegram.rs
src/service.rs
tests/workspace_tests.rs
tests/workspace_rss_entry_tests.rs
tests/gateway_workspace_tests.rs
```

**RED:** extend existing file/process confinement and gateway tests across allowed/default/named/denied/reopen cases, symlink replacement after admission and no implicit cwd; add real RSS session entry tests.

**GREEN:** canonical workspace capability frozen at admission; user-facing selection and error semantics remain in RSS.

**RSS entry acceptance:** invoke the real RSS workspace/session entry with a fake capability host and assert durable selected canonical path, denial/error mapping and reopen behavior without provider runtime.

**Commit:** `feat(workspace): bind sessions to allowed roots`

### Task 11: Wire RSS approval decisions into execution

**Objective:** gate mutating effects through RSS approval policy and generic Rust lifecycle enforcement.

**RSS owner:** modify `rss/tools/dispatch.rss`, `rss/storage/approvals.rss`; decide read/write/process policy, risk class, sanitized summary, approve/reject/expire semantics and user-facing outcomes.

**Necessary Rust primitives:** modify `src/service.rs`, `src/capabilities/lifecycle.rs`; durable approval records, canonical call hash, expiry, execution token, approval ceiling, revalidation, cancellation/recovery and no-effect-before-approval.

**Bridge contract:** RSS sends descriptor/hash/risk intent/sanitized summary to generic lifecycle/storage calls. Rust validates the frozen RSS descriptor and approval ceiling before issuing a token; RSS cannot forge, reuse or downgrade the token/risk class.

**Files:**

```text
src/service.rs
src/capabilities/lifecycle.rs
rss/tools/dispatch.rss
rss/storage/approvals.rss
src/gateway/api_server.rs
src/gateway/telegram.rs
tests/approval_e2e_tests.rs
tests/approval_rss_entry_tests.rs
```

**RED:** no-effect-before-approval, reject/expire/stop/restart/replay cases, changed-name/arguments/parent revalidation, and an RSS risk-class downgrade attempt after approval; sanitized-record and no-secret assertions.

**GREEN:** generic Rust lifecycle validates descriptor/hash/ceiling and RSS retains public dispatch/approval ownership.

**RSS entry acceptance:** run the real RSS tool dispatch and approval entries with a fake capability host, prove exactly one typed terminal result for rejection/expiry/recovery/replay and no native effect before approval.

**Commit:** `feat(approval): gate mutating tool effects`

### Task 12: Wire production compaction

**Objective:** make the RSS compaction policy durable and callable from provider turns and gateway actions.

**RSS owner:** modify `rss/agent/main.rss`, `rss/agent/compact.rss` and the typed command declarations in `rss/storage/compactions.rss`; decide threshold, explicit request, pair preservation, summary/error policy and continue/fail behavior.

**Necessary Rust primitives:** modify `src/service.rs` as needed; preserve durable transaction/generation, crash/reopen, cancellation and exactly-once commit/recovery. Rust does not select compaction thresholds or summary semantics.

**Bridge contract:** RSS emits typed `compaction.start`, `message.compact`, `compaction.commit`/`compaction.fail` storage commands. Rust/storage validates durable ordering and generation and returns committed state; RSS interprets it.

**Files:**

```text
src/service.rs
rss/agent/main.rss
rss/agent/compact.rss
rss/storage/compactions.rss
src/gateway/api_server.rs
src/gateway/telegram.rs
tests/compaction_e2e_tests.rs
tests/compaction_rss_entry_tests.rs
tests/agent_loop_e2e_tests.rs
```

**RED:** threshold, explicit request, crash/reopen, provider-context, pair-preservation and bounded-history assertions.

**GREEN:** durable compaction before provider request with original history readable on failure and retained tail behavior unchanged.

**RSS entry acceptance:** run a long real RSS coding loop across compaction and reopen, invoke explicit HTTP/Telegram compaction through RSS, and assert no lost parent chain, exact generation and bounded context.

**Commit:** `feat(agent): compact long running sessions`

### Task 13: Documentation, migration and release integration

**Objective:** publish the RSS-first architecture, bridge contract, configuration migration and release procedure without stale ownership claims.

**RSS owner:** documentation describes RSS provider/auth/refresh/retry/selection/default/session/workspace/approval/compaction policy and the opaque bridge; examples map to real RSS entries and host calls. Migration text explains business-setting interpretation without prescribing Rust workflow logic.

**Necessary Rust primitives:** packaging/build/resource verification only; no new provider business workflow. Existing Rust security/resource requirements and compatibility gates remain documented.

**Bridge contract:** documentation samples use credential IDs, trusted policy handles and sanitized provider data only. No sample contains token-like values, raw `api_key`, arbitrary authority or a direct provider Authorization header.

**Files:**

```text
README.md
docs/configuration.md
docs/deployment.md
docs/examples/config.yaml
docs/examples/auth.yaml
rss/auth/commands.rss
rss/config/selection.rss
tests/documentation_consistency_tests.rs
tests/migration_tests.rs
```

**RED:** documentation consistency/ownership scan catches stale Rust OAuth/refresh/provider-selection claims, raw `api_key` examples, missing RSS entries, incorrect thresholds or broken legacy invocation references.

**GREEN:**

- Remove stale claims that OpenAI Chat remains core-blocked.
- Document current protocol matrix accurately.
- Migrate supported `RUSTSCRIPT_AGENT_*` behavior settings into `config.yaml`; keep only home/bootstrap migration inputs in environment.
- Document `auth.yaml` backup/restore and permission requirements without showing token examples that resemble real secrets.
- Add public `config.yaml` and redacted `auth.yaml` examples under `docs/examples/`; the auth example uses placeholders and contains no token-like value.
- Document the section 1B bridge and Stage A/B/C acceptance status until the corresponding gates pass.
- Merge the integration stack into `master` using repository history rules.
- Build source and packaged binaries from a clean checkout.

**RSS entry acceptance:** run documentation ownership scans plus a clean packaged RSS entry with `config.yaml` and `auth.yaml`; verify examples exercise structural config/auth, opaque provider bridge and sanitized output without requiring live credentials.

**Commit:** `docs(agent): document authenticated production setup`

---

## 12. Verification matrix

Every implementation task follows RED → GREEN → refactor. Final gates run serially with the project target-slot rules:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-features --all-targets
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace --all-features --all-targets -- --test-threads=1
cargo test --locked --workspace --all-features --all-targets --release -- --test-threads=1
```

Additional mandatory RSS ownership/bridge gates:

- verify every model-visible tool descriptor, schema, validator, dispatcher and formatter is sourced from `rss/tools/*`.
- verify every provider/auth/refresh/retry/selection/default/source/workspace/approval/compaction business decision is sourced from RSS/provider adapters or trusted policy data, with no parallel Rust workflow engine.
- scan production Rust source for provider-name-to-domain/default branches, Rust Codex workflow state, Rust refresh manager/retry policy, the removed `agent::tool_dispatch`, `NativeToolExecutor`, built-in public tool ordering and branches keyed by the six public tool names.
- register and execute a fixture-only RSS tool without changing any Rust enum or public-name dispatch table.
- execute a real RSS entry for every Task 1+ bridge surface using a fake/injected host; each filtered test command must report at least one selected test.
- verify provider requests use the opaque handle contract; `rss/providers/profile.rss`, `rss/llm/types.rss`, `rss/llm/openai_chat.rss` and related adapters contain no raw `api_key` field or direct provider Authorization assembly.
- verify production host catalogs omit unrestricted pd-vm filesystem/process APIs that bypass execution-token checks.
- verify trusted provider/domain mapping comes from trusted policy/configuration; an RSS/user authority replacement is rejected before transport.
- crash before/after `tool_prepare`, each capability effect and `tool_commit`; verify durable-first ordering, interrupted recovery and no automatic repeat of mutating effects.
- scan persisted SQLite, YAML, event, message, artifact and log fixtures for exact synthetic access/refresh/device/code-verifier secrets and raw `api_key` values.
- crash at every boundary: before auth write, after temp fsync, after rename, after refresh response, after durable provider request and before provider completion.
- concurrent process refresh using a one-use fake refresh token; assert one network refresh or generation adoption and one valid final credential.
- replay a completed provider/tool step after access-token rotation; assert no duplicate external effect.
- run CLI/gateway from a clean directory with only installed resources, `config.yaml` and `auth.yaml`.
- verify `auth.yaml` never appears in workspace tools, provider prompts or HTTP API responses.
- verify Task 1 remains reopened until Stage A passes and Task 2 remains unaccepted until its snapshot review and bridge gate pass.

---

## 13. Delivery contract

The finished system must satisfy all of these statements:

1. Every model-visible tool is defined and implemented in `rss/tools/*`.
2. RSS owns public tool schemas, validation, dispatch, algorithms and result formatting; Rust owns only generic confined capabilities and lifecycle enforcement.
3. RSS owns provider/auth/refresh/retry/selection/default/source/workspace/approval/compaction business behavior; Rust owns generic security/resource primitives and trusted enforcement.
4. Rust production code contains no `NativeToolExecutor`, built-in public tool list/schema, provider-name business switch or public-name dispatch branches.
5. `rss/agent/main.rss` calls RSS tool dispatch directly; `agent::tool_dispatch` is removed.
6. A new RSS-only tool can be registered and executed without editing Rust dispatch code.
7. A fresh user can create config, run Codex device login, select a workspace and start the bundled coding agent without editing RSS or injecting a test provider.
8. OAuth access tokens refresh automatically and atomically: RSS decides when/how and Rust performs opaque-handle transport, CAS/locks and persistence.
9. `config.yaml` contains no credentials; `auth.yaml` contains no behavior policy.
10. Codex device-login policy is implemented in RSS; generic OAuth transport, PKCE, callback, storage and secret handling are implemented as Rust primitives inside `rustscript-agent`.
11. No OAuth functionality is added to RustScript core.
12. Raw auth material is absent from durable agent state, events, metrics, logs, artifacts and error text; RSS sees only sanitized provider data and opaque handles.
13. Provider/domain mapping is driven by trusted policy; RSS cannot replace the authorized authority or final Authorization boundary.
14. Mutating tool effects respect workspace and approval policy.
15. Long sessions compact durably and reopen without losing tool parent relationships.
16. Every Task 1+ capability has a real RSS entry acceptance through the explicit bridge; foundation tasks do not depend on future provider/runtime functionality.
17. Full debug and release suites pass from the final integrated commit.

---

## 14. Main risks and chosen trade-offs

- **RSS business logic still needs native safeguards:** every effect requires a Rust-issued execution token, and every provider request requires a trusted policy/opaque credential handle. Production host catalogs exclude unrestricted file/process APIs and arbitrary provider authorities that could bypass workspace, approval, deadline or durable lifecycle checks.
- **Structural schemas span Rust and RSS:** Rust keeps bounded typed declarations and persistence records where they express generic structure; RSS owns interpretation and policy. The plan avoids duplicating generic data merely to satisfy file ownership.
- **Migration can change output contracts:** each tool and provider bridge migrates against exact old/new fixtures before old native dispatch or raw `api_key` paths are removed. Public tool names and durable message/event shapes remain compatible.
- **YAML contains plaintext tokens:** initial scope uses strict local-file protection, locks and atomic writes. OS keychain integration may be added later behind the same `AuthStore` trait without changing RSS or provider contracts.
- **Codex device endpoints are provider-specific:** endpoint paths, defaults, response interpretation, pending/retry policy and state machine stay in RSS/config policy; Rust exports generic bounded transport, callback, handle and token persistence primitives.
- **Refresh tokens may rotate on every use:** RSS decides refresh timing and classification; per-credential serialization plus generation revalidation is mandatory from the first release.
- **Codex backend needs trusted headers:** account metadata may be derived host-side under explicit policy and exposed only in sanitized form; provider header intent stays in RSS while the host rejects untrusted security-header overrides.
- **Existing provider bridge carries raw `api_key`:** Stage C is a hard gate before authenticating runtime. The old profile/request shape cannot coexist with the opaque contract.
- **Multiple auth entries:** named credentials are supported now; automatic pool rotation remains outside this plan.
- **Environment migration:** behavior settings move to `config.yaml`; environment remains only for selecting the agent home during bootstrap and for temporary compatibility reads.
- **Staged acceptance status:** the integrated Task 1 commit is preserved but reopened for the boundary address. The interrupted Task 2 snapshot requires review before continuation. These statuses remain visible until their focused RSS entry and bridge gates pass.
