# Agent 配置、认证与 Provider 设计

**状态：** 当前设计

本文描述 `rustscript-agent` 的配置/凭据边界、RSS 与 Native host 的 bridge 契约，以及 provider、workspace、approval、compaction 的所有权划分。它合并并取代早期的生产认证实施计划；任务序号、阶段状态和执行记录不再保留。

## 1. 所有权边界

RSS 是 agent 业务行为的主实现层：provider 选择与适配、登录/refresh 编排、retry/polling、模型请求与响应整形、session/workspace policy、approval、compaction，以及用户可见的业务错误，均由 RSS/provider adapter 决定。

Native Rust 只提供通用基础能力和安全执行边界：有界解析、typed structural schema、可信 authority enforcement、secret storage/transport、PKCE 原语、callback listener、CAS/锁、fsync、取消与资源上限。Rust 可以保留结构字段声明；字段含义、默认策略和工作流决策交由 RSS 解释。

Rust 与 RSS 通过受限 host bridge 协作。provider/domain 映射由可信 policy 驱动，RSS 只能使用 policy 授权的 provider/authority，不能以请求参数替换 authority。原始 access/refresh token、authorization code、device auth ID、PKCE verifier 等保持 host-side opaque；RSS 只接收 bounded、sanitized provider data 与不可伪造的 opaque handle。

## 2. RSS ↔ Rust host bridge

### 2.1 数据类别

- **Structural values：** 有界 typed map/record，用于 YAML、JSON、请求 envelope 和持久化记录。Rust 可以声明并校验这些形状；RSS 赋予 provider/business 含义。
- **Sanitized provider data：** 状态码、有界公开 header、有界非 secret body 字段、retry 时间、expiry 数字、公开账户元数据和去掉 secret 字段后的 typed error facts。RSS 可以解释这些值。
- **Opaque handles：** host 发行的不可伪造引用，绑定 credential、provider policy、callback session、generation、run 或 capability token。RSS 可以把它传回 host，但不能检查、伪造、铸造新 authority，也不能转成原始 secret 字符串。VM 复制别名同一个 host entry，不产生新能力。

### 2.2 可信策略与准入

host 在准入时从 operator 编写的 `config.yaml` 和不可变的部署/宿主 ceiling 生成可信策略快照。`config.yaml` 是 host 准入的 operator 控制面输入；RSS 代码、模型输出、用户/run payload 和 provider 响应都是不可信数据，不能创建、扩大或替换 policy entry。显式自定义 provider 仍可配置：operator 在 `config.yaml` 声明命名 provider 后，host 可在满足通用界限和部署 ceiling 时准入其 HTTPS authority/path/header 策略。未知 provider 名称不会仅因未知而被拒绝；只有校验失败、trust 准入失败或 ceiling 越界才拒绝。

策略快照对一个 `policy_generation` 不可变，包含准入的 provider authority/path-prefix、公开 header allowlist/default、规范 workspace root、最大 approval/risk ceiling、资源 ceiling，以及 RSS 需要的 bounded public selection data。RSS 只能选择已准入的 entry 或请求更低风险的操作，不能添加 root、authority、path、header 值、risk class 或 resource limit。

准入时 host 向 RSS 入口上下文注入不可构造的 opaque policy handle。每次 bridge 调用检查 handle、冻结的 `policy_generation`、command/run scope、operation class、有限 deadline 和 revoke 状态。config reload 发布下一代 generation，并拒绝旧 handle 用于新 admission；已准入 run 可以在 run deadline、取消或显式 revoke 之前继续使用其不可变旧快照。reload 不会扩大该 run 的 authority。显式 revoke、scope 不符、过期 generation 或过期 handle 都以 typed policy error 失败关闭，并执行零 native effect。

### 2.3 当前 host 函数

生产 auth host 注册以下函数（名称以源码为准）：

```text
config::load_snapshot(host_home)
auth::load_metadata(credential_id, policy_handle)
auth::access_handle(credential_id, expected_generation, policy_handle)
auth::refresh_handle(credential_id, expected_generation, policy_handle)
auth::save_if_generation(request)
auth::delete(credential_id, policy_handle)
oauth::pkce_begin(policy_handle, public_intent)
oauth::callback_wait(callback_handle)
oauth::transport(request, credential_use)
workspace::open(selection, policy_handle)
agent_runtime::tool_prepare(metadata)
agent_runtime::tool_commit(execution_token, result)
```

`host_home` 由 Rust CLI/gateway host 在 RSS 运行前解析并有界校验；RSS 和模型/用户输入不能提供或覆盖它。`oauth::transport` 还提供 payload/capture 变体和 result/close 配套函数，用于有界请求与流式响应，本文不展开。

`ProviderRequest` 只携带 policy handle、method、path、公开 header 和公开请求体；`oauth::transport(request, credential_use)` 另取独立的 `credential_use`（`none`、`OpaqueAccessHandle` 或 `OpaqueRefreshHandle`）。host 只使用显式 `credential_use`，不从 `ProviderRequest` 读取凭据，也不接受 RSS/用户提供的 URL、`Host`、`Authorization`、cookie 或 authority 替换。

`sanitized provider response` 只包含 bounded status、allowlisted public header、去掉 secret 字段的结构化 body、可选 `retry_after_ms`，以及绑定本请求/session 的 opaque secret slots。access token、refresh token、authorization code、device auth ID、PKCE verifier 和原始响应字段留在 host-side；Rust 只在最终 transport 边界添加 `Authorization`，且不把它发布到 event、message、metric、artifact、log 或 error。

### 2.4 handle 生命周期

host 在 RSS value 空间之外保存 handle entry，每次使用检查 class、scope、generation、deadline 和 transaction state。TTL 是上界，不承诺 handle 在到期前一直有效。

- policy handle：绑定 `policy_generation`、command/run scope 和准入 ceiling；在 operation 允许范围内可复用；跨 run、扩大 operation 或过期 generation 的重放失败关闭；reload 对新 admission 拒绝旧 handle，显式 revoke/取消/scope 结束撤销它，重启从新快照重新发行。
- callback/state/verifier handle：绑定单个 OAuth flow、policy generation 和 callback session；callback 或 code exchange 的终态消费它；复制别名同一次等待，第二次使用返回 `handle_replayed`；超时、取消、错误或重启撤销。
- device session handle：绑定一次 credential attempt、provider policy 和 run/command；只允许该 session 内有界 polling，同一时刻一个 poll 在途；终态成功/错误消费；并发或跨 run poll 失败关闭。
- access handle：绑定 credential ID、credential generation、run/request scope，TTL 取 credential expiry、request deadline 和 host cap 5 分钟的最小值；一个 provider request，最终 transport 开始时消费；复制别名同一次授权，重放或不同 provider policy 失败关闭。
- refresh handle：绑定 credential ID、期望 generation、一次授权 refresh transaction 和 policy generation，TTL 为 refresh transaction deadline（host cap 60 秒）；一次 single-flight refresh transport，发送前检查 generation；复制别名同一 transaction，第二次或并发使用返回 `handle_replayed`/`generation_conflict`。
- secret slot：绑定 response/credential ID、slot label、期望 generation 和 save transaction；仅允许一次 `auth::save_if_generation`，成功 CAS 消费；错误 label、跨 generation 重放失败关闭。

VM marshaller 拒绝 string conversion、暴露内容的 reflection、以 hash 铸造新 authority、generic snapshot 和 durable serialization，返回 `opaque_nonserializable`；log/event/error 只记录 handle class 和 typed outcome。host revoke 移除 live entry，并可尽力清理 host-owned transient buffer；可执行的保证是未来 bridge 使用失败关闭，且原始 secret 材料不进入 RSS 可见或持久化表面。

## 3. `config.yaml`

默认 home：

```text
~/.rustscript-agent/
├── config.yaml
├── auth.yaml
├── auth.yaml.lock
└── state.db
```

`RUSTSCRIPT_AGENT_HOME` 可以覆盖整个 home，用于测试、容器和多实例隔离。不得分别用环境变量覆盖 token、refresh token 或 OAuth endpoint。

当前 v1 结构（`src/config_file.rs` 的 `ConfigFile`）：

```yaml
version: 1
agent:
  source: bundled:coding
  max_turns: 64
  max_tool_calls: 128
  max_tool_output_bytes: 1048576
model:
  provider: example-provider
  model: gpt-4o
providers:
  example-provider:
    protocol: openai-chat-completions
    base_url: https://api.example.com
    oauth:
      flow: authorization-code-pkce
      issuer: https://issuer.example
      client_id: public-client-id
      authorization_path: /oauth/authorize
      token_endpoint: https://issuer.example/oauth/token
      redirect_uri: http://127.0.0.1/callback
      refresh_skew_seconds: 120
workspaces:
  allowed_roots:
    - /home/user/src
  default: /home/user/src/project
  named:
    project: /home/user/src/project
approvals:
  read: allow
  write: ask
  process: ask
compaction:
  enabled: true
  max_context_messages: 120
  retained_tail: 32
```

规则：

- `config.yaml` 拒绝 `access_token`、`refresh_token`、`id_token`、`api_key`、`authorization`、`cookie`、`password`、任意 header 和类似 credential-bearing key，覆盖每一层嵌套。
- Rust 把 provider/model/source/workspace/approval/compaction 字段当作 bounded structural data；RSS/provider adapter 解释其含义、选择和默认。turns、tool calls 和 output bytes 等资源 ceiling 仍由 Rust capability 执行，不能超过可信 ceiling。
- provider 的 endpoint/path/flow 字段是公开结构值。RSS 拥有解释和 provider 默认；Rust 执行通用 URL 语法、大小和 scheme 检查，并对照可信 provider policy 验证最终请求，不在 Rust 硬编码 `openai-codex` 字段语义。
- provider endpoint 必须是 HTTPS，例外是本地 OAuth listener 生成的显式 loopback HTTP callback URL。
- `workspaces.allowed_roots` 和 `approvals.*` 是 operator policy 候选，进入同一不可变快照。host 规范化 root 并执行最大 approval/risk ceiling；RSS 可以在结果内选择，不能添加 root 或提高 ceiling。
- `auth` 只是 credential ID 引用。host 可以检查引用存在性和结构一致性；provider 匹配与选择策略是 RSS 决策。示例省略 `auth`，表示不引用 credential；需要时应填写 `<auth.yaml>` 中实际存在的 ID。
- 未知 root/provider/auth key 以 path-qualified error 拒绝启动。

## 4. `auth.yaml`

`auth.yaml` 只保存凭据和 token 生命周期状态，不保存 model、base URL、workspace path、timeout policy 等行为配置。

公开投影（`AuthConfig` / `CredentialConfig`）包含：

```text
version
credentials.<id>.provider
credentials.<id>.kind
credentials.<id>.source
credentials.<id>.token_type
credentials.<id>.expires_at_ms
credentials.<id>.scopes
credentials.<id>.account_id        optional
credentials.<id>.generation
credentials.<id>.status            active | reauth_required | disabled
credentials.<id>.last_refresh_at_ms
credentials.<id>.has_refresh_token
```

私有存储条目另有 access token 和可选 refresh token secret slot；它们不进入公开投影、Debug、序列化和 RSS。Rust 保留这些字段的 typed 持久化声明并校验边界、required storage shape 和 secret separation；RSS/provider adapter 解释 `provider`、`kind`、`source`、`status`、scope 含义和生命周期转换。

规则：

- 只持久化 runtime 和 refresh 所需字段。device code、user code、authorization code、PKCE verifier、PKCE state、请求体和 transient error 不进入该文件。
- `id_token` 默认不持久化，除非某个 provider 的后续 runtime 行为要求。
- `account_id` 是可选的 sanitized provider metadata，本身不构成授权。
- refresh token rotation 递增 `generation`。writer 在网络调用前观察 generation，并在 auth lock 内重新读取后再提交。
- 终态 refresh error 设置 `status: reauth_required`，不删除最后一个 token pair。瞬态网络/5xx/429 保持 credential active，返回可重试的 typed error；RSS 决定业务分类和用户动作。存在 refresh slot 不表示每个 provider/flow 都能 refresh。

## 5. 文件安全与并发

- home 目录 Unix mode `0700`；`auth.yaml`、lock 和替换文件 mode `0600`。
- 拒绝 symlink auth 文件和不安全 parent traversal；支持时使用 no-follow/openat 风格检查。
- 解析前先做有界字节读取。
- 保存使用同目录 exclusive 临时文件、flush、fsync、原子 rename 和父目录 fsync。
- read-modify-write 使用进程内 mutex 加跨进程 lock。
- 私有存储条目不对 secret 字节提供 `Debug` 输出；公开的结构投影不含 secret 字段，可安全用于诊断。只提供 redacted summary。
- Windows 测试验证原子替换和可用的 ACL/file 行为，不声称 POSIX mode 保证。
- 损坏 YAML 在有界读取后移动或复制到带时间戳的 `.corrupt` artifact；启动/登录返回 typed error，不静默以空 credential set 启动。
- 原始 token 字节只存在于 host store 和最终 transport 边界；bridge 只暴露 opaque handle 和 sanitized metadata。

## 6. CLI

`rustscript-agent` 的 Rust 层只负责 argv、home、TTY/browser/cancellation 和进程退出映射。RSS 拥有命令含义、provider 选择、source/default policy、auth status 解释、logout 语义和用户可见业务错误。

```text
rustscript-agent auth login PROVIDER
rustscript-agent auth status [PROVIDER]
rustscript-agent auth logout ID
rustscript-agent config path
rustscript-agent config check
rustscript-agent run --script PATH --allow-host HOST
rustscript-agent --script PATH --allow-host HOST
```

最后一行是 `run` 的兼容别名。登录只写 `auth.yaml`；provider/model/source 选择只写 `config.yaml`。status 不打印 token 前后缀或长度；logout 原子删除一个命名 credential，不影响其他 credential；`config check` 校验 config/auth 引用并报告 missing/disabled/reauth-required，不打印 secret。device login 在 SSH 下不尝试绑定公网 callback。Ctrl-C 以 typed cancellation 退出，不留半条 credential。

## 7. Provider runtime 与凭据解析

run admission 时，RSS 冻结选中的 provider、credential ID 和 provider 配置 hash 作为非 secret 逻辑输入。每次真实 provider 请求前：

1. RSS 通过 sanitized config/auth bridge 解析 provider/model 选择和命名 credential 引用。
2. RSS 判断是否需要 refresh；需要时取得 `auth::refresh_handle(credential_id, expected_generation, policy_handle)`，通过 `oauth::transport(request, credential_use)` 执行 provider 特定的 refresh policy，并用 `auth::save_if_generation(request)` 保存 rotation 后的 slot。
3. host 返回 opaque access handle 和 sanitized provider metadata。
4. RSS/provider adapter 构造请求体、path、公开协议 header 和 retry 决策。
5. Rust 校验可信 provider policy，在最终 transport 边界组装 `Authorization`，执行有界 transport，并在调用后丢弃带 token 的 profile。

不存在决定 refresh 或 provider 行为的 Rust `AuthManager`。`src/service.rs` 和 `src/runtime/rss_runner.rs` 只保留通用 admission、取消、durable redaction 和 bridge 调用边界。

access/refresh token 不进入：

- `RunContext` 或其 SQLite JSON；
- provider fingerprint 输入；
- `model.requested` / `model.completed` event payload；
- assistant/tool message；
- metric label；
- artifact 文件；
- panic/error 字符串。

durable provider fingerprint 使用 model、protocol、sanitized provider options 和 canonical messages；credential ID 与 token generation 不参与，refresh 不改变逻辑请求身份。

provider 侧由 RSS 决定 401 是否触发同逻辑 step 的一次 refresh-and-retry（不产生重复 `model.requested` 行或 turn 计数），并区分 429/quota 与过期认证。streaming 和取消沿用既有 durable provider 契约。

## 8. Workspace 选择

- `workspaces.allowed_roots` 定义规范允许根。
- `workspaces.default` 可选且必须位于某个 allowed root 下。
- `workspaces.named` 提供显式命名选择；名称是有界公开 selector token。
- `POST /v1/runs` 接受 workspace selector，`POST /v1/sessions/{session_id}/workspace` 把选择绑定到 session。
- Telegram session 命令可以选择/查询 workspace；选定规范路径持久绑定到 session。
- admission 只解析一次路径，打开目录 capability 并冻结到 `RunLimits`。
- admission 后的 symlink 替换不能逃出已打开 root。
- 未配置默认时，请求不能隐式选择进程 cwd。

RSS 拥有 workspace 名称/路径选择、session 绑定策略、Telegram/API 命令含义和用户可见错误；Rust 拥有规范化、root confinement、no-follow/symlink replacement 抵抗、admission freeze、durable session record 和取消。bridge 调用为 `workspace::open(selection, policy_handle)`；RSS 不能提供 capability token、添加 root 或绕过 allowed roots。

## 9. Approval

RSS 拥有 approval policy、risk-class 含义、request/decision 转换、sanitized summary 和用户可见结果；Rust 拥有 durable record、execution token、approval ceiling 和 effect revalidation。

- `read_file` 和 `search_files` 遵循配置的 read policy。
- `write_file` 和 `patch` 默认 `ask`。
- `terminal` 和 `process` 默认 `ask`。
- 在 `tool.started` 或 native effect 之前持久化 `approval.request` 记录，带 canonical call identity 和 expiry。
- HTTP 和 Telegram 都提供 approve/reject。
- approval 后恢复同一个 durable tool call；revalidation 检测 name/arguments/parent 是否变化。
- rejection、expiry、stop 和 restart 产生一个 typed terminal tool result，零 native effect。
- approval record 只含 sanitized summary，不含完整文件内容、命令输出或 credential。

风险类只能由 RSS 在 descriptor 中提出；Rust 以冻结 descriptor、host 准入 ceiling 和实际 capability 校验，RSS 不能在 approval 后降级风险，也不能把 ceiling 提高。

## 10. Compaction

`rss/agent/compact.rss` 接入 `AgentService`。RSS 拥有 threshold/trigger policy、tool-pair preservation、summary 构造、显式动作和 failure/continue policy；Rust/storage 拥有 durable transaction、generation、recovery 和 cancellation 原语。

- provider 请求前，配置的 message/token 界限越界时触发。
- HTTP 与 Telegram 提供显式 compaction 动作。
- 保留 tool-call/tool-result 配对和 durable generation 契约。
- compaction 失败时原始 history 仍可读，按显式 RSS policy 失败或继续。
- 重启时 pending compaction 恰好恢复或失败一次。
- 下一次 provider 请求使用 committed summary 加 retained tail。

详细状态机、schema 与恢复语义见
[durable state design](2026-08-09_agent-durable-state.md)。

## 11. 当前边界

本设计不新增以下能力：parallel tool calls、subagents、durable scheduler、多 gateway 共享同一 SQLite、OpenAI Responses/Anthropic 的完整 provider 覆盖。自定义 Responses adapter 和 Anthropic Messages 仍返回 typed `not_implemented`，不发送请求。Codex Responses 是 access-only 路径；完整 refresh/lifecycle 支持不在当前声明内。

Rust 不包含 provider-name 业务分支、Rust 侧 OAuth workflow state machine、Rust refresh manager/retry policy，或按公共工具名分派的执行器。第三方 native 动态库、多机分布式事务和进程内存恢复不在保证内。
