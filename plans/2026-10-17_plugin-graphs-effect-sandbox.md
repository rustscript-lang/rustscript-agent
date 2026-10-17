# RSS 插件图与 Agent Effect 沙盒实施计划

> **实施状态：** 已获准按本方案进行并发开发。独立工作区、依赖顺序、真实验证与独立审查继续作为合入门禁；下文拟新增能力须经相应阶段验收，不能因计划存在而视为已交付。

**Goal:** 将 tools 和可替换的 harness 业务逻辑组成可版本化、可解析依赖、可原子切换的 RSS 插件图；让工具对托管工作区和插件状态的 effect 在 Native 沙盒内执行，并支持一致 checkpoint、分支恢复和版本回退。

**Architecture:** 使用不可变插件包、闭合依赖图、按 run 固定的 graph lock，以及独立的 Native effect broker。代码版本、工作区版本、插件状态版本分别管理，通过显式 checkpoint/部署记录建立关联。热重载面向新 run 生效；恢复通过新分支与新 run 完成，保留旧执行记录。

**Tech Stack:** 当前 RustScript/RSS + Rust Native + Axum + 现有 typed SQLite/RSS storage；Linux 首期使用经过能力探测的 rootless OCI 后端。包版本解析预计新增 `semver` Rust 依赖；不计划改 Core、语言语法、JIT 或 VMBC。

---

## 1. 当前依据与设计边界

工作区：`/mnt/TEMP/workspace/rustscript-agent/worktrees/workspace-session-binding-10-959a765d`。

当前分支 `feat/production-delivery-integration`，已提交基线 `2f9678be44448fa5a28d3870c7eda63c7abd1573`。工作区包含尚未提交的 SSE、工具续轮和真实 API E2E 修复；实施时须先保全并单独验收这批修改，不能用已提交基线的测试结果代替当前候选验收。

已读取的复用点：
- `rss/tools/types.rss`、`registry.rss`、`dispatch.rss`：六工具描述、固定分派及 RSS 实现。
- `src/registry.rs:923`：`ToolRegistrySnapshot` 已为不可变工具描述/校验器集合；其 identity 只用于一致性，不授予权限。
- `src/runtime/module_snapshot.rs`：模块树源码快照和隔离编译；这与 effect 工作区快照属于不同概念。
- `src/runtime/closed_bundle.rs`：现有有界、闭合 import 图编译，可作为包入口校验基础。
- `src/service.rs`：admission、run 固定 registry、durable context、恢复与提交门。
- `src/capabilities/lifecycle.rs`、`src/runtime/agent_host.rs`：`tool_prepare` / `tool_commit`、token、parent、approval 与 replay。
- `src/capabilities/confined_io.rs`：dirfd/openat2 文件边界。
- `src/capabilities/vm_io/bounded_process.rs:2016` 附近：当前子进程由 `std::process::Command` 启动，清空环境、固定 cwd，并使用 process group。所读启动路径未提供完整 OS namespace/seccomp 根文件系统隔离；不能据此承诺任意 terminal 程序的 effect 已被沙盒约束。
- `rss/storage/*.rss`：业务 SQL、迁移与持久化投影继续由 RSS 管理；Native 负责授权与提交不变量。
- `src/gateway/api_server.rs`、`tests/support/live_http_delivery.rs`：实际 HTTP admission、SSE 与消息查询测试入口。

环境只做了只读发现：存在 `/usr/sbin/runc`、`/usr/bin/unshare`；未发现 bwrap、podman、crun、fuse-overlayfs。工作区 statfs 报告 `ext2/ext3`；这不能证明可用的 CoW 或 snapshot 能力。尚未验证 rootless namespaces、cgroup 委派、seccomp 或运行时版本。

### 范围选择

推荐先覆盖 Linux、单机、托管工作区、RSS 插件。第三方 native 动态库、多机分布式事务、进程 RAM/连接恢复、任意网站操作撤销不列入首期保证。

插件化范围包括：
- tools；
- agent 主循环策略、Guardian 评估策略；
- context 选择、compaction、prompt 组合；
- provider 请求/响应 codec 与路由策略；
- delivery 格式化、事件投影、受控状态读写策略。

必须保留在可信 Native 核心的部分：权限交集、credential/secret 保管、执行 token 验证、工作区授权、绝对 deadline/cancel、进程隔离、持久化原子提交、effect journal、恢复协调和管理面鉴权。RSS 插件可提出策略和请求，不能替换这些强制边界。存储后端协议和全局 schema 的升级受宿主兼容规则约束，不开放第三方插件直接写控制面数据库。

---

## 2. 方案比较与推荐

### A. 推荐：RSS 插件 + 不可变 graph + Native effect broker + rootless OS 沙盒

复用现有 RSS/VM、typed host 与 registry。业务扩展保持 RSS；Native 收敛为授权、生命周期和真实 OS 操作。支持多图并存和精确回退；需要新增插件调用桥、版本化工作区与隔离后端。

### B. 每个插件都做独立 OCI 服务

隔离更直观、语言自由度高，但简单 tool 也需要 IPC、协议管理和服务生命周期；现有 RSS 调度与资源 API 需要大量重做。可保留为将来的 `PluginExecutor` 后端，不作为首期默认。

### C. Rust 动态库插件 + 原目录备份

接入看似直接，但同进程 native 插件可绕过 broker；目录备份不能约束 terminal 对其他路径或网络的 effect，也难以提供一致回退。不采用。

---

## 3. 对外语义：先固定四种不同操作

1. **reload / activate graph**：新 run 使用新插件闭包；在途 run 继续使用原图。
2. **rollback graph**：将未来 run 的默认图切回保留的旧图，创建新的 activation generation；不回拨 generation，不修改旧 run。
3. **checkpoint / restore effects**：记录并恢复托管工作区和受控插件状态；不撤销模型费用、已收到的事件或外部远端事实。
4. **resume from checkpoint**：从 checkpoint 产生新 branch/run，显式选择原图或经过兼容迁移的新图，重新授权 Native 资源。

“热”表示 API Server 不停机、旧/新图并存。首期不在一条正在执行的模型/工具调用中替换代码，也不静默改写既有 run 的工具 schemas。若要在会话中立即采用新工具，由客户端显式开始新 run；若发生工具集合/状态契约不兼容，必须生成新会话分支或拒绝继承，不能沿用旧 pending call。

---

## 4. 插件包、版本与依赖图

### 4.1 不可变包

包目录只包含 manifest、RSS 源码、受控资源和测试描述。安装阶段复制到宿主拥有的不可变 store，完成闭合源码捕获后再编译，执行时不重新读取可变开发目录。

拟定 manifest 示例，字段均为新设计：

```yaml
format: rustscript.plugin/v1
id: org.rustscript.tools.files
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: write_file.rss
  export: invoke
dependencies:
  - alias: text
    id: org.rustscript.lib.text
    version: ">=1.0.0, <2.0.0"
capabilities:
  - workspace.read
  - workspace.write
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
        - kind: workspace.fs.write
          scope: bound_workspace
          recovery: checkpoint
      delegated: []
state:
  scope: run
  schema: 1
```

- `(publisher namespace, id, version)` 唯一；同版本不同内容拒绝覆盖。开发变更产生新的 revision，不能就地修改 active 包。
- `artifact_id` 是 store 分配的不可变对象标识，`graph_id` 是持久化 lock 对象标识；二者均不构成权限。
- 第三方发布包需要管理员接受的发布者与签名；本地 unsigned 开发包只能由管理员显式导入受限开发空间。签名可信不扩大 capability。
- 首期安装入口为受控本地目录。禁止自动执行安装脚本、自动拉取依赖、跟随符号链接或解包到任意宿主路径；在线 registry 后续单独设计。
- manifest 严格解析：拒绝未知安全字段、重复 key、YAML alias/tag/merge 扩展及超预算输入。包数量、文件数、字节数、图深度、编译耗时和诊断输出均有界；现有界限不因插件加载被取消。
- 初始配置上界：每图最多 64 个包、256 条依赖边、深度 16；闭包源码仍受现有 256 文件 / 8 MiB 总量约束；每包最多 32 个可选版本，求解最多 4096 个决策节点。达到上界返回具体 budget 错误，不扩大现有 compiler/runtime 限制。运行时缓存以实际对象大小与条目数双重计量，实施时复用并核实既有上界。
- 包分为宿主内置 `system` 与受限 `tenant` 扩展。第三方签名和安装不会将 tenant 包提升为 system 包；控制面存储迁移及强制策略适配器只能来自宿主兼容的 system 集合。两者都不能绕过 Native 的原子提交和权限校验。

### 4.2 三类依赖边

- `library`：纯 RSS 库，静态链接到调用者的 VM，不拥有独立权限或状态。
- `plugin`：显式插件调用边，经 Native broker 进入被调用插件的独立 VM/调用主体。
- `host ABI`：对宿主 named types、capability 接口和事件契约的兼容要求。

禁止以普通 RSS 跨包 import 绕过 plugin 主体边界。Native 根据已校验 manifest 生成静态入口映射；用户输入不能构造 import、export 或磁盘路径。禁止并入整个插件集合后向单个 VM 授予所有插件 capability 的并集。

### 4.3 解析与 lock

- 首期每个 graph 内每个 package 只允许一个具体版本；不同 graph 可同时运行不同版本。
- resolver 只查询管理员安装的候选，确定性排序、有限搜索。缺失、冲突、循环、歧义、超预算均返回带最小冲突链的 typed 错误。
- 生成持久化 `GraphLock`：准确 package revision、完整依赖边、入口、接口 schema、host ABI、权限声明、每个入口的直接/委托 effect 契约及解析后的传递闭包、状态 schema、编译环境兼容标识。
- `PreparedGraph` 在 admission 前预解析、编译和验证，不运行有 effect 的 load hook。昂贵工作不得进入全局提交门或挤占原有 admission 时间。
- 共享缓存只允许经过审计的不可变公共源码/Program/schema；Native resources、AuthHost、workspace 句柄、token、cancel 和带 owner 的对象每次调用重新绑定。缓存必须有容量和失效规则。

### 4.4 类型与存储记录

新增核心 named records：`PluginManifest`、`PackageRevision`、`GraphLock`、`ActivationRecord`、`PluginInvocationContext`、`EntryEffectContract`、`EffectRequirement`、`DelegatedEffectRequirement`、`EffectIntent`、`EffectReceipt`、`WorkspaceHead`、`CheckpointRecord`。它们分别记录不可变对象引用、owner、schema version、期望 generation/epoch 与状态，不以任意 map/unknown 暴露新的 host API。

每个插件 entry 的输入/输出 schema 在 prepare 时验证并安装为带 package 命名空间的契约，拒绝同名冲突。通用调度桥使用 Native 已验证的 payload/resource 引用；跨 VM 由 broker 解封数据并重新发行本 VM 包装，不复制调用者的 guest resource。已有工具的内部 RSS map 兼容层不能成为新增 host 接口的开放动态通道。

新增持久化记录采用 graph/package/activation、run graph pin、effect journal、workspace root/head、checkpoint 和 plugin state ref 的分离集合。它们通过 typed storage 命令加入既有 RSS SQL 事务，外部插件不能提供 SQL 字符串或自行修改这些记录。数据库约束验证 owner/ref 存在性与单调 generation，权限仍由 Native 检查。

### 4.5 仓库内 YAML schema 与同步维护门禁

YAML 格式的 machine-readable schema 是正式交付物，必须随开发保持 up-to-date 并 check in repo；只在文档里给示例、只在本地生成或只上传构建产物均不满足要求。

拟定仓库路径：
- `schemas/plugin-manifest.schema.yaml`：包 manifest。
- `schemas/effect-contract.schema.yaml`：入口 direct/delegated effects、kind、scope 和 recovery。
- `schemas/plugin-graph-lock.schema.yaml`：持久化 graph lock。
- `schemas/v1/checkpoint.schema.yaml`：checkpoint 的可序列化公开结构。
- `schemas/README.md`：schema 方言、版本映射、兼容规则、校验/生成命令与维护方式。

约束：
1. 采用 YAML 表达的 JSON Schema Draft 2020-12；manifest `format`、effect `contract`、其他记录版本与对应 schema 显式映射。各 schema 与本地 refs 一并提交，运行时和 CI 不从网络解析远端 schema。
2. 字段、required、默认值、enum、scope、依赖结构、effect catalog 可序列化契约或兼容规则发生变化时，对应 YAML schema、Rust/RSS 消费者、正反例 fixture 和文档必须在同一个变更中更新；提交时一并纳入版本控制。新增文件须实际 tracked，不能仅存在于忽略目录。
3. 公开结构契约以仓库中的 YAML schema 为单一来源；Native 使用这些确切的本地 schema 验证去重后的数据，再执行更强的语义、依赖与授权检查。提供确定性的 YAML → canonical JSON 生成/检查入口，生成快照也需 check in；CI/test 要求重新生成无差异。结构校验、Native 语义校验和真实 authority 校验分别给出正反例，不能声称 JSON Schema 可以单独表达全部语义。
4. CI 必须验证所有 schema 自身合法、全部示例通过、负例被拒绝，并运行 schema 与实际解析器/类型的漂移测试。需要更新 schema 却未更新，或 schema 修改后实际消费者未对齐，均阻止合并。
5. 不兼容修改发布新 schema/contract 版本，保留仍被已安装包、graph、run 或 checkpoint 引用的旧版本；禁止覆盖旧 schema 后继续使用同一版本标识。向后兼容修改也必须同步提交，不能靠以后补文档。
6. schema 是结构契约，权限、依赖闭包、目标授权和实际 effect 校验仍由 Native 执行；schema 校验通过不能替代这些检查。YAML 重复 key/alias/tag 等限制在转换为 JSON 数据之前执行。

---

## 5. 调用主体、权限与 harness 插件化

### 5.1 调用流程

```text
HTTP / Telegram admission
  → 固定 GraphLock + ToolRegistrySnapshot + workspace binding
  → RSS main 插件
      → Native plugin-call broker
          → RSS Guardian / tool / codec / context 插件
              → Native effect broker
                  → 托管文件视图 / OS 沙盒 / 受控远端 adapter
  → durable result + workspace publication
  → 固定版本的 delivery projection / outbox
```

- 跨插件只传已验证、限长的 named request/result，以及宿主控制的调用上下文。不得通过 JSON、整数或复制 guest resource 跨 VM 搬运权限。
- Native 可以基于原有 run authority 给子调用重新发行本 VM 的资源包装；保留 graph、plugin revision、run、branch epoch、effect、owner 和绝对 deadline 绑定。
- 有效权限取管理员策略、可信工作区授权、run 授权、调用者可委托权限、被调用者声明的交集；依赖声明不能自授权限。
- caller 到 callee 的调用只允许 lock 中声明的边。禁止递归插件调用图；业务循环留在明确的 RSS 主循环中，并受原预算限制。
- 凭据引用可以作为公开配置；实际 access/refresh、TLS key、认证头、FD 不进入插件状态、manifest、snapshot 或日志。

### 5.2 从当前六工具迁移

保持现有工具名称和 JSON schemas。`rss/tools/dispatch.rss` 从静态六工具入口逐步变为 graph 固定的声明式路由；具体 file/search/patch/process 业务继续在 RSS。

`tool_prepare` 仍先验证 parent、run、registry、审批与状态，再记录 started/intent 和发行一次性授权；`tool_commit` 仍负责 durable result。新的 plugin revision / branch epoch / effect ID 加入同一授权事实，不能仅检查工具名称。

持久化重放必须同时匹配 graph、tool revision、branch lineage 与 call identity。重启后从 run 的 lock 恢复原图；无法找到原包时返回 `plugin_artifact_unavailable`，不以当前 active 版本继续旧调用。

### 5.3 状态约束

- `invocation` / `run` / `session` 状态分别使用 Native 管理的有界版本化根引用。
- 首期可变状态限于 run/session；服务级共享状态仅提供只读配置或宿主定义的事务 API，第三方插件不得自行全局写入。
- 状态迁移是独立、纯函数、无权限的 RSS entry，输入旧 schema，输出新 schema；不能执行 SQL DDL、网络或文件操作。
- 新状态写入新对象，不覆盖旧对象。需要切换 session 状态 schema 时取得该 session 的维护 lease，并等待其旧 run 到达终止边界；其他 session 不暂停。
- 无法迁回旧状态时，graph rollback 返回 `state_incompatible` 或显式选择较早 checkpoint；禁止静默丢失新状态。
- `rss/storage/schema.rss` 的控制面迁移使用向前兼容、扩展优先的宿主发布流程；它不随任意插件 activate 自动执行。

---

## 6. 热重载、回退与对象保留

候选图生命周期：

```text
installed → resolved → prepared → validated → staged → active
                                 ↘ rejected
active → retired（仍可被旧 run / checkpoint / outbox 引用）
```

激活事务：
1. 在提交门外完成源码闭包、版本求解、编译、contract 检查、权限 diff、无 effect 的健康检查及必要的状态迁移准备。
2. 管理员检查图 diff，提交 `expected_generation`。
3. 原子提交新的 activation record 和 active graph/state-default 引用；更新内存。并发激活失败方返回 conflict，不能覆盖胜出方。
4. 后续 admission 在原有原子事务内记录 graph lock 和 registry，不重新编译候选。
5. 旧 run、旧 provider continuation、background process、pending delivery 使用它们已固定的版本完成。

- 回退为一次新的激活：例如 generation 8 指向以前保留的 graph；generation 不下降，防止 ABA。
- 不兼容 ABI/schema、增加权限、改动已绑定工具 schemas 均不自动激活。
- watcher 只发出“候选变化”信号。写到一半的包、编译失败或未确认的权限提升不会替换 active 图。
- 显式撤销某插件时可禁止新调用并按策略取消在途 run；“已撤销”不能被旧 run pin 或 snapshot 恢复解除。
- GC 以 run/session/checkpoint/activation/outbox 的 durable refs 和 Native 活跃 lease 为依据；有引用的包、状态和文件树不得删除。保留失败候选的有界诊断，不无限保留构建缓存。

---

## 7. Effect 显式契约、分类和可回退保证

### 7.1 所有插件入口必须显式声明 effects

这是安装、依赖解析、激活与运行时的强制契约，覆盖 tool、main、Guardian、context、codec、delivery、library 和状态迁移入口。

- manifest 必须包含带版本的 `effects`，每个可调用 export 必须给出 `direct` 和 `delegated`。缺失、未知 kind、未覆盖入口或不明确的通配声明直接拒绝；不采用“省略等于纯”的规则。
- `direct` 是本入口可能直接触发的 effect 上界；`delegated` 是本入口允许通过依赖调用触发的 effect 上界，按依赖 alias 和准确 entry 列出。调用者声明委托 effect 不会得到被调用插件的凭据或直接 host 能力。
- 纯入口必须显式声明 `direct: []`、`delegated: []`。普通返回值和 Native 自身的计量/安全审计不计为插件 effect；插件主动写状态、发事件、读取时钟/随机数、调用模型和发送消息均必须声明。纯入口不得偷偷使用这些能力。
- 每条声明采用 Native 已知的 effect kind 和该 kind 的 typed scope；例如 workspace 绑定、状态命名空间、受控 provider/远端 adapter。参数中的实际目标仍要由 Native 在执行前按该 scope 校验，不能用模型提供的 path/URL 放大范围。
- `recovery` 描述期望的恢复能力，实际可用性由 Native effect catalog 和 adapter 决定。插件不能把远端发送标成 checkpoint，也不能把 managed 写入标成 pure；冲突在 prepare/activation 时拒绝。
- effect 契约描述“可能做什么”；capability grant 决定“本次允许做什么”。实际执行必须同时属于已固定声明、caller 可委托上界、被调入口上界、管理员/run/workspace 授权，并通过当前撤销、deadline 和 budget 校验。

纯入口示例：

```yaml
effects:
  contract: agent.effects/v1
  entries:
    normalize:
      direct: []
      delegated: []
```

委托文件写入示例：

```yaml
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct: []
      delegated:
        - dependency: files
          entry: invoke
          allow:
            - kind: workspace.fs.read
              scope: bound_workspace
              recovery: none
            - kind: workspace.fs.write
              scope: bound_workspace
              recovery: checkpoint
```

其中 `files` 必须在 manifest dependencies 中声明。解析后，将 callee entry 的全部可能 effects 连同它继续委托的 effects，经过目标绑定映射后检查为 caller 该边 `allow` 的子集；有一个未覆盖项就返回 `undeclared_transitive_effect`。闭包只包含显式允许的调用边，不能把依赖图的权限并集发给 VM。后台 job、回调和 outbox consumer 同样必须声明入口与委托边，并固定原 graph/effect 上界；不能通过异步调度隐藏 effect。新增外部投递订阅也必须进入 graph 的 effect diff 和审批。

### 7.2 静态校验、动态拦截与版本兼容

1. prepare 读取闭合 RSS/compiled imports，与应用侧 Native `EffectCatalog` 的准确 host ABI 对照。每个 effectful host 入口必须有明确 metadata；未知项拒绝。首期可采用保守的模块 imports 上界，不能声称已经具备语言级精确函数 effect 推导。
2. effectful host 调用只绑定到相应的受控 bridge；跨插件调用校验锁定的 delegated 边。无法确定目标的动态调用不得绕过检查。
3. Native 在真实 effect 开始前检查已固定入口契约。未声明操作返回 `undeclared_effect`，不得先执行再仅记录告警。journal 中保存声明契约 revision 和实际 receipt；契约声明不能替代真实 receipt。
4. 对任意 terminal 程序，静态 argv 分析不能证明精确 effect。必须保守声明 `process.spawn`、`process.output` 及允许的 workspace 读写上界，并由 namespace、挂载和网络隔离约束其全部后代；执行脚本不能绕过声明扩大边界。
5. effect 新增、scope 扩张、callee effects 扩张或 recovery 保证降低都属于安全契约变更。即使包版本标为 patch，也必须生成 graph effect diff 并重新审批，不允许自动热激活。scope 变窄或 effect 删除也要检查依赖调用兼容。
6. Graph/API 管理视图显示入口级直接 effects、委托 effects、解析闭包、实际 grant 和恢复保证；调用审计可对照实际 receipt。模型可见的工具 metadata 从这个固定契约投影，不能由模型编写或修改声明。

首期 effect catalog 至少区分：`workspace.fs.read/write`、`plugin_state.read/write`、`process.spawn/output`、`clock.read`、`random.read`、`model.request`、`event.emit`、`delivery.send` 和受控远端 adapter 的 read/write。具体命名和 scope 是有版本的 host contract；不使用一个 `filesystem` 或 `network` 大标签隐藏所有行为。

### 可以完整恢复的受控对象

- 托管工作区内的文件树、内容和声明支持的权限元数据。
- Native 管理的插件 run/session 状态。
- 已终止本地进程产生的上述文件变化。

### 需要终止并重新启动的对象

- 进程、线程、打开的 FD、socket、锁和内存。checkpoint 只在无活动写入者的安全边界成立，不保存这些运行态。
- 后台 job 是 open effect；spawn 返回成功不表示整个 job 已完成。checkpoint/restore 要求先停止并确认所有后代退出。首期可先拒绝 sandbox profile 的 writable background 模式，后续以明确的 open-effect lease 支持，不能假装已 snapshot。

### 不能承诺通用撤销的对象

- 模型请求、费用、已经流出的 stdout/SSE、已发送通知。
- 远端 HTTP 写入、支付、邮件、Git push、第三方 DB 修改。

这些行为必须由专门 adapter 标记为 `remote_read`、`compensatable` 或 `irreversible`。补偿需要目标服务明确支持的协议，失败会进入 reconciliation 状态。未知 effect 默认拒绝；不能通过恢复本地 journal 把远端事实标为未发生。

首期 sandbox tool 默认禁网、无 daemon socket、无宿主设备和凭据。确需远端能力时，只能通过已审批的 Native broker adapter；provider 的 LLM transport 是单独的宿主能力，不向任意 tool 开放网络。

---

## 8. 真正的 OS 沙盒与统一文件视图

### 8.1 后端选择

选定 rootless OCI 作为首期进程后端，优先评估当前 runc；必须在实施阶段固定兼容版本并验证 rootless 能力。不得假定现有二进制已经具备所需配置。

强制能力：
- user/mount/PID/network namespace，private rootfs，默认无网络；
- 只读的固定 toolchain/rootfs，只有该 effect 的工作区和私有 temp 可写；
- 无宿主 home、Hermes pool、SSH agent、Docker socket、宿主 `/proc` 或设备挂载；
- 最小 capabilities、no_new_privs、宿主审定的 seccomp policy；
- cgroup v2 的进程数、内存/CPU 与整树终止；rootless 委派不可用时该 strict backend 不可用；
- 明确且有界的 FD 继承、stdin/stdout/stderr、wall deadline 和输出预算。

不用 Docker daemon group 权限作为不可信代码的默认执行边界。不采用 cwd/环境变量替代 namespace。无法满足 mandatory 能力时返回 `sandbox_unavailable`，不退回宿主 `Command`。

工具链镜像由管理员预置并固定版本；执行期间不拉取镜像、不自动安装依赖。Rust linker、动态库、解释器等只读依赖必须作为镜像的一部分，不能为编译成功额外挂载宿主根目录。

### 8.2 同一个 WorkspaceView

RSS 的 `read_file/write_file/patch/search_files` 与 terminal 子进程使用同一个 Native 发行的 `WorkspaceView`。Native FS adapter 指向该 effect 的私有视图 dirfd，子进程挂载同一视图；不允许一个写宿主原目录、另一个写容器目录。

所有文件系统路径继续受原相对路径、symlink、magic-link、长度和枚举限制。Native object store、控制面 DB、插件包目录不在 tool 挂载空间。

### 8.3 工作区导入、发布和回退范围

首期以托管工作区为事务单位：
- 从授权源目录创建初始 seed，后续 run 在私有 branch 工作；原源目录不自动被覆写。
- 对仍被外部写入的普通目录，复制不能提供跨文件的线性一致快照。严格导入必须依赖管理员静止源或经过验证的文件系统 snapshot；否则显式标记为普通导入、检测可见竞争并拒绝不一致，不能承诺来源的时间点一致性。
- 管理端维护 `workspace_head` 引用；run 成功可按策略原子发布到托管 head。head 的 CAS 失败保留 private branch，返回 conflict；不覆盖其他 run 的更新。
- 导出到宿主使用新目录的 staging + rename。对任意现有宿主目录做多文件合并不具备通用原子性，列为独立显式操作，不列入首期完整回退保证。

该模型会改变当前直接写原工作区的行为，API 必须返回 branch/head 与 publication 状态，客户端不能把“已 staged”显示成“宿主原目录已更新”。

---

## 9. Native Effect Broker 与 crash-safe 提交

### 9.1 事务单位

同步写工具默认使用子 effect view：基于当前 branch head 建立私有可写视图，在其中执行 RSS 多步文件操作或 terminal。工具成功后关闭写入者并生成不可变结果树；失败可丢弃子视图，父 head 不变。

初始后端采用有界复制创建独立树，避免假设 reflink/OverlayFS。后续可增加有能力探测和一致语义测试的 CoW 后端。禁止用普通 hardlink 把可写树与不可变 snapshot 共享 inode；也不能复制宿主外部 hardlink、device、socket 或提权元数据。

大型工作区的复制开销必须测量。只读 toolchain/依赖缓存不进入每次复制；可写 build 输出仍属于 effect 和配额，不能因性能需求绕过隔离。

### 9.2 与现有 lifecycle 对接

```text
prepare/approval
  → durable tool.started + effect.intent
  → 发行绑定 graph/plugin/run/branch epoch 的一次性授权
  → Native effect 执行，所有输出进入私有 view
  → quiesce + sync + 不可变 tree/receipt 准备
  → durable effect receipt + branch-head CAS + tool result
  → 内存 publication + provider continuation
```

- 源码编译、文件树复制、进程等待和 fsync 等重活在全局提交门外。
- SQLite 仍是控制面原子点：不可变文件对象先落盘，事务只发布它们的引用。崩溃产生的未引用对象按 journal 回收；已提交引用不能指向未持久化树。
- 现有 tool_call/started 配对、不成功不发行 token、取消/超时/撤销门禁、原始 deadline、输出预算和去重不变量继续保留。
- RSS 报告的 effect 类型只是请求，Native 以实际已发行能力和真实操作生成 receipt；不相信插件自称“纯函数”。
- 若 Native 已完成 effect 而 RSS 未提交工具结果，恢复读取已持久化 receipt；不得再次执行已经发生的操作。状态不明则返回 `effect_indeterminate`，保留分支并等待显式 reconcile，不自动重复 terminal。
- shared-service 可变状态和不具备事务协议的远端 effect 不伪装成上述本地原子事务。

建议 journal 状态：`intent → running → prepared → committed`；异常分支 `aborted / interrupted / indeterminate / needs_reconciliation`。每条记录绑定准确 owner、effect、call、graph、plugin revision、branch epoch、父/子 root 与 output artifact。

---

## 10. Checkpoint 与恢复协议

### 10.1 Checkpoint 内容

`Checkpoint` 保存：
- workspace immutable root 与 branch lineage；
- 插件状态根及其 schema/revision；
- graph lock、registry identity、公开配置 revision；
- 业务 history cursor、已闭合 call/output 边界、parent run；
- 已知不可逆 effect 的 high-water mark 和受控 artifact refs。

不保存 access/refresh、VM heap、Native token、FD、socket、活进程、审批授权或整个控制面 DB 文件。

### 10.2 创建条件

1. 取得该 branch/session 的维护 lease，并让相关 run 在工具批次闭合的协作安全点暂停新 provider 请求和 tool dispatch。已有 provider stream / effect 必须先 settled；不在半个模型调用或半组 tool outputs 上截断。暂停等待受管理请求期限和原 run 剩余期限共同约束，不能延长原 run。
2. 在提交门外等待当前 effect settled。活动写进程存在时返回 `checkpoint_busy`；显式 quiesce 模式才先取消、终止并确认该沙盒的全部后代退出。
3. Native 在提交门内重新验证原 graph、head、状态 revision、history cursor 和 lease；checkpoint 只落在完整模型工具批次结束的位置，不能保留无对应 output 的 pending tool_call。发生相关并发变化时拒绝或在原期限内重新准备，不能记录混合状态。
4. 原子记录 checkpoint 引用并释放维护 lease。其他工作区继续运行；不使用服务级全局暂停。

### 10.3 恢复

- 用户恢复产生新 branch。若目标 branch 有活动 run，先显式取消并等待实际资源退出；不在执行中替换脚下目录。
- 使用 checkpoint 的确切 graph；选择新 graph 时先通过独立的 schema/state 兼容准备。
- branch epoch 递增；旧 token、process handle 和未完成 effect 的权限全部失效。重新检查当前 workspace/credential/plugin 撤销策略。
- 新 run 从 checkpoint 的闭合历史前缀开始，保留 lineage；旧 run、旧事件、旧计费及旧投递记录保持只读。后续新调用使用新 call ID 和 parent。
- 新 run 有明确的新 admission/deadline；不复活旧 run，不重置旧 run 的计时来绕过超时。
- 已在远端发生的行为或用户已经收到的进度不被抹除；恢复结果附带 `external_effects_not_reverted` 清单。
- 不能用 SQLite 文件回滚实现该功能，否则会错误恢复权限、usage、审批和投递游标。

---

## 11. 拟新增管理 API 与事件

以下均为拟定新接口，不能在实现前对外宣称存在。普通 run 的既有 HTTP routes 保持兼容。

现有 `POST /v1/runs` 拟增加可选 `workspace_branch`、`graph_id`：普通新分支默认采用 active graph，恢复分支默认采用 checkpoint 的 graph。显式指定其他图必须通过部署空间许可和状态兼容检查；graph ID 本身不授予任意已安装插件的调用权。响应增加实际固定的 graph、branch、epoch 和 publication 策略。新字段必须进入 typed 请求契约，不能继续落入任意 options 或由客户端路径生成 Native authority。

插件管理面，要求独立管理员作用域并绑定 tenant：
- `POST /v1/plugins/install`：受控来源导入，返回不可变 revision。
- `POST /v1/plugin-graphs/resolve`：解析 lock + diff，不激活。
- `POST /v1/plugin-graphs/{graph_id}/prepare`：编译/验证，返回状态。
- `POST /v1/plugin-activations`：携带 graph、目标部署空间、expected_generation。
- `GET /v1/plugin-graphs/{graph_id}`：节点、边、contract、权限和错误链。
- `POST /v1/plugin-activations/{activation_id}/rollback`：产生新 activation，权限与正常激活相同。

工作区管理面，要求该 workspace 的读/恢复/发布权限：
- `POST /v1/workspaces/{workspace_id}/checkpoints`。
- `POST /v1/workspaces/{workspace_id}/branches`：可指定 checkpoint 来源。
- `POST /v1/workspaces/{workspace_id}/restore`：返回新 branch，不能偷偷回写原目录。
- `POST /v1/workspaces/{workspace_id}/publish`：携带 branch、expected_head。
- `GET /v1/runs/{run_id}/effects`：有界 receipt/journal 列表。

新增 SSE 字段与事件保持显式 schema/version：
- 每个 run 可查询 `graph_id`、`activation_generation`、`workspace_branch`、`head`。
- `plugin.graph_activated`、`effect.started/committed/aborted`、`checkpoint.created`、`workspace.restored/published`。
- plugin/event version 不能在已冻结的 run 中改变语义；delivery outbox 对应的投影版本随记录固定。
- 最终 `run.completed` 在配置要求的 workspace publication 完成后发出；若仅 staged，结果显式声明 staged branch。
- 管理对象标识一律由 Native 查询并验证 owner；不能把 path、graph ID 或签名当作授权。

---

## 12. 分阶段实施任务与文件清单

所有代码任务遵循 RED → GREEN → REFACTOR：先增加具体失败断言并实际运行，再做最小实现，然后运行该目标及直接邻接回归。下面列出的新文件和测试目标均为拟创建；实际实现若文件落点调整，须先更新本计划。不要为完成一个阶段一次性拆散整个 `service.rs`。

### M0：验收基线与宿主能力探测

**T01 基线固定**
- 读取当前改动和真实 API E2E 记录；将既有生产修复与本计划实现分开管理。
- Test：`tests/codex_access_live_e2e_tests.rs` 已有 `live_rust_program::real_api_server_http_rust_program_e2e`；普通回归先运行 `service_tests`、`rss_process_tool_tests`、`real_tool_continuation_tests`。
- 不重复真实凭据测试作为日常单测；新真实 E2E 在最终阶段显式 opt-in。

**T02 sandbox 能力报告**
- Create：`src/sandbox/{mod.rs,types.rs,probe.rs}`、`tests/sandbox_backend_tests.rs`。OS 隔离后端独立于 workspace/effect 事务模块，便于独立实现与验证。
- RED：缺少 mandatory namespace/cgroup/seccomp 任一项时 `strict_backend_is_unavailable_without_all_required_controls` 必须失败关闭。
- GREEN：只读能力报告与单独的受控启动探针；不修改系统 sysctl，不自动提升权限。
- Gate：`cargo test --locked --test sandbox_backend_tests`。缺少宿主条件是明确的交付前置条件，不能将跳过隔离用例记为 PASS。

### M1：manifest、依赖图与持久化 lock

**T03 manifest 与包存储**
- Create：`src/plugins/{mod.rs,types.rs,manifest.rs,store.rs}`、`tests/plugin_manifest_tests.rs`、`tests/plugin_schema_sync_tests.rs`、`schemas/plugin-manifest.schema.yaml`、`schemas/effect-contract.schema.yaml`、`schemas/README.md`。
- 先增加 schema/解析器漂移与正反例测试；从本任务开始，每个新增 YAML 格式都要有仓库内 schema，后续实现修改必须同步更新。
- RED：重复字段、路径逃逸、symlink 包、同版本覆盖、缺失发布者授权、缺失 effects、未覆盖 export、未知 effect 和伪造 recovery 均拒绝；显式空 effect 的纯入口及有效受限写入口接受。
- GREEN：严格有界解析、Native 所有的不可变包目录和 typed metadata；根据需要在 `Cargo.toml`/`Cargo.lock` 添加 `semver`。
- Gate：`cargo test --locked --test plugin_manifest_tests --test plugin_schema_sync_tests`；提交前确认相关 YAML schemas 已 tracked，CI 拒绝未同步或生成后有差异的版本。

**T04 resolver 与 closed bundle 集成**
- Create：`src/plugins/{resolver.rs,graph.rs}`、`tests/plugin_graph_tests.rs`、`schemas/plugin-graph-lock.schema.yaml`；同步扩展 `tests/plugin_schema_sync_tests.rs`。
- Modify：`src/runtime/closed_bundle.rs` 的 crate 内复用接口，不扩展 Core。
- RED：冲突链、缺依赖、循环、越权 host import、未声明的直接 effect、callee 传递 effect 未被 allow 覆盖、不同文件枚举顺序造成不同解；正控为准确且满足入口 effect 上界的固定闭包。
- GREEN：版本求解、不可变 lock、受限入口解析及准备。
- Gate：`cargo test --locked --test plugin_graph_tests`。

**T05 lock / activation 的 storage 协议**
- Create：`rss/storage/plugins.rss`、`tests/plugin_store_recovery_tests.rs`。
- Modify：`rss/storage/schema.rss`、`rss/storage/main.rss`、`src/domain.rs`、`src/sqlite_storage_rows.rs`。
- RED：提交失败无半激活；重启重建同一 lock；有 durable 引用时不能 GC。
- GREEN：向前兼容的对象/引用记录，SQLite 访问继续走生产 typed SDK/RSS 路径。
- Gate：`cargo test --locked --test plugin_store_recovery_tests`。

### M2：按 run 固定图与 RSS 插件调用边界

**T06 admission / replay 固定图**
- Create：`tests/plugin_run_pinning_tests.rs`。
- Modify：`src/service.rs`、`src/registry.rs`、`src/durable_provider.rs`、`rss/storage/admission.rss`、`rss/storage/runs.rss`。
- RED：A run 开始后激活 B，A 的后续 provider/tool/replay 仍为 A；新 run 为 B；重启不改用 active 图；缺 A 包明确失败。
- GREEN：既有 admission 事务加入 lock/ref 固定；prepared graph 在门外准备，不新增热路径编译。
- Gate：`cargo test --locked --test plugin_run_pinning_tests --test provider_durable_replay_loop_tests`。

**T07 typed 插件调用桥与工具适配**
- Create：`src/plugins/invocation.rs`、`src/runtime/plugin_host.rs`、`tests/plugin_invocation_tests.rs`。
- Modify：`src/runtime/{agent_host.rs,host_types.rs,rss_runner.rs}`、`rss/tools/{registry.rss,dispatch.rss}`。
- RED：A 无法调用未声明的 B；B 不能继承 A 的其他权限；resource 无法借 JSON 跨 VM；同名不同 revision 不能重放旧结果；缺失 effect 的真实 Native 操作在发生前被拒绝；纯入口不能通过库、时钟或插件委托隐藏 effect。
- GREEN：独立调用主体、Native 重新发行子 VM 资源、六工具 schemas 不变。
- Gate：`cargo test --locked --test plugin_invocation_tests --test rss_process_tool_tests`。
- 该阶段只为内置可信包提供兼容路径；在 M3 通过前不开放不可信进程插件。

### M3：统一 effect view 与 OS 隔离

**T08 托管文件树和子 effect view**
- Create：`src/effects/{mod.rs,types.rs,workspace.rs,tree_store.rs}`、`tests/effect_workspace_tests.rs`。
- Modify：`src/capabilities/{filesystem.rs,confined_io.rs}`。
- RED：写 view 不改 seed；文件工具与 terminal 看到同一内容；失败工具的父 head 不变；可写 view 不与 checkpoint 共享可写 inode。
- GREEN：有界复制后端、private temp、原子 Native refs、quota 和安全文件类型处理。
- Gate：`cargo test --locked --test effect_workspace_tests`。

**T09 rootless OCI 进程后端**
- Create：`src/sandbox/oci.rs`、`tests/sandbox_isolation_tests.rs`。
- Modify：`src/capabilities/process.rs`、`src/capabilities/vm_io/bounded_process.rs`。
- RED：尝试访问宿主哨兵文件、网络、daemon socket、宿主 PID namespace 必须拒绝；fork/setsid 后代在终止后实际消失。
- GREEN：固定 OCI profile、工具链 rootfs、namespace/seccomp/cgroup 策略、Native launcher 生命周期。
- Gate：`cargo test --locked --test sandbox_isolation_tests`；缺后端时给明确 NOT RUN 结果，发布验收不接受以 ignore 替代隔离证明。

**T10 effect journal 与真实工具提交**
- Create：`src/effects/{broker.rs,journal.rs}`、`rss/storage/effects.rss`、`tests/effect_commit_recovery_tests.rs`。
- Modify：`src/capabilities/{lifecycle.rs,types.rs}`、`src/service.rs`、`rss/storage/schema.rss`。
- RED：在 intent、文件准备、持久化 receipt、head CAS、result 提交各点崩溃，重启后无已提交悬空 root、无重复已执行 terminal。
- GREEN：将 Native receipt 和现有 started/result 绑定；不扩大 token 权限、不绕过审批、不重置 deadline。
- Gate：`cargo test --locked --test effect_commit_recovery_tests --test real_tool_continuation_tests`。

### M4：checkpoint、恢复与插件状态

**T11 checkpoint 和 branch restore**
- Create：`src/effects/{checkpoint.rs,recovery.rs}`、`rss/storage/checkpoints.rss`、`tests/effect_checkpoint_tests.rs`、`schemas/v1/checkpoint.schema.yaml`；同步扩展 schema 一致性测试。
- RED：活动 writer 拒绝 checkpoint；恢复前确认沙盒后代退出；旧 epoch token 被拒绝；旧审计/usage/审批记录不被删除或复活。
- GREEN：闭合 history cursor + root refs；恢复新 branch/new run，重新授权。
- Gate：`cargo test --locked --test effect_checkpoint_tests`。

**T12 有版本的插件状态**
- Create：`src/plugins/state.rs`、`tests/plugin_state_migration_tests.rs`。
- Modify：`rss/storage/plugins.rss`、`src/plugins/types.rs`。
- RED：无 inverse 的破坏性迁移不能声称可 graph rollback；旧 run 不观察新 schema；迁移崩溃不切换 active ref。
- GREEN：纯迁移、新状态对象、session 维护 lease 和 checkpoint 兼容检查。
- Gate：`cargo test --locked --test plugin_state_migration_tests`。

### M5：热重载、回退与 harness 业务模块迁移

**T13 原子激活、回退和 GC**
- Create：`src/plugins/{activation.rs,retention.rs}`、`tests/plugin_hot_reload_tests.rs`。
- RED：两个管理请求同 generation 只有一个成功；回退 generation 递增；旧 run 与 pending delivery 固定旧图；引用对象不能删除；patch 版本新增 effect、扩大 scope 或降低 recovery 保证时不得自动激活。
- GREEN：候选图准备、权限 diff、CAS 激活、可审计撤销和保留策略。
- Gate：`cargo test --locked --test plugin_hot_reload_tests`。

**T14 harness 按边界迁移**
- Create：`rss/plugins/` 内置 manifest/入口、`tests/harness_plugin_tests.rs`。
- Modify：`rss/agent/{main.rss,guardian.rss,compact.rss,provider_runtime.rss}`、`rss/llm/provider_dispatch.rss`、`src/prompt/coding.rs`、`src/runtime/delivery.rs`。
- 按顺序完成独立 RED/GREEN：context/prompt → Guardian 策略 → provider codec → delivery 投影 → main 策略。
- 每一步证明替换该插件不改变 Native grant、durable 事件身份、固定 schemas、秘密边界和停止行为。
- Gate：`cargo test --locked --test harness_plugin_tests --test agent_loop_tests --test prompt_tests --test codex_responses_codec_tests`。
- 存储底层与强制授权逻辑不因“插件化”移入可任意替换的普通插件。

### M6：真正的对外 API 与操作界面

**T15 插件 / 工作区管理 API**
- Create：`src/gateway/{plugins.rs,workspaces.rs}`、`tests/plugin_admin_api_tests.rs`、`tests/effect_admin_api_tests.rs`。
- Modify：`src/gateway/api_server.rs`、`src/config.rs`、`src/cli.rs`。
- RED：普通 run token 不可激活插件；跨 tenant、workspace、branch 越权失败；冲突返回 409；不存在和无权的对象不泄露私有路径。
- GREEN：typed 管理请求、管理员作用域、dry-run/diff、effect/checkpoint/publication 响应。
- Gate：`cargo test --locked --test plugin_admin_api_tests --test effect_admin_api_tests`。

**T16 HTTP 全链路 E2E 与崩溃矩阵**
- Create：`tests/plugin_effect_api_e2e_tests.rs`。
- Modify：`tests/support/live_http_delivery.rs`；最终新增 opt-in live case 于 `tests/codex_access_live_e2e_tests.rs` / support。
- 从真实 socket 上的 `POST /api/sessions`、`POST /v1/runs` 发起，禁止用内部 SDK 代交任务后把 SSE 接收等同于 API 入口验证。
- 场景：A 图 run 写/编译 Rust → checkpoint → 激活 B → A run 继续使用 A → 新 run 使用 B → 恢复 checkpoint 到新分支 → 回退默认图 → HTTP 查询 graph、effects、messages，并验证最终 delivery 与 durable 数据一致。
- 普通 E2E 使用确定性 provider fixture，真实工具和真实 OS 后端；最后单独 opt-in 实际模型写程序。真实场景通过并不替代 crash、越权和资源回收负控。
- Gate：`cargo test --locked --test plugin_effect_api_e2e_tests`，再执行明确授权的 ignored live case。

---

## 13. 必须覆盖的测试矩阵

### 插件与版本
- 安装重复、损坏包、签名/发布者失败、依赖缺失/冲突/循环、契约不兼容。
- 仓库 YAML schemas 自身合法、跨 schema 本地 refs 可解析、示例/负例与实际解析器一致；类型或 effect 契约变更而 schema 未更新时 CI 必须失败；生成文件无漂移且被版本控制。
- effect 声明缺失、纯入口伪装、direct/delegated 边界、传递 effect 漏报、未知 host effect、伪造恢复能力、版本升级 effect 扩张及 runtime before-effect denial。
- Native imports 越权、跨包直接 import 绕过、插件 ID 与 graph ID 伪造。
- A/B 并存、并发 activation、rollback ABA、重启恢复、缺包、GC 与缓存容量。
- 源目录在准备后改变，已准备图仍只执行原始已捕获源码；旧 VM owner 资源不可在新 VM 使用。

### 文件、进程与恢复
- 创建/修改/删除/rename、执行权限、空目录、受限 symlink/hardlink 及超额文件树。
- terminal 使用绝对路径、子进程派生、setsid、持有旧 FD、超时、取消、输出淹没、磁盘不足。
- 文件工具写入后 terminal 立即读取；terminal 写入后 RSS read_file 返回同一 view。
- snapshot 后修改再 restore，保证受控树与状态一致；不能恢复已撤销权限。
- 所有关键 FS/SQLite publication 崩溃点；receipt 已存在时不重复 effect，未知状态不假成功。
- 不改变 global suite concurrency，不使用放宽 deadline、取消断言或 retry-until-pass 使测试通过。

### API、交付与外部 effect
- 401/403、cross-tenant、409 CAS conflict、202 admission、实际 SSE 完成、消息/graph/effect 查询。
- rollback 不删除已经投递的正文；outbox 继续使用固定版本；消息 ID、seq 和最终正文与数据库投影一致。
- 模型调用用量不随 checkpoint 恢复清零；远端 effect 标为不可恢复或需要 reconcile。
- 隔离检查用管理员预置的无敏感哨兵；不得读取真实凭据来证明逃逸被阻止。

### 真实最终验收
- 模型自行生成 Rust 源码，真实文件写入/读回、编译、至少三个测试与正常/空/非法 CLI 分支，最终答复通过 API Server HTTP SSE 收到。
- 模型生成物由父级独立编译核验；snapshot 前后文件与状态按受控 Native API 验证。
- 如用户再次授权 Hermes pool access-only，仍只在隔离副本填假 refresh，记录零刷新请求；真实 token 不进入日志或插件快照。
- 真实 OS 后端不可用、缺少 cgroup 委派、某负控未执行时按实际记录，不能报告整个沙盒已验收。

验证命令随阶段使用上述具名 targets，并保持现有 lease 的 target/TMP/offline/jobs 设置。最终在有后端能力的环境执行 Debug/Release 相关矩阵、`cargo fmt --all --check`、`cargo clippy --locked --all-features --all-targets -- -D warnings`、`git diff --check`。是否执行全 workspace suite 以变更范围及既有规则决定；不把 no-run 或零选中测试计为通过。

---

## 14. 上线顺序与验收门

1. **G1 插件基础完成**：manifest/resolver/lock、精确回放和 run pinning 通过；仅内置受信包可用。
2. **G2 沙盒执行完成**：文件工具与 terminal 的统一 view、真实 OS 越权负控、进程全树终止及 journal recovery 通过。
3. **G3 本地效果回退完成**：checkpoint、branch、状态迁移、epoch 撤销与 crash 矩阵通过。
4. **G4 插件热重载完成**：原子激活、旧/新图并存、回退兼容、retention 与 harness 迁移通过。
5. **G5 对外功能完成**：实际 HTTP admission → 工具 effects → snapshot/restore → graph rollback → 最终 delivery 全链路通过。

可独立发布的首个可用切片为：内置 tools 的版本化 graph + mandatory OS 沙盒 + 托管工作区 checkpoint。随后补齐 harness 扩展点与管理 API；不在 G2 前把第三方进程插件作为可用功能开放。

实施仍需实测并报告的环境条件：rootless runtime 版本、user namespace 策略、cgroup v2 委派、seccomp 可用性、toolchain 镜像和存储配额。方案选型已明确，能力不足时给出具体缺项；不得通过宿主裸执行、临时特权或弱化测试绕过。

## 15. 设计自检结论

- YAML 格式的 machine-readable schemas 纳入仓库版本控制，与实现、fixture 和文档同步更新，CI 对 drift 与兼容版本执行门禁。
- 每个插件入口显式声明直接/委托 effects，纯入口显式为空；传递闭包和真实 Native 操作都受该上界约束，声明不授予权限。
- 插件版本回退、状态回退和外部行为补偿已分开定义。
- 所有 effectful 扩展均受 Native broker 与原权限/取消不变量约束。
- 不在运行中替换 frozen tools/schema；明确新 run、旧 run、旧 outbox 的版本归属。
- 不承诺任意外部目录的原子多文件合并，不承诺活进程内存或远端服务通用撤销。
- 不快照/回滚控制面 DB、凭据、审批和 usage。
- 当前仅产出设计计划；以上新类型、模块、路由和测试均待实现与实测。
