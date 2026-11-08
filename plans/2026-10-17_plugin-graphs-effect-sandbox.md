# RSS 插件图与 effect 沙箱设计

**状态：** 当前设计

**范围：** RSS 插件图，以及 tools 调用的 effect 声明、准入和托管执行。插件图包括图模型、manifest、exports、library 依赖、resolve、compiler、load、pin、closure、cache、activation、hot reload、persistence，以及这些图上的 runtime 执行。Tools 对托管工作区和插件状态的 effect 经 Native broker 执行。保留原 Native 授权、root、clock、取消，以及迟到批准不执行。托管支持 checkpoint、restore、branch、publish、replay 和 effect 账本查询，以及这些操作对应的管理接口。

进程继续使用现有有界 `std::process::Command` 后端及其取消、清理。本文不实施、不验收新的 OS namespace、OCI、cgroup、seccomp 或调试器隔离。OS 隔离资格不作为交付项。Native tools 效果测试使用现有受控后端和 fixture。

provider codec、delivery projection、main policy，以及 context、prompt、Guardian 的新插件行为不作为实现任务。既有内置 agent、reviewer、provider、默认 prompt 和 compaction 语义保持不变。既有 Tool 与 effect 安全约束保持不变。

平台为 Linux x86_64。不增加 32 位或 x32。不改 Core、语言语法、JIT 或 VMBC。不新增 admin/tenant 系统。不新增本文未列出的 route、limit 或 SDK effect kind。不另开 schema 版本或兼容 lane。

**架构：** 不可变插件包、闭合依赖图、按 run 固定的 graph lock，以及独立的 Native effect broker。代码版本、工作区版本、插件状态版本分别记录，通过显式 checkpoint 和 activation 记录关联。hot reload 面向新 run。恢复产生新 branch 与新 run，保留旧执行记录。

**技术基础：** 当前 RustScript/RSS + Rust Native + Axum + 现有 typed SQLite/RSS storage。版本求解使用 resolver 已依赖的 `semver`。进程执行使用 `src/capabilities/vm_io/bounded_process.rs` 的现有 argv 后端。不增加 OCI runtime。

---

## 1. 设计依据与边界

已核对的复用点：

- `rss/tools/types.rss`、`registry.rss`、`dispatch.rss`：现有工具描述、固定分派及 RSS 实现。
- `src/registry.rs`：`ToolRegistrySnapshot` 是不可变工具描述和校验器集合。其 identity 只用于一致性，不授予权限。
- `src/runtime/module_snapshot.rs`：模块树源码快照和隔离编译。它与 effect 工作区快照是不同对象。
- `src/runtime/closed_bundle.rs`：有界闭合 import 图编译，上限 256 个文件、8 MiB 源码。插件加载复用该接口，不扩大上限，不改 Core。
- `src/service.rs`：admission、run 固定 registry、durable context、恢复与提交门。
- `src/capabilities/lifecycle.rs`、`src/runtime/agent_host.rs`：`tool_prepare` / `tool_commit`、token、parent、approval 与 replay。
- `src/capabilities/confined_io.rs`：dirfd/openat2 文件边界。
- `src/capabilities/vm_io/bounded_process.rs`：子进程由 `std::process::Command` 按 argv 启动。该模块不提供 namespace、seccomp 或根文件系统隔离。不能据此承诺任意 terminal 程序已被 OS 隔离。本文不添加该隔离。
- `src/plugins/`：manifest、store、resolve、prepare、pin、schema。`PLUGIN_KINDS` 只有 `library` 和 `tool`。
- `src/effects/`：托管文件树、journal、checkpoint、restore。该模块不接入 OCI。
- `rss/storage/*.rss`：业务 SQL、迁移与持久化投影继续由 RSS 管理。Native 负责授权与提交不变量。外部插件不能提供 SQL 字符串。
- 已注册 HTTP（完整列表见第 11 节）：`POST /v1/runs`、`POST /v1/workspaces/{workspace_id}/checkpoints`、`POST /v1/workspaces/{workspace_id}/restore`、`GET /v1/runs/{run_id}/effects`。

插件化范围：

- tool 包及其 library 依赖；
- 上述包的图模型、manifest、exports、解析、编译、加载、pin、闭包、缓存、激活、热重载、持久化和按 run 执行。

不在当前实现范围内：

- 把 agent 主循环、Guardian、context 选择、compaction、prompt 组合、provider codec 或 delivery projection 做成可替换插件；
- 新的 OS 隔离后端；
- 新的 admin/tenant 产品。

必须留在可信 Native 核心、且本文不放宽的部分：权限交集、credential/secret 保管、执行 token 验证、工作区授权、绝对 deadline 与 cancel、现有进程边界、持久化原子提交、effect journal、恢复协调。RSS 插件可以提出请求，不能替换这些强制边界。存储后端协议和全局 schema 升级沿用宿主规则。第三方插件不直接写控制面数据库。

既有内置 agent、reviewer、provider、默认 prompt、compaction 和 delivery 行为保持原语义。本文只约束它们不被插件替换，不改写它们。

当前保证限于 Linux、单机、托管工作区和 RSS `library`/`tool` 包。第三方 native 动态库、多机分布式事务、进程内存或连接恢复、任意网站操作撤销、任意外部副作用回滚，都不在保证内。

---

## 2. 方案选择

### A. 采用：RSS 插件 + 不可变 graph + Native effect broker + 托管工作区视图

复用现有 RSS/VM、typed host 与 registry。tool 扩展保持 RSS。Native 负责授权、生命周期和托管文件操作。多图可以并存，回退指向已保留的旧图。进程仍走现有 Command 后端。

### B. 不采用：把主循环、provider、delivery 或 Guardian 改成可替换业务插件

这些模块的现有语义保持为约束。本文不把它们做成插件产品。图 lock 可以记录已有 `harness_selection` 字段，见第 4 节。该字段不授权新的 prompt、context 或 Guardian 行为。

### C. 不采用：Rust 动态库插件 + 原目录备份

同进程 native 插件可绕过 broker。目录备份不能给出托管工作区的一致 head，也不能约束 terminal 对其他路径的写入。

---

## 3. 对外语义：四种操作

1. **reload / activate graph**：新 run 使用新插件闭包。在途 run 继续使用原图。
2. **rollback graph**：未来 run 的默认图切回保留的旧图，并创建新的 activation generation。generation 不回拨。旧 run 不修改。
3. **checkpoint / restore effects**：记录并恢复托管工作区不可变树，以及 checkpoint 覆盖的受控插件状态根。不撤销模型费用、已经发出的事件或外部远端事实。不保存进程、线程、FD、socket 或内存。
4. **resume from checkpoint**：从 checkpoint 产生新 branch 和新 run。显式选择原图，或经过状态兼容准备的新图。Native 资源重新授权。

“热”表示 API Server 不停机，旧图与新图并存。不在一条正在执行的模型调用或工具调用中替换代码，也不改写既有 run 已固定的工具 schemas。会话中要使用新工具时，由客户端开始新 run。工具集合或状态契约不兼容时，生成新会话分支或拒绝继承，不沿用旧 pending call。

---

## 4. 插件包、版本与依赖图

### 4.1 不可变包

包目录只包含 manifest、RSS 源码、受控资源和测试描述。安装时复制到宿主拥有的不可变 store，完成闭合源码捕获后再编译。执行时不重新读取可变开发目录。

manifest 字段以仓库内 `schemas/plugin-manifest.schema.yaml` 和 `src/plugins/error.rs` 为准。示例：

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

- `kind` 只允许 `library` 或 `tool`。
- `(id, version)` 唯一。同版本不同内容拒绝覆盖。开发变更产生新 revision，不就地修改 active 包。
- `artifact_id` 是 store 分配的不可变对象标识。`graph_id` 是持久化 lock 对象标识。二者都不构成权限。
- 安装使用现有 `InstallAuthorization` 与 `PackageTrust`。签名可信不扩大 capability。本地未签名开发包只能进入受限开发空间。
- 安装入口为受控本地目录。禁止自动执行安装脚本、自动拉取依赖、跟随符号链接或解包到任意宿主路径。不设计在线 registry。
- manifest 严格解析：拒绝未知安全字段、重复 key、YAML alias/tag/merge 及超预算输入。包数量、文件数、字节数、图深度、编译耗时和诊断输出均有界。现有界限不因插件加载被取消。
- 现有上界不提高：每图最多 64 个包、256 条依赖边、深度 16；闭包源码 256 文件 / 8 MiB；每包最多 32 个可选版本；求解最多 4096 个决策节点。达到上界返回具体 budget 错误。运行时缓存按实际对象大小与条目数计量，复用既有上界。
- 宿主内置包与后来安装的包使用现有 trust 区分。安装不把扩展包提升为控制面迁移或强制策略适配器。两类包都不能绕过 Native 原子提交和权限校验。

### 4.2 三类依赖边

- `library`：纯 RSS 库，链入调用者的 VM，不拥有独立权限或状态。
- `plugin`：显式插件调用边，经 Native broker 进入被调用插件的独立 VM 和调用主体。
- `host ABI`：对宿主 named types、capability 接口和事件契约的兼容要求。

图 lock 边上的 provenance 保持 `direct`、`plugin` 或 `library`。禁止用普通 RSS 跨包 import 绕过 plugin 主体边界。Native 根据已校验 manifest 生成静态入口映射。用户输入不能构造 import、export 或磁盘路径。禁止把多个插件的 capability 并集授予单个 VM。

### 4.3 解析、编译、加载、pin 与 cache

- 每个 graph 内每个 package 只允许一个具体版本。不同 graph 可以同时运行不同版本。
- resolver 只查询已安装候选，确定性排序，有限搜索。缺失、冲突、循环、歧义、超预算均返回带最小冲突链的 typed 错误。
- 持久化 `GraphLock` 记录 package revision、依赖边、入口、接口 schema、host ABI、权限声明、每个入口的 direct/delegated effect 及解析后的传递闭包、状态 schema、编译环境标识。
- `GraphLock.harness_selection` 是图契约字段，取值包括 `Unselected`、`ToolOnly` 和 `ContextPrompt`。当前执行模式是 `ToolOnly`。`ContextPrompt` 与另外两个变体一样保留为可读、可校验的 lock 形状，不作为向后兼容产品，也不另开迁移 lane。它不授权新的 prompt、context 或 Guardian 插件行为，也不改变内置策略。
- `PreparedGraph` 在 admission 前完成 resolve、compiler、load 和验证。load 不运行有 effect 的 hook。昂贵工作不进入全局提交门，不挤占原有 admission 时间。
- admission 把 graph lock pin 到 run。后续 provider、tool 和 replay 使用该 pin。缺包返回 `plugin_artifact_unavailable`，不以当前 active 版本继续旧调用。
- 共享 cache 只保存经过审计的不可变公共源码、Program 和 schema。Native resources、AuthHost、workspace 句柄、token、cancel 和带 owner 的对象每次调用重新绑定。缓存有容量和失效规则。

### 4.4 类型与存储记录

使用现有 named records，不平行新增一套 host API：`GraphLock`、`PackageRevision`、`InstalledPackage`、activation pointer/history、`CheckpointRecord`、managed effect journal、`ManagedWorkspaceHead`、plugin state root ref。它们记录不可变对象引用、owner、schema version、期望 generation/epoch 与状态。不以任意 map 或 unknown 暴露新的 host API。

每个插件 entry 的输入/输出 schema 在 prepare 时验证，并安装为带 package 命名空间的契约。同名冲突拒绝。通用调度桥使用 Native 已验证的 payload 和 resource 引用。跨 VM 由 broker 解封数据并重新发行本 VM 包装，不复制调用者的 guest resource。已有工具的内部 RSS map 兼容层不能成为新的开放动态 host 通道。

持久化记录分为 graph/package/activation、run graph pin、effect journal、workspace root/head、checkpoint 和 plugin state ref。它们通过 typed storage 命令加入既有 RSS SQL 事务。外部插件不能提供 SQL 字符串或自行修改这些记录。数据库约束验证 owner/ref 存在性与单调 generation。权限仍由 Native 检查。

### 4.5 仓库内 YAML schema

YAML schema 随实现提交到仓库。只在文档中给示例、只在本地生成或只上传构建产物，都不满足要求。

现有契约文件：

- `schemas/plugin-manifest.schema.yaml`
- `schemas/effect-contract.schema.yaml`
- `schemas/plugin-graph-lock.schema.yaml`
- `schemas/plugin-activation.schema.yaml`
- `schemas/plugin-graph-ref.schema.yaml`
- `schemas/v1/checkpoint.schema.yaml`
- `schemas/managed-workspace.schema.yaml`
- `schemas/managed-effect.schema.yaml`
- `schemas/managed-checkpoint.schema.yaml`（含 `ManagedPublishRequest`、`ManagedPublishReceipt`、`ManagedWorkspacePublication`，当前 v1，不开新版本与兼容 lane）
- `schemas/managed-restore.schema.yaml`
- `schemas/README.md`
- `schemas/canonical/` 中与上述 YAML 对应的生成快照

约束：

1. schema 使用仓库内本地文件。运行时和 CI 不从网络解析远端 schema。现有 `format`、`contract` 和记录版本标识保持为当前 v1 事实。本文不发布新的 schema 版本，也不保留多版本升级矩阵。
2. 字段、required、enum、scope、依赖结构或 effect catalog 发生变化时，对应 YAML schema、Rust/RSS 消费者、正反例 fixture 和文档在同一个变更中更新。新增文件必须被版本控制跟踪。
3. 公开结构以仓库 YAML schema 为结构来源。Native 用这些本地 schema 验证结构，再执行语义、依赖与授权检查。`cargo run --example plugin_schema_sync -- --check` 是现有漂移检查。结构校验通过不能代替 Native 语义校验和 authority 校验。
4. CI 验证 schema 自身合法、示例通过、负例被拒绝，并运行 schema 与解析器的漂移测试。schema 与消费者不一致时阻止合并。
5. schema 不表达 capability 相等、semver 满足、依赖闭包或发布者授权。`checkpoint` 只允许出现在 `workspace.fs.write`。`replay` 不属于 v1 recovery。activation schema 是结构记录，文件存在本身不表示 hot reload 已完成。
6. YAML 重复 key、alias、tag 在转换为 JSON 数据之前拒绝。

---

## 5. 调用主体与权限

### 5.1 调用流程

```text
HTTP admission
  → pin GraphLock + ToolRegistrySnapshot + workspace binding
  → RSS tool 插件
      → Native plugin-call broker
          → Native effect broker
              → 托管工作区视图 / 现有 bounded process 后端
  → durable result + workspace publication
```

- 跨插件只传已验证、限长的 named request/result，以及宿主控制的调用上下文。不得通过 JSON、整数或复制 guest resource 跨 VM 搬运权限。
- Native 可以基于原有 run authority 给子调用重新发行本 VM 的资源包装。包装绑定 graph、plugin revision、run、branch epoch、effect、owner 和绝对 deadline。
- 有效权限取宿主策略、可信工作区授权、run 授权、调用者可委托权限、被调用者声明的交集。依赖声明不能自授权限。
- caller 到 callee 只允许 lock 中声明的边。禁止递归插件调用图。业务循环留在现有 RSS 主循环中，并受原预算限制。本文不替换该主循环。
- 凭据引用可以作为公开配置。实际 access/refresh、TLS key、认证头和 FD 不进入插件状态、manifest、snapshot 或日志。
- 既有 delivery 和 outbox 继续使用该 run 已固定的记录。本文不改写 delivery projection。

### 5.2 从当前工具接入

保持现有工具名称和 JSON schemas。`rss/tools/dispatch.rss` 使用 graph 固定的声明式路由。file、search、patch、process 的业务实现继续在 RSS。

该声明式路由是 captured embedding RSS 包内的一张 name→RSS callable 表，键为现有六个工具名，值为各模块既有 `invoke(context: map) -> map`。`dispatch`、`invoke_prepared` 与审批前预检共用该表，不另设 producer，不引入 Rust 按公共名执行器、JSON 选择程序或默认执行器。表随包源码与 `invoke_prepared` entry 一同被 pin 固定，仍只有一个 `ToolOnly` 根、既有 descriptor 顺序、registry identity 来源和 Native 授权/生命周期。registry 命中但表中无 route 时在 Native prepare/effect 前 fail closed。

`process` 与 `terminal.background=true` 的 managed 整体 typed 拒绝由下述 managed process 生命周期取代：`terminal background=true` 是唯一 live-handle producer（提交非发布 receipt，`candidate=None`），`process` 的六个既有限制动作只消费同 run 已注册 handle。两者仍要求已固定 contract 中各自的 effect 声明，声明缺失保持既有 typed 拒绝，public JSON、handle 字符串或历史结果都不构成授权。

`tool_prepare` 仍先验证 parent、run、registry、审批与状态，再记录 started/intent 并发行一次性授权。`tool_commit` 仍负责 durable result。plugin revision、branch epoch 和 effect ID 加入同一授权事实，不能只检查工具名称。

持久化重放必须同时匹配 graph、tool revision、branch lineage 与 call identity。重启后从 run 的 lock 恢复原图。无法找到原包时返回 `plugin_artifact_unavailable`。

迟到批准不执行。取消和原 deadline 在 effect 开始前再次检查。批准到达时 run 已取消、已过 deadline 或授权已撤销的，不启动工具。

### 5.3 插件状态

- `invocation`、`run`、`session` 状态使用 Native 管理的有界版本化根引用。
- 可变状态限于 run/session。服务级共享状态只提供只读配置或宿主定义的事务 API。第三方插件不得自行全局写入。
- 状态迁移是独立、纯函数、无权限的 RSS entry。输入旧 schema，输出新 schema。不能执行 SQL DDL、网络或文件操作。
- 新状态写入新对象，不覆盖旧对象。切换 session 状态 schema 时取得该 session 的维护 lease，并等待其旧 run 到达终止边界。其他 session 不暂停。
- 无法迁回旧状态时，graph rollback 返回 `state_incompatible`，或显式选择较早 checkpoint。禁止静默丢失新状态。
- 插件 activate 不执行 `rss/storage/schema.rss` 的控制面迁移。

### 5.4 managed process 生命周期当前契约

一个 branch 只有一个 Native writer owner；一个 run 只有一张 process registry。两者都在内存中，不新增持久 enum、列或 public API。

- 门状态：`Idle / Opening(owner_run, call) / Open(owner_run, view) / Finalizing(owner_run, call) / ShuttingDown(owner_run) / Unresolved(history)`。`Opening` 在同一个临界区内检查文件 admission、预留 writer owner、预留 run 累计 attempt（32，OS spawn 前预留，spawn 开始后不退还）并取既有 quota/view ticket；view 复制在临界区外，安装成功才 `Open`，OS spawn 只在 `Open` 之后。同 run 的并发首发串行化：一个 Fresh 建 view，其余在 deadline 内等到 `Open` 后 Join 同一 root，不复制第二棵树。
- 文件调用、checkpoint 和 restore 共用该门：`Opening/Open/Finalizing/ShuttingDown/Unresolved` 期间文件 admission 返回既有 `managed_writer_busy`，早于 durable intent；checkpoint/restore 在 `Unresolved` 时返回既有 `managed_writer_indeterminate`。
- `wait/kill` 的发布身份取自 producer view 原始 base（`base_head/base_version/base_root`），不把旧 root 挂到更新 head；base 已前进时走既有 CAS `Conflict` 并按 Stale retire，不产生无 candidate 的成功 read_only。`wait/kill` 需要 contract 同时声明 `process.spawn@bound_process` 与 `workspace.fs.write@bound_workspace recovery:none`；缺失在 seal 期 typed 拒绝。
- `Finalizing` 从 quiescence 复查到 prepare/commit/durable 读回/view disposition 全程排他：新 spawn、stdin、close、kill 与文件 admission 都被拒绝。仍有 sibling Live 时只返回真实控制结果（`read_only` + `outside_tree_not_reverted`），view 保持 `Open`，需要后续 publisher。
- 提交 outcome 未知（commit/读回/disposition 任一不明）时保持 `Finalizing` 与原 deadline，default Drop 与 shutdown 请求都不重开、不覆盖状态；只有同 call 的 durable 读回把结果定为 committed/conflict/no-submit 后才执行对应 idempotent disposition。
- stop、deadline、run terminal、graph revoke、restore 消费同一个 typed idempotent cleanup 结果（Quiescent/TimedOut/Failed）。超时或失败保留 handle/view/ticket 与 owner generation，禁止 clean terminal、generation 推进、view retire 和新 restore 发布，重复 cleanup 不重放 spawn、不重发信号。
- `PluginControlStore::revoke_graph` 成功后必须通知已注册的同进程 Native owner；只登记 service hook 不算完成，只读 storage 也不构成通知。监听者按 run 生命周期弱引用注册并在移除时剪除。
- 重启由既有 typed history 派生 fail-closed gate：只有精确 producer handle → 同 owner 的 wait/kill finalizer → 同 base 的 committed TreeWrite 覆盖关系才算 resolved；普通文件写入、无关 owner、较早 publisher、conflict、taint、settled、空缺 handle、空 registry 都不证明 drainage，一律 `Unresolved`。扫描复用既有有界启动预算与 cursor 完整性检查，截断即 fail closed。不做 PID 重附、不发信号、不按时间自动清除。
- replay 返回原 canonical 结果且不产生新的 OS 动作；fresh 重复 kill 只观察终态 entry；`process_lineage_tainted` 继续作为独立 fence，不作为 drain 证据。

---

## 6. 热重载、回退与对象保留

候选图生命周期：

```text
installed → resolved → prepared → validated → staged → active
                                 ↘ rejected
active → retired（仍可被旧 run / checkpoint 引用）
```

激活事务：

1. 在提交门外完成源码闭包、版本求解、编译、contract 检查、权限 diff、无 effect 的健康检查，以及必要的状态迁移准备。
2. 宿主授权检查图 diff，提交 `expected_generation`。授权使用现有安装和 workspace/owner 校验，不新增 tenant 角色。
3. 原子提交新的 activation record 和 active graph/state-default 引用，并更新内存。并发激活的失败方返回 conflict，不能覆盖胜出方。
4. 后续 admission 在原有原子事务内记录 graph lock 和 registry，不重新编译候选。
5. 旧 run 使用已 pin 的图完成。既有 provider continuation 和 pending delivery 也保持该 pin。本文不改写这些子系统。

- 回退是一次新的激活。例如 generation 8 指向以前保留的 graph。generation 不下降。
- 不兼容 ABI/schema、增加权限、改动已绑定工具 schemas，均不自动激活。
- watcher 只发出“候选变化”信号。写到一半的包、编译失败或未确认的权限提升不会替换 active 图。
- 显式撤销某插件时，可以禁止新调用，并按既有取消策略停止在途 run。“已撤销”不能被旧 run pin 或 snapshot 恢复解除。
- GC 以 run、session、checkpoint、activation 的 durable refs 和 Native 活跃 lease 为依据。有引用的包、状态和文件树不得删除。失败候选只保留有界诊断。

---

## 7. Effect 显式契约与可回退范围

### 7.1 工具和库入口必须显式声明 effects

这是安装、依赖解析、激活与运行时的强制契约，覆盖 `tool` 入口、`library` 入口和纯状态迁移入口。不要求 main、Guardian、context、codec 或 delivery 入口。

- manifest 必须包含带版本的 `effects`。每个可调用 export 必须给出 `direct` 和 `delegated`。缺失、未知 kind、未覆盖入口或不明确的通配声明直接拒绝。省略不等于纯。
- `direct` 是本入口可能直接触发的 effect 上界。`delegated` 是本入口允许通过依赖调用触发的 effect 上界，按依赖 alias 和准确 entry 列出。调用者声明委托 effect，不会得到被调用插件的凭据或直接 host 能力。
- 纯入口必须显式声明 `direct: []`、`delegated: []`。普通返回值和 Native 自身的计量、安全审计不计为插件 effect。插件主动写状态、发事件、读取时钟、调用模型或发送消息，必须声明对应既有 kind。纯入口不得使用这些能力。
- 每条声明使用 Native 已知的 effect kind 和该 kind 的 typed scope。参数中的实际目标仍由 Native 在执行前按该 scope 校验。模型提供的 path 或 URL 不能放大范围。
- `recovery` 只有 `none` 和 `checkpoint`。`checkpoint` 只允许用于 `workspace.fs.write`。插件不能把 `process.spawn`、`remote.write`、`model.request`、`delivery.send` 或其他 kind 标成 `checkpoint`。冲突在 prepare 和 activation 时拒绝。
- effect 契约描述可能做什么。capability grant 决定本次允许做什么。实际执行必须同时属于已固定声明、caller 可委托上界、被调入口上界、run/workspace 授权，并通过当前撤销、deadline 和 budget 校验。默认拒绝。

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

`files` 必须在 manifest dependencies 中声明。解析后，callee entry 的全部可能 effects，连同它继续委托的 effects，经目标绑定映射后必须是 caller 该边 `allow` 的子集。有一个未覆盖项就返回 `undeclared_transitive_effect`。闭包只包含显式允许的调用边。后台 job 和回调若会触发 tool effect，必须声明入口与委托边，并固定原 graph/effect 上界。不能通过异步调度隐藏 effect。本文不新增外部投递订阅。

### 7.2 静态校验、动态拦截与 catalog

1. prepare 读取闭合 RSS/compiled imports，与 Native effect catalog 对照。每个 effectful host 入口必须有明确 metadata。未知项拒绝。当前使用保守的模块 imports 上界，不声称已经具备语言级精确函数 effect 推导。
2. effectful host 调用只绑定到相应的受控 bridge。跨插件调用校验锁定的 delegated 边。无法确定目标的动态调用不得绕过检查。
3. Native 在真实 effect 开始前检查已固定入口契约。未声明操作返回 `undeclared_effect`，不得先执行再只记录告警。journal 保存声明契约 revision 和实际 receipt。契约声明不能替代真实 receipt。
4. 对 terminal 程序，静态 argv 分析不能证明精确 effect。必须声明 `process.spawn` 以及允许的 `workspace.fs.read` / `workspace.fs.write` 上界。执行使用现有 bounded process 后端和托管工作区视图。脚本不能绕过声明扩大托管视图。本文不用 namespace、挂载或网络隔离作为验收条件。
5. effect 新增、scope 扩张、callee effects 扩张或 recovery 保证降低，都属于安全契约变更。即使包版本标为 patch，也必须生成 graph effect diff 并重新审批，不允许自动热激活。scope 变窄或 effect 删除也要检查依赖调用兼容。
6. 图管理视图显示入口级直接 effects、委托 effects、解析闭包、实际 grant 和恢复保证。调用审计对照实际 receipt。模型可见的工具 metadata 从固定契约投影，不能由模型编写或修改声明。

既有 effect catalog，不增删 kind：

| kind | scope | recovery |
| --- | --- | --- |
| `workspace.fs.read` | `bound_workspace` | `none` |
| `workspace.fs.write` | `bound_workspace` | `none` 或 `checkpoint` |
| `process.spawn` | `bound_process` | `none` |
| `clock.read` | `bound_run` | `none` |
| `model.request` | `bound_run` | `none` |
| `remote.write` | `bound_run` | `none` |
| `event.emit` | `bound_run` | `none` |
| `delivery.send` | `bound_delivery` | `none` |
| `secret.use` | `bound_secret` | `none` |

`model.request`、`delivery.send`、`remote.write`、`event.emit` 和 `secret.use` 留在 catalog 中，用于声明、默认拒绝和越权拦截。声明它们不会新建 provider codec、delivery projection、远端 adapter 或 secret 子系统，也不会授予这些能力。对应执行仍走既有宿主路径。未知 kind 拒绝。

### 7.3 可以恢复的对象

- 托管工作区内已经提交到不可变树的文件内容和该树声明支持的元数据。导入一致性只有 `ordinary_copy`。复制不提供外部仍在写入的目录的跨文件时间点快照。本文不实现文件系统 snapshot 后端。
- checkpoint 覆盖的 Native 插件 run/session 状态根。
- 已结束写入、并且结果已进入上述不可变树的本地文件变化。

### 7.4 不能快照的运行态

- 进程、线程、打开的 FD、socket、锁和内存。checkpoint 在仍有可写 view 时返回 `CheckpointBusy`。restore 在仍有可写 view 时返回 `Busy`。
- `ManagedWriterState` 只有 `Settled` 和 `NoProcess`。活动写进程存在时不建立 checkpoint。本文不保存进程镜像，也不把 OS 整树终止当作交付项。现有进程取消和清理保持原行为。

### 7.5 不能撤销的对象

- 模型请求、费用、已经流出的 stdout/SSE、已发送通知。
- 远端 HTTP 写入、支付、邮件、Git push、第三方数据库修改。
- 任意进程的外部副作用。

这些行为不因恢复本地 journal 而变成未发生。`ManagedExternalEffects` 使用 `NoneClaimed` 或 `OutsideTreeNotReverted`。恢复结果携带 `external_effects_not_reverted`。未知 effect 默认拒绝。不能通过恢复把远端事实标为未发生。

---

## 8. 托管工作区视图

RSS 的文件工具与 terminal 子进程使用同一个 Native 发行的 `WorkspaceView`。Native FS adapter 指向该 effect 的私有视图。子进程的工作目录指向同一视图。不允许一个写宿主原目录、另一个写另一棵树。

所有文件系统路径继续受原相对路径、symlink、长度和枚举限制。Native object store、控制面 DB 和插件包目录不在 tool 可写空间。

树操作使用有界复制，不假设 reflink 或 OverlayFS。不增加 CoW 后端。禁止用普通 hardlink 把可写树与不可变 snapshot 共享 inode。不复制宿主外部 hardlink、device、socket 或提权元数据。

现有树上限不提高：`MAX_TREE_ENTRIES` 1_000_000，`MAX_TREE_BYTES` 64 MiB，`MAX_TREE_DEPTH` 32，`MAX_LINEAGE` 64。

导入、发布和回退：

- 从授权源目录创建初始 seed。后续 run 在私有 branch 工作。原源目录不自动被覆写。
- 导入一致性只接受 `ordinary_copy`。对仍被外部写入的普通目录，不承诺时间点一致。本文不依赖、不实现文件系统 snapshot。
- 管理端维护 `workspace_head`。run 成功可按策略原子发布到托管 head。head 的 CAS 失败保留 private branch，返回 conflict，不覆盖其他 run 的更新。
- 对任意现有宿主目录做多文件合并不具备通用原子性。该操作不列入完整回退保证。
- API 返回 branch、head 与 publication 状态。`Staged` 不表示宿主原目录已更新。publication 状态使用现有 `ReadOnly`、`Committed`、`Staged`、`Conflict`、`NotPublished`、`Indeterminate`。

---

## 9. Native Effect Broker 与提交

同步写工具默认使用子 effect view：基于当前 branch head 建立私有可写视图，在其中执行 RSS 文件操作或现有 terminal 后端。工具成功后关闭写入者并生成不可变结果树。失败可丢弃子视图，父 head 不变。

与现有 lifecycle 对接：

```text
prepare/approval
  → durable tool.started + effect intent
  → 发行绑定 graph/plugin/run/branch epoch 的一次性授权
  → 再次检查取消、原 deadline、撤销和迟到批准
  → Native effect 执行，输出进入私有 view
  → writer settled + 不可变 tree/receipt 准备
  → durable effect receipt + branch-head CAS + tool result
  → 内存 publication
```

- 源码编译、文件树复制、进程等待和 fsync 在全局提交门外。
- SQLite 仍是控制面原子点。不可变文件对象先落盘，事务只发布它们的引用。崩溃产生的未引用对象按 journal 回收。已提交引用不能指向未持久化树。
- 现有 tool_call/started 配对、不成功不发行 token、取消、超时、撤销、原始 deadline、输出预算和去重不变量继续保留。
- RSS 报告的 effect 类型只是请求。Native 以实际已发行能力和真实操作生成 receipt。不相信插件自称纯函数。
- Native 已完成 effect 而 RSS 未提交工具结果时，恢复读取已持久化 receipt，不得再次执行已经发生的操作。状态不明则返回 `effect_indeterminate`，保留分支并等待显式 reconcile，不自动重复 terminal。
- 不具备事务协议的远端 effect 不伪装成本地原子事务。`Indeterminate` 不能记为成功。

journal 绑定 owner、effect、call、graph、plugin revision、branch epoch、父/子 root 与 output artifact。工作区 journal kind 使用现有 `Imported`、`Published`、`Discarded`、`Checkpoint`、`Restored`。不另造一套状态机名称。

---

## 10. Checkpoint 与恢复协议

### 10.1 Checkpoint 内容

`Checkpoint` 保存：

- workspace immutable root 与 branch lineage；
- 插件状态根及其 schema/revision；
- graph lock、registry identity、公开配置 revision；
- 业务 history cursor、已闭合 call/output 边界、parent run；
- 已知不可逆 effect 的 high-water mark 和受控 artifact refs。

不保存 access/refresh、VM heap、Native token、FD、socket、活进程、审批授权或整个控制面 DB 文件。公开 checkpoint 标识不能单独恢复分支。`restore_from_public_ids` 返回 `AuthorityRequired`。

### 10.2 创建条件

1. 取得该 branch/session 的维护 lease。相关 run 在工具批次闭合的协作安全点暂停新的 tool dispatch。已有 effect 必须先 settled。不在半个模型调用或半组 tool outputs 上截断。暂停等待受管理请求期限和原 run 剩余期限共同约束，不能延长原 run。
2. 在提交门外等待当前 effect settled。可写 view 仍打开时返回 `CheckpointBusy`。不把 OS 后代命名空间清理作为前置条件。
3. Native 在提交门内重新验证原 graph、head、状态 revision、history cursor 和 lease。checkpoint 只落在完整工具批次结束的位置，不能保留无对应 output 的 pending tool_call。发生相关并发变化时拒绝，或在原期限内重新准备。不能记录混合状态。
4. 原子记录 checkpoint 引用并释放维护 lease。其他工作区继续运行。不使用服务级全局暂停。

### 10.3 恢复

- 恢复产生新 branch。目标 branch 有活动 run 时，先按既有取消路径停止并等待现有进程后端报告退出。不在执行中替换脚下目录。
- 默认使用 checkpoint 的确切 graph。选择新 graph 时先通过独立的 schema/state 兼容准备。
- branch epoch 递增。旧 token、process handle 和未完成 effect 的权限失效。重新检查当前 workspace 和 plugin 撤销策略。
- 新 run 从 checkpoint 的闭合历史前缀开始，保留 lineage。旧 run、旧事件、旧计费及旧投递记录保持只读。后续新调用使用新 call ID 和 parent。
- 新 run 有明确的新 admission 和 deadline。不复活旧 run，不重置旧 run 的计时来绕过超时。
- 已在远端发生的行为，或用户已经收到的进度，不被抹除。恢复结果附带 `external_effects_not_reverted`。
- 不用 SQLite 文件回滚实现该功能。文件回滚会错误恢复权限、usage、审批和投递游标。
- lineage 达到 64 时拒绝继续增长。

---

## 11. 管理 API 与事件

普通 run 的既有 HTTP routes 保持兼容。已注册的管理接口按现有契约维护；不新增本列表以外的 route。

现有 `POST /v1/runs` 可携带可选字段 `workspace_branch`、`graph_id`。普通新分支默认采用 active graph。恢复分支默认采用 checkpoint 的 graph。显式指定其他图必须通过部署空间许可和状态兼容检查。graph ID 本身不授予任意已安装插件的调用权。响应增加实际固定的 graph、branch、epoch 和 publication 状态。这些字段进入 typed 请求契约，不能落入任意 options，也不能由客户端路径生成 Native authority。

已注册：

- `POST /v1/workspaces/{workspace_id}/checkpoints`
- `POST /v1/workspaces/{workspace_id}/restore`
- `POST /v1/workspaces/{workspace_id}/branches`
- `POST /v1/workspaces/{workspace_id}/publish`
- `GET /v1/runs/{run_id}/effects`
- `POST /v1/plugins/install`
- `POST /v1/plugin-graphs/resolve`
- `POST /v1/plugin-graphs/{graph_id}/prepare`
- `POST /v1/plugin-activations`
- `GET /v1/plugin-graphs/{graph_id}`
- `POST /v1/plugin-activations/{activation_id}/rollback`

`GET /v1/runs/{run_id}/effects` 使用该 run 的 typed managed binding 与 Native source-root 查询授权。RSS 在 `LIMIT` 前按 run、profile、session、workspace、branch 过滤。实现位于 `src/gateway/effects.rs`、`src/gateway/api_server.rs`、`src/service/managed_effects.rs`、`src/effects/journal.rs`、`src/gateway/store.rs` 和 `rss/storage/effects.rss`。该查询只覆盖 effect 账本。

安装和激活使用现有 `InstallAuthorization` 与 workspace/owner 校验。run token 不能激活插件。不新增 tenant，也不新增独立管理员产品。跨 workspace 或跨 branch 的未授权访问失败。冲突返回 409。不存在和无权的对象不泄露私有路径。对象标识由 Native 查询并验证 owner。path、graph ID 和签名都不能充当授权。

每个 run 可查询 `graph_id`、`activation_generation`、`workspace_branch`、`head`。最终 `run.completed` 在配置要求 workspace publication 完成时等待 publication；仅 staged 时结果显式声明 staged branch。

---

## 12. 当前边界与未纳入

- 插件图模型、manifest、exports、library 依赖、resolve、compiler、load、pin、closure、cache、activation、hot reload、persistence 和对应 runtime 执行属于当前设计。
- Tools 调用虚拟化、effect 声明、admission、默认拒绝、原 Native 授权、root、clock、取消、迟到批准不执行，属于当前设计。
- 托管工作区和插件状态的 checkpoint、restore、branch、publish、replay、effect 账本查询及对应管理接口属于当前设计。
- `PLUGIN_KINDS` 仍只有 `library` 和 `tool`。effect catalog 和 recovery 规则不扩大。现有包、闭包、树和 lineage 上界不提高。
- `ContextPrompt` 保留为图 lock 变体。它不构成新的 prompt、context 或 Guardian 实现任务。
- catalog 中的 `model.request`、`delivery.send`、`remote.write`、`event.emit`、`secret.use` 只用于声明和拒绝。它们不构成新子系统。
- 内置 agent、reviewer、provider、默认 prompt、compaction 和 delivery 语义不改。
- 不承诺任意进程、活 FD 或外部副作用可以快照或回滚。导入只有 `ordinary_copy`。
- 不实施 OS namespace、OCI、cgroup、seccomp 或调试器隔离。
- 不新增 admin/tenant 系统，不新增未列出的 route、limit 或 SDK API，不开兼容版本 lane。
