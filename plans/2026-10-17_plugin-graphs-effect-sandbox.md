# RSS 插件图与 Tools 调用虚拟化实施计划

> **范围：** 本计划实现 RSS 插件图，以及 tools 调用的 effect 声明、准入和托管执行。插件图包括图模型、manifest、exports、library 依赖、resolve、compiler、load、pin、closure、cache、activation、hot reload、persistence，以及这些图上的 runtime 执行。Tools 对托管工作区和插件状态的 effect 经 Native broker 执行。保留原 Native 授权、root、clock、取消，以及迟到批准不执行。托管支持 checkpoint、restore、branch、publish、replay 和 effect 账本查询，以及这些操作对应的管理接口。
>
> 进程继续使用现有有界 `std::process::Command` 后端及其取消、清理。本计划不实施、不验收新的 OS namespace、OCI、cgroup、seccomp 或调试器隔离。OS 隔离资格不作为交付项。Native tools 效果测试使用现有受控后端和 fixture。
>
> provider codec、delivery projection、main policy，以及 context、prompt、Guardian 的新插件行为不作为实现任务。既有内置 agent、reviewer、provider、默认 prompt 和 compaction 语义保持不变。既有 Tool 与 effect 安全约束保持不变。
>
> 平台为 Linux x86_64。不增加 32 位或 x32。不改 Core、语言语法、JIT 或 VMBC。不新增 admin/tenant 系统。不新增下文未列出的 route、limit 或 SDK effect kind。不另开 schema 版本或兼容 lane。

**Goal:** 将 tools 与其 library 依赖组成可版本化、可解析、可原子切换的 RSS 插件图。工具对托管工作区和受控插件状态的 effect 在 Native 准入后执行，并在托管范围内支持 checkpoint、分支恢复和版本回退。

**Architecture:** 不可变插件包、闭合依赖图、按 run 固定的 graph lock，以及独立的 Native effect broker。代码版本、工作区版本、插件状态版本分别记录，通过显式 checkpoint 和 activation 记录关联。hot reload 面向新 run。恢复产生新 branch 与新 run，保留旧执行记录。

**Tech Stack:** 当前 RustScript/RSS + Rust Native + Axum + 现有 typed SQLite/RSS storage。版本求解使用 resolver 已依赖的 `semver`。进程执行使用 `src/capabilities/vm_io/bounded_process.rs` 的现有 argv 后端。不增加 OCI runtime。

---

## 1. 当前依据与设计边界

本计划的验收绑定到对应提交的源码和执行记录。修改时保全范围外的既有改动；编译、运行和静态检查分别记录，不把旧候选的通过结果转为新源码的资格。

### 首期 A 本地验收

- 已完成一个 `AcceptedPublisher`、`ToolOnly`、stateless tool 链接一个纯 leaf library 的首期接入；真实 `read_file` 授权读取、library 字符串处理与原托管提交保持完整。
- 已覆盖完整 graph lock 与已捕获代码固定、A/B 并存、真实 Native 首次执行与精确回放、同控制面撤销后的新鲜授权、只读历史保留及纯 leaf 运行失败。全局缓存仅保留不可变 builtin/schema 材料，不缓存执行权限。
- 绝对 deadline 与取消仍来自原准入 root。四个只读回放探针的初始预算为 10s；独立 2s 真实 child-clock 场景、Native 执行类探针和生产默认配置保持原边界。查询 cut、精确错误、单次完成与历史断言不变。
- 本地验证：library 611 通过、0 失败、6 忽略；六个相关集成 target 共 103 个唯一测试通过；全项目格式检查、全 target/all-features clippy `-D warnings` 与 schema `--check` 通过。六例聚焦属于 library 子集，不重复累计。独立代码审查已接受本切片；远端 CI 与发布另行核验。
- 该验收限于首期 A。T07 正式 tool→tool、T14 多库和全量工具接入、stateful child、新拓扑 checkpoint/restore 及对应剩余 T15/T16 链路继续按既定后续范围推进；当前 typed 不支持边界保留。

已核对的复用点：

- `rss/tools/types.rss`、`registry.rss`、`dispatch.rss`：现有工具描述、固定分派及 RSS 实现。
- `src/registry.rs`：`ToolRegistrySnapshot` 是不可变工具描述和校验器集合。其 identity 只用于一致性，不授予权限。
- `src/runtime/module_snapshot.rs`：模块树源码快照和隔离编译。它与 effect 工作区快照是不同对象。
- `src/runtime/closed_bundle.rs`：有界闭合 import 图编译，上限 256 个文件、8 MiB 源码。插件加载复用该接口，不扩大上限，不改 Core。
- `src/service.rs`：admission、run 固定 registry、durable context、恢复与提交门。
- `src/capabilities/lifecycle.rs`、`src/runtime/agent_host.rs`：`tool_prepare` / `tool_commit`、token、parent、approval 与 replay。
- `src/capabilities/confined_io.rs`：dirfd/openat2 文件边界。
- `src/capabilities/vm_io/bounded_process.rs`：子进程由 `std::process::Command` 按 argv 启动。该模块不提供 namespace、seccomp 或根文件系统隔离。不能据此承诺任意 terminal 程序已被 OS 隔离。本计划不添加该隔离。
- `src/plugins/`：manifest、store、resolve、prepare、pin、schema。`PLUGIN_KINDS` 只有 `library` 和 `tool`。
- `src/effects/`：托管文件树、journal、checkpoint、restore。该模块不接入 OCI。
- `rss/storage/*.rss`：业务 SQL、迁移与持久化投影继续由 RSS 管理。Native 负责授权与提交不变量。外部插件不能提供 SQL 字符串。
- 已注册 HTTP：`POST /v1/runs`、`POST /v1/workspaces/{workspace_id}/checkpoints`、`POST /v1/workspaces/{workspace_id}/restore`、`GET /v1/runs/{run_id}/effects`。

插件化范围：

- tool 包及其 library 依赖；
- 上述包的图模型、manifest、exports、解析、编译、加载、pin、闭包、缓存、激活、热重载、持久化和按 run 执行。

不在本计划实现范围内：

- 把 agent 主循环、Guardian、context 选择、compaction、prompt 组合、provider codec 或 delivery projection 做成可替换插件；
- 新的 OS 隔离后端；
- 新的 admin/tenant 产品。

必须留在可信 Native 核心、且本计划不放宽的部分：权限交集、credential/secret 保管、执行 token 验证、工作区授权、绝对 deadline 与 cancel、现有进程边界、持久化原子提交、effect journal、恢复协调。RSS 插件可以提出请求，不能替换这些强制边界。存储后端协议和全局 schema 升级沿用宿主规则。第三方插件不直接写控制面数据库。

既有内置 agent、reviewer、provider、默认 prompt、compaction 和 delivery 行为保持原语义。本计划只约束它们不被插件替换，不改写它们。

首期保证限于 Linux、单机、托管工作区和 RSS `library`/`tool` 包。第三方 native 动态库、多机分布式事务、进程内存或连接恢复、任意网站操作撤销、任意外部副作用回滚，都不在保证内。

---

## 2. 方案比较与推荐

### A. 采用：RSS 插件 + 不可变 graph + Native effect broker + 托管工作区视图

复用现有 RSS/VM、typed host 与 registry。tool 扩展保持 RSS。Native 负责授权、生命周期和托管文件操作。多图可以并存，回退指向已保留的旧图。进程仍走现有 Command 后端。

### B. 不采用：把主循环、provider、delivery 或 Guardian 改成可替换业务插件

这些模块的现有语义保持为约束。本计划不把它们做成插件产品。图 lock 可以记录已有 `harness_selection` 字段，见第 4 节。该字段不授权新的 prompt、context 或 Guardian 行为。

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
- 首期安装入口为受控本地目录。禁止自动执行安装脚本、自动拉取依赖、跟随符号链接或解包到任意宿主路径。不在本计划设计在线 registry。
- manifest 严格解析：拒绝未知安全字段、重复 key、YAML alias/tag/merge 及超预算输入。包数量、文件数、字节数、图深度、编译耗时和诊断输出均有界。现有界限不因插件加载被取消。
- 现有上界，本计划不提高：每图最多 64 个包、256 条依赖边、深度 16；闭包源码 256 文件 / 8 MiB；每包最多 32 个可选版本；求解最多 4096 个决策节点。达到上界返回具体 budget 错误。运行时缓存按实际对象大小与条目数计量，复用既有上界。
- 宿主内置包与后来安装的包使用现有 trust 区分。安装不把扩展包提升为控制面迁移或强制策略适配器。两类包都不能绕过 Native 原子提交和权限校验。

### 4.2 三类依赖边

- `library`：纯 RSS 库，链入调用者的 VM，不拥有独立权限或状态。
- `plugin`：显式插件调用边，经 Native broker 进入被调用插件的独立 VM 和调用主体。
- `host ABI`：对宿主 named types、capability 接口和事件契约的兼容要求。

图 lock 边上的 provenance 保持 `direct`、`plugin` 或 `library`。禁止用普通 RSS 跨包 import 绕过 plugin 主体边界。Native 根据已校验 manifest 生成静态入口映射。用户输入不能构造 import、export 或磁盘路径。禁止把多个插件的 capability 并集授予单个 VM。

### 4.3 解析、编译、加载、pin 与 cache

- 每个 graph 内每个 package 只允许一个具体版本。不同 graph 可同时运行不同版本。
- resolver 只查询已安装候选，确定性排序，有限搜索。缺失、冲突、循环、歧义、超预算均返回带最小冲突链的 typed 错误。
- 持久化 `GraphLock` 记录 package revision、依赖边、入口、接口 schema、host ABI、权限声明、每个入口的 direct/delegated effect 及解析后的传递闭包、状态 schema、编译环境标识。
- `GraphLock.harness_selection` 是图契约字段，取值包括 `Unselected`、`ToolOnly` 和 `ContextPrompt`。本计划的执行模式是 `ToolOnly`。`ContextPrompt` 与另外两个变体一样保留为可读、可校验的 lock 形状，不作为向后兼容产品，也不另开迁移 lane。它不授权新的 prompt、context 或 Guardian 插件行为，也不改变内置策略。
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

1. schema 使用仓库内本地文件。运行时和 CI 不从网络解析远端 schema。现有 `format`、`contract` 和记录版本标识保持为当前 v1 事实。本计划不发布新的 schema 版本，也不保留多版本升级矩阵。
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
- caller 到 callee 只允许 lock 中声明的边。禁止递归插件调用图。业务循环留在现有 RSS 主循环中，并受原预算限制。本计划不替换该主循环。
- 凭据引用可以作为公开配置。实际 access/refresh、TLS key、认证头和 FD 不进入插件状态、manifest、snapshot 或日志。
- 既有 delivery 和 outbox 继续使用该 run 已固定的记录。本计划不改写 delivery projection。

### 5.2 从当前工具迁移

保持现有工具名称和 JSON schemas。`rss/tools/dispatch.rss` 从静态入口改为 graph 固定的声明式路由。file、search、patch、process 的业务实现继续在 RSS。

该声明式路由是 captured embedding RSS 包内的一张 name→RSS callable 表，键为现有六个工具名，值为各模块既有 `invoke(context: map) -> map`。`dispatch`、`invoke_prepared` 与审批前预检共用该表，不另设 producer，不引入 Rust 按公共名执行器、JSON 选择程序或默认执行器。表随包源码与 `invoke_prepared` entry 一同被 pin 固定，仍只有一个 `ToolOnly` 根、既有 descriptor 顺序、registry identity 来源和 Native 授权/生命周期。registry 命中但表中无 route 时在 Native prepare/effect 前 fail closed。

`process` 与 `terminal.background=true` 原有的 managed 整体 typed 拒绝由下述 managed process 生命周期取代：`terminal background=true` 是唯一 live-handle producer（提交非发布 receipt，`candidate=None`），`process` 的六个既有限制动作只消费同 run 已注册 handle。两者仍要求已固定 contract 中各自的 effect 声明，声明缺失保持既有 typed 拒绝，public JSON、handle 字符串或历史结果都不构成授权。本条路由完成仍不代表 T14 全量接入完成。

`tool_prepare` 仍先验证 parent、run、registry、审批与状态，再记录 started/intent 并发行一次性授权。`tool_commit` 仍负责 durable result。plugin revision、branch epoch 和 effect ID 加入同一授权事实，不能只检查工具名称。

持久化重放必须同时匹配 graph、tool revision、branch lineage 与 call identity。重启后从 run 的 lock 恢复原图。无法找到原包时返回 `plugin_artifact_unavailable`。

迟到批准不执行。取消和原 deadline 在 effect 开始前再次检查。批准到达时 run 已取消、已过 deadline 或授权已撤销的，不启动工具。

### 5.3 插件状态

- `invocation`、`run`、`session` 状态使用 Native 管理的有界版本化根引用。
- 首期可变状态限于 run/session。服务级共享状态只提供只读配置或宿主定义的事务 API。第三方插件不得自行全局写入。
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
5. 旧 run 使用已 pin 的图完成。既有 provider continuation 和 pending delivery 也保持该 pin。本计划不改写这些子系统。

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

`files` 必须在 manifest dependencies 中声明。解析后，callee entry 的全部可能 effects，连同它继续委托的 effects，经目标绑定映射后必须是 caller 该边 `allow` 的子集。有一个未覆盖项就返回 `undeclared_transitive_effect`。闭包只包含显式允许的调用边。后台 job 和回调若会触发 tool effect，必须声明入口与委托边，并固定原 graph/effect 上界。不能通过异步调度隐藏 effect。本计划不新增外部投递订阅。

### 7.2 静态校验、动态拦截与 catalog

1. prepare 读取闭合 RSS/compiled imports，与 Native effect catalog 对照。每个 effectful host 入口必须有明确 metadata。未知项拒绝。首期使用保守的模块 imports 上界，不声称已经具备语言级精确函数 effect 推导。
2. effectful host 调用只绑定到相应的受控 bridge。跨插件调用校验锁定的 delegated 边。无法确定目标的动态调用不得绕过检查。
3. Native 在真实 effect 开始前检查已固定入口契约。未声明操作返回 `undeclared_effect`，不得先执行再只记录告警。journal 保存声明契约 revision 和实际 receipt。契约声明不能替代真实 receipt。
4. 对 terminal 程序，静态 argv 分析不能证明精确 effect。必须声明 `process.spawn` 以及允许的 `workspace.fs.read` / `workspace.fs.write` 上界。执行使用现有 bounded process 后端和托管工作区视图。脚本不能绕过声明扩大托管视图。本计划不用 namespace、挂载或网络隔离作为验收条件。
5. effect 新增、scope 扩张、callee effects 扩张或 recovery 保证降低，都属于安全契约变更。即使包版本标为 patch，也必须生成 graph effect diff 并重新审批，不允许自动热激活。scope 变窄或 effect 删除也要检查依赖调用兼容。
6. 图管理视图显示入口级直接 effects、委托 effects、解析闭包、实际 grant 和恢复保证。调用审计对照实际 receipt。模型可见的工具 metadata 从固定契约投影，不能由模型编写或修改声明。

既有 effect catalog，本计划不增删 kind：

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

- 托管工作区内已经提交到不可变树的文件内容和该树声明支持的元数据。导入一致性只有 `ordinary_copy`。复制不提供外部仍在写入的目录的跨文件时间点快照。本计划不实现文件系统 snapshot 后端。
- checkpoint 覆盖的 Native 插件 run/session 状态根。
- 已结束写入、并且结果已进入上述不可变树的本地文件变化。

### 7.4 不能快照的运行态

- 进程、线程、打开的 FD、socket、锁和内存。checkpoint 在仍有可写 view 时返回 `CheckpointBusy`。restore 在仍有可写 view 时返回 `Busy`。
- `ManagedWriterState` 只有 `Settled` 和 `NoProcess`。活动写进程存在时不建立 checkpoint。本计划不保存进程镜像，也不把 OS 整树终止当作交付项。现有进程取消和清理保持原行为。

### 7.5 不能撤销的对象

- 模型请求、费用、已经流出的 stdout/SSE、已发送通知。
- 远端 HTTP 写入、支付、邮件、Git push、第三方数据库修改。
- 任意进程的外部副作用。

这些行为不因恢复本地 journal 而变成未发生。`ManagedExternalEffects` 使用 `NoneClaimed` 或 `OutsideTreeNotReverted`。恢复结果携带 `external_effects_not_reverted`。未知 effect 默认拒绝。不能通过恢复把远端事实标为未发生。

---

## 8. 托管工作区视图

RSS 的文件工具与 terminal 子进程使用同一个 Native 发行的 `WorkspaceView`。Native FS adapter 指向该 effect 的私有视图。子进程的工作目录指向同一视图。不允许一个写宿主原目录、另一个写另一棵树。

所有文件系统路径继续受原相对路径、symlink、长度和枚举限制。Native object store、控制面 DB 和插件包目录不在 tool 可写空间。

树操作使用有界复制，不假设 reflink 或 OverlayFS。本计划不增加 CoW 后端。禁止用普通 hardlink 把可写树与不可变 snapshot 共享 inode。不复制宿主外部 hardlink、device、socket 或提权元数据。

现有树上限不提高：`MAX_TREE_ENTRIES` 1_000_000，`MAX_TREE_BYTES` 64 MiB，`MAX_TREE_DEPTH` 32，`MAX_LINEAGE` 64。

导入、发布和回退：

- 从授权源目录创建初始 seed。后续 run 在私有 branch 工作。原源目录不自动被覆写。
- 导入一致性只接受 `ordinary_copy`。对仍被外部写入的普通目录，不承诺时间点一致。本计划不依赖、不实现文件系统 snapshot。
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

普通 run 的既有 HTTP routes 保持兼容。下文已注册的接口按现有契约维护。尚未注册的接口在实现前不能对外宣称存在。不新增本列表以外的 route。

现有 `POST /v1/runs` 可增加计划内可选字段 `workspace_branch`、`graph_id`。普通新分支默认采用 active graph。恢复分支默认采用 checkpoint 的 graph。显式指定其他图必须通过部署空间许可和状态兼容检查。graph ID 本身不授予任意已安装插件的调用权。响应增加实际固定的 graph、branch、epoch 和 publication 状态。这些字段进入 typed 请求契约，不能落入任意 options，也不能由客户端路径生成 Native authority。

已注册：

- `POST /v1/workspaces/{workspace_id}/checkpoints`
- `POST /v1/workspaces/{workspace_id}/restore`
- `GET /v1/runs/{run_id}/effects`

`GET /v1/runs/{run_id}/effects` 使用该 run 的 typed managed binding 与 Native source-root 查询授权。RSS 在 `LIMIT` 前按 run、profile、session、workspace、branch 过滤。实现位于 `src/gateway/effects.rs`、`src/gateway/api_server.rs`、`src/service/managed_effects.rs`、`src/effects/journal.rs`、`src/gateway/store.rs` 和 `rss/storage/effects.rss`。该查询只覆盖 effect 账本，不覆盖本节其余管理接口。

仍属本计划、且名称已经确定的管理接口：

- `POST /v1/plugins/install`：受控来源导入，返回不可变 revision。
- `POST /v1/plugin-graphs/resolve`：解析 lock 和 diff，不激活。
- `POST /v1/plugin-graphs/{graph_id}/prepare`：编译和验证，返回状态。
- `POST /v1/plugin-activations`：携带 graph、目标部署空间、`expected_generation`。
- `GET /v1/plugin-graphs/{graph_id}`：节点、边、contract、权限和错误链。
- `POST /v1/plugin-activations/{activation_id}/rollback`：产生新 activation。权限与正常激活相同。
- `POST /v1/workspaces/{workspace_id}/branches`：可指定 checkpoint 来源。
- `POST /v1/workspaces/{workspace_id}/publish`：携带 branch、`expected_head`。

安装和激活使用现有 `InstallAuthorization` 与 workspace/owner 校验。run token 不能激活插件。不新增 tenant，也不新增独立管理员产品。跨 workspace 或跨 branch 的未授权访问失败。冲突返回 409。不存在和无权的对象不泄露私有路径。对象标识由 Native 查询并验证 owner。path、graph ID 和签名都不能充当授权。

新增 SSE 字段与事件保持显式 schema，且只使用下列已列名称：

- 每个 run 可查询 `graph_id`、`activation_generation`、`workspace_branch`、`head`。
- `plugin.graph_activated`、`effect.started`、`effect.committed`、`effect.aborted`、`checkpoint.created`、`workspace.restored`、`workspace.published`。
- 已冻结 run 中的 plugin/event 语义不改变。既有 delivery/outbox 继续使用该 run 已固定的记录。
- 配置要求 workspace publication 完成时，最终 `run.completed` 在该 publication 完成后发出。仅 staged 时，结果显式声明 staged branch。

---

## 12. 分阶段实施任务与文件清单

代码任务遵循 RED、GREEN、REFACTOR：先增加具体失败断言并实际运行，再做最小实现，然后运行该目标及直接邻接回归。文件落点若调整，先更新本计划。不要为完成一个阶段一次性拆散整个 `service.rs`。

T02 和 T09 已移出本计划。编号不回收，也不另开替代任务。

### M0：验收基线

**T01 基线固定**

- 将既有生产修复与本计划实现分开管理。未提交的无关修改保持原样。
- 普通回归使用现有 `tests/service_tests.rs`、`tests/rss_process_tool_tests.rs`、`tests/real_tool_continuation_tests.rs`。
- 不把真实凭据、真实外网或真实用户数据测试作为本计划门禁。

### M1：manifest、依赖图与持久化 lock

**T03 manifest 与包存储**

- 维护 `src/plugins/{mod.rs,manifest.rs,store.rs,schema.rs,yaml.rs,error.rs}`、`tests/plugin_manifest_tests.rs`、`tests/plugin_schema_sync_tests.rs`，以及第 4.5 节列出的 manifest/effect schema。
- RED：重复字段、路径逃逸、symlink 包、同版本覆盖、缺失发布者授权、缺失 effects、未覆盖 export、未知 effect 和非法 recovery 均拒绝。显式空 effect 的纯入口，以及 `workspace.fs.write` 的 `checkpoint` recovery，可以接受。`process.spawn` 声称 `checkpoint` 时拒绝。
- GREEN：严格有界解析、Native 所有的不可变包目录和 typed metadata。继续使用现有 `semver` 依赖，不增加第二个求解器。
- Gate：`cargo test --locked --test plugin_manifest_tests --test plugin_schema_sync_tests`。

**T04 resolver、compiler 与 closed bundle**

- 维护 `src/plugins/{resolve.rs,prepare.rs}`、`tests/plugin_graph_tests.rs`、`schemas/plugin-graph-lock.schema.yaml`。
- 复用 `src/runtime/closed_bundle.rs` 的 crate 内接口。不扩展 Core，不提高 256 文件 / 8 MiB。
- RED：冲突链、缺依赖、循环、越权 host import、未声明的直接 effect、callee 传递 effect 未被 allow 覆盖、不同文件枚举顺序造成不同解。正控为满足入口 effect 上界的固定闭包。
- GREEN：版本求解、不可变 lock、受限入口解析、compiler 和 load。`ToolOnly` 可执行。`ContextPrompt` 只作为既有 lock 变体保持可校验。
- Gate：`cargo test --locked --test plugin_graph_tests`。

**T05 lock、pin 与 activation 的 storage 协议**

- 维护 `rss/storage/plugins.rss`、`tests/plugin_store_recovery_tests.rs`。
- 需要时修改 `rss/storage/schema.rss`、`rss/storage/main.rss`、`src/domain.rs`、`src/sqlite_storage_rows.rs`。插件 activate 不触发控制面迁移。
- RED：提交失败无半激活。重启重建同一 lock。有 durable 引用时不能 GC。
- GREEN：对象和引用记录走现有 typed SDK/RSS 路径。
- Gate：`cargo test --locked --test plugin_store_recovery_tests`。

### M2：按 run 固定图与 RSS 插件调用边界

**T06 admission / replay 固定图**

- 使用现有 `tests/tools_pin_production_ab.rs`、`tests/tools_pinned_commit_outcome.rs`、`tests/provider_durable_replay_loop_tests.rs`。不另建平行 pin 测试目标。
- 修改 `src/service.rs`、`src/registry.rs`、`src/plugins/pin.rs`、`src/durable_provider.rs`、`rss/storage/admission.rss`、`rss/storage/runs.rss` 中与 graph pin 直接相关的部分。不改 provider 协议。
- RED：A run 开始后激活 B，A 的后续 tool 和 replay 仍为 A。新 run 为 B。重启不改用 active 图。缺 A 包明确失败。
- GREEN：既有 admission 事务加入 lock/ref 固定。prepared graph 在门外准备，不在热路径编译。
- Gate：`cargo test --locked --test tools_pin_production_ab --test tools_pinned_commit_outcome --test provider_durable_replay_loop_tests`。

**T07 typed 插件调用桥与工具适配**

首期收敛为 T14 的单 tool＋纯 library 可执行链接；本任务的 tool→tool 正式调用延期。后续首个 plugin-call 只支持可信 stateless caller→callee、一次同步调用和一个真实 effect，不同时引入 library、嵌套、并行或多个子 effect。独立 VM/主体、Native 重新发行授权、权限交集、有界 typed data 与原 clock/cancel/epoch/撤销必须同期完成。纯库和严格 stateless child 无 T12 功能依赖；共享文件仍由单写者串行修改。

- 维护 `src/runtime/native_tools.rs`、`src/runtime/agent_host.rs`、`rss/tools/{registry.rss,dispatch.rss}`、`tests/tools_pin_invoke_tracer.rs`。
- RED：A 无法调用未声明的 B。B 不能继承 A 的其他权限。resource 无法借 JSON 跨 VM。同名不同 revision 不能重放旧结果。缺失 effect 的真实 Native 操作在发生前被拒绝。纯入口不能通过库、时钟或插件委托隐藏 effect。迟到批准不执行。
- GREEN：独立调用主体、Native 重新发行子 VM 资源、现有工具 schemas 不变。
- Gate：`cargo test --locked --test tools_pin_invoke_tracer --test rss_process_tool_tests`。
- 本阶段只连接内置可信 tool/library 包。不开放不可信 native 进程插件。

### M3：托管 effect view 与提交

**T08 托管文件树和子 effect view**

- 维护 `src/effects/{mod.rs,types.rs,workspace.rs,tree_store.rs}`、`tests/effect_workspace_tests.rs`。
- 需要时修改 `src/capabilities/{filesystem.rs,confined_io.rs}`，使文件工具与 terminal 使用同一托管视图。不把该修改扩展成 OS 隔离后端。
- RED：写 view 不改 seed。文件工具与 terminal 看到同一内容。失败工具的父 head 不变。可写 view 不与 checkpoint 共享可写 inode。导入非 `ordinary_copy` 时拒绝。
- GREEN：有界复制、private temp、原子 Native refs、现有 quota 和安全文件类型处理。
- Gate：`cargo test --locked --test effect_workspace_tests`。

**T10 effect journal 与真实工具提交**

- 维护 `src/effects/{broker.rs,journal.rs}`、`rss/storage/effects.rss`、`tests/effect_commit_recovery_tests.rs`。
- 需要时修改 `src/capabilities/{lifecycle.rs,types.rs}`、`src/service.rs`。不扩大 token 权限，不绕过审批，不重置 deadline。
- RED：在 intent、文件准备、持久化 receipt、head CAS、result 提交各点崩溃后，重启无已提交悬空 root，无重复已执行 terminal。receipt 已存在时不重复 effect。未知状态不报成功。
- GREEN：Native receipt 与现有 started/result 绑定。取消、原 clock 和迟到批准仍阻止未开始的执行。
- Gate：`cargo test --locked --test effect_commit_recovery_tests --test real_tool_continuation_tests`。

### M4：checkpoint、恢复与插件状态

**T11 checkpoint 和 branch restore**

- 维护 `src/effects/checkpoint.rs`、`rss/storage/checkpoints.rss`、`tests/effect_checkpoint_tests.rs`、`tests/managed_checkpoint_restore_tests.rs`、`tests/managed_checkpoint_api_tests.rs`，以及现有 checkpoint/restore schema。
- RED：活动 writer 拒绝 checkpoint。旧 epoch token 被拒绝。公开 ID 不能恢复。旧审计、usage 和审批记录不被删除或复活。外部 effect 仍标为未撤销。
- GREEN：闭合 history cursor 与 root refs。恢复产生新 branch 和新 run，并重新授权。
- Gate：`cargo test --locked --test effect_checkpoint_tests --test managed_checkpoint_restore_tests --test managed_checkpoint_api_tests`。

**T12 有版本的插件状态**

GC 采用最小正确结构：worker 在每次 put 执行前复核健康，所有 collector 失败顺序结算；最后 owner 在 registry 锁内记录固定大小 dirty generation，有限 sweep 只确认覆盖代次。保留现有状态层级、纯迁移和精确 checkpoint，不删除重做。不引入逐 producer 状态机、持久脏表、后台 GC 或重试调度。两项收尾、直接并发回归、既定最终同源门禁与独立审查闭合后停止；E1 剩余组合补证、E2 typed 错误码映射及 sweep 成本优化后移。

- 维护 `src/plugins/state.rs`、`src/plugins/pin.rs`、`src/plugins/manifest.rs`、`rss/storage/plugins.rss`、`src/effects/journal.rs` 与 `src/service/managed_checkpoints.rs` 中的版本化 state root。测试使用 `tests/plugin_state_migration_tests.rs`；该文件是本任务的原定测试目标，不另起名称。
- 状态对象是有界 canonical JSON，先持久化再以 root revision CAS 发布；run binding 固定该 run 可见的 root revision，session 切换 schema 前取得既有 session maintenance lease 并等待该 session 旧 run terminal。
- 纯迁移是 manifest `state.migration.entry` 指向的同包 RSS entry，仅允许 `json`/`bytes` 与包内模块；生成器与 `canonical` schema 同步。`state::read`/`state::write` 复用 workspace effect 声明与 sealed Native pin，不新增 effect kind。
- RED：无 inverse 的破坏性迁移不能声称可 graph rollback。旧 run 不观察新 schema。迁移崩溃不切换 active ref。迁移入口若执行文件、网络或 SQL，则拒绝。
- GREEN：纯迁移、新状态对象、session 维护 lease 和 checkpoint 兼容检查。
- Gate：`cargo test --locked --test plugin_state_migration_tests`。

### M5：热重载、回退与 tool 包接入

**T13 原子激活、回退和 GC**

- 维护 `src/plugins/control_store.rs`、`tests/plugin_hot_reload_tests.rs`。
- RED：两个管理请求同 generation 只有一个成功。回退 generation 递增。旧 run 固定旧图。引用对象不能删除。patch 版本新增 effect、扩大 scope 或降低 recovery 保证时不得自动激活。
- GREEN：候选图准备、权限 diff、CAS 激活、可审计撤销和保留策略。
- Gate：`cargo test --locked --test plugin_hot_reload_tests`。

**T14 tool 包的图接入**

首期仅一个 AcceptedPublisher、ToolOnly、stateless tool 链接一个纯 leaf library，以现有 read_file 的真实授权读取→library 字符串处理→原提交为交付行为。library 单源文件、无依赖/状态/capabilities/direct/delegated effect，独立纯编译，string 输入/输出；组合闭包统一计入既有预算。复用 prepare/closed_bundle/Program/pin，保留静态工具路由，仅窄化新拓扑/catalog并同步支持既有 graph_revoke。plugin 调用继续拒绝，不迁移全部工具。

新拓扑 checkpoint/restore 首期明确返回既有 typed 不支持错误，原无边图能力保持。后续分别扩多库、单层 stateless child、新拓扑 checkpoint/restore、stateful child；只有 stateful child 依赖已接受 T12。首期真实 prepare/pin/read/library结果/commit、A/B pin/replay和直接安全负控通过即停止，不将后续迭代算作隐藏尾项。首期不表示 T07 正式调用或 T14 全量接入完成。

**当前实施范围（六名称 captured callable 路由）**

上述单 `read_file`＋纯 leaf 是首期历史停点，其中“保留静态工具路由”已被本轮范围取代。已接受的一/二纯 leaf、S1 stateless child、S2 stateful child/restore 生产形状保持有效，本轮不重写。

本轮只改 `rss/tools/dispatch.rss`：包内声明式 name→RSS callable 表覆盖六个现有名称，`dispatch`、`invoke_prepared` 与审批前预检共用同一张表。表、单一 `ToolOnly` 根、`invoke_prepared` entry、六个 schema 与描述顺序、registry identity 来源、Native `tool_prepare`/`tool_commit`/pin 均不变；registry 命中但无 route 时在 Native prepare/effect 前 fail closed，不回落任何默认执行器。六条工具按现有真实支持模式验证。`process_control` 与 `terminal.background=true` 的 managed 行为按 5.4 的当前生命周期契约实现，不再作为整体 typed 拒绝。

验收状态：六个工具按当前真实支持模式完成 managed 全行为资格；同一 captured callable 表的 A/B 固定、文件与进程的 admission、发布、配额、撤销、cleanup、restart、deadline、取消和 ENOSPC 负控已有执行证据。一/二纯 leaf、S1 stateless caller→callee 与 S2 stateful child 的 checkpoint/restore 已完成准入范围内的恢复验证。第三 leaf、多 callee、任意拓扑、逐名称 A/B 全交叉组合及 OS 隔离不属于当前验收范围。

保留图加载 tools 所需的内置包、manifest、exports 和 library 依赖。不迁移无关业务模块。

- 内置 tool/library 包进入插件 store，并由 graph resolve、load、pin。
- 不修改 `rss/agent/main.rss`、`rss/agent/guardian.rss`、`rss/agent/compact.rss`、`rss/agent/provider_runtime.rss`、`rss/llm/provider_dispatch.rss`、`src/prompt/coding.rs`、`src/runtime/delivery.rs` 来安装新的可替换策略。这些文件的既有语义保持不变。
- `harness_selection = ToolOnly` 是本任务的执行模式。`ContextPrompt` 只保持 lock 可读和可校验。
- RED：替换或 pin tool 包不改变 Native grant、durable 事件身份、固定工具 schemas、秘密边界和停止行为。纯 library 不能获得 capability。
- 不把 `tests/prompt_tests.rs` 或 `tests/codex_responses_codec_tests.rs` 作为本任务验收。`tests/agent_loop_tests.rs` 只作为内置循环未被改写的回归。
- Gate：`cargo test --locked --test plugin_graph_tests --test tools_pin_production_ab --test tools_pin_invoke_tracer`。

### M6：管理 API 与范围内端到端测试

**T15 插件、工作区与 effect 管理 API**

- 已注册的 effect 查询和 workspace checkpoint/restore 保持现有授权。继续用 `tests/effect_admin_api_tests.rs`、`tests/managed_checkpoint_api_tests.rs`。
- 第 11 节尚未注册的 graph 管理、branch 和 publish 接口仍在本任务内。图管理测试目标保持 `tests/plugin_admin_api_tests.rs`。不另起测试名。
- 修改 `src/gateway/api_server.rs` 以注册上述已列 route。工作区传输继续在 `src/gateway/workspaces.rs`。图管理传输放在 `src/gateway/plugins.rs`。publish 实现位于 `src/service/managed_publications.rs`。不修改 `src/cli.rs` 来增加管理命令。不在 `src/config.rs` 增加 tenant 配置。
- RED：普通 run token 不可激活插件。跨 workspace、跨 branch 越权失败。冲突返回 409。不存在和无权的对象不泄露私有路径。
- GREEN：typed 管理请求、现有 owner 授权、effect/checkpoint/publication 响应。
- Gate：`cargo test --locked --test plugin_admin_api_tests --test effect_admin_api_tests --test managed_checkpoint_api_tests`。

**T16 范围内 HTTP 链路**

既有无边拓扑已接受场景保留。tool＋library 的首期历史验收限于真实读取、library 结果、固定图与撤销/停止控制，当时以 typed 拒绝隔离未启用的 checkpoint/restore。当前准入的一/二纯 leaf、S1 stateless child、S2 stateful child 已补齐对应 checkpoint/restore 链路与捕获图、不可变根、撤销和历史保持验证；后续不以首期 typed 拒绝描述当前支持能力。

- 测试目标保持 `tests/plugin_effect_api_e2e_tests.rs`。不另起名称。
- 从真实 socket 上的现有 `POST /api/sessions`、`POST /v1/runs` 发起。禁止用内部 SDK 代交后把 SSE 接收等同于 API 入口验证。
- 可以复用 `tests/support/live_http_delivery.rs` 的现有 HTTP 支撑。不改 delivery projection，不改 provider 协议，不把该文件的修改当作 delivery 重写验收。
- 场景：A 图 run 对托管工作区写入，checkpoint，激活 B，A run 继续使用 A，新 run 使用 B，恢复 checkpoint 到新分支，回退默认图。HTTP 查询 graph pin、effects 和既有 messages。既有消息记录与 durable 记录保持一致。该检查不构成 delivery projection 重写验收。
- 使用确定性 provider fixture、真实工具和现有 bounded process 后端。不跑真实外网，不使用真实用户数据，不把 OS 隔离负控当作通过条件。
- crash、越权和资源回收负控仍须执行。跳过这些负控不能记为通过。
- Gate：`cargo test --locked --test plugin_effect_api_e2e_tests`。不要求 `tests/codex_access_live_e2e_tests.rs` 的真实模型用例。

---

## 13. 必须覆盖的测试矩阵

### 插件与版本

- 安装重复、损坏包、发布者授权失败、依赖缺失、冲突、循环、契约不兼容。
- 仓库 YAML schemas 自身合法。本地 refs 可解析。示例和负例与实际解析器一致。类型或 effect 契约变更而 schema 未更新时 CI 失败。生成文件无漂移且被版本控制。
- effect 声明缺失、纯入口伪装、direct/delegated 边界、传递 effect 漏报、未知 host effect、非法 recovery、版本升级 effect 扩张，以及 runtime 在 effect 发生前拒绝。
- Native imports 越权、跨包直接 import 绕过、插件 ID 与 graph ID 伪造。
- A/B 并存、并发 activation、rollback 后 generation 仍递增、重启恢复、缺包、GC 与缓存容量。
- 源目录在准备后改变，已准备图仍只执行原始已捕获源码。旧 VM owner 资源不可在新 VM 使用。

### 文件、进程与恢复

- 创建、修改、删除、rename、空目录、受限 symlink/hardlink 及超额文件树。超额使用现有树上限，不提高上限。
- terminal 的超时、取消、输出预算和磁盘不足，使用现有 bounded process 后端和 fixture。不把宿主哨兵逃逸、namespace、seccomp 或 cgroup 负控列为验收。
- 文件工具写入后，terminal 立即读取同一 view。terminal 写入后，RSS 文件读取返回同一 view。
- checkpoint 后修改再 restore，受控树与已覆盖插件状态一致。不能恢复已撤销权限。
- 关键 FS 和 SQLite publication 崩溃点。receipt 已存在时不重复 effect。未知状态不报成功。
- 不改变 global suite concurrency；不改变 harness 默认 deadline，执行中不延长 D、不重置时钟、不弱化取消断言，也不使用 retry-until-pass 使测试通过。四个只读 468 轮次沿用已授权的 fixture 初始 10s，独立 2s 时钟不变。

### API 与外部 effect

- 401/403、409 CAS conflict、既有 admission 状态、实际 SSE 完成、消息查询、graph 查询、effect 查询。
- rollback 不删除已经发出的正文。既有 outbox 继续使用该 run 已固定的记录。消息 ID、seq 和最终正文与既有数据库投影一致。不为此重写 delivery。
- 模型调用用量不随 checkpoint 恢复清零。远端 effect 和进程外部副作用标为未撤销。
- 测试不读取真实凭据，不访问真实外网，不使用真实用户数据。

实现阶段运行上文具名 targets，并保持现有 lease 的 target、TMP、offline 和 jobs 设置。最终执行与变更范围相应的 `cargo fmt --all --check`、`cargo clippy --locked --all-features --all-targets -- -D warnings` 和 `git diff --check`。是否执行全 workspace suite，按变更范围及既有规则决定。no-run 或零选中测试不计为通过。

---

## 14. 上线顺序与验收门

1. **G1 插件基础完成**：manifest、resolver、compiler、load、lock、精确回放和 run pinning 通过。仅内置受信 tool/library 包可用。
2. **G2 托管执行完成**：文件工具与 terminal 的统一 view、现有进程后端上的取消和预算、journal recovery 通过。不含 OS 越权负控。
3. **G3 本地托管回退完成**：checkpoint、branch、插件状态迁移、epoch 撤销与 crash 矩阵通过。外部副作用仍标为未撤销。
4. **G4 插件热重载完成**：原子激活、旧图与新图并存、回退兼容和 retention 通过。不含 main、Guardian、prompt、provider codec 或 delivery 迁移。
5. **G5 对外功能完成**：实际 HTTP admission、工具 effects、checkpoint/restore、graph rollback，以及 effect 查询通过。不含 delivery projection 或 provider 协议重写。

可独立使用的首个切片是：内置 tools 的版本化 graph，加上托管工作区 checkpoint。管理 API 按第 11 节补齐。不把第三方 native 进程插件作为可用功能开放。

存储配额不足时返回现有 quota 错误。不得通过直接宿主写入、绕过审批、重置 deadline 或减弱断言来通过验收。

---

## 15. 设计自检

- 插件图模型、manifest、exports、library 依赖、resolve、compiler、load、pin、closure、cache、activation、hot reload、persistence 和对应 runtime 执行仍在计划内。
- Tools 调用虚拟化、effect 声明、admission、默认拒绝、原 Native 授权、root、clock、取消、迟到批准不执行，仍在计划内。
- 托管工作区和插件状态的 checkpoint、restore、branch、publish、replay、effect 账本查询及对应管理接口仍在计划内。
- `PLUGIN_KINDS` 仍只有 `library` 和 `tool`。effect catalog 和 recovery 规则不扩大。现有包、闭包、树和 lineage 上界不提高。
- `ContextPrompt` 保留为图 lock 变体。它不构成新的 prompt、context 或 Guardian 实现任务。
- catalog 中的 `model.request`、`delivery.send`、`remote.write`、`event.emit`、`secret.use` 只用于声明和拒绝。它们不构成新子系统。
- 内置 agent、reviewer、provider、默认 prompt、compaction 和 delivery 语义不改。
- 不承诺任意进程、活 FD 或外部副作用可以快照或回滚。导入只有 `ordinary_copy`。
- 不实施 OS namespace、OCI、cgroup、seccomp 或调试器隔离。
- 不新增 admin/tenant 系统，不新增未列出的 route、limit 或 SDK API，不开兼容版本 lane。
- 计划存在不表示上述能力已经交付。
