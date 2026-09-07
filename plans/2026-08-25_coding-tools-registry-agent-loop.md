# Coding Tools, Registry, Dispatch, and Agent Loop Implementation Plan

**Goal:** 完成 `rustscript-agent` 首个可实际修改代码并运行验证命令的 serial coding agent 闭环。

**Architecture:** RSS 继续拥有 serial agent policy 与 provider protocol mapping；native Rust embedding 拥有工具注册、权限、OS effects、事件提交和 durable state。`RunContext.tool_schemas` 从 registry 快照生成，RSS loop 依次执行 provider call、tool dispatch、tool-result message 回填和下一轮 provider call，最终由 `AgentService` 提交 terminal state。

**Tech Stack:** Rust 2024、RustScript RSS、Axum/Tokio、SQLite durable store、OpenAI Chat adapter、RustScript custom host extensions、RustScript core bounded process/filesystem APIs。

---

## 1. Scope boundary

### In scope

- Coding tools：`read_file`、`search_files`、`write_file`、`patch`、`terminal`、`process`。
- Tool descriptor registry、toolset selection、JSON Schema validation、risk class。
- Tool dispatch、tool output normalization、bounded output、typed errors。
- OpenAI Chat 路径上的完整 serial agent loop。
- system prompt 最小 coding harness：workspace、repo instructions、执行纪律、完成前验证。
- durable assistant/tool messages、tool lifecycle events、stop/deadline propagation。
- 一个真实仓库 E2E：读文件、修改、运行测试、给出最终回答。

### Out of scope

- OpenAI-compatible `chat/completions` 或 Responses API。
- Anthropic adapter 与更多 provider。
- skills/memory/delegation/cron 完整产品能力。
- browser、web、image、voice tools。
- parallel tool execution；首版严格 serial。

## 2. Tool contracts

### 2.1 Common result envelope

每个工具返回：

```json
{
  "ok": true,
  "content": "model-visible text",
  "data": {},
  "error": null,
  "truncated": false,
  "artifacts": []
}
```

失败返回 `ok=false`，`error` 至少包含 `code` 与 `message`。模型可见输出和 durable event payload 都必须满足大小上限；大输出保存到受限 artifact store，并在 `artifacts` 中给出 opaque id。

### 2.2 Initial tools

- `read_file(path, offset?, limit?)`
- `search_files(pattern, path?, target?, file_glob?, limit?, offset?)`
- `write_file(path, content)`
- `patch(path, old_string, new_string, replace_all?)`
- `terminal(argv, cwd?, timeout_ms?, max_output_bytes?, stdin?)`
- `process(action, process_id, data?, timeout_ms?, offset?, limit?)`

`terminal` 接受 argv array，不接受 shell command string。若未来需要 shell，单独注册高风险工具，首版不加入。

## 3. Native registry and execution tasks

### Task 1: Freeze registry and descriptor contracts

**Files:**
- Create: `src/tools/mod.rs`
- Create: `src/tools/registry.rs`
- Create: `src/tools/types.rs`
- Modify: `src/domain.rs`
- Modify: `src/lib.rs`
- Test: `tests/tool_registry_tests.rs`
- Test: `tests/domain_contract_tests.rs`

**Steps:**

1. 先写失败测试，固定 descriptor 顺序、唯一名称、toolset、risk class、schema 与 registry hash。
2. 将 `ToolDescriptor` 作为唯一公开描述类型；registry entry 额外持有 native executor。
3. schema 在注册阶段完成自校验；非法 schema 或重复名称使构造失败。
4. registry 快照不可在 run 中途变化。
5. 首版 toolset 仅包含 `coding` 与 `process`。

### Task 2: Populate RunContext from registry

**Files:**
- Modify: `src/service.rs`
- Modify: `src/config.rs`
- Test: `tests/service_tests.rs`
- Test: `tests/agent_loop_tests.rs`

**Steps:**

1. 将当前空 `tool_schemas` 替换为 session/run 启动时的 registry snapshot。
2. 将 toolset hash 写入 session/run metadata，并在 resume 时核对。
3. `provider_options` 从解析后的 provider profile 注入，不再固定为空 map。
4. limits 增加 `max_turns`、`max_tool_calls`、`max_tool_output_bytes`、workspace root。
5. 测试同一 run 的 tool schema 与 hash 在全生命周期不变。

### Task 3: Implement confined file tools

**Files:**
- Create: `src/tools/files.rs`
- Create: `src/tools/artifacts.rs`
- Modify: `src/tools/mod.rs`
- Modify: `src/config.rs`
- Test: `tests/file_tool_tests.rs`

**Steps:**

1. 先写 path traversal、symlink escape、offset/limit、UTF-8、binary、输出超限测试。
2. 所有路径相对 workspace root 解析，并通过 core root-confined helper 打开。
3. `search_files` 使用 Rust library API 遍历与匹配，不启动 shell；限制文件数、扫描字节数、深度和 wall time。
4. `write_file` 使用同目录临时文件、flush、atomic replace；保留文件权限策略。
5. `patch` 要求唯一 match，除非 `replace_all=true`；返回修改摘要和 diff 预算内预览。
6. oversized result 写 artifact，模型消息只携带摘要与 artifact id。

### Task 4: Implement terminal and process tools

**Files:**
- Create: `src/tools/terminal.rs`
- Create: `src/tools/process.rs`
- Modify: `src/tools/mod.rs`
- Modify: `src/config.rs`
- Test: `tests/terminal_tool_tests.rs`
- Test: `tests/process_tool_tests.rs`

**Steps:**

1. 使用 RustScript core bounded process API；禁止回退到 `io::popen`。
2. foreground `terminal` 等待 terminal result；background 模式创建 service-owned process record。
3. `process` 支持 `poll`、`wait`、`log`、`write`、`close`、`kill`。
4. process id 绑定 profile/session/run owner，其他 owner 查询返回 typed denial。
5. stop、run deadline、session deletion 和 service shutdown 触发 process cleanup。
6. stdout/stderr 使用 bounded ring/artifact storage；API 永不返回无限输出。

### Task 5: Add argument validation and dispatch

**Files:**
- Create: `src/tools/dispatch.rs`
- Modify: `src/tools/registry.rs`
- Modify: `src/events.rs`
- Modify: `src/service.rs`
- Test: `tests/tool_dispatch_tests.rs`

**Steps:**

1. 在执行 effect 前进行 tool name lookup 与 JSON Schema validation。
2. dispatch context 包含 run/session/profile/workspace/cancellation/deadline。
3. 依次提交 `tool.requested`、`tool.started`、`tool.output`、`tool.completed` 或 `tool.failed`。
4. unknown tool、bad arguments、deadline、cancel、output overflow 均映射为 typed tool result，供模型下一轮读取。
5. effect 前后都检查 run terminal ownership，避免 stop 后继续发布事件。
6. 首版一次只执行一个 tool call；模型一轮返回多个 calls 时按原顺序执行。

## 4. Agent loop tasks

### Task 6: Replace the blocked policy skeleton with a real serial loop

**Files:**
- Modify: `rss/agent/main.rss`
- Modify: `rss/llm/harness.rss`
- Modify: `rss/llm/types.rss`
- Modify: `src/runtime/rss_runner.rs`
- Test: `tests/agent_loop_tests.rs`
- Test: `tests/provider_tests.rs`

**Steps:**

1. 保留现有 turn/retry/backoff/max-turn semantics，删除 `provider.call` 与 `tool.dispatch` blocked terminal path。
2. loop 构造 canonical `LlmRequest`，调用已选 provider adapter。
3. text-only response 形成 final answer。
4. tool-call response 顺序 dispatch；每个结果追加 canonical `tool_result` content block。
5. 完成一组 tools 后再次调用 provider。
6. `max_turns`、`max_tool_calls`、retry budget 到达上限时产生 typed run failure。
7. parallel/task 仍返回明确 unsupported。

### Task 7: Durable message and event integration

**Files:**
- Modify: `src/service.rs`
- Modify: `src/gateway/store.rs`
- Modify: `rss/storage/messages.rss`
- Modify: `rss/storage/events.rss`
- Test: `tests/storage_tests.rs`
- Test: `tests/service_tests.rs`
- Test: `tests/gateway_tests.rs`

**Steps:**

1. durable message 支持 assistant tool calls 与 tool result fields。
2. 每次 provider/tool step 在对外可见前完成 durable commit。
3. restart recovery 不重复执行已完成 effect；pending effect 采用明确 failed/cancelled reconciliation，禁止猜测成功。
4. final assistant message 与 `run.completed` 保持原子 terminal commit。
5. usage、finish reason、tool_call_id 和 parent message linkage 落库。

### Task 8: Add minimal coding system prompt builder

**Files:**
- Create: `src/prompt/mod.rs`
- Create: `src/prompt/coding.rs`
- Modify: `src/service.rs`
- Test: `tests/prompt_tests.rs`

**Steps:**

1. 注入 workspace root、平台、工具清单、输出限制与当前日期来源。
2. 从 workspace root 读取 `AGENTS.md`、`CLAUDE.md`、`.cursorrules`；使用确定性优先级与总字节预算。
3. 指示模型先读取相关文件，修改后执行目标测试，完成前检查实际输出。
4. 不自动加入 skills、memory、delegation 指令。
5. system prompt 对同一 run 固定，避免中途 schema/prompt 漂移。

### Task 9: Wire service execution and cancellation

**Files:**
- Modify: `src/service.rs`
- Modify: `src/runtime/rss_runner.rs`
- Modify: `src/runtime/delivery.rs`
- Modify: `src/metrics.rs`
- Test: `tests/service_tests.rs`
- Test: `tests/run_lifecycle_tests.rs`

**Steps:**

1. run worker 拥有 provider/tool loop 的唯一 cancellation token。
2. stop 同时中断 provider HTTP、RSS invocation 与当前 tool/process。
3. deadline 覆盖整个 run，不在每次 provider/tool call 后重置。
4. metrics 增加 model calls、tool calls、tool failures、turns 与 truncation counts；不记录工具参数原文。
5. worker 退出后确认 execution scope 与 process table 无 owner residue。

## 5. End-to-end acceptance

### Task 10: Real coding repository E2E

**Files:**
- Create: `tests/coding_agent_e2e_tests.rs`
- Create: `tests/fixtures/coding_repo/` or generate under tempdir
- Modify: `README.md`
- Modify: `docs/configuration.md`

**Scenario:**

1. temp git repo 含一个失败测试和 `AGENTS.md`。
2. scripted provider 首轮请求读取文件。
3. 第二轮请求 patch。
4. 第三轮请求运行精确测试 argv。
5. 最后一轮输出完成摘要。
6. 断言文件内容、测试 exit code、tool event 顺序、durable messages 和 final run state。
7. 再运行 stop-during-terminal 与 output-limit E2E，断言无子进程残留。

**Release gate:**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --test coding_agent_e2e_tests
```

## 6. Completion definition

本计划完成必须同时满足：

- `RunContext.tool_schemas` 有真实 coding descriptors。
- provider 能返回 tool calls。
- dispatch 会执行真实受限文件/进程操作。
- tool results 会进入下一轮模型消息。
- 模型能完成一个真实修改与测试流程。
- stop/deadline 会终止当前工具和子进程。
- durable state 可重放已发生的消息与事件。
- 全程不依赖 OpenAI-compatible 推理 API。
