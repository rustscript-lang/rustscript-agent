# rustscript-agent Gateway Review Findings

**Review baseline:** the complete standalone project history from `274d549` through `e550827b91358dee25b0c1438727d5ede199e0e1`.

**Review mode:** read-only review by `gpt-5.6-sol` with high reasoning. No tests or files were run/changed by the reviewer. The main agent owns the follow-up implementation.

## Blocking findings and directions

1. **SSE event payload does not match Hermes/Yahu consumption**
   - `src/gateway.rs:295-305,1142-1151`.
   - `delta`, `output`, and `usage` are nested under `data`, while the consumer reads top-level fields.
   - Define fixed Hermes-compatible event fixtures and emit the expected top-level shape. Verify delta accumulation, completion, and terminal events with the real consumer parser.

2. **Stop/interrupt does not stop the underlying run**
   - `src/gateway.rs:841-863,1017-1154`.
   - State is changed without a task handle or cancellation token; workers can continue and write after cancellation.
   - Store a run task handle and cancellation token. Stop transitions to `stopping`, signals the worker, and lets the worker emit one terminal event after confirmed exit.

3. **Several advertised compatibility routes are placeholders**
   - `session_chat_handler`, `run_job_handler`, `interrupt_subagent_handler`.
   - Reuse one executor/session/history/model-selection path, or return an explicit unsupported error and remove the compatibility claim until implemented.

4. **Concurrency, budgets, event history, and run records are unbounded**
   - Add global and per-session limits, queue/429 semantics, run deadlines, VM budgets, event/run TTLs, and shutdown drain/cancel behavior.

5. **Authentication and port configuration fail open**
   - `AgentGatewayConfig`, auth middleware, gateway binary configuration.
   - Require a sufficiently strong bearer secret in production, use constant-time comparison, reject invalid configuration, and keep empty ports distinct from unrestricted ports. Add CORS/security headers and the Hermes error envelope.

6. **Synchronous persistence blocks Tokio and can report success after a failed write**
   - Move SQLite/full serialization to a database actor or blocking worker; persist only after mutating operations; return success only after durable commit; model runs/events for restart recovery.

7. **Request fields and VM output are not mapped to the public contract**
   - Preserve conversation history, model/provider/instructions, structured input and metadata. Convert VM values through an explicit JSON projection rather than Debug formatting.

8. **Validation, error envelope, dependencies, and roadmap need alignment**
   - Add strict ID/source/title/input/job validation and consistent status/error mapping; use published or pinned sibling dependencies; correct binary/package names and verification commands in README/plan.

## Implementation order

1. Lock the Hermes/Yahu API fixture and SSE event model.
2. Make run lifecycle cancellation authoritative.
3. Implement or demote placeholder routes.
4. Add authentication, limits, deadlines, persistence actor, and recovery.
5. Align request/response projection, dependencies, README, and roadmap.
