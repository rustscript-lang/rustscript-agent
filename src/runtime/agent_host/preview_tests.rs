//! Round-8 Guardian preview tests: the closed `PreviewArguments` projection and
//! the `ask` path that reads it.
//!
//! The round-7 text carriers stopped `dispatch` from filling an `arguments` map,
//! so `guardian::action_preview` had nothing to render and every write/execute
//! approval failed closed with `approval_preview_unavailable`. These tests drive
//! the boundary the way production does: a real RSS source compiled against the
//! published agent catalog, a real restricted registry, a real VM, real host
//! state. Nothing is asserted against the adapter in isolation, and the ask-path
//! case runs the real `rss/agent/main.rss` loop.

use super::*;
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, VmStatus,
    compile_source_at_path_with_flavor_and_options, compile_source_with_flavor_and_options,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CANCEL: Duration = Duration::from_secs(30);
const MIB: usize = 1024 * 1024;

/// A clock that starts at 1 s instead of the unix epoch, so the lifecycle's
/// deadline is in the future for the whole test.
struct FixtureClock {
    now_ms: Mutex<u64>,
}

impl FixtureClock {
    fn new(now_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            now_ms: Mutex::new(now_ms),
        })
    }
}

impl crate::capabilities::LifecycleClock for FixtureClock {
    fn now_ms(&self) -> u64 {
        *self.now_ms.lock().expect("clock")
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// In-memory durable tool lifecycle: this test never needs a real replay store,
/// only a lifecycle that admits a fresh (non-replayed) call.
#[derive(Default)]
struct MemoryDurable {
    results: Mutex<HashMap<String, JsonValue>>,
}

impl crate::capabilities::DurableToolLifecycle for MemoryDurable {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), crate::capabilities::LifecycleError> {
        Ok(())
    }

    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), crate::capabilities::LifecycleError> {
        Ok(())
    }

    fn replay_result(
        &self,
        _run_id: &str,
        call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<JsonValue>, crate::capabilities::LifecycleError> {
        Ok(self.results.lock().expect("results").get(call_id).cloned())
    }

    fn commit_started(
        &self,
        _record: &crate::capabilities::DurableStarted,
    ) -> Result<(), crate::capabilities::LifecycleError> {
        Ok(())
    }

    fn commit_result(
        &self,
        call_id: &str,
        result: &JsonValue,
    ) -> Result<JsonValue, crate::capabilities::LifecycleError> {
        self.results
            .lock()
            .expect("results")
            .insert(call_id.to_string(), result.clone());
        Ok(result.clone())
    }

    fn interrupt(&self, _call_id: &str) -> Result<(), crate::capabilities::LifecycleError> {
        Ok(())
    }
}

/// The real capability lifecycle the ask path needs: `tool_replay` refuses to
/// run without one, so a fixture here is the difference between "the preview
/// works" and "the product path actually reaches the approval request".
struct LifecycleFixture {
    lifecycle: crate::capabilities::CapabilityLifecycle,
    owner: crate::capabilities::CapabilityOwner,
    root: std::path::PathBuf,
}

impl Drop for LifecycleFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl LifecycleFixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "preview-approval-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("workspace root");
        let owner = crate::capabilities::CapabilityOwner::new("profile-1", "session-1", "run-1")
            .expect("capability owner");
        let lifecycle = crate::capabilities::CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity("registry-1")
            .workspace(&root)
            .limits(crate::capabilities::LifecycleLimits {
                max_tool_calls: 8,
                max_output_bytes: 64 * 1024,
                max_summary_bytes: 256,
            })
            .deadline_ms(60_000)
            .clock(FixtureClock::new(1_000) as Arc<dyn crate::capabilities::LifecycleClock>)
            .tokens(Arc::new(crate::capabilities::UuidIssuer)
                as Arc<dyn crate::capabilities::TokenIssuer>)
            .durable(Arc::new(MemoryDurable::default())
                as Arc<dyn crate::capabilities::DurableToolLifecycle>)
            .approval(Arc::new(crate::capabilities::AllowAllApproval)
                as Arc<dyn crate::capabilities::ApprovalGate>)
            .cancellation(Arc::new(crate::capabilities::NeverCancelled)
                as Arc<dyn crate::capabilities::CancellationFlag>)
            .generation(1)
            .build()
            .expect("capability lifecycle");
        Self {
            lifecycle,
            owner,
            root,
        }
    }
}

const PROBE: &str = r#"
use agent;

/// The one call `guardian::action_preview` makes: the tool's arguments text in,
/// the closed projection out.
pub fn arguments(text: string) -> AgentPreviewArguments {
    agent::preview_arguments(text)
}

pub fn run() -> map {
    { ok: true }
}
"#;

fn probe_vm(provider: Arc<dyn AgentProviderHost>) -> Vm {
    let catalog = agent_host_catalog();
    let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone());
    let compiled = compile_source_with_flavor_and_options(PROBE, SourceFlavor::RustScript, options)
        .expect("compile the preview-arguments probe against the published catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    register_agent_host_functions(&mut registry, catalog.as_ref())
        .expect("register the published agent descriptors");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted registry");
    vm.host_context().set_module_state(AgentHostState {
        child_call: None,
        child_read: None,
        provider,
        cancellation: RunCancellation::with_timeout(CANCEL),
        sleeps: Arc::new(Mutex::new(SleepLog::default())),
        skip_sleep: true,
        metrics: None,
        lifecycle: None,
        capability_owner: None,
        filesystem: None,
        processes: None,
        artifacts: None,
        leases: Arc::new(Mutex::new(HashMap::new())),
        control_hook: None,
        pinned_tool: None,
        allow_stateless_pin: false,
        expected_call: None,
        plugin_state_call: None,
        provider_arguments: Default::default(),
    });
    assert!(matches!(
        vm.run().expect("probe root frame"),
        VmStatus::Halted
    ));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let callable = vm
        .resolve_exported_callable(name)
        .unwrap_or_else(|_| panic!("export {name}"));
    vm.invoke_callable(callable, args)
        .unwrap_or_else(|error| panic!("invoke {name}: {error}"))
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected a map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn text_field(value: &Value, name: &str) -> String {
    match field(value, name) {
        Value::String(text) => text.as_str().to_string(),
        other => panic!("{name} is not a string: {other:?}"),
    }
}

/// One logical `Option` slot as the guest sees it: `None`, or the payload.
fn option_slot(value: &Value, name: &str) -> Option<Value> {
    let slot = field(value, name);
    let (some, payload) = rustscript_vm::option::payload(&slot)
        .unwrap_or_else(|error| panic!("{name} is not one canonical Option carrier: {error}"));
    if !some {
        return None;
    }
    Some(payload.cloned().expect("Some carries a payload"))
}

fn arguments(text: &str) -> Value {
    let mut vm = probe_vm(Arc::new(ScriptedProvider::new()));
    invoke(&mut vm, "arguments", &[Value::string(text)])
}

#[test]
fn preview_arguments_projects_the_write_call_into_named_options() {
    let projected = arguments(r#"{"path":"notes.txt","content":"hello","unknown_key":true}"#);

    assert_eq!(field(&projected, "ok"), Value::Bool(true));
    assert_eq!(field(&projected, "code"), Value::string(""));
    assert_eq!(
        option_slot(&projected, "path"),
        Some(Value::string("notes.txt"))
    );
    assert_eq!(
        option_slot(&projected, "content"),
        Some(Value::string("hello"))
    );
    // Everything the write call did not send stays a `None` carrier, so the
    // preview can distinguish "absent" from "present but empty".
    for absent in [
        "old_string",
        "new_string",
        "replace_all",
        "argv",
        "stdin",
        "cwd",
        "timeout_ms",
        "max_output_bytes",
        "background",
        "action",
        "process_id",
        "data",
        "offset",
        "limit",
    ] {
        assert_eq!(option_slot(&projected, absent), None, "{absent}");
    }
    // An unknown tool argument is ignored: the projection is closed, it does
    // not police the tool's own argument set.
    assert!(
        !matches!(&projected, Value::Map(entries) if entries
            .iter()
            .any(|(key, _)| matches!(key, Value::String(name) if name.as_ref() == "unknown_key"))),
        "only declared fields cross: {projected:?}"
    );
}

#[test]
fn preview_arguments_projects_the_terminal_and_process_fields() {
    let terminal = arguments(
        r#"{"argv":["echo","hi"],"cwd":"/work","timeout_ms":1500,"background":true,"stdin":""}"#,
    );
    assert_eq!(field(&terminal, "ok"), Value::Bool(true));
    match option_slot(&terminal, "argv").expect("argv present") {
        Value::Array(items) => {
            assert_eq!(items.len(), 2);
        }
        other => panic!("argv is not an array: {other:?}"),
    }
    assert_eq!(option_slot(&terminal, "cwd"), Some(Value::string("/work")));
    assert_eq!(option_slot(&terminal, "timeout_ms"), Some(Value::Int(1500)));
    assert_eq!(
        option_slot(&terminal, "background"),
        Some(Value::Bool(true))
    );

    let process = arguments(r#"{"action":"poll","process_id":"p-1","limit":5}"#);
    assert_eq!(option_slot(&process, "action"), Some(Value::string("poll")));
    assert_eq!(
        option_slot(&process, "process_id"),
        Some(Value::string("p-1"))
    );
    assert_eq!(option_slot(&process, "limit"), Some(Value::Int(5)));
    assert_eq!(option_slot(&process, "offset"), None);
}

#[test]
fn preview_arguments_refuses_malformed_text_instead_of_publishing_empty_options() {
    // A refusal, never an empty projection that would render as "the action had
    // no arguments".
    for (text, code) in [("", "invalid_request"), ("not json", "invalid_request")] {
        let projected = arguments(text);
        assert_eq!(
            field(&projected, "ok"),
            Value::Bool(false),
            "refused: {text:?}"
        );
        assert_eq!(field(&projected, "code"), Value::string(code), "{text:?}");
        assert_eq!(option_slot(&projected, "path"), None);
    }

    // The projected shape is closed: a JSON array is not a tool argument object.
    let array = arguments("[1,2]");
    assert_eq!(field(&array, "ok"), Value::Bool(false));
    assert_eq!(field(&array, "code"), Value::string("invalid_request"));

    let oversized = format!("{{\"content\":\"{}\"}}", "a".repeat(4 * MIB + 1));
    let projected = arguments(&oversized);
    assert_eq!(field(&projected, "ok"), Value::Bool(false));
    assert_eq!(
        field(&projected, "code"),
        Value::string("payload_too_large")
    );
}

#[test]
fn preview_arguments_refuses_a_wrongly_typed_field_by_name() {
    for (text, field_name) in [
        (r#"{"path":7}"#, "path"),
        (r#"{"content":["a"]}"#, "content"),
        (r#"{"replace_all":"yes"}"#, "replace_all"),
        (r#"{"timeout_ms":"fast"}"#, "timeout_ms"),
        (r#"{"argv":["ok",1]}"#, "argv"),
        (r#"{"process_id":true}"#, "process_id"),
    ] {
        let projected = arguments(text);
        assert_eq!(field(&projected, "ok"), Value::Bool(false), "{text}");
        assert_eq!(
            field(&projected, "code"),
            Value::string("preview_arguments_invalid"),
            "{text}"
        );
        let message = text_field(&projected, "message");
        assert!(
            message.contains(field_name),
            "the refusal names the offending field: {message}"
        );
    }
}

/// A provider host that answers provider turns from a script and records the
/// durable approval commands the loop issues, so the ask path can be observed
/// from the host side as well as from the guest's decision.
struct AskPathProvider {
    provider: Arc<ScriptedProvider>,
    request_answer: JsonValue,
    resolve_answer: JsonValue,
    seen: Mutex<Vec<(String, JsonValue)>>,
}

impl AgentProviderHost for AskPathProvider {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue {
        self.provider.call(request, cancellation)
    }

    fn approval_storage(
        &self,
        operation: &str,
        payload: &JsonValue,
        _cancellation: &RunCancellation,
    ) -> JsonValue {
        self.seen
            .lock()
            .expect("approval log")
            .push((operation.to_string(), payload.clone()));
        match operation {
            "request" => self.request_answer.clone(),
            _ => self.resolve_answer.clone(),
        }
    }
}

fn main_loop_vm(provider: Arc<dyn AgentProviderHost>, fixture: &LifecycleFixture) -> Vm {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss");
    let source = std::fs::read_to_string(&path).expect("read the real agent main");
    let catalog = agent_host_catalog();
    let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone());
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        options,
    )
    .expect("compile the real agent main against the published catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    for builtin in crate::runtime::host_compose::RESTRICTED_STANDARD_BUILTINS {
        registry.allow_builtin(builtin).expect("admit builtin");
    }
    register_agent_host_functions(&mut registry, catalog.as_ref())
        .expect("register the published agent descriptors");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted registry");
    vm.host_context().set_module_state(AgentHostState {
        child_call: None,
        child_read: None,
        provider,
        cancellation: RunCancellation::with_timeout(CANCEL),
        sleeps: Arc::new(Mutex::new(SleepLog::default())),
        skip_sleep: true,
        metrics: None,
        lifecycle: Some(Arc::new(fixture.lifecycle.clone())),
        capability_owner: Some(fixture.owner.clone()),
        filesystem: None,
        processes: None,
        artifacts: None,
        leases: Arc::new(Mutex::new(HashMap::new())),
        control_hook: None,
        pinned_tool: None,
        allow_stateless_pin: true,
        expected_call: None,
        plugin_state_call: None,
        provider_arguments: Default::default(),
    });
    assert!(matches!(
        vm.run().expect("main root frame"),
        VmStatus::Halted
    ));
    vm
}

/// The approval-request row the loop writes, echoed back by the storage host.
fn request_answer() -> JsonValue {
    json!({
        "ok": true,
        "result": {
            "columns": [
                "id", "run_id", "session_id", "tool_call_id", "tool_name",
                "arguments_json", "risk_class", "state", "decision_scope",
                "one_time", "requested_at_ms", "expires_at_ms",
                "resolved_at_ms", "resolver", "decision_reason"
            ],
            "rows": [[
                "guardian-approval:run-1:call-1", "run-1", "session-1", "call-1",
                "write_file", "{}", "write", "pending", "single_call", 1, 0, 0,
                null, null, null
            ]]
        }
    })
}

#[test]
fn write_call_with_text_arguments_builds_a_preview_and_enters_approval() {
    let scripted = Arc::new(ScriptedProvider::new());
    scripted.push_envelope(json!({
        "ok": true,
        "response": {
            "text": "",
            "tool_calls": [{
                "id": "call-1",
                "name": "write_file",
                "arguments_json": "{\"path\":\"notes.txt\",\"content\":\"APPROVAL_SENTINEL\"}"
            }]
        }
    }));
    scripted.push_envelope(json!({
        "ok": true,
        "response": {
            "text": "{\"outcome\":\"allow\",\"risk_level\":\"low\",\"user_authorization\":\"medium\",\"rationale\":\"the user asked for this file\"}"
        }
    }));
    let provider = Arc::new(AskPathProvider {
        provider: scripted.clone(),
        request_answer: request_answer(),
        resolve_answer: json!({"ok": true, "result": {"rows_affected": 1}}),
        seen: Mutex::new(Vec::new()),
    });
    let fixture = LifecycleFixture::new("ask");
    let mut vm = main_loop_vm(provider.clone(), &fixture);

    let context = super::json_to_vm_value(&json!({
        "profile_id": "profile-1",
        "session_id": "session-1",
        "run_id": "run-1",
        "metadata": {"registry_identity": "registry-1"},
        "provider": "openai",
        "model": "request-model",
        "input": {"message": "write the file notes.txt"},
        "system_prompt": "run constraints",
        "coding_system_prompt": "coding prompt",
        "config": {"max_retries": 0},
        "limits": {"max_turns": 3, "max_tool_calls": 2},
        "approval_settings": {"write": "ask", "reviewer": "guardian", "required": true},
        "tools": [{"name": "write_file", "risk_class": "write"}]
    }));
    let decision = invoke(&mut vm, "run", &[context]);

    // The durable approval request is the observable proof that the action
    // entered the approval path instead of failing closed at the preview.
    let seen = provider.seen.lock().expect("approval log").clone();
    let request = seen
        .iter()
        .find(|(operation, _)| operation == "request")
        .map(|(_, payload)| payload.clone())
        .unwrap_or_else(|| {
            panic!("no approval request was persisted: {seen:?} decision: {decision:?}")
        });
    let preview = request["owner_preview"]
        .as_str()
        .unwrap_or_else(|| panic!("owner_preview is not text: {request}"));
    assert!(
        preview.starts_with("write_file "),
        "preview must describe the write action: {preview:?}"
    );
    assert!(
        preview.contains("\"path\":\"notes.txt\""),
        "preview must name the target path: {preview:?}"
    );
    assert!(
        preview.contains("content_bytes"),
        "preview must report the bounded content size: {preview:?}"
    );
    assert!(
        !preview.contains("APPROVAL_SENTINEL"),
        "file content never reaches the owner preview: {preview:?}"
    );

    // It was not the preview that stopped the action: neither the decision
    // reason nor the typed error code is the fail-closed preview refusal.
    let reason = text_field(&decision, "reason");
    assert_ne!(
        reason, "approval_preview_unavailable",
        "the preview must not fail closed for a text-carried write call: {decision:?}"
    );
    let error = field(&decision, "error");
    assert_ne!(
        text_field(&error, "code"),
        "approval_preview_unavailable",
        "the preview must not fail closed for a text-carried write call: {decision:?}"
    );
    assert_eq!(
        field(&decision, "tool_calls_used"),
        Value::Int(1),
        "the write call reached the dispatch boundary: {decision:?}"
    );
}
