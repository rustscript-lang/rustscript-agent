use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, RunCancellation,
    capabilities::{
        AllowAllApproval, CancellationFlag, CapabilityLifecycle, CapabilityOwner, DurableStarted,
        DurableToolLifecycle, LifecycleClock, LifecycleError, LifecycleLimits, ProcessCapability,
        ProcessLimits, SystemClock, UuidIssuer,
    },
};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Durable {
    results: Mutex<HashMap<String, Value>>,
    interruptions: Mutex<Vec<String>>,
    parents: Mutex<HashMap<(String, String, String), Value>>,
}
impl DurableToolLifecycle for Durable {
    fn parent_arguments(
        &self,
        run: &str,
        call: &str,
        tool: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        self.parents
            .lock()
            .unwrap()
            .get(&(run.into(), call.into(), tool.into()))
            .cloned()
            .map(Some)
            .ok_or(LifecycleError::MissingParent)
    }
    fn assert_active_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn prepare_parent(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn replay_result(&self, _: &str, call: &str, _: &str) -> Result<Option<Value>, LifecycleError> {
        Ok(self.results.lock().unwrap().get(call).cloned())
    }
    fn commit_started(&self, _: &DurableStarted) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn commit_result(&self, call: &str, value: &Value) -> Result<Value, LifecycleError> {
        self.results
            .lock()
            .unwrap()
            .insert(call.into(), value.clone());
        Ok(value.clone())
    }
    fn interrupt(&self, call: &str) -> Result<(), LifecycleError> {
        self.interruptions.lock().unwrap().push(call.into());
        Ok(())
    }
}
struct Cancel(RunCancellation);
impl CancellationFlag for Cancel {
    fn is_cancelled(&self) -> bool {
        self.0.requested().is_some() || self.0.deadline_passed()
    }
}
#[derive(Default)]
struct Issuer(Mutex<String>);
impl rustscript_agent::capabilities::TokenIssuer for Issuer {
    fn issue(&self) -> String {
        let token = UuidIssuer.issue();
        *self.0.lock().unwrap() = token.clone();
        token
    }
}

struct RootGuard(PathBuf);
impl Drop for RootGuard {
    fn drop(&mut self) {
        if self.0.exists() {
            let removed = fs::remove_dir_all(&self.0);
            if !std::thread::panicking() {
                removed.unwrap();
            }
        }
    }
}

pub struct NativeFixture {
    pub root: PathBuf,
    _root_guard: RootGuard,
    pub host: AgentHostBridges,
    pub processes: Arc<ProcessCapability>,
    pub runner: AgentRunner,
    durable: Arc<Durable>,
    issuer: Arc<Issuer>,
}

pub struct PreparedCall {
    call: String,
    tool: String,
    pub arguments: Value,
}

impl NativeFixture {
    pub fn new(run: &str) -> Self {
        let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("native-process-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root_guard = RootGuard(root.clone());
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        // Compile before starting the original lifecycle clock.
        let runner = AgentRunner::from_source(r#"
fn text(context: map, key: string) -> string {
    let value: string = context[key];
    value
}
pub fn run(context: map) -> map {
    agent_runtime::invoke_pinned_tool({
        tool_name: text(context, "tool_name"), call_id: text(context, "call_id"),
        canonical_arguments: text(context, "canonical_arguments"), canonical_input: text(context, "canonical_input"),
        run_id: text(context, "run_id"), registry_identity: text(context, "registry_identity"),
        argument_digest: text(context, "argument_digest"), risk_class: "execute", summary: text(context, "tool_name"),
        untrusted_graph_id: ""
    })
}
"#, AgentConfig::default()).unwrap();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let owner = CapabilityOwner::new("process-fixture", "session", run).unwrap();
        let durable = Arc::new(Durable::default());
        let issuer = Arc::new(Issuer::default());
        let lifecycle = Arc::new(
            CapabilityLifecycle::builder()
                .owner(owner.clone())
                .registry_identity(
                    rustscript_agent::bundled_tool_registry()
                        .unwrap()
                        .identity(),
                )
                .workspace(&root)
                .limits(LifecycleLimits {
                    max_tool_calls: 32,
                    max_output_bytes: 65536,
                    max_summary_bytes: 256,
                })
                .deadline_ms(SystemClock.now_ms() + 30000)
                .clock(Arc::new(SystemClock))
                .tokens(issuer.clone())
                .durable(durable.clone())
                .approval(Arc::new(AllowAllApproval))
                .cancellation(Arc::new(Cancel(cancellation.clone())))
                .build()
                .unwrap(),
        );
        let processes = Arc::new(
            ProcessCapability::new(
                lifecycle.as_ref().clone(),
                owner.clone(),
                ProcessLimits::default(),
            )
            .unwrap(),
        );
        let host = AgentHostBridges {
            lifecycle: Some(lifecycle),
            capability_owner: Some(owner),
            cancellation: Some(cancellation),
            processes: Some(processes.clone()),
            ..AgentHostBridges::default()
        };
        Self {
            root,
            _root_guard: root_guard,
            host,
            processes,
            runner,
            durable,
            issuer,
        }
    }
    pub fn interrupt_current_child(&self) -> Arc<dyn Fn() + Send + Sync> {
        let lifecycle = self.host.lifecycle.as_ref().unwrap().clone();
        let issuer = self.issuer.clone();
        Arc::new(move || {
            let token = issuer.0.lock().unwrap().clone();
            drop(lifecycle.lease(&token).unwrap());
        })
    }
    pub fn parent_call(&self, call: &str, tool: &str, original_arguments: Value) -> PreparedCall {
        let run = self
            .host
            .capability_owner
            .as_ref()
            .unwrap()
            .run()
            .to_string();
        let key = (run, call.to_string(), tool.to_string());
        let mut parents = self.durable.parents.lock().unwrap();
        if let Some(original) = parents.get(&key) {
            assert_eq!(original, &original_arguments, "parent facts are immutable");
        } else {
            parents.insert(key, original_arguments.clone());
        }
        PreparedCall {
            call: call.into(),
            tool: tool.into(),
            arguments: original_arguments,
        }
    }
    pub fn invoke(&self, prepared: PreparedCall) -> Value {
        self.invoke_with(self.host.clone(), prepared)
    }
    pub fn invoke_with(&self, host: AgentHostBridges, prepared: PreparedCall) -> Value {
        let PreparedCall {
            call,
            tool,
            arguments: args,
        } = prepared;
        let identity = rustscript_agent::bundled_tool_registry()
            .unwrap()
            .identity()
            .to_string();
        let run = host.capability_owner.as_ref().unwrap().run().to_string();
        let input = json!({"run_id": run, "registry_identity": identity, "admitted_registry_identity": identity,
            "registry": rustscript_agent::bundled_tool_registry().unwrap().snapshot().schemas(),
            "call": {"id": call, "name": tool, "arguments": args}});
        let canonical = args.to_string();
        let request = json!({"tool_name": tool, "call_id": call, "canonical_arguments": canonical,
            "argument_digest": canonical, "canonical_input": input.to_string(), "run_id": run,
            "registry_identity": identity, "risk_class": "execute", "summary": tool});
        let value = self
            .runner
            .clone()
            .with_host(host)
            .run_with_context(to_vm(&request))
            .unwrap();
        let outer = from_vm(&value);
        if let Some(result) = outer["canonical_result"].as_str().filter(|s| !s.is_empty()) {
            serde_json::from_str(result).unwrap()
        } else {
            outer
        }
    }
    pub fn start(&self, call: &str) -> String {
        let prepared = self.parent_call(
            call,
            "terminal",
            json!({"argv": ["/bin/cat"], "background": true}),
        );
        let value = self.invoke(prepared);
        assert_eq!(value["ok"], true, "start result: {value}");
        value["data"]["process_id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical start result lacks process_id: {value}"))
            .into()
    }
    pub fn interrupted(&self, call: &str) -> bool {
        self.durable
            .interruptions
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == call)
    }
}
impl Drop for NativeFixture {
    fn drop(&mut self) {
        self.processes.shutdown_all();
        self.host
            .lifecycle
            .as_ref()
            .unwrap()
            .recover_open_tokens()
            .unwrap();
        let removed = fs::remove_dir_all(&self.root);
        if !std::thread::panicking() {
            removed.unwrap();
        }
    }
}
fn to_vm(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(v) => VmValue::Bool(*v),
        Value::Number(v) => VmValue::Int(v.as_i64().unwrap()),
        Value::String(v) => VmValue::string(v),
        Value::Array(v) => VmValue::Array(Arc::new(v.iter().map(to_vm).collect())),
        Value::Object(v) => VmValue::map(
            v.iter()
                .map(|(k, v)| (VmValue::string(k), to_vm(v)))
                .collect(),
        ),
    }
}
fn from_vm(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Bool(v) => json!(v),
        VmValue::Int(v) => json!(v),
        VmValue::String(v) => json!(v.to_string()),
        VmValue::Map(v) => Value::Object(
            v.iter()
                .map(|(k, v)| {
                    let VmValue::String(k) = k else {
                        panic!("string key")
                    };
                    (k.to_string(), from_vm(v))
                })
                .collect(),
        ),
        VmValue::Array(v) => Value::Array(v.iter().map(from_vm).collect()),
        _ => panic!("unexpected result value"),
    }
}
