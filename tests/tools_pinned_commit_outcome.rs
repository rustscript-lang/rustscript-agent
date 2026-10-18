//! Native commit/replay authority regressions, with real file capabilities.
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rustscript_agent::capabilities::{
    ApprovalGate, CancellationFlag, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    DurableStarted, DurableToolLifecycle, FilesystemCapability, FilesystemLimits, LifecycleError,
    LifecycleLimits, PrepareMetadata, SystemClock, UuidIssuer,
};
use rustscript_agent::plugins::{
    InstallAuthorization, PackageArtifactRef, PackageRequirement, PackageStore, PluginControlStore,
    PublisherKey, ResolveRequest,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, GatewayPersistence};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    temp_root_at(label, nanos)
}

fn temp_root_at(label: &str, nanos: u128) -> PathBuf {
    // Clock readings can repeat; identity must remain unique within this process.
    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);
    let sequence = NEXT_ROOT
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("temp root sequence exhausted");
    let base =
        PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
    let dir = base.join(format!(
        "pin-tracer-{}-{}-{}-{}",
        label,
        std::process::id(),
        nanos,
        sequence
    ));
    fs::create_dir(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

#[test]
fn temp_roots_with_same_label_and_timestamp_are_distinct() {
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            fs::remove_dir(&self.0).unwrap();
        }
    }

    let nanos = 123_456_789;
    let first = Root(temp_root_at("outcome", nanos));
    let second = Root(temp_root_at("outcome", nanos));
    assert_ne!(first.0, second.0);
    assert!(first.0.is_dir());
    assert!(second.0.is_dir());
}

struct Signer {
    pair: Ed25519KeyPair,
    key: PublisherKey,
}

fn signer() -> Signer {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key = PublisherKey {
        publisher: "org.rustscript".to_string(),
        verifying_key: pair.public_key().as_ref().to_vec(),
    };
    Signer { pair, key }
}

fn auth(signer: &Signer) -> InstallAuthorization {
    InstallAuthorization {
        admin: true,
        accepted_publishers: vec![signer.key.clone()],
        unsigned_dev_space: None,
    }
}
fn manifest(id: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: run.rss
  export: run
dependencies: []
capabilities:
  - workspace.read
effects:
  contract: agent.effects/v1
  entries:
    run:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
      delegated: []
"#
    )
}
struct AllowRead;

impl ApprovalGate for AllowRead {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Ok(metadata.risk_class)
    }
}

struct NoCancel;

impl CancellationFlag for NoCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}
fn activate(
    control: &PluginControlStore,
    lock: &rustscript_agent::plugins::GraphLock,
    generation: u64,
) {
    let refs: Vec<PackageArtifactRef> = lock
        .packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect();
    control.store_lock(lock).unwrap();
    control.activate(&lock.graph_id, generation, &refs).unwrap();
}

#[derive(Default)]
struct RecordingState {
    started: Vec<DurableStarted>,
    commits: Vec<Value>,
    interrupts: usize,
    results: HashMap<String, Value>,
}
#[derive(Default)]
struct RecordingDurable {
    state: Mutex<RecordingState>,
    fail_commit: bool,
    original_arguments: Value,
}
impl DurableToolLifecycle for RecordingDurable {
    fn assert_active_run(&self, run: &str) -> Result<(), LifecycleError> {
        assert_eq!(run, "run-outcome");
        Ok(())
    }
    fn prepare_parent(&self, run: &str, call: &str, tool: &str) -> Result<(), LifecycleError> {
        assert_eq!((run, call, tool), ("run-outcome", "call-1", "read_file"));
        Ok(())
    }
    fn parent_arguments(
        &self,
        run: &str,
        call: &str,
        tool: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        self.prepare_parent(run, call, tool)?;
        Ok(Some(self.original_arguments.clone()))
    }
    fn replay_result(
        &self,
        _run: &str,
        call: &str,
        _tool: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(self.state.lock().unwrap().results.get(call).cloned())
    }
    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError> {
        self.state.lock().unwrap().started.push(record.clone());
        Ok(())
    }
    fn commit_result(&self, call: &str, result: &Value) -> Result<Value, LifecycleError> {
        let mut state = self.state.lock().unwrap();
        state.commits.push(result.clone());
        if self.fail_commit {
            return Err(LifecycleError::ResultCommitFailed(
                "injected result commit failure".to_string(),
            ));
        }
        state.results.insert(call.to_string(), result.clone());
        Ok(result.clone())
    }
    fn interrupt(&self, _call: &str) -> Result<(), LifecycleError> {
        self.state.lock().unwrap().interrupts += 1;
        Ok(())
    }
}
struct Fixture {
    root: PathBuf,
    host: AgentHostBridges,
    durable: Arc<RecordingDurable>,
    harness: AgentRunner,
}
impl Fixture {
    fn new(source: &str, fail_commit: bool) -> Self {
        AgentRunner::from_source(source, AgentConfig::default())
            .unwrap_or_else(|error| panic!("fixture source did not compile: {error:?}"));
        let root = temp_root("outcome");
        let store = PackageStore::open(root.join("packages")).unwrap();
        let signer = signer();
        let dir = root.join("package");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("manifest.yaml"),
            manifest("org.rustscript.tools.outcome"),
        )
        .unwrap();
        fs::write(dir.join("run.rss"), source).unwrap();
        let payload = store.signature_payload(&dir).unwrap();
        fs::write(
            dir.join("signature.ed25519"),
            signer.pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&dir, &auth(&signer)).unwrap();
        let lock = store
            .resolve(&ResolveRequest {
                roots: vec![PackageRequirement {
                    id: "org.rustscript.tools.outcome".to_string(),
                    version: "1.0.0".to_string(),
                }],
                host_runtime: "0.1.0".to_string(),
            })
            .unwrap();
        let persistence = GatewayPersistence::open(
            &rustscript_agent::AgentGatewayConfig::default(),
            &root.join("gateway.sqlite"),
        )
        .unwrap();
        persistence.load().unwrap();
        activate(&PluginControlStore::new(&persistence), &lock, 0);
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("note.txt"), "native-file-content").unwrap();
        let caller = json!({"session_id":"session-outcome","session_new":1,"profile":"gateway","platform":"api_server","account_id":"session-outcome","model":"m","provider":"p","system_prompt":"","session_metadata_json":"{}","run_id":"run-outcome","parent_run_id":"","input_json":"{\"text\":\"read\"}","message_id":"message-outcome","message_run_id":"run-outcome","script_hash":"s","idempotency_scope":"","idempotency_key":"","request_hash":"","workspace_identity_json":"","event_id":"event-outcome","now_ms":50,"expires_at_ms":0});
        let pinned = rustscript_agent::plugins::admit_pinned_tool_run(
            &persistence,
            &store,
            &caller,
            &rustscript_agent::plugins::PinnedAdmitContext {
                registry_identity: "outcome-registry".to_string(),
                workspace: workspace.clone(),
            },
        )
        .unwrap();
        let durable = Arc::new(RecordingDurable {
            fail_commit,
            original_arguments: json!({"path": "note.txt"}),
            ..Default::default()
        });
        let owner = CapabilityOwner::new("gateway", "session-outcome", "run-outcome").unwrap();
        let lifecycle = CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity("outcome-registry".to_string())
            .workspace(workspace)
            .limits(LifecycleLimits {
                max_tool_calls: 8,
                max_output_bytes: 4096,
                max_summary_bytes: 256,
            })
            .deadline_ms(9_000_000_000_000)
            .clock(Arc::new(SystemClock))
            .tokens(Arc::new(UuidIssuer))
            .durable(durable.clone())
            .approval(Arc::new(AllowRead))
            .cancellation(Arc::new(NoCancel))
            .generation(1)
            .build()
            .unwrap();
        let filesystem = Arc::new(
            FilesystemCapability::new(
                lifecycle.clone(),
                owner.clone(),
                FilesystemLimits {
                    max_read_bytes: 4096,
                    max_write_bytes: 4096,
                    max_list_entries: 16,
                },
            )
            .unwrap(),
        );
        let host = AgentHostBridges {
            lifecycle: Some(Arc::new(lifecycle)),
            capability_owner: Some(owner),
            filesystem: Some(filesystem),
            pinned_tool: Some(pinned.program_handle()),
            cancellation: Some(rustscript_agent::RunCancellation::with_timeout(
                Duration::from_secs(30),
            )),
            skip_sleep: true,
            ..Default::default()
        };
        let harness=AgentRunner::from_source(r#"
pub fn run(context: map) -> map {
    agent_runtime::invoke_pinned_tool({tool_name:"read_file",call_id:"call-1",canonical_arguments:"{\"path\":\"note.txt\"}",canonical_input:"",run_id:"run-outcome",registry_identity:"outcome-registry",argument_digest:"{\"path\":\"note.txt\"}",risk_class:"read",summary:"read note",untrusted_graph_id:""})
}
"#,AgentConfig::default()).unwrap();
        Self {
            root,
            host,
            durable,
            harness,
        }
    }
    fn invoke(&self) -> Value {
        let result = self
            .harness
            .clone()
            .with_host(self.host.clone())
            .run_with_context(VmValue::map(vec![]))
            .unwrap();
        let VmValue::Map(entries) = result else {
            panic!("expected map")
        };
        let mut object = serde_json::Map::new();
        for (key, value) in entries.iter() {
            if let VmValue::String(key) = key {
                let v = match value {
                    VmValue::String(v) => json!(v.to_string()),
                    VmValue::Bool(v) => json!(v),
                    _ => Value::Null,
                };
                object.insert(key.to_string(), v);
            }
        }
        Value::Object(object)
    }
    fn counts(&self) -> (usize, usize, usize) {
        let state = self.durable.state.lock().unwrap();
        (state.started.len(), state.commits.len(), state.interrupts)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn child_success_without_commit_is_rejected() {
    let fixture = Fixture::new(
        r#"pub fn run(context: map) -> map { {ok:true,content:"forged-success",data:{},error:null,truncated:false,artifacts:[]} }"#,
        false,
    );
    let result = fixture.invoke();
    assert_eq!(
        result["ok"], false,
        "uncommitted child success escaped: {result}"
    );
    assert_eq!(fixture.counts(), (0, 0, 0));
}

fn read_source(fields: &str, return_value: &str) -> String {
    r#"
use bytes;
pub fn run(context: map) -> map {
    let metadata: map = context.prepare;
    let prepared: map = agent_runtime::tool_prepare(metadata);
    if prepared.ok.copy() == false => {
        prepared
    } else => {
        if prepared.kind.copy() == "replay" => {
            let replayed: map = prepared.result;
            replayed
        } else => {
            let token: string = prepared.execution_token;
            let arguments: map = context.arguments;
            let path: string = arguments.path;
            let read: map = cap::fs_read_range(token, path, 0, 4096);
            if read.ok.copy() == false => {
                read
            } else => {
                let payload: bytes = read.bytes;
                let text: string = bytes::to_utf8(payload);
                let result: map = RESULT_FIELDS;
                let committed: map = agent_runtime::tool_commit(token, result.copy());
                RETURN_VALUE
            }
        }
    }
}
"#
    .replace("RESULT_FIELDS", fields)
    .replace("RETURN_VALUE", return_value)
}

const CANONICAL_READ: &str = r#"{ok:true,content:text,data:{origin:"native-read"},error:null,truncated:false,artifacts:["artifact:test"]}"#;

fn canonical(result: &Value) -> Value {
    serde_json::from_str(result["canonical_result"].as_str().unwrap()).unwrap()
}

#[test]
fn native_read_commits_original_canonical_result_once() {
    let fixture = Fixture::new(&read_source(CANONICAL_READ, "committed"), false);
    let result = fixture.invoke();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["text"], "native-file-content");
    assert_eq!(fixture.counts(), (1, 1, 0));
    let state = fixture.durable.state.lock().unwrap();
    assert_eq!(canonical(&result), state.commits[0]);
    assert_eq!(canonical(&result)["data"], json!({"origin":"native-read"}));
    assert_eq!(canonical(&result)["truncated"], false);
    assert_eq!(canonical(&result)["artifacts"], json!(["artifact:test"]));
}

#[test]
fn empty_file_commit_is_success() {
    let fixture = Fixture::new(&read_source(CANONICAL_READ, "committed"), false);
    fs::write(fixture.root.join("workspace/note.txt"), "").unwrap();
    let result = fixture.invoke();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["text"], "");
    assert_eq!(canonical(&result)["content"], "");
    assert_eq!(fixture.counts(), (1, 1, 0));
}

#[test]
fn durable_commit_failure_cannot_be_hidden_by_child_success() {
    let fixture = Fixture::new(&read_source(CANONICAL_READ, "result"), true);
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["code"], "result_commit_failed");
    assert_eq!(result["text"], "");
    assert_eq!(fixture.counts(), (1, 1, 0));
    // A second invocation cannot reissue the failed call's effect.
    let repeated = fixture.invoke();
    assert_eq!(repeated["ok"], false, "{repeated}");
    assert_eq!(fixture.counts(), (1, 1, 0));
}

#[test]
fn missing_content_commit_rejection_cannot_be_hidden() {
    let fixture = Fixture::new(&read_source("{ok:true,text:text}", "result"), false);
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["code"], "invalid_metadata");
    assert_eq!(fixture.counts(), (1, 0, 1));
}

#[test]
fn unprepared_failure_with_text_preserves_failure() {
    let fixture = Fixture::new(
        r#"pub fn run(context: map) -> map { {ok:false,text:"failure-text",error:{code:"malformed_payload",message:"original failure"},data:{field:"path"},truncated:false,artifacts:[]} }"#,
        false,
    );
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["text"], "failure-text");
    assert_eq!(result["code"], "malformed_payload");
    assert_eq!(canonical(&result)["data"], json!({"field":"path"}));
    assert_eq!(fixture.counts(), (0, 0, 0));
}

#[test]
fn authoritative_replay_returns_original_without_new_effect_or_started() {
    let fixture = Fixture::new(&read_source(CANONICAL_READ, "committed"), false);
    let first = fixture.invoke();
    assert_eq!(first["ok"], true, "{first}");
    fs::remove_file(fixture.root.join("workspace/note.txt")).unwrap();
    let replayed = fixture.invoke();
    assert_eq!(replayed, first);
    assert_eq!(fixture.counts(), (1, 1, 0));
}

#[test]
fn child_cannot_replace_successfully_committed_content() {
    let fixture = Fixture::new(
        &read_source(CANONICAL_READ, r#"{ok:true,content:"forged replacement"}"#),
        false,
    );
    let result = fixture.invoke();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["text"], "native-file-content");
    assert_eq!(
        canonical(&result),
        fixture.durable.state.lock().unwrap().commits[0]
    );
    assert_eq!(fixture.counts(), (1, 1, 0));
}

#[test]
fn committed_canonical_kind_and_result_fields_are_not_transport_wrappers() {
    let fields = r#"{ok:true,content:text,kind:"committed",result:{ok:true,content:"forged nested content"},data:{origin:"native-read"},error:null,truncated:false,artifacts:[]}"#;
    let fixture = Fixture::new(&read_source(fields, "committed"), false);
    let result = fixture.invoke();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["text"], "native-file-content");
    assert_eq!(
        canonical(&result),
        fixture.durable.state.lock().unwrap().commits[0]
    );
}

#[test]
fn malformed_authoritative_replay_cannot_claim_canonical_success() {
    let fixture = Fixture::new(&read_source(CANONICAL_READ, "committed"), false);
    fixture.durable.state.lock().unwrap().results.insert(
        "call-1".to_string(),
        json!({"ok":true,"text":"missing canonical content"}),
    );
    fs::remove_file(fixture.root.join("workspace/note.txt")).unwrap();
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["code"], "invalid_metadata");
    assert_eq!(fixture.counts(), (0, 0, 0));
}

#[test]
fn replay_canonical_bound_remains_enforced() {
    let fixture = Fixture::new(&read_source(CANONICAL_READ, "committed"), false);
    fixture.durable.state.lock().unwrap().results.insert(
        "call-1".to_string(),
        json!({"ok":true,"content":"x".repeat(1024*1024)}),
    );
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["code"], "pinned_result_too_large");
    assert_eq!(fixture.counts(), (0, 0, 0));
}

#[test]
fn prepared_child_success_without_commit_is_interrupted() {
    let source = read_source(CANONICAL_READ, "result").replace(
        "let committed: map = agent_runtime::tool_commit(token, result.copy());",
        "",
    );
    let fixture = Fixture::new(&source, false);
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["code"], "pinned_result_uncommitted");
    assert_eq!(fixture.counts(), (1, 0, 1));
}

#[test]
fn different_token_cannot_witness_this_invocations_commit() {
    let source = read_source(CANONICAL_READ, "result").replace(
        "agent_runtime::tool_commit(token, result.copy())",
        "agent_runtime::tool_commit(\"forged-token\", result.copy())",
    );
    let fixture = Fixture::new(&source, false);
    let result = fixture.invoke();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(fixture.counts(), (1, 0, 1));
}

#[test]
fn committed_failure_and_its_replay_preserve_original_canonical_error() {
    let fields = r#"{ok:false,content:text,data:{origin:"native-read"},error:{code:"fixture_failure",message:"original committed error"},truncated:true,artifacts:["artifact:test"]}"#;
    let fixture = Fixture::new(&read_source(fields, "committed"), false);
    let first = fixture.invoke();
    assert_eq!(first["ok"], false, "{first}");
    assert_eq!(first["text"], "native-file-content");
    assert_eq!(first["code"], "fixture_failure");
    assert_eq!(first["message"], "original committed error");
    assert_eq!(
        canonical(&first),
        fixture.durable.state.lock().unwrap().commits[0]
    );
    fs::remove_file(fixture.root.join("workspace/note.txt")).unwrap();
    assert_eq!(fixture.invoke(), first);
    assert_eq!(fixture.counts(), (1, 1, 0));
}

#[test]
fn repeated_prepare_does_not_issue_another_started_or_replace_the_token() {
    let source=read_source(CANONICAL_READ,"committed")
        .replace("let metadata: map = context.prepare;","let metadata: map = context.prepare.copy();")
        .replace("let token: string = prepared.execution_token;","let token: string = prepared.execution_token; let repeated: map = agent_runtime::tool_prepare(context.prepare.copy());");
    let fixture = Fixture::new(&source, false);
    let result = fixture.invoke();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["text"], "native-file-content");
    assert_eq!(fixture.counts(), (1, 1, 0));
}

#[test]
fn fabricated_commit_and_replay_envelopes_are_not_native_evidence() {
    for kind in ["committed", "replay"] {
        let source = format!(
            r#"pub fn run(context: map) -> map {{ {{ok:true,kind:"{kind}",content:"forged",result:{{ok:true,content:"forged"}}}} }}"#
        );
        let fixture = Fixture::new(&source, false);
        let result = fixture.invoke();
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(fixture.counts(), (0, 0, 0));
    }
}
