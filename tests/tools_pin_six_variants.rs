//! Signed original-leaf preparation and real Native service effect proofs.

use rustscript_agent::plugins::PluginControlStore;
use rustscript_agent::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ScriptedProvider};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Arc};

#[path = "support/signed_tool_effects.rs"]
mod signed_tool_effects;

#[path = "support/signed_pinned_variants.rs"]
mod signed_pinned_variants;

#[test]
fn signed_search_variant_can_prepare_the_unchanged_production_leaf() {
    let (store, lock) = signed_pinned_variants::signed_search_variant();
    let prepared = store.prepare(&lock).unwrap_or_else(|error| {
        panic!("signed search variant must prepare the original production leaf: {error:?}")
    });
    let package_id = "org.rustscript.tools.varianta";
    assert!(prepared.program(package_id).is_some());
    assert_eq!(
        prepared.captured_source(package_id, "leaf.rss").unwrap(),
        include_bytes!("../rss/tools/search_files.rss")
    );
}

struct Effects {
    root: PathBuf,
    workspace: PathBuf,
    state: AgentGatewayState,
    a: rustscript_agent::plugins::GraphLock,
    b: rustscript_agent::plugins::GraphLock,
    generation: u64,
}

impl Effects {
    fn new(tool: &str, overflow: bool) -> Self {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("effects-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        let home = root.join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&root, &workspace, &home] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        fs::write(home.join("config.yaml"), format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\napprovals:\n  read: allow\n  write: allow\n  process: allow\n", workspace.display(), workspace.display())).unwrap();
        let (store, a, b) = signed_tool_effects::install_pair(&root, tool, overflow);
        let state = AgentGatewayState::with_sqlite_path(
            AgentGatewayConfig::default(),
            root.join("acceptance.sqlite"),
        )
        .unwrap()
        .with_workspace_home(&home);
        state.service().install_validated_tool_store(store).unwrap();
        let persistence = state.persistence().unwrap();
        let control = PluginControlStore::new(persistence.as_ref());
        control.store_lock(&a).unwrap();
        control.store_lock(&b).unwrap();
        let generation = control
            .activate(&a.graph_id, 0, &signed_tool_effects::artifact_refs(&a))
            .unwrap()
            .generation;
        Self {
            root,
            workspace,
            state,
            a,
            b,
            generation,
        }
    }

    async fn admit(&self) -> rustscript_agent::AdmittedRun {
        self.state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"perform the supplied tool call"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
    }

    fn activate_b(&mut self) {
        let persistence = self.state.persistence().unwrap();
        let control = PluginControlStore::new(persistence.as_ref());
        self.generation = control
            .activate(
                &self.b.graph_id,
                self.generation,
                &signed_tool_effects::artifact_refs(&self.b),
            )
            .unwrap()
            .generation;
    }

    async fn execute(
        &self,
        run: &rustscript_agent::AdmittedRun,
        provider: Arc<dyn rustscript_agent::AgentProviderHost>,
        calls: usize,
    ) -> Vec<Value> {
        self.execute_expected(run, provider, calls, &[]).await
    }

    async fn execute_expected(
        &self,
        run: &rustscript_agent::AdmittedRun,
        provider: Arc<dyn rustscript_agent::AgentProviderHost>,
        calls: usize,
        failed: &[&str],
    ) -> Vec<Value> {
        self.state.service().inject_provider_host(provider);
        self.state
            .service()
            .clone()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        let events = self.state.service().run_events(&run.run_id);
        for event in [
            "tool.requested",
            "tool.started",
            "tool.output",
            "tool.completed",
        ] {
            assert_eq!(
                events.iter().filter(|e| e["event"] == event).count(),
                if event == "tool.completed" {
                    calls - failed.len()
                } else {
                    calls
                },
                "{event}: {events:?}"
            );
        }
        assert!(
            events
                .iter()
                .filter(|e| e["event"] == "tool.completed")
                .all(|e| e["data"]["ok"] == true),
            "{events:?}"
        );
        let failures: Vec<_> = events
            .iter()
            .filter(|e| e["event"] == "tool.failed")
            .map(|e| e["data"]["tool_call_id"].as_str().unwrap())
            .collect();
        assert_eq!(failures, failed);
        let persistence = self.state.persistence().unwrap();
        let durable = persistence
            .event_replay(
                &json!({"run_id":run.run_id,"after_seq":0,"max_events":512,"max_bytes":2097152}),
            )
            .unwrap();
        let columns = durable["columns"].as_array().unwrap();
        let kind = columns.iter().position(|c| c == "event_type").unwrap();
        let rows = durable["rows"].as_array().unwrap();
        let payload = columns.iter().position(|c| c == "payload_json").unwrap();
        for name in [
            "tool.requested",
            "tool.started",
            "tool.output",
            "tool.completed",
            "tool.failed",
            "model.requested",
            "model.completed",
        ] {
            let live: Vec<_> = events
                .iter()
                .filter(|e| e["event"] == name)
                .map(|e| e["data"].clone())
                .collect();
            let persisted: Vec<Value> = rows
                .iter()
                .filter(|r| r[kind] == name)
                .map(|r| serde_json::from_str(r[payload].as_str().unwrap()).unwrap())
                .collect();
            assert_eq!(
                live, persisted,
                "durable {name} must retain exact Native facts"
            );
        }
        let reviews = events
            .iter()
            .filter(|e| e["event"] == "tool.started" && e["data"]["risk_class"] != "read")
            .count();
        for name in ["model.requested", "model.completed"] {
            assert_eq!(
                events.iter().filter(|e| e["event"] == name).count(),
                calls + 1 + reviews
            );
        }
        for event in [
            "tool.requested",
            "tool.started",
            "tool.output",
            "tool.completed",
        ] {
            assert_eq!(
                rows.iter().filter(|r| r[kind] == event).count(),
                if event == "tool.completed" {
                    calls - failed.len()
                } else {
                    calls
                },
                "durable {event}: {durable}"
            );
        }
        let messages =
            serde_json::to_value(self.state.service().session_messages(&run.session_id)).unwrap();
        let results: Vec<_> = messages
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|m| m["content"].as_array().into_iter().flatten())
            .filter(|b| b["type"] == "tool_result")
            .cloned()
            .collect();
        assert_eq!(results.len(), calls, "{messages}");
        let stored_messages = persistence.message_list(&run.session_id, 0).unwrap();
        let content_column = stored_messages["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|c| c == "content_json")
            .unwrap();
        let stored_results: Vec<Value> = stored_messages["rows"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|row| {
                serde_json::from_str::<Vec<Value>>(row[content_column].as_str().unwrap()).unwrap()
            })
            .filter(|block| block["type"] == "tool_result")
            .collect();
        assert_eq!(
            stored_results, results,
            "durable canonical blocks must equal public results"
        );
        println!(
            "NATIVE_EFFECT {}",
            json!({"root":self.root,"run":run.run_id,"results":results,"events":events})
        );
        results
    }

    fn assert_original_arguments(&self, run: &rustscript_agent::AdmittedRun, expected: &Value) {
        let events = self.state.service().run_events(&run.run_id);
        let started: Vec<_> = events
            .iter()
            .filter(|e| e["event"] == "tool.started")
            .collect();
        assert_eq!(started.len(), 1);
        let original: Value =
            serde_json::from_str(started[0]["data"]["argument_digest"].as_str().unwrap()).unwrap();
        assert_eq!(
            &original, expected,
            "Native parent facts preserve caller arguments before signed wrapper variation"
        );
    }

    fn assert_pin(&self, run: &rustscript_agent::AdmittedRun, a: bool) {
        let persistence = self.state.persistence().unwrap();
        let receipt = PluginControlStore::new(persistence.as_ref())
            .pin_for_run(&run.run_id)
            .unwrap();
        assert_eq!(
            receipt["graph_id"],
            if a {
                &self.a.graph_id
            } else {
                &self.b.graph_id
            }
            .as_str()
        );
    }
}

fn response(call: Option<Value>) -> Value {
    json!({"text":if call.is_some() { "" } else { "done" },"tool_calls":call.into_iter().collect::<Vec<_>>(),"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"})
}

fn one_call(tool: &str, arguments: &Value) -> Arc<ScriptedProvider> {
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"effect-call","name":tool,"arguments":arguments}),
    )));
    if matches!(tool, "write_file" | "patch" | "terminal") {
        let mut approval = response(None);
        approval["text"] = json!(
            r#"{"outcome":"allow","risk_level":"low","user_authorization":"unknown","rationale":"bounded fixture approval"}"#
        );
        provider.push_ok(approval);
    }
    provider.push_ok(response(None));
    provider
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_search_lists_real_files_and_keeps_admitted_a_after_b_activation() {
    let mut f = Effects::new("search_files", false);
    fs::write(f.workspace.join("alpha.txt"), "alpha").unwrap();
    fs::write(f.workspace.join("beta.txt"), "beta").unwrap();
    let arguments = json!({"pattern":"*.txt","target":"files"});
    let a = f.admit().await;
    f.activate_b();
    let out_a = f.execute(&a, one_call("search_files", &arguments), 1).await;
    f.assert_original_arguments(&a, &arguments);
    f.assert_pin(&a, true);
    assert!(out_a[0].to_string().contains("alpha.txt"), "{out_a:?}");
    assert!(!out_a[0].to_string().contains("beta.txt"));
    let b = f.admit().await;
    let out_b = f.execute(&b, one_call("search_files", &arguments), 1).await;
    f.assert_original_arguments(&b, &arguments);
    f.assert_pin(&b, false);
    assert!(out_b[0].to_string().contains("beta.txt"), "{out_b:?}");
    assert!(!out_b[0].to_string().contains("alpha.txt"));
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_write_changes_real_bytes_for_a_and_b() {
    let mut f = Effects::new("write_file", false);
    let args = json!({"path":"written.txt","content":"caller-content"});
    let a = f.admit().await;
    f.activate_b();
    f.execute(&a, one_call("write_file", &args), 1).await;
    f.assert_original_arguments(&a, &args);
    f.assert_pin(&a, true);
    assert_eq!(
        fs::read(f.workspace.join("written.txt")).unwrap(),
        b"A-write\n"
    );
    fs::remove_file(f.workspace.join("written.txt")).unwrap();
    let b = f.admit().await;
    f.execute(&b, one_call("write_file", &args), 1).await;
    f.assert_original_arguments(&b, &args);
    f.assert_pin(&b, false);
    assert_eq!(
        fs::read(f.workspace.join("written.txt")).unwrap(),
        b"B-write\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_patch_changes_real_bytes_for_a_and_b() {
    let mut f = Effects::new("patch", false);
    fs::write(f.workspace.join("patch.txt"), b"prefix ORIGINAL suffix\n").unwrap();
    let args = json!({"path":"patch.txt","old_string":"ORIGINAL","new_string":"caller-content"});
    let a = f.admit().await;
    f.activate_b();
    f.execute(&a, one_call("patch", &args), 1).await;
    f.assert_original_arguments(&a, &args);
    f.assert_pin(&a, true);
    assert_eq!(
        fs::read(f.workspace.join("patch.txt")).unwrap(),
        b"prefix A-patch suffix\n"
    );
    fs::write(f.workspace.join("patch.txt"), b"prefix ORIGINAL suffix\n").unwrap();
    let b = f.admit().await;
    f.execute(&b, one_call("patch", &args), 1).await;
    f.assert_original_arguments(&b, &args);
    f.assert_pin(&b, false);
    assert_eq!(
        fs::read(f.workspace.join("patch.txt")).unwrap(),
        b"prefix B-patch suffix\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_terminal_returns_actual_bin_stdout_for_a_and_b() {
    let mut f = Effects::new("terminal", false);
    let args = json!({"argv":["/bin/printf","caller-content"],"timeout_ms":250});
    let a = f.admit().await;
    f.activate_b();
    let out_a = f.execute(&a, one_call("terminal", &args), 1).await;
    f.assert_original_arguments(&a, &args);
    f.assert_pin(&a, true);
    assert_eq!(out_a[0]["result"]["stdout"], "A-terminal\n");
    assert_eq!(out_a[0]["result"]["exit_code"], 0);
    let b = f.admit().await;
    let out_b = f.execute(&b, one_call("terminal", &args), 1).await;
    f.assert_original_arguments(&b, &args);
    f.assert_pin(&b, false);
    assert_eq!(out_b[0]["result"]["stdout"], "B-terminal\n");
    assert_eq!(out_b[0]["result"]["exit_code"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_search_large_result_reaches_bounded_native_publication() {
    let f = Effects::new("search_files", true);
    for index in 0..20 {
        fs::write(
            f.workspace
                .join(format!("file-{index:02}-{}.txt", "x".repeat(70))),
            "real-file",
        )
        .unwrap();
    }
    let run = f.admit().await;
    let results = f
        .execute(
            &run,
            one_call("search_files", &json!({"pattern":"*","target":"files"})),
            1,
        )
        .await;
    assert_eq!(results[0]["is_error"], false);
    assert!(
        results[0]["content"]
            .as_str()
            .unwrap()
            .starts_with("artifact "),
        "{results:?}"
    );
    assert!(
        f.state
            .service()
            .run_events(&run.run_id)
            .iter()
            .any(|e| e["event"] == "tool.completed" && e["data"]["truncated"] == true)
    );
}

// This provider emits calls only. Every process id is recovered from Native's
// preceding result in this same run; no foreign or invented handle is supplied.
#[derive(Default)]
struct ProcessCalls {
    step: std::sync::atomic::AtomicUsize,
    handle: std::sync::Mutex<Option<String>>,
    requests: std::sync::Mutex<Vec<Value>>,
    processes: Option<Arc<rustscript_agent::capabilities::ProcessCapability>>,
    pids: std::sync::Mutex<Vec<u32>>,
}

fn process_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => object
            .get("process_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| object.values().find_map(process_id)),
        Value::Array(array) => array.iter().rev().find_map(process_id),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .as_ref()
            .and_then(process_id),
        _ => None,
    }
}

impl rustscript_agent::AgentProviderHost for ProcessCalls {
    fn call(&self, request: &Value, _: &rustscript_agent::RunCancellation) -> Value {
        self.requests.lock().unwrap().push(request.clone());
        // DurableProvider strips its private step key before transport.
        // Classify the real tool-free Guardian request by its system message.
        assert!(request.get("_provider_step_key").is_none());
        let system = &request["messages"][0];
        if system
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .or_else(|| system["content"].as_str())
            .is_some_and(|text| {
                text.starts_with("You are Guardian, reviewing one proposed tool action.")
            })
        {
            let mut approval = response(None);
            approval["text"] = json!(
                r#"{"outcome":"allow","risk_level":"low","user_authorization":"unknown","rationale":"bounded fixture approval"}"#
            );
            return json!({"ok":true,"response":approval,"error":{}});
        }
        let step = self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        if step == 1 {
            *self.pids.lock().unwrap() = self.processes.as_ref().unwrap().live_pids();
            assert_eq!(self.pids.lock().unwrap().len(), 1);
        }
        let call = if step == 0 {
            Some(
                json!({"id":"spawn","name":"terminal","arguments":{"argv":["/bin/cat"],"background":true}}),
            )
        } else if step <= 6 {
            let mut handle = self.handle.lock().unwrap();
            if handle.is_none() {
                *handle = Some(
                    process_id(request)
                        .expect("Native terminal result contains its actual process id"),
                );
            }
            let (action, extra) = match step {
                1 => ("write", json!({"data":"caller-stdin\n"})),
                2 => ("wait", json!({"timeout_ms":50})),
                3 => ("poll", json!({})),
                4 => ("log", json!({"offset":0,"limit":4096})),
                5 => ("kill", json!({})),
                6 => ("poll", json!({})),
                _ => unreachable!(),
            };
            let mut arguments = extra;
            arguments["action"] = json!(action);
            arguments["process_id"] = json!(handle.as_ref().unwrap());
            Some(json!({"id":format!("process-{step}"),"name":"process","arguments":arguments}))
        } else {
            None
        };
        json!({"ok":true,"response":response(call),"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_process_uses_each_runs_native_child_stdin_poll_log_and_kill() {
    let mut f = Effects::new("process", false);
    let a = f.admit().await;
    f.activate_b();
    let provider_a = process_provider(&f, &a);
    let out_a = f
        .execute_expected(&a, provider_a.clone(), 7, &["process-6"])
        .await;
    f.assert_pin(&a, true);
    assert_eq!(out_a[1]["result"]["wrote_bytes"], 8);
    for block in &out_a[2..5] {
        assert_eq!(block["result"]["stdout"], "A-stdin\n");
    }
    assert_eq!(out_a[4]["result"]["stdout"], "A-stdin\n", "{out_a:?}");
    assert_eq!(out_a[5]["result"]["status"], "signaled");
    assert_eq!(out_a[5]["result"]["signal"], 9);
    assert_eq!(out_a[6]["is_error"], true);
    assert_eq!(out_a[6]["error"]["code"], "cancelled");
    assert_process_gone(&provider_a);
    let b = f.admit().await;
    let provider_b = process_provider(&f, &b);
    let out_b = f
        .execute_expected(&b, provider_b.clone(), 7, &["process-6"])
        .await;
    f.assert_pin(&b, false);
    assert_eq!(out_b[1]["result"]["wrote_bytes"], 8);
    for block in &out_b[2..5] {
        assert_eq!(block["result"]["stdout"], "B-stdin\n");
    }
    assert_eq!(out_b[4]["result"]["stdout"], "B-stdin\n", "{out_b:?}");
    assert_eq!(out_b[5]["result"]["status"], "signaled");
    assert_eq!(out_b[5]["result"]["signal"], 9);
    assert_eq!(out_b[6]["is_error"], true);
    assert_eq!(out_b[6]["error"]["code"], "cancelled");
    assert_process_gone(&provider_b);
    let actions_a = assert_process_parent_arguments(&f, &a, &handle_from(&provider_a));
    let actions_b = assert_process_parent_arguments(&f, &b, &handle_from(&provider_b));
    assert_eq!(
        actions_a, actions_b,
        "compare public action payloads after projecting each run's own identity"
    );
    let handle_a = provider_a.handle.lock().unwrap().clone().unwrap();
    let handle_b = provider_b.handle.lock().unwrap().clone().unwrap();
    assert_ne!(
        handle_a, handle_b,
        "opaque Native identities are run-owned and may differ"
    );
    println!("NATIVE_PROCESS_IDS {}", json!({"a":handle_a,"b":handle_b}));
}

fn process_provider(f: &Effects, run: &rustscript_agent::AdmittedRun) -> Arc<ProcessCalls> {
    Arc::new(ProcessCalls {
        processes: f
            .state
            .service()
            .capability_host_bridges(&run.run_id)
            .unwrap()
            .unwrap()
            .processes,
        ..Default::default()
    })
}

fn assert_process_gone(provider: &ProcessCalls) {
    let pids = provider.pids.lock().unwrap();
    assert_eq!(pids.len(), 1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    for pid in pids.iter() {
        let path = PathBuf::from(format!("/proc/{pid}"));
        while path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            !path.exists(),
            "owned child {pid} must disappear after kill"
        );
    }
    assert!(provider.processes.as_ref().unwrap().live_pids().is_empty());
}

fn handle_from(provider: &ProcessCalls) -> String {
    provider.handle.lock().unwrap().clone().unwrap()
}

fn assert_process_parent_arguments(
    f: &Effects,
    run: &rustscript_agent::AdmittedRun,
    handle: &str,
) -> Vec<Value> {
    let events = f.state.service().run_events(&run.run_id);
    let mut arguments: Vec<Value> = events
        .iter()
        .filter(|e| e["event"] == "tool.started")
        .map(|e| serde_json::from_str(e["data"]["argument_digest"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(arguments.len(), 7);
    assert_eq!(arguments[0], json!({"argv":["/bin/cat"],"background":true}));
    let expected = [
        json!({"action":"write","data":"caller-stdin\n"}),
        json!({"action":"wait","timeout_ms":50}),
        json!({"action":"poll"}),
        json!({"action":"log","offset":0,"limit":4096}),
        json!({"action":"kill"}),
        json!({"action":"poll"}),
    ];
    for (actual, expected) in arguments[1..].iter_mut().zip(expected) {
        assert_eq!(actual["process_id"], handle);
        actual.as_object_mut().unwrap().remove("process_id");
        assert_eq!(*actual, expected);
    }
    arguments
}

fn assert_native_overflow(
    f: &Effects,
    run: &rustscript_agent::AdmittedRun,
    block: &Value,
    artifacts: &rustscript_agent::capabilities::ArtifactCapability,
    stdout: &str,
) {
    assert_eq!(block["is_error"], false, "{block}");
    assert_eq!(block["truncated"], true, "{block}");
    let id = block["artifact"]["id"].as_str().unwrap();
    let (bytes, metadata) = artifacts
        .stored(id)
        .expect("committed result artifact remains visible");
    assert_eq!(bytes, format!("stdout:\n{stdout}stderr:\n").into_bytes());
    assert_eq!(metadata["run"], run.run_id);
    assert_eq!(metadata["call_id"], block["tool_call_id"]);
    assert_eq!(metadata.as_object().unwrap().len(), 3);
    assert!(metadata["owner"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(block["result"]["overflow_encoding"], "labeled-utf8");
    assert_eq!(block["result"]["overflow_stdout_bytes"], stdout.len());
    assert_eq!(block["result"]["overflow_stderr_bytes"], 0);
    let completed = f
        .state
        .service()
        .run_events(&run.run_id)
        .into_iter()
        .find(|e| {
            e["event"] == "tool.completed" && e["data"]["tool_call_id"] == block["tool_call_id"]
        })
        .unwrap();
    assert_eq!(completed["data"]["artifacts"], json!([id]));
    assert_eq!(completed["data"]["truncated"], true);
    println!(
        "NATIVE_BOUNDED_PROCESS_OVERFLOW {}",
        json!({"run":run.run_id,"call":block["tool_call_id"],"id":id,"bytes":bytes.len(),"metadata":metadata})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_terminal_overflow_publishes_real_labeled_result_artifact() {
    let f = Effects::new("terminal", true);
    let run = f.admit().await;
    let artifacts = f
        .state
        .service()
        .capability_host_bridges(&run.run_id)
        .unwrap()
        .unwrap()
        .artifacts
        .unwrap();
    let args = json!({"argv":["/bin/printf","caller-content"],"timeout_ms":250});
    let results = f.execute(&run, one_call("terminal", &args), 1).await;
    f.assert_original_arguments(&run, &args);
    assert_native_overflow(
        &f,
        &run,
        &results[0],
        &artifacts,
        &format!("A-{}\n", "x".repeat(1200)),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_process_overflow_publishes_real_child_output_as_bounded_artifacts() {
    let f = Effects::new("process", true);
    let run = f.admit().await;
    let artifacts = f
        .state
        .service()
        .capability_host_bridges(&run.run_id)
        .unwrap()
        .unwrap()
        .artifacts
        .unwrap();
    let provider = process_provider(&f, &run);
    let results = f
        .execute_expected(&run, provider.clone(), 7, &["process-6"])
        .await;
    assert_process_parent_arguments(&f, &run, &handle_from(&provider));
    assert_native_overflow(
        &f,
        &run,
        &results[4],
        &artifacts,
        &format!("A-{}\n", "x".repeat(1200)),
    );
    assert_process_gone(&provider);
}
