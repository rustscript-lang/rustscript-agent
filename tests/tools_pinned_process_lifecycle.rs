//! Production Main -> retained Native dispatcher -> fresh child VM process calls.
#[path = "support/pinned_process_fixture.rs"]
mod pinned_process_fixture;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, AgentHostBridges, AgentProviderHost, RunCancellation,
    capabilities::ProcessCapability,
    service::{AdmitRunRequest, AgentService},
};
use serde_json::{Value, json};

struct Fixture {
    root: PathBuf,
    state: Option<AgentGatewayState>,
}

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("pinned-process-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let mut fixture = Self {
            root: root.clone(),
            state: None,
        };
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        let workspace = root.join("workspace");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(home.join("config.yaml"), format!(
            "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n", workspace.display(), workspace.display(), workspace.display()
        )).unwrap();
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600)).unwrap();
        let state = AgentGatewayState::with_agent_file_and_sqlite(
            AgentGatewayConfig::default(),
            rustscript_agent::bundled_agent_main_path(),
            &root.join("gateway.sqlite3"),
        )
        .unwrap()
        .with_workspace_home(home);
        fixture.state = Some(state);
        fixture
    }

    fn service(&self) -> Arc<AgentService> {
        self.state.as_ref().unwrap().service()
    }

    fn cleanup(mut self) {
        let state = self.state.take().unwrap();
        state.persistence().unwrap().shutdown();
        drop(state);
        fs::remove_dir_all(&self.root).unwrap();
        assert!(!self.root.exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.service().shutdown_capability_host();
            state.persistence().unwrap().shutdown();
            drop(state);
        }
        if self.root.exists() {
            let removed = fs::remove_dir_all(&self.root);
            if !std::thread::panicking() {
                removed.unwrap();
            }
        }
    }
}

fn response(calls: Value, text: &str) -> Value {
    json!({"ok": true, "response": {
        "text": text, "tool_calls": calls,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "", "stop_reason": if text.is_empty() {"tool_calls"} else {"stop"}
    }, "error": {}})
}

fn tool(id: &str, name: &str, arguments: Value) -> Value {
    response(
        json!([{"id": id, "name": name, "arguments": arguments}]),
        "",
    )
}

fn result(request: &Value, call_id: &str) -> Value {
    let block = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|message| message["content"].as_array().into_iter().flatten())
        .find(|block| block["type"] == "tool_result" && block["tool_call_id"] == call_id)
        .unwrap_or_else(|| panic!("missing {call_id} result"));
    json!({"ok": block["is_error"] == false, "data": block["result"], "content": block["content"], "error": block["error"]})
}

#[derive(Default)]
struct Sequence {
    step: usize,
    handle: String,
    host: Option<AgentHostBridges>,
    results: Vec<(String, Value)>,
    poll_deadline: Option<Instant>,
    polls: usize,
}

struct InteractiveProvider {
    service: Weak<AgentService>,
    run_id: Mutex<String>,
    sequence: Mutex<Sequence>,
    pause_before_write: Option<Arc<Pause>>,
}

#[derive(Default)]
struct Pause {
    entered: std::sync::atomic::AtomicBool,
    released: Mutex<bool>,
    cv: std::sync::Condvar,
}
impl Pause {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.cv.notify_all();
    }
    fn hold(&self) {
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut released = self.released.lock().unwrap();
        while !*released {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "owned provider pause deadline");
            released = self.cv.wait_timeout(released, remaining).unwrap().0;
        }
    }
}
struct ReleasePause(Arc<Pause>);
impl Drop for ReleasePause {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl InteractiveProvider {
    fn new(service: &Arc<AgentService>) -> Arc<Self> {
        Arc::new(Self {
            service: Arc::downgrade(service),
            run_id: Mutex::new(String::new()),
            sequence: Mutex::new(Sequence::default()),
            pause_before_write: None,
        })
    }
}

impl AgentProviderHost for InteractiveProvider {
    fn call(&self, request: &Value, cancellation: &RunCancellation) -> Value {
        if request
            .pointer("/messages/0/content/0/text")
            .and_then(Value::as_str)
            .is_some_and(|text| text.starts_with("You are Guardian,"))
        {
            return response(
                json!([]),
                r#"{"outcome":"allow","risk_level":"low","user_authorization":"unknown","rationale":"bounded owned process fixture"}"#,
            );
        }
        let service = self.service.upgrade().unwrap();
        let run_id = self.run_id.lock().unwrap().clone();
        let host = service.capability_host_bridges(&run_id).unwrap().unwrap();
        let mut seq = self.sequence.lock().unwrap();
        if let Some(original) = &seq.host {
            assert!(Arc::ptr_eq(
                original.lifecycle.as_ref().unwrap(),
                host.lifecycle.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                original.processes.as_ref().unwrap(),
                host.processes.as_ref().unwrap()
            ));
            assert_eq!(original.capability_owner, host.capability_owner);
            assert_eq!(
                original.cancellation.as_ref().unwrap().deadline_instant(),
                cancellation.deadline_instant()
            );
        } else {
            seq.host = Some(host);
        }
        let next = match seq.step {
            0 => tool(
                "start",
                "terminal",
                json!({"argv": ["/bin/cat"], "background": true, "timeout_ms": 30000}),
            ),
            1 => {
                let value = result(request, "start");
                assert_eq!(value["ok"], true, "terminal result: {value}");
                seq.handle = value["data"]["process_id"].as_str().unwrap().to_string();
                seq.results.push(("start".into(), value));
                tool(
                    "poll-before",
                    "process",
                    json!({"action": "poll", "process_id": seq.handle}),
                )
            }
            2 => {
                if let Some(pause) = &self.pause_before_write {
                    pause.hold();
                }
                let value = result(request, "poll-before");
                assert_eq!(value["ok"], true, "poll: {value}");
                assert_eq!(value["data"]["status"], "running", "poll: {value}");
                seq.results.push(("poll-before".into(), value));
                tool(
                    "write",
                    "process",
                    json!({"action": "write", "process_id": seq.handle, "data": "PINNED_CHILD_ECHO\n", "timeout_ms": 2000}),
                )
            }
            3 => {
                let value = result(request, "write");
                assert_eq!(value["ok"], true, "write: {value}");
                assert_eq!(value["data"]["wrote_bytes"], "PINNED_CHILD_ECHO\n".len());
                seq.results.push(("write".into(), value));
                seq.poll_deadline = Some(Instant::now() + Duration::from_secs(2));
                tool(
                    "poll-echo-0",
                    "process",
                    json!({"action": "poll", "process_id": seq.handle}),
                )
            }
            4 => {
                let id = format!("poll-echo-{}", seq.polls);
                let value = result(request, &id);
                assert_eq!(value["ok"], true, "echo poll: {value}");
                if value["data"]["stdout"] != "PINNED_CHILD_ECHO\n" {
                    assert!(
                        Instant::now() < seq.poll_deadline.unwrap(),
                        "missing real stdout: {value}"
                    );
                    seq.polls += 1;
                    std::thread::sleep(Duration::from_millis(5));
                    return tool(
                        &format!("poll-echo-{}", seq.polls),
                        "process",
                        json!({"action": "poll", "process_id": seq.handle}),
                    );
                }
                seq.results.push((id, value));
                tool(
                    "kill",
                    "process",
                    json!({"action": "kill", "process_id": seq.handle}),
                )
            }
            5 => {
                let value = result(request, "kill");
                assert_eq!(value["ok"], true, "kill: {value}");
                assert_eq!(value["data"]["status"], "signaled", "kill: {value}");
                seq.results.push(("kill".into(), value));
                // `poll` deliberately reports a killed process as cancelled;
                // `log` observes the same terminal snapshot without cancelling Main.
                tool(
                    "poll-exited",
                    "process",
                    json!({"action": "log", "process_id": seq.handle}),
                )
            }
            6 => {
                let value = result(request, "poll-exited");
                assert_eq!(
                    value["data"]["status"], "signaled",
                    "exit confirmation: {value}"
                );
                seq.results.push(("poll-exited".into(), value));
                response(json!([]), "real process lifecycle complete")
            }
            _ => panic!("unexpected business continuation"),
        };
        seq.step += 1;
        next
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn production_pinned_terminal_process_cross_call_poll_write_kill() {
    let fixture = Fixture::new();
    let service = fixture.service();
    let provider = InteractiveProvider::new(&service);
    service.inject_provider_host(provider.clone());
    let admitted = service.admit_external_with_workspace_selector(
        AdmitRunRequest { input: json!("I authorize /bin/cat in the project workspace, then process poll, write PINNED_CHILD_ECHO newline, poll stdout, kill, and confirm exit."), platform: "http".into(), ..AdmitRunRequest::default() },
        Some("name:project".into())
    ).await.unwrap();
    *provider.run_id.lock().unwrap() = admitted.run_id.clone();
    let worker = service
        .clone()
        .run_worker(admitted.run_id.clone(), String::new());
    tokio::time::timeout(Duration::from_secs(8), worker)
        .await
        .expect("owned worker completion");
    let events = service.run_events(&admitted.run_id);
    assert!(
        events.iter().any(|event| event["event"] == "run.completed"),
        "terminal names: {:?}",
        events
            .iter()
            .map(|event| &event["event"])
            .collect::<Vec<_>>()
    );
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(service.capability_host_closed(&admitted.run_id));
    let sequence = provider.sequence.lock().unwrap();
    assert_eq!(sequence.step, 7);
    let process: &Arc<ProcessCapability> =
        sequence.host.as_ref().unwrap().processes.as_ref().unwrap();
    assert_eq!(process.table_len(), 0);
    assert_eq!(process.active_stdin_workers(), 0);
    for (id, _) in &sequence.results {
        assert!(
            events.iter().any(|event| matches!(
                event["event"].as_str(),
                Some("tool.completed" | "tool.failed")
            ) && event["data"]["tool_call_id"] == id.as_str()),
            "missing durable lifecycle for {id}"
        );
    }
    drop(sequence);
    drop(provider);
    drop(service);
    fixture.cleanup();
}

#[test]
fn child_registration_failure_reaps_only_its_process_and_preserves_siblings() {
    use pinned_process_fixture::NativeFixture;
    let fixture = NativeFixture::new("first-run");
    let other = NativeFixture::new("other-run");
    let mut forged = fixture.parent_call(
        "forged-parent",
        "terminal",
        json!({"argv": ["/bin/cat"], "background": true}),
    );
    forged.arguments = json!({"argv": ["/bin/sh", "-c", "exit 0"], "background": true});
    let rejected = fixture.invoke(forged);
    assert_eq!(rejected["code"], "pinned_call_mismatch", "{rejected}");
    assert_eq!(fixture.processes.table_len(), 0);
    let sibling = fixture.start("sibling");
    let separate = other.start("separate");
    assert_eq!(fixture.processes.table_len(), 1);
    let marker = fixture.root.join("unpublished.pid");
    let pid = Arc::new(Mutex::new(None));
    let interrupt_child = fixture.interrupt_current_child();
    fixture.processes.set_after_os_spawn_hook(Arc::new({
        let marker = marker.clone();
        let pid = pid.clone();
        move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let child = loop {
                if let Ok(text) = fs::read_to_string(&marker)
                    && let Ok(child) = text.parse::<u32>()
                {
                    break child;
                }
                assert!(Instant::now() < deadline, "owned child PID protocol");
                std::thread::sleep(Duration::from_millis(5));
            };
            *pid.lock().unwrap() = Some(child);
            // Drop precisely the current child's real execution lease.
            // Its committed sibling retains the original run generation.
            interrupt_child();
        }
    }));
    let unpublished = fixture.parent_call(
        "unpublished",
        "terminal",
        json!({
            "argv": ["/bin/sh", "-c", "printf '%s' \"$$\" > unpublished.pid; exec /bin/cat"],
            "background": true
        }),
    );
    let failed = fixture.invoke(unpublished);
    assert_eq!(
        failed["ok"], false,
        "registration must fail closed: {failed}"
    );
    let child = pid.lock().unwrap().expect("actual owned child PID");
    assert!(
        !PathBuf::from(format!("/proc/{child}")).exists(),
        "unpublished child must be reaped"
    );
    assert_eq!(fixture.processes.table_len(), 1);
    assert!(fixture.interrupted("unpublished"));
    for (owner, handle) in [(&fixture, &sibling), (&other, &separate)] {
        let write = owner.parent_call("write-after-failure", "process", json!({"action": "write", "process_id": handle, "data": "SURVIVING_OWNER\n", "timeout_ms": 2000}));
        let written = owner.invoke(write);
        assert_eq!(written["ok"], true, "legal sibling write: {written}");
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut ordinal = 0;
        loop {
            let poll = owner.parent_call(
                &format!("survivor-poll-{ordinal}"),
                "process",
                json!({"action": "poll", "process_id": handle}),
            );
            let polled = owner.invoke(poll);
            assert_eq!(polled["ok"], true, "legal sibling poll: {polled}");
            if polled["data"]["stdout"] == "SURVIVING_OWNER\n" {
                break;
            }
            assert!(Instant::now() < deadline, "surviving child stdout");
            ordinal += 1;
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let foreign_call = other.parent_call(
        "foreign-process",
        "process",
        json!({"action": "write", "process_id": sibling, "data": "FORBIDDEN", "timeout_ms": 2000}),
    );
    let foreign = other.invoke(foreign_call);
    assert_eq!(foreign["ok"], false, "other-run handle must fail");
    assert_eq!(foreign["error"]["code"], "process_not_found");
    fixture
        .host
        .cancellation
        .as_ref()
        .unwrap()
        .request(rustscript_agent::CancellationReason::Requested);
    fixture.processes.shutdown_all();
    assert_eq!(fixture.processes.table_len(), 0);
    let write = other.parent_call("other-after-cancel", "process", json!({"action": "write", "process_id": separate, "data": "STILL_LIVE\n", "timeout_ms": 2000}));
    let written = other.invoke(write);
    assert_eq!(
        written["ok"], true,
        "separate run after original cancellation: {written}"
    );
    assert_eq!(other.processes.table_len(), 1);
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !predicate() {
        assert!(Instant::now() < deadline, "owned operation readiness");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_one_production_run_preserves_other_live_process_continuations() {
    let fixture = Fixture::new();
    let service = fixture.service();
    let first = rustscript_agent::ScriptedProvider::new();
    first.push_envelope(tool(
        "first-start",
        "terminal",
        json!({"argv": ["/bin/cat"], "background": true}),
    ));
    first.push_envelope(response(json!([]), r#"{"outcome":"allow","risk_level":"low","user_authorization":"unknown","rationale":"bounded fixture"}"#));
    first.push_hang();
    service.inject_provider_host(Arc::new(first.clone()));
    let first_run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!(
                    "I authorize an owned background /bin/cat in project; I will stop it."
                ),
                platform: "http".into(),
                ..AdmitRunRequest::default()
            },
            Some("name:project".into()),
        )
        .await
        .unwrap();
    let first_worker = tokio::spawn(
        service
            .clone()
            .run_worker(first_run.run_id.clone(), String::new()),
    );
    wait_for(|| first.call_count() == 3 && service.process_owner_count(&first_run.run_id) == 1)
        .await;
    let first_pids = service.process_owner_pids(&first_run.run_id);
    assert_eq!(first_pids.len(), 1);

    let pause = Arc::new(Pause::default());
    let release = ReleasePause(pause.clone());
    let second = Arc::new(InteractiveProvider {
        service: Arc::downgrade(&service),
        run_id: Mutex::new(String::new()),
        sequence: Mutex::new(Sequence::default()),
        pause_before_write: Some(pause.clone()),
    });
    service.inject_provider_host(second.clone());
    let second_run = service.admit_external_with_workspace_selector(
        AdmitRunRequest { input: json!("I authorize /bin/cat, poll, write PINNED_CHILD_ECHO newline, poll stdout, kill and confirm exit."), platform: "http".into(), ..AdmitRunRequest::default() },
        Some("name:project".into())
    ).await.unwrap();
    *second.run_id.lock().unwrap() = second_run.run_id.clone();
    let second_worker = tokio::spawn(
        service
            .clone()
            .run_worker(second_run.run_id.clone(), String::new()),
    );
    wait_for(|| pause.entered.load(std::sync::atomic::Ordering::Acquire)).await;
    let second_pids = service.process_owner_pids(&second_run.run_id);
    assert_eq!(second_pids.len(), 1);
    assert_ne!(first_pids, second_pids);
    assert_eq!(service.stop(&first_run.run_id).as_deref(), Some("stopping"));
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    tokio::time::timeout_at(cleanup_deadline.into(), first_worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(service.process_owner_count(&first_run.run_id), 0);
    assert!(
        first_pids
            .iter()
            .all(|pid| !PathBuf::from(format!("/proc/{pid}")).exists())
    );
    assert_eq!(service.process_owner_count(&second_run.run_id), 1);
    assert!(
        second_pids
            .iter()
            .all(|pid| PathBuf::from(format!("/proc/{pid}")).exists())
    );
    assert!(
        service
            .run_events(&first_run.run_id)
            .iter()
            .any(|event| event["event"] == "run.cancelled")
    );
    drop(release);
    tokio::time::timeout(Duration::from_secs(8), second_worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.sequence.lock().unwrap().step, 7);
    assert!(
        service
            .run_events(&second_run.run_id)
            .iter()
            .any(|event| event["event"] == "run.completed")
    );
    assert_eq!(service.process_owner_count(&second_run.run_id), 0);
    assert!(
        second_pids
            .iter()
            .all(|pid| !PathBuf::from(format!("/proc/{pid}")).exists())
    );
    drop(second);
    drop(service);
    fixture.cleanup();
}

#[tokio::test]
async fn joining_one_storage_worker_keeps_the_separate_repository_usable() {
    let first = Fixture::new();
    let second = Fixture::new();
    let owned = first.state.as_ref().unwrap().persistence().unwrap();
    let sibling = second.state.as_ref().unwrap().persistence().unwrap();
    owned.shutdown();
    assert!(owned.load().is_err());
    assert!(sibling.load().is_ok());
    first.cleanup();
    assert!(sibling.load().is_ok());
    second.cleanup();
}
