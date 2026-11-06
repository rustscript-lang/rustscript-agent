use super::*;

fn configure_gateway_child_scratch(
    command: &mut std::process::Command,
    read_env: impl Fn(&str) -> Option<std::ffi::OsString>,
) {
    let root = PathBuf::from(
        read_env("RUSTSCRIPT_AGENT_TEST_TMP")
            .expect("RUSTSCRIPT_AGENT_TEST_TMP must name the assigned scratch directory"),
    );
    assert!(
        root.is_absolute() && root.is_dir(),
        "RUSTSCRIPT_AGENT_TEST_TMP must be an existing absolute scratch directory"
    );
    for key in [
        "TMPDIR",
        "TMP",
        "TEMP",
        "TEMPDIR",
        "TEST_TMPDIR",
        "RUSTSCRIPT_AGENT_TEST_TMP",
        "RUSTSCRIPT_AGENT_TEST_TMPDIR",
    ] {
        command.env(key, &root);
    }
    if let Some(cef) = read_env("CEF_PATH") {
        command.env("CEF_PATH", cef);
    }
}

#[test]
fn gateway_child_environment_uses_assigned_root_and_optional_cef_only() {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap());
    for cef in [None, Some(root.join("cef").into_os_string())] {
        let mut command =
            std::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"));
        command.env_clear();
        configure_gateway_child_scratch(&mut command, |key| match key {
            "RUSTSCRIPT_AGENT_TEST_TMP" => Some(root.clone().into_os_string()),
            "CEF_PATH" => cef.clone(),
            _ => panic!("unexpected ambient environment read: {key}"),
        });
        let actual = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut expected = [
            "TMPDIR",
            "TMP",
            "TEMP",
            "TEMPDIR",
            "TEST_TMPDIR",
            "RUSTSCRIPT_AGENT_TEST_TMP",
            "RUSTSCRIPT_AGENT_TEST_TMPDIR",
        ]
        .map(|key| (std::ffi::OsStr::new(key), Some(root.as_os_str())))
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
        if let Some(cef) = &cef {
            expected.insert(std::ffi::OsStr::new("CEF_PATH"), Some(cef.as_os_str()));
        }
        assert_eq!(actual, expected);
    }
}

#[test]
fn gateway_child_environment_requires_an_assigned_directory() {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap());
    for invalid in [
        None,
        Some(std::ffi::OsString::new()),
        Some(std::ffi::OsString::from("relative")),
        Some(
            root.join(uuid::Uuid::new_v4().simple().to_string())
                .into_os_string(),
        ),
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                let mut command =
                    std::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"));
                command.env_clear();
                configure_gateway_child_scratch(&mut command, |key| {
                    assert_eq!(key, "RUSTSCRIPT_AGENT_TEST_TMP");
                    invalid.clone()
                });
            })
            .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn normal_managed_binary_reaches_listener_with_private_store_and_acknowledged_owned_shutdown()
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let fixture = ManagedFixture::new(|_| {});
    fixture.state.service().shutdown().await.unwrap();
    let ManagedFixture {
        root, home, state, ..
    } = fixture;
    drop(state);
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_rustscript-agent-gateway"));
    let mut command = tokio::process::Command::new(&executable);
    command
        .kill_on_drop(true)
        .env_clear()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("RUSTSCRIPT_AGENT_HOME", &home)
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_MANAGED_WORKSPACE", root.join("workspace"))
        .env("RUSTSCRIPT_AGENT_STATE_DB", root.join("gateway.sqlite"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    configure_gateway_child_scratch(command.as_std_mut(), |key| std::env::var_os(key));
    let mut child = command.spawn().unwrap();
    let pid = child.id().unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut ready = None;
    for _ in 0..16 {
        match tokio::time::timeout_at(deadline, stderr.next_line()).await {
            Ok(Ok(Some(line))) if line.contains("listening on http://127.0.0.1:") => {
                ready = line
                    .rsplit_once("http://")
                    .and_then(|(_, address)| address.parse::<std::net::SocketAddr>().ok());
                break;
            }
            Ok(Ok(Some(_))) => {}
            _ => break,
        }
    }
    if ready.is_none() {
        let _ = child.start_kill();
        let status = child.wait().await.unwrap();
        panic!("normal managed binary did not reach its listener; owned child status={status}");
    }
    let owned = fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|path| path == executable)
        && fs::read_link(format!("/proc/{pid}/cwd"))
            .is_ok_and(|path| path == std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let initialized = root.join(".gateway.sqlite.effects/store-id").is_file();
    let no_import = fs::read_dir(root.join(".gateway.sqlite.effects/trees"))
        .is_ok_and(|entries| entries.count() == 0);
    let served: Result<bool, String> = async {
        let mut socket =
            tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(ready.unwrap()))
                .await
                .map_err(|_| "connect deadline")?
                .map_err(|_| "connect failed")?;
        socket
            .write_all(
                b"GET /health/detailed HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .map_err(|_| "request failed")?;
        let mut prefix = [0; 512];
        let received = tokio::time::timeout_at(deadline, socket.read(&mut prefix))
            .await
            .map_err(|_| "response deadline")?
            .map_err(|_| "response failed")?;
        Ok(prefix[..received].starts_with(b"HTTP/1.1 200"))
    }
    .await;
    if owned {
        unsafe { libc::kill(pid as i32, libc::SIGINT) };
    } else {
        let _ = child.start_kill();
    }
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            child.start_kill().unwrap();
            let status = child.wait().await.unwrap();
            panic!("owned binary exceeded shutdown acknowledgement bound: {status}");
        }
    };
    drop(stderr);
    assert!(owned);
    assert!(
        initialized && no_import,
        "startup must create the private store without importing before current admission authority"
    );
    assert_eq!(served, Ok(true));
    assert!(status.success(), "owned gateway exit status={status}");
    assert!(child.id().is_none());
}

#[test]
fn normal_gateway_binary_rejects_managed_without_persistence_before_binding_listener() {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-binary-{}", uuid::Uuid::new_v4().simple()));
    let home = root.join("home");
    let workspace = root.join("workspace");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir(&workspace).unwrap();
    for (source, database, expected) in [
        (workspace.as_os_str(), None, "persistence"),
        (workspace.as_os_str(), Some(":memory:"), "persistent"),
        (
            std::ffi::OsStr::new("relative"),
            Some(":memory:"),
            "absolute",
        ),
    ] {
        let mut command =
            std::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"));
        command
            .env_clear()
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("RUSTSCRIPT_AGENT_HOME", &home)
            .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
            .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
            .env("RUSTSCRIPT_AGENT_MANAGED_WORKSPACE", source);
        configure_gateway_child_scratch(&mut command, |key| std::env::var_os(key));
        if let Some(database) = database {
            command.env("RUSTSCRIPT_AGENT_STATE_DB", database);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(!diagnostic.contains("listening on"));
        assert!(
            diagnostic.contains(expected),
            "normal binary must reject the managed startup condition: {diagnostic}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_source_persistent_constructor_installs_managed_store_and_requires_current_authority()
 {
    let fixture = ManagedFixture::new(|_| {});
    fixture.state.service().shutdown().await.unwrap();
    let ManagedFixture {
        root,
        home,
        config,
        state,
    } = fixture;
    drop(state);
    let source =
        "pub fn run(context:map)->map {{kind:\"run.completed\",answer:\"constructor reached\"}}";
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        config,
        source,
        root.join("gateway.sqlite"),
    )
    .unwrap()
    .with_workspace_home(home);
    let run = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"normal custom source persistent constructor"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    state
        .service()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    assert!(
        state
            .service()
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "run.completed")
    );
    assert!(root.join(".gateway.sqlite.effects/store-id").is_file());
    state.service().shutdown().await.unwrap();
}

/// Second-process restart qualification. The helper runs in the current
/// integration-test binary as an independent OS process: it reopens the
/// fixture's persistent store and performs one real production admission.
struct RestartWindowProvider {
    covered: bool,
    turns: std::sync::Mutex<usize>,
}

impl rustscript_agent::AgentProviderHost for RestartWindowProvider {
    fn call(
        &self,
        request: &serde_json::Value,
        _cancellation: &rustscript_agent::RunCancellation,
    ) -> Value {
        let handle = find_process_id(request).unwrap_or_default();
        let reply = |call: Option<Value>| {
            json!({"text":if call.is_some() { "" } else { "done" },
                "tool_calls":call.into_iter().collect::<Vec<_>>(),
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"})
        };
        let turn = {
            let mut turns = self.turns.lock().unwrap();
            *turns += 1;
            *turns
        };
        let response = if self.covered {
            match turn {
                1 => reply(Some(json!({"id":"spawn","name":"terminal","arguments":{
                    "argv":["/bin/sh","-c","printf 'child\n'; sleep 0.4"],
                    "background":true,"timeout_ms":5000}}))),
                2 => reply(Some(json!({"id":"wait","name":"process","arguments":{
                    "action":"wait","process_id":handle,"timeout_ms":5000}}))),
                _ => reply(None),
            }
        } else {
            match turn {
                1 => reply(Some(json!({"id":"spawn","name":"terminal","arguments":{
                    "argv":["/bin/sh","-c","sleep 30"],
                    "background":true,"timeout_ms":60000}}))),
                _ => reply(None),
            }
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_history_second_process_helper() {
    let Ok(scenario) = std::env::var("RUSTSCRIPT_AGENT_RESTART_HELPER") else {
        return;
    };
    let home = PathBuf::from(std::env::var("RESTART_HELPER_HOME").expect("helper home"));
    let source = PathBuf::from(std::env::var("RESTART_HELPER_SOURCE").expect("helper source"));
    let database = PathBuf::from(std::env::var("RESTART_HELPER_DB").expect("helper db"));
    let mut config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: source,
            quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: Default::default(),
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, &database)
        .expect("helper reopen")
        .with_workspace_home(&home);
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"after-restart","name":"write_file",
        "arguments":{"path":"after.txt","content":"after"}}))));
    provider.push_ok(response(None));
    state.service().inject_provider_host(provider);
    let outcome = match state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"second process admission"}),
                ..Default::default()
            },
            None,
        )
        .await
    {
        Ok(run) => {
            state
                .service()
                .clone()
                .run_worker(run.run_id.clone(), "ignored".into())
                .await;
            "admitted".to_string()
        }
        Err(error) => format!("{error:?}"),
    };
    if outcome.contains("managed_restart_unresolved") {
        println!("HELPER admission=unresolved");
    } else if outcome == "admitted" {
        println!("HELPER admission=admitted");
    } else {
        println!("HELPER admission=other:{outcome}");
    }
    let _ = scenario;
    state.service().shutdown().await.expect("helper shutdown");
}

fn run_second_process(scenario: &str, root: &std::path::Path) -> String {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("startup_matrix::restart_history_second_process_helper")
        .arg("--nocapture")
        .env("RUSTSCRIPT_AGENT_RESTART_HELPER", scenario)
        .env("RESTART_HELPER_HOME", root.join("home"))
        .env("RESTART_HELPER_SOURCE", root.join("workspace"))
        .env("RESTART_HELPER_DB", root.join("gateway.sqlite"));
    configure_gateway_child_scratch(&mut command, |key| std::env::var_os(key));
    let output = command.output().expect("second process");
    assert!(
        output.status.success(),
        "helper status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|line| line.starts_with("HELPER admission="))
        .expect("helper admission line");
    line.trim().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_restart_second_process_requires_a_covering_finalizer() {
    for covered in [false, true] {
        let fixture = ManagedFixture::new(|_| {});
        let provider: Arc<dyn rustscript_agent::AgentProviderHost> =
            Arc::new(RestartWindowProvider {
                covered,
                turns: std::sync::Mutex::new(0),
            });
        fixture.state.service().inject_provider_host(provider);
        let run = fixture
            .state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"restart history producer"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        fixture
            .state
            .service()
            .clone()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        if !covered {
            // Paired positive control: after the run's typed terminal cleanup
            // proved this same process quiescent and released the branch
            // writer, the next admission is allowed even though durable
            // history still has no wait/kill finalizer for the producer.
            let positive = Arc::new(ScriptedProvider::new());
            positive.push_ok(response(Some(json!({
                "id":"after-quiescent",
                "name":"write_file",
                "arguments":{"path":"after-quiescent.txt","content":"after"}
            }))));
            positive.push_ok(response(None));
            fixture.state.service().inject_provider_host(positive);
            let second = fixture
                .state
                .service()
                .admit_external_with_workspace_selector(
                    AdmitRunRequest {
                        input: json!({"message":"same process after quiescent"}),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .expect("a proven live quiescent branch admits the next run");
            fixture
                .state
                .service()
                .clone()
                .run_worker(second.run_id.clone(), "ignored".into())
                .await;
        }
        fixture.state.service().shutdown().await.unwrap();
        let ManagedFixture { root, state, .. } = fixture;
        drop(state);
        let line = run_second_process(if covered { "covered" } else { "uncovered" }, &root);
        if covered {
            assert!(
                line.contains("admission=admitted"),
                "a producer with an exact covering wait finalizer resolves: {line}"
            );
        } else {
            assert!(
                line.contains("admission=unresolved"),
                "an uncovered committed producer fails closed in a second process: {line}"
            );
        }
    }
}

/// Provider that drives a real background producer on a selected branch and,
/// for the covered control, its exact Native wait finalizer.
struct BranchProducerProvider {
    covered: bool,
    turns: std::sync::Mutex<usize>,
    handles: std::sync::Mutex<Vec<String>>,
}

fn request_handles(value: &Value) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, field) in fields {
                    if key == "process_id"
                        && let Value::String(id) = field
                        && !out.iter().any(|seen| seen == id)
                    {
                        out.push(id.clone());
                    }
                    walk(field, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

impl rustscript_agent::AgentProviderHost for BranchProducerProvider {
    fn call(&self, request: &Value, _cancel: &rustscript_agent::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        *self.handles.lock().unwrap() = request_handles(request);
        let handle = self
            .handles
            .lock()
            .unwrap()
            .first()
            .cloned()
            .unwrap_or_default();
        let reply = |call: Value| {
            json!({"text":"","tool_calls":[call],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"})
        };
        let response = match turn {
            1 => reply(json!({"id":"spawn","name":"terminal","arguments":{
                "argv":["/bin/sh","-c",if self.covered {"printf 'covered'; sleep 0.3"} else {"sleep 30"}],
                "background":true,"timeout_ms":60000}})),
            2 if self.covered => reply(json!({"id":"wait","name":"process","arguments":{
                "action":"wait","process_id":handle,"timeout_ms":5000}})),
            _ => json!({"text":"done","tool_calls":[],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"}),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

async fn admit_branch_run(
    service: &Arc<rustscript_agent::AgentService>,
    branch_id: &str,
    covered: bool,
) -> rustscript_agent::AdmittedRun {
    service.inject_provider_host(Arc::new(BranchProducerProvider {
        covered,
        turns: std::sync::Mutex::new(0),
        handles: std::sync::Mutex::new(Vec::new()),
    }));
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"branch producer run"}),
                workspace_branch: Some(branch_id.to_string()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("branch producer admission");
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    run
}

/// A supported `branch_create` receipt replay is the cold-start first touch of
/// that branch object. It must install the same startup seal and derive/adopt
/// the branch's durable history before any later admission can OS-spawn. An
/// uncovered producer stays Unresolved; empty and covered histories admit.
/// This reopens a fresh Native runtime over the same store in this test
/// process; it is not a second OS process end-to-end.
#[tokio::test(flavor = "multi_thread")]
async fn branch_create_receipt_replay_is_fenced_until_startup_derivation() {
    use rustscript_agent::effects::{
        ManagedBranchCreateRequest, ManagedEffectGetRequest, ManagedOwnerScope, ManagedSourceCas,
    };
    let fixture = ManagedFixture::new(|config| {
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
        config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy
            .branch = true;
    });
    let service = fixture.state.service();
    let seed = fixture
        .calls(vec![json!({"id":"seed","name":"write_file","arguments":{
            "path":"seed.txt","content":"seed"}})])
        .await;
    let persistence = fixture.state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: seed.session_id.clone(),
                run_id: seed.run_id.clone(),
            },
            call_id: "seed".into(),
        })
        .unwrap()
        .expect("seed receipt");
    let identity = record.identity.workspace.clone();
    let head = persistence.managed_workspace_head(&identity).unwrap();
    let source = ManagedSourceCas {
        store_id: head.store_id.clone(),
        workspace_id: head.workspace_id.clone(),
        branch_id: head.branch_id.clone(),
        epoch: head.epoch,
        head_object_id: head.head_object_id.clone(),
        head_version: head.head_version,
    };
    let branch_request = |request_id: &str| ManagedBranchCreateRequest {
        workspace_id: identity.workspace_id.clone(),
        source_branch_id: identity.branch_id.clone(),
        checkpoint_id: None,
        expected_source: Some(source.clone()),
        request_id: request_id.to_string(),
    };
    let uncovered = service
        .create_managed_branch(branch_request("8f6f9d0e-1c2b-4f40-9d1a-2b3c4d5e6f70"))
        .await
        .expect("uncovered branch create")
        .branch;
    let clean = service
        .create_managed_branch(branch_request("8f6f9d0e-1c2b-4f40-9d1a-2b3c4d5e6f71"))
        .await
        .expect("clean branch create")
        .branch;
    let covered = service
        .create_managed_branch(branch_request("8f6f9d0e-1c2b-4f40-9d1a-2b3c4d5e6f72"))
        .await
        .expect("covered branch create")
        .branch;
    let fresh_head = persistence
        .managed_workspace_head(&rustscript_agent::effects::ManagedWorkspaceIdentity {
            branch_id: uncovered.branch_id.clone(),
            ..identity.clone()
        })
        .unwrap();
    assert!(!fresh_head.process_lineage_tainted);
    admit_branch_run(&service, &uncovered.branch_id, false).await;
    admit_branch_run(&service, &covered.branch_id, true).await;
    drop(persistence);
    service.shutdown().await.unwrap();
    drop(service);
    let ManagedFixture {
        root, home, config, state,
    } = fixture;
    drop(state);
    // Cold Native runtime: no in-memory branch map, same durable store.
    let state2 = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .expect("cold reopen")
        .with_workspace_home(&home);
    let service2 = state2.service();
    // Historical branch receipts remain replayable facts for every branch.
    for (request_id, branch) in [
        (
            "8f6f9d0e-1c2b-4f40-9d1a-2b3c4d5e6f70",
            &uncovered,
        ),
        (
            "8f6f9d0e-1c2b-4f40-9d1a-2b3c4d5e6f71",
            &clean,
        ),
        (
            "8f6f9d0e-1c2b-4f40-9d1a-2b3c4d5e6f72",
            &covered,
        ),
    ] {
        let receipt = service2
            .create_managed_branch(branch_request(request_id))
            .await
            .expect("historical branch receipt replay");
        assert!(receipt.replayed, "the existing receipt is replayed");
        assert_eq!(receipt.branch.branch_id, branch.branch_id);
    }
    // The uncovered producer history must fence the branch before admission.
    let blocked = service2
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"cold uncovered admission"}),
                workspace_branch: Some(uncovered.branch_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await;
    let message = blocked.as_ref().err().map(|error| format!("{error:?}"));
    assert!(
        message
            .as_deref()
            .is_some_and(|message| message.contains("managed_restart_unresolved")),
        "an uncovered replayed branch must not OS-spawn: {blocked:?}"
    );
    // Empty history positive control.
    let admitted_clean = service2
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"clean branch admission"}),
                workspace_branch: Some(clean.branch_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("an empty replayed history resolves");
    service2
        .clone()
        .run_worker(admitted_clean.run_id.clone(), "ignored".into())
        .await;
    // Covered history: the replay derivation resolves the Native writer (the
    // refusal below is the independent existing process-lineage-taint fence of
    // a branch that ran a process, not a restart-unresolved verdict).
    let covered_admission = service2
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"covered branch admission"}),
                workspace_branch: Some(covered.branch_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await;
    match covered_admission {
        Ok(run) => {
            service2
                .clone()
                .run_worker(run.run_id.clone(), "ignored".into())
                .await;
        }
        Err(error) => {
            let message = format!("{error:?}");
            assert!(
                !message.contains("managed_restart_unresolved"),
                "a covered producer history must derive Resolved: {message}"
            );
            assert!(
                message.contains("managed_source_conflict"),
                "the remaining refusal is the pre-existing lineage-taint fence: {message}"
            );
        }
    }
    service2.shutdown().await.unwrap();
}
