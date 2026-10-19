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
