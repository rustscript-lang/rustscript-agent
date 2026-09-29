use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        },
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

fn fixture_home() -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
    let home = root.join(format!(
        "oauth-transport-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&home).expect("private home");
    #[cfg(unix)]
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("config");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("auth")
        .replace("1788440000000", "1900000000000");
    fs::write(home.join("auth.yaml"), auth).expect("auth");
    #[cfg(unix)]
    for name in ["config.yaml", "auth.yaml"] {
        fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600)).expect("file mode");
    }
    home
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected map")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn vm() -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/transport_contract.rss");
    let source = fs::read_to_string(&path).expect("real RSS entry");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real RSS entry");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host")
    .register(&mut registry, catalog.as_ref())
    .expect("register");
    registry.bind_vm_cached(&mut vm).expect("bind registry");
    assert!(matches!(vm.run().expect("root"), VmStatus::Halted));
    vm
}

#[test]
fn policy_and_credential_use_rejections_never_send() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let context = host.bind_vm(&mut vm).expect("bind");
    let home = field(&context, "host_home").clone();
    let probe = vm
        .resolve_exported_callable("probe")
        .expect("real RSS probe");
    for (path, method, header, kind, supplied) in [
        (
            "https://evil.example/oauth/token",
            "GET",
            "accept",
            "none",
            false,
        ),
        ("/other/endpoint", "GET", "accept", "none", false),
        ("//evil.example/oauth/token", "GET", "accept", "none", false),
        ("/oauth/token", "DELETE", "accept", "none", false),
        ("/oauth/token", "GET", "Host", "none", false),
        ("/oauth/token", "GET", "Authorization", "none", false),
        ("/oauth/token", "GET", "cookie", "none", false),
        ("/oauth/token", "GET", "accept", "access", false),
        ("/oauth/token", "GET", "accept", "refresh", false),
        ("/oauth/token", "GET", "accept", "authorization_code", false),
        ("/oauth/token", "GET", "accept", "device", false),
        ("/oauth/token", "GET", "accept", "mystery", false),
        ("/oauth/token", "GET", "accept", "none", true),
    ] {
        let failure = vm
            .invoke_callable(
                probe.clone(),
                &[
                    home.clone(),
                    Value::string("fixture-codex"),
                    Value::string(path),
                    Value::string(method),
                    Value::string(header),
                    Value::string(kind),
                    Value::Bool(supplied),
                ],
            )
            .expect_err("denied before send");
        let text = failure.to_string();
        assert!(!text.contains("SYNTHETIC_ACCESS_TOKEN"), "{text}");
        assert!(
            transport.take_sent().is_empty(),
            "sent on {path} {kind} {header}"
        );
    }
    let failure = vm
        .invoke_callable(
            probe,
            &[
                home,
                Value::string("unadmitted"),
                Value::string("/oauth/token"),
                Value::string("GET"),
                Value::string("accept"),
                Value::string("none"),
                Value::Bool(false),
            ],
        )
        .expect_err("credential admission");
    assert!(failure.to_string().contains("credential_not_admitted"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn rss_no_credential_transport_returns_sanitized_public_body_and_host_slots() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        serde_json::json!({
            "access_token": "SYNTHETIC_ACCESS_TOKEN",
            "refresh_token": "SYNTHETIC_REFRESH_TOKEN",
            "public": "accepted"
        }),
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let context = host.bind_vm(&mut vm).expect("bind home");
    let callable = vm.resolve_exported_callable("run").expect("entry");
    let response = vm
        .invoke_callable(callable, &[field(&context, "host_home").clone()])
        .expect("transport");
    assert_eq!(field(&response, "ok"), &Value::Bool(true));
    assert_eq!(field(&response, "status"), &Value::Int(200));
    let Value::Array(headers) = field(&response, "public_headers") else {
        panic!("typed headers")
    };
    assert_eq!(headers.len(), 1);
    assert_eq!(field(&headers[0], "name"), &Value::string("content-type"));
    assert_eq!(
        field(&headers[0], "value"),
        &Value::string("application/json")
    );
    assert_eq!(
        field(&response, "body_without_secret_fields"),
        &Value::string(r#"{"public":"accepted"}"#)
    );
    assert!(matches!(field(&response, "access_slot"), Value::Int(_)));
    assert!(matches!(field(&response, "refresh_slot"), Value::Int(_)));
    for secret in ["SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_REFRESH_TOKEN"] {
        assert!(!format!("{response:?}").contains(secret));
    }
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, "https://auth.openai.com/oauth/token");
    assert_eq!(sent[0].method, "GET");
    assert_eq!(
        sent[0].headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    assert!(!format!("{:?}", sent[0]).contains("SYNTHETIC_ACCESS_TOKEN"));
}

#[test]
fn missing_transport_fails_without_network() {
    let mut vm = vm();
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    let run = vm.resolve_exported_callable("run").expect("run");
    let failure = vm
        .invoke_callable(run, &[home])
        .expect_err("no transport dependency");
    assert!(failure.to_string().contains("transport_unavailable"));
}

#[test]
fn hostile_responses_never_reach_value() {
    for body in [
        format!("{{\"access_token\":\"{}\"}}", "X".repeat(65536)),
        "{\"Authorization\": \"SYNTHETIC_ACCESS_TOKEN\", \"nested\": [".to_owned()
            + &"[".repeat(10)
            + &"]".repeat(10)
            + "}",
        "{not-json\"SYNTHETIC_ACCESS_TOKEN\"}".to_owned(),
    ] {
        let mut vm = vm();
        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_raw(200, &body);
        let oauth = Arc::new(OAuthHost::new(
            transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let host = AuthHost::new(
            fixture_home(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("host")
        .with_oauth_host(oauth);
        let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
        let run = vm.resolve_exported_callable("run").expect("run");
        let failure = vm
            .invoke_callable(run, &[home])
            .expect_err("malicious body denied");
        assert!(!failure.to_string().contains("SYNTHETIC_ACCESS_TOKEN"));
        assert_eq!(transport.take_sent().len(), 1);
    }
}

struct CancelAfterSend {
    cancel: RunCancellation,
    sent: std::sync::atomic::AtomicUsize,
}
impl rustscript_agent::auth::oauth::BoundedHttpsTransport for CancelAfterSend {
    fn send(
        &self,
        _: &rustscript_agent::auth::oauth::PreparedHttpsRequest,
        _: &rustscript_agent::auth::oauth::OAuthIoContext,
    ) -> Result<
        rustscript_agent::auth::oauth::RawHttpsResponse,
        rustscript_agent::auth::oauth::OAuthError,
    > {
        self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.cancel.request(CancellationReason::Requested);
        Ok(rustscript_agent::auth::oauth::RawHttpsResponse {
            status: 200, headers: Default::default(),
            body: br#"{"access_token":"SYNTHETIC_ACCESS_TOKEN","refresh_token":"SYNTHETIC_REFRESH_TOKEN"}"#.to_vec(),
        })
    }
}

#[test]
fn late_scope_cancellation_discards_new_slots() {
    let mut vm = vm();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let transport = Arc::new(CancelAfterSend {
        cancel: cancellation.clone(),
        sent: Default::default(),
    });
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(fixture_home(), cancellation)
        .expect("host")
        .with_oauth_host(oauth);
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    let run = vm.resolve_exported_callable("run").expect("run");
    let failure = vm
        .invoke_callable(run, &[home])
        .expect_err("late cancellation");
    assert!(failure.to_string().contains("policy_inactive"));
    assert!(!failure.to_string().contains("SYNTHETIC_ACCESS_TOKEN"));
    assert_eq!(transport.sent.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn foreign_home_and_revoked_owner_never_send() {
    let mut origin = vm();
    let origin_host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("origin");
    let foreign = field(
        &origin_host.bind_vm(&mut origin).expect("origin bind"),
        "host_home",
    )
    .clone();
    let mut target = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home = field(&host.bind_vm(&mut target).expect("bind"), "host_home").clone();
    let run = target.resolve_exported_callable("run").expect("run");
    for invalid in [foreign, Value::Int(i64::MAX)] {
        target
            .invoke_callable(run.clone(), &[invalid])
            .expect_err("foreign or forged home");
        assert!(transport.take_sent().is_empty());
    }
    host.revoke();
    let failure = target
        .invoke_callable(run, &[home])
        .expect_err("revoked owner");
    assert!(failure.to_string().contains("policy_inactive"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn supplied_refresh_handle_is_denied_before_send() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    let probe = vm
        .resolve_exported_callable("probe_refresh")
        .expect("refresh probe");
    let failure = vm
        .invoke_callable(probe, &[home])
        .expect_err("none with refresh denied");
    assert!(failure.to_string().contains("credential_use_unsupported"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn expired_bound_policy_never_sends() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(1)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    let snapshot = vm
        .resolve_exported_callable("snapshot_only")
        .expect("snapshot");
    let policy = vm
        .invoke_callable(snapshot, std::slice::from_ref(&home))
        .expect("policy");
    let deadline = host
        .trusted_transport_policy(&mut vm, &policy, "fixture-codex")
        .expect("policy")
        .deadline;
    std::thread::sleep(
        deadline.saturating_duration_since(std::time::Instant::now()) + Duration::from_millis(5),
    );
    let run = vm.resolve_exported_callable("run").expect("run");
    let failure = vm.invoke_callable(run, &[home]).expect_err("expired owner");
    assert!(failure.to_string().contains("policy_inactive"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn unsupported_device_handle_is_terminalized_with_accompanying_slots() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    for _ in 0..65 {
        transport.push_raw(200, r#"{"device_code":"SYNTHETIC_DEVICE_CODE","access_token":"SYNTHETIC_ACCESS_TOKEN","refresh_token":"SYNTHETIC_REFRESH_TOKEN"}"#);
    }
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    let run = vm.resolve_exported_callable("run").expect("run");
    for _ in 0..65 {
        let failure = vm
            .invoke_callable(run.clone(), std::slice::from_ref(&home))
            .expect_err("device handle unsupported");
        assert!(failure.to_string().contains("response_handle_unsupported"));
        assert!(!failure.to_string().contains("SYNTHETIC_DEVICE_CODE"));
        assert_eq!(vm.host_context().resource_count(), 2);
    }
    assert_eq!(transport.take_sent().len(), 65);
}

#[cfg(feature = "config-fixture")]
#[test]
fn copied_cross_vm_policy_is_denied_before_transport() {
    let mut origin = vm();
    let origin_host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("origin");
    let origin_home = field(
        &origin_host.bind_vm(&mut origin).expect("bind origin"),
        "host_home",
    )
    .clone();
    let snapshot = origin
        .resolve_exported_callable("snapshot_only")
        .expect("snapshot");
    let foreign_policy = origin
        .invoke_callable(snapshot, &[origin_home])
        .expect("issued policy");
    let mut target = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home = field(
        &host.bind_vm(&mut target).expect("bind target"),
        "host_home",
    )
    .clone();
    let snapshot = target
        .resolve_exported_callable("snapshot_only")
        .expect("snapshot");
    let local = target
        .invoke_callable(snapshot, &[home])
        .expect("local policy");
    let probe = target
        .resolve_exported_callable("probe_policy")
        .expect("policy probe");
    for invalid in [foreign_policy, Value::Int(i64::MAX)] {
        target
            .invoke_callable(probe.clone(), &[invalid])
            .expect_err("foreign or forged policy");
        assert!(transport.take_sent().is_empty());
    }
    transport.push_raw(200, "{}");
    assert_eq!(
        field(
            &target
                .invoke_callable(probe, &[local])
                .expect("local policy"),
            "ok"
        ),
        &Value::Bool(true)
    );
    assert_eq!(transport.take_sent().len(), 1);
}

#[cfg(feature = "config-fixture")]
#[test]
fn partial_slot_issue_rolls_back_first_slot() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_ACCESS_TOKEN","refresh_token":"SYNTHETIC_REFRESH_TOKEN"}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    // Snapshot creates the policy resource; 61 fixture slots leave exactly one arena slot.
    let snapshot = vm
        .resolve_exported_callable("snapshot_only")
        .expect("snapshot entry");
    vm.invoke_callable(snapshot, std::slice::from_ref(&home))
        .expect("policy");
    for _ in 0..61 {
        host.fixture_slot(&mut vm, "fixture-codex", 0, false, "fixture-secret")
            .expect("fill arena");
    }
    assert_eq!(vm.host_context().resource_count(), 63);
    let run = vm.resolve_exported_callable("run").expect("run");
    let failure = vm
        .invoke_callable(run, &[home])
        .expect_err("second slot has no capacity");
    assert!(failure.to_string().contains("resource_limit"));
    assert_eq!(vm.host_context().resource_count(), 63);
}
