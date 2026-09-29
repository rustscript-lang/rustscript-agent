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
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc, time::Duration};

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
fn access_transport_injects_bearer_and_preserves_slot_generation() {
    let mut vm = vm();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_NEW_ACCESS","public":"ok"}"#,
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
    let home = field(&host.bind_vm(&mut vm).expect("bind"), "host_home").clone();
    let call = vm
        .resolve_exported_callable("access_transport")
        .expect("RSS entry");
    let response = vm.invoke_callable(call, &[home]).expect("access transport");
    assert_eq!(field(&response, "status"), &Value::Int(200));
    assert_eq!(
        field(&response, "body"),
        &Value::string(r#"{"public":"ok"}"#)
    );
    assert!(matches!(field(&response, "access_slot"), Value::Int(_)));
    assert!(!format!("{response:?}").contains("SYNTHETIC_NEW_ACCESS"));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN")
    );
    assert!(!format!("{:?}", sent[0]).contains("SYNTHETIC_ACCESS_TOKEN"));
    assert_eq!(vm.host_context().resource_count(), 3);
}

fn bound_bridge() -> (Vm, AuthHost, Arc<ScriptedHttpsTransport>, Value) {
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
    (vm, host, transport, home)
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let call = vm.resolve_exported_callable(name).expect("RSS entry");
    vm.invoke_callable(call, args)
}

#[test]
fn refresh_transport_injects_form_once_and_closes_alias() {
    let (mut vm, _, transport, home) = bound_bridge();
    let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
    let refresh = invoke(&mut vm, "issue_refresh", std::slice::from_ref(&policy)).expect("refresh");
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_NEW_ACCESS","refresh_token":"SYNTHETIC_NEW_REFRESH"}"#,
    );
    let args = [
        policy.clone(),
        refresh.clone(),
        Value::string("fixture-codex"),
        Value::string("/oauth/token"),
        Value::string("refresh"),
        Value::string("grant_type=refresh_token"),
    ];
    let response = invoke(&mut vm, "send_refresh", &args).expect("refresh send");
    assert_eq!(field(&response, "status"), &Value::Int(200));
    assert!(matches!(field(&response, "access_slot"), Value::Int(_)));
    assert!(matches!(field(&response, "refresh_slot"), Value::Int(_)));
    assert!(!format!("{response:?}").contains("SYNTHETIC_NEW_REFRESH"));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].body,
        "grant_type=refresh_token&refresh_token=SYNTHETIC_REFRESH_TOKEN"
    );
    assert!(!format!("{:?}", sent[0]).contains("SYNTHETIC_REFRESH_TOKEN"));
    assert_eq!(vm.host_context().resource_count(), 4);
    assert!(invoke(&mut vm, "send_refresh", &args).is_err());
    assert!(transport.take_sent().is_empty());
}

#[test]
fn access_local_rejection_retains_handle_for_retry_then_replay_fails() {
    let (mut vm, _, transport, home) = bound_bridge();
    let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
    let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy)).expect("access");
    let mut args = [
        policy,
        access,
        Value::string("fixture-codex"),
        Value::string("/oauth/token"),
        Value::string("access"),
        Value::string(""),
    ];
    for (index, value) in [
        (2, "unadmitted"),
        (3, "//evil.example/token"),
        (4, "refresh"),
        (5, "refresh_token=forged"),
    ] {
        let original = args[index].clone();
        args[index] = Value::string(value);
        let failure = invoke(&mut vm, "send_access", &args).expect_err("local denial");
        assert!(!failure.to_string().contains("SYNTHETIC_ACCESS_TOKEN"));
        assert_eq!(vm.host_context().resource_count(), 3);
        assert!(transport.take_sent().is_empty());
        args[index] = original;
    }
    transport.push_raw(200, "{}");
    assert_eq!(
        field(
            &invoke(&mut vm, "send_access", &args).expect("retry"),
            "status"
        ),
        &Value::Int(200)
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(transport.take_sent().len(), 1);
    assert!(invoke(&mut vm, "send_access", &args).is_err());
    assert!(transport.take_sent().is_empty());
}

#[test]
fn refresh_rejects_shapes_and_local_form_then_retries() {
    let (mut vm, _, transport, home) = bound_bridge();
    let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
    let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy)).expect("access");
    let refresh = invoke(&mut vm, "issue_refresh", std::slice::from_ref(&policy)).expect("refresh");
    let both = [policy.clone(), access, refresh.clone()];
    assert!(invoke(&mut vm, "send_both", &both).is_err());
    let mut args = [
        policy,
        refresh,
        Value::string("fixture-codex"),
        Value::string("/oauth/token"),
        Value::string("refresh"),
        Value::string("grant_type=refresh_token"),
    ];
    for (index, invalid) in [
        (2, "unadmitted"),
        (3, "//evil.example/token"),
        (4, "access"),
        (5, "refresh_token=forged"),
    ] {
        let valid = args[index].clone();
        args[index] = Value::string(invalid);
        assert!(invoke(&mut vm, "send_refresh", &args).is_err());
        assert_eq!(vm.host_context().resource_count(), 4);
        assert!(transport.take_sent().is_empty());
        args[index] = valid;
    }
    transport.push_raw(200, "{}");
    assert_eq!(
        field(
            &invoke(&mut vm, "send_refresh", &args).expect("retry"),
            "status"
        ),
        &Value::Int(200)
    );
    assert_eq!(vm.host_context().resource_count(), 3);
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn foreign_resources_wrong_class_and_generation_fail_before_send() {
    let (mut origin, _, _, home) = bound_bridge();
    let policy = invoke(&mut origin, "snapshot_only", &[home]).expect("policy");
    let access =
        invoke(&mut origin, "issue_access", std::slice::from_ref(&policy)).expect("access");
    let refresh =
        invoke(&mut origin, "issue_refresh", std::slice::from_ref(&policy)).expect("refresh");
    assert!(
        invoke(
            &mut origin,
            "issue_wrong_generation",
            std::slice::from_ref(&policy)
        )
        .is_err()
    );
    let (mut target, _, transport, target_home) = bound_bridge();
    let target_policy = invoke(&mut target, "snapshot_only", &[target_home]).expect("policy");
    let defaults = [
        Value::string("fixture-codex"),
        Value::string("/oauth/token"),
        Value::string("access"),
        Value::string(""),
    ];
    for (policy_arg, handle_arg) in [
        (policy.clone(), access.clone()),
        (target_policy.clone(), access.clone()),
        (target_policy.clone(), refresh.clone()),
        (target_policy.clone(), Value::Int(i64::MAX)),
    ] {
        let args = [vec![policy_arg, handle_arg], defaults.to_vec()].concat();
        assert!(invoke(&mut target, "send_access", &args).is_err());
        assert!(transport.take_sent().is_empty());
    }
    let bad = [
        policy,
        refresh,
        defaults[0].clone(),
        defaults[1].clone(),
        defaults[2].clone(),
        defaults[3].clone(),
    ];
    assert!(invoke(&mut origin, "send_access", &bad).is_err());
}

#[test]
fn send_error_closes_access_and_refresh_resources() {
    for (issue, send, kind, body) in [
        ("issue_access", "send_access", "access", ""),
        (
            "issue_refresh",
            "send_refresh",
            "refresh",
            "grant_type=refresh_token",
        ),
    ] {
        let (mut vm, _, transport, home) = bound_bridge();
        let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
        let handle = invoke(&mut vm, issue, std::slice::from_ref(&policy)).expect("issue");
        let args = [
            policy,
            handle,
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string(kind),
            Value::string(body),
        ];
        let failure = invoke(&mut vm, send, &args).expect_err("scripted send failure");
        assert!(!failure.to_string().contains("SYNTHETIC"));
        assert_eq!(transport.take_sent().len(), 1);
        assert_eq!(vm.host_context().resource_count(), 2);
        assert!(invoke(&mut vm, send, &args).is_err());
        assert!(transport.take_sent().is_empty());
    }
}

#[test]
fn transport_slot_saves_only_at_issued_generation() {
    let (mut vm, _, transport, home) = bound_bridge();
    let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
    let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy)).expect("access");
    transport.push_raw(200, r#"{"access_token":"SYNTHETIC_NEW_ACCESS"}"#);
    let args = [
        policy.clone(),
        access,
        Value::string("fixture-codex"),
        Value::string("/oauth/token"),
        Value::string("access"),
        Value::string(""),
    ];
    let response = invoke(&mut vm, "send_access", &args).expect("response");
    let slot = field(&response, "access_slot").clone();
    let wrong = [policy.clone(), slot.clone(), Value::Int(3)];
    assert!(invoke(&mut vm, "save_transport_slot", &wrong).is_err());
    let right = [policy, slot.clone(), Value::Int(4)];
    assert_eq!(
        invoke(&mut vm, "save_transport_slot", &right).expect("CAS"),
        Value::Int(5)
    );
    assert!(invoke(&mut vm, "save_transport_slot", &right).is_err());
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn terminal_handles_reclaim_resource_budget_across_repeated_requests() {
    let (mut vm, _, transport, home) = bound_bridge();
    let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
    for (issue, send, kind, body) in [
        ("issue_access", "send_access", "access", ""),
        (
            "issue_refresh",
            "send_refresh",
            "refresh",
            "grant_type=refresh_token",
        ),
    ] {
        for _ in 0..70 {
            let handle =
                invoke(&mut vm, issue, std::slice::from_ref(&policy)).expect("capacity available");
            transport.push_raw(200, "{}");
            let args = [
                policy.clone(),
                handle,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string(kind),
                Value::string(body),
            ];
            assert_eq!(
                field(&invoke(&mut vm, send, &args).expect("send"), "status"),
                &Value::Int(200)
            );
            assert_eq!(vm.host_context().resource_count(), 2);
        }
    }
    assert_eq!(transport.take_sent().len(), 140);
}

#[test]
fn cancellation_after_credential_send_reclaims_handle_without_slots() {
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
    let policy = invoke(&mut vm, "snapshot_only", &[home]).expect("policy");
    let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy)).expect("access");
    let args = [
        policy,
        access,
        Value::string("fixture-codex"),
        Value::string("/oauth/token"),
        Value::string("access"),
        Value::string(""),
    ];
    let failure = invoke(&mut vm, "send_access", &args).expect_err("cancelled");
    assert!(!failure.to_string().contains("SYNTHETIC_ACCESS_TOKEN"));
    assert_eq!(transport.sent.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert!(invoke(&mut vm, "send_access", &args).is_err());
    assert_eq!(transport.sent.load(std::sync::atomic::Ordering::SeqCst), 1);
}

struct HostileHeadersTransport {
    response: rustscript_agent::auth::oauth::RawHttpsResponse,
}

impl rustscript_agent::auth::oauth::BoundedHttpsTransport for HostileHeadersTransport {
    fn send(
        &self,
        _: &rustscript_agent::auth::oauth::PreparedHttpsRequest,
        _: &rustscript_agent::auth::oauth::OAuthIoContext,
    ) -> Result<
        rustscript_agent::auth::oauth::RawHttpsResponse,
        rustscript_agent::auth::oauth::OAuthError,
    > {
        Ok(self.response.clone())
    }
}

#[test]
fn rss_transport_never_exposes_hostile_response_headers() {
    let secret = "HEADER_ONLY_SECRET_9c73";
    for (content_type, retry_after, body, expected_headers, expected_retry, malformed) in [
        (
            format!("application/json; charset=\"{secret}\""),
            secret.to_owned(),
            r#"{"access_token":"SYNTHETIC_ACCESS_TOKEN","public":"accepted"}"#.to_owned(),
            true,
            Value::Null,
            false,
        ),
        (
            format!("text/plain; boundary={secret}"),
            "12".to_owned(),
            r#"{"public":"accepted"}"#.to_owned(),
            false,
            Value::Int(12_000),
            false,
        ),
        (
            format!("\r\napplication/json; charset={secret}"),
            "12".to_owned(),
            r#"{"public":"accepted"}"#.to_owned(),
            false,
            Value::Int(12_000),
            false,
        ),
        (
            format!("application/json; charset={secret}"),
            secret.to_owned(),
            format!("{{not-json-{secret}}}"),
            false,
            Value::Null,
            true,
        ),
    ] {
        let mut vm = vm();
        let headers = BTreeMap::from([
            ("x-access-token".to_owned(), secret.to_owned()),
            ("Content-Type".to_owned(), content_type),
            ("Retry-After".to_owned(), retry_after),
        ]);
        let transport = Arc::new(HostileHeadersTransport {
            response: rustscript_agent::auth::oauth::RawHttpsResponse {
                status: 200,
                headers,
                body: body.into_bytes(),
            },
        });
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
        let run = vm.resolve_exported_callable("run").expect("run");
        let response = vm.invoke_callable(run, &[home]);
        if malformed {
            let failure = response.expect_err("malformed body").to_string();
            assert!(!failure.contains(secret), "{failure}");
            assert!(!failure.contains("SYNTHETIC_ACCESS_TOKEN"), "{failure}");
            continue;
        }
        let response = response.expect("JSON body");
        let debug = format!("{response:?}");
        assert!(!debug.contains(secret), "{debug}");
        assert!(!debug.contains("SYNTHETIC_ACCESS_TOKEN"), "{debug}");
        assert_eq!(field(&response, "status"), &Value::Int(200));
        if expected_retry == Value::Null {
            let Value::Map(entries) = &response else {
                panic!("expected map")
            };
            assert!(
                !entries
                    .iter()
                    .any(|(key, _)| key == &Value::string("retry_after_ms"))
            );
        } else {
            assert_eq!(field(&response, "retry_after_ms"), &expected_retry);
        }
        let Value::Array(headers) = field(&response, "public_headers") else {
            panic!("typed headers")
        };
        if expected_headers {
            assert_eq!(headers.len(), 1, "{debug}");
            assert_eq!(field(&headers[0], "name"), &Value::string("content-type"));
            assert_eq!(
                field(&headers[0], "value"),
                &Value::string("application/json")
            );
            assert!(matches!(field(&response, "access_slot"), Value::Int(_)));
        } else {
            assert!(headers.is_empty(), "{debug}");
        }
        assert_eq!(
            field(&response, "body_without_secret_fields"),
            &Value::string(r#"{"public":"accepted"}"#)
        );
    }
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
