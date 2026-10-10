//! Real RSS access issuance and authenticated transport.

use rustscript_agent::{
    RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        },
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmError, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

struct PrivateHome(PathBuf);

impl PrivateHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!(
            "auth-access-result-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read config fixture")
            .replace("auth.openai.com", "auth.example.test");
        fs::write(path.join("config.yaml"), config).expect("write synthetic .test config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("write auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self(path)
    }
}

impl Drop for PrivateHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS record, got {value:?}")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS field {name} in {value:?}"))
}

fn fixture_vm(host: &AuthHost, catalog: &rustscript_vm::HostApiCatalog) -> Vm {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/access_result/main.rss");
    let source = fs::read_to_string(&path).expect("real access-issuance RSS fixture");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::new(catalog.clone())),
    )
    .expect("compile real access-issuance RSS against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog)
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

#[test]
fn genuine_access_issuance_result_publishes_transports_and_reports_actual_codes() {
    const RESPONSE_ACCESS: &str = "ACCESS_RESULT_RESPONSE_PRIVATE_9f4c";

    let home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{RESPONSE_ACCESS}","public":"accepted"}}"#),
    );
    let host = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("native auth host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let catalog = auth_host_catalog();
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let policy = invoke(&mut vm, "snapshot", &[field(&context, "host_home").clone()])
        .expect("native policy snapshot");

    // Negative: unadmitted credential id returns the actual admission code.
    let unadmitted = invoke(
        &mut vm,
        "issue_result",
        &[
            Value::string("unknown-credential"),
            Value::Int(4),
            policy.clone(),
        ],
    )
    .expect("unadmitted issuance is a guest-readable result");
    assert_eq!(field(&unadmitted, "ok"), &Value::Bool(false));
    assert!(matches!(field(&unadmitted, "value"), Value::Null));
    assert_eq!(
        field(field(&unadmitted, "error"), "code"),
        &Value::string("credential_not_admitted")
    );
    assert!(
        transport.take_sent().is_empty(),
        "admission failure sends nothing"
    );

    // Negative: wrong expected generation returns the actual store code.
    let wrong_generation = invoke(
        &mut vm,
        "issue_result",
        &[
            Value::string("fixture-codex"),
            Value::Int(999),
            policy.clone(),
        ],
    )
    .expect("wrong generation is a guest-readable result");
    assert_eq!(field(&wrong_generation, "ok"), &Value::Bool(false));
    assert!(matches!(field(&wrong_generation, "value"), Value::Null));
    assert_eq!(
        field(field(&wrong_generation, "error"), "code"),
        &Value::string("access_unavailable")
    );
    assert!(
        transport.take_sent().is_empty(),
        "generation failure sends nothing"
    );

    // Positive: genuine opaque publication on the same still-valid policy.
    let issued = invoke(
        &mut vm,
        "issue_result",
        &[
            Value::string("fixture-codex"),
            Value::Int(4),
            policy.clone(),
        ],
    )
    .expect("valid issuance is a typed result");
    assert_eq!(field(&issued, "ok"), &Value::Bool(true));
    assert!(matches!(field(&issued, "error"), Value::Null));
    let inner = field(&issued, "value");
    assert_eq!(field(inner, "ok"), &Value::Bool(true));
    assert!(matches!(field(inner, "error"), Value::Null));
    let access = field(inner, "handle").clone();
    assert!(
        transport.take_sent().is_empty(),
        "issuance does not transport"
    );

    // The retrieved handle is sent through the existing native transport.
    let sent_result = invoke(
        &mut vm,
        "send_access",
        &[
            Value::string("fixture-codex"),
            access,
            policy.clone(),
            Value::string("/oauth/token"),
        ],
    )
    .expect("native transport result");
    assert_eq!(field(&sent_result, "ok"), &Value::Bool(true));
    let response = field(&sent_result, "value");
    assert_eq!(field(response, "status"), &Value::Int(200));
    assert_eq!(
        field(response, "body_without_secret_fields"),
        &Value::string(r#"{"public":"accepted"}"#)
    );
    let rendered = format!("{unadmitted:?}{wrong_generation:?}{issued:?}{sent_result:?}");
    for secret in [
        "SYNTHETIC_ACCESS_TOKEN",
        "SYNTHETIC_REFRESH_TOKEN",
        RESPONSE_ACCESS,
    ] {
        assert!(!rendered.contains(secret), "RSS output leaked {secret}");
    }

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native send");
    assert_eq!(sent[0].url, "https://auth.example.test/oauth/token");
    assert_eq!(sent[0].method, "GET");
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN")
    );
}
