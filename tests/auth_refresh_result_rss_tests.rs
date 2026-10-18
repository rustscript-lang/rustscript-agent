//! Real RSS refresh issuance publication and authenticated refresh transport.

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
            "auth-refresh-result-{}-{}",
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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/refresh_result/main.rss");
    let source = fs::read_to_string(&path).expect("real refresh-issuance RSS fixture");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::new(catalog.clone())),
    )
    .expect("compile real refresh-issuance RSS against exact auth catalog");
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

fn native_host(
    home: &PrivateHome,
    transport: Arc<ScriptedHttpsTransport>,
) -> (AuthHost, Arc<rustscript_vm::HostApiCatalog>) {
    let host = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("native auth host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let catalog = auth_host_catalog();
    (host, catalog)
}

fn bind_policy(host: &AuthHost, vm: &mut Vm) -> Value {
    let context = host.bind_vm(vm).expect("bind native owner");
    invoke(vm, "snapshot", &[field(&context, "host_home").clone()]).expect("native policy snapshot")
}

#[test]
fn genuine_refresh_issuance_denials_and_publication_are_typed() {
    const FIXTURE_ACCESS: &str = "SYNTHETIC_ACCESS_TOKEN";
    const FIXTURE_REFRESH: &str = "SYNTHETIC_REFRESH_TOKEN";

    let home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let (host, catalog) = native_host(&home, transport.clone());
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

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

    // Negative: admitted credential with the wrong generation returns the actual store code.
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
        &Value::string("refresh_unavailable")
    );
    assert!(
        transport.take_sent().is_empty(),
        "generation failure sends nothing"
    );

    // Issue and transport within one guest callable after both denials;
    // do not infer resource liveness from a Rust-side integer carrier.
    transport.push_raw(200, r#"{"public":"after-denials"}"#);
    let recovered = invoke(
        &mut vm,
        "issue_and_send_result",
        &[
            Value::string("fixture-codex"),
            Value::Int(4),
            policy.clone(),
        ],
    )
    .expect("denied issuance leaves the same VM and policy usable");
    assert_eq!(field(&recovered, "ok"), &Value::Bool(true), "{recovered:?}");
    assert_eq!(field(&recovered, "first_status"), &Value::Int(200));
    assert_eq!(
        field(&recovered, "first_body"),
        &Value::string(r#"{"public":"after-denials"}"#)
    );
    assert_eq!(field(&recovered, "replay_ok"), &Value::Bool(false));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, "https://auth.example.test/oauth/token");
    assert_eq!(sent[0].method, "POST");
    assert!(sent[0].body.contains(FIXTURE_REFRESH));

    let rendered = format!("{unadmitted:?}{wrong_generation:?}{recovered:?}");
    for secret in [FIXTURE_REFRESH, FIXTURE_ACCESS] {
        assert!(!rendered.contains(secret), "RSS output leaked {secret}");
    }
}

#[test]
fn refresh_issue_and_send_records_first_wire_and_native_replay() {
    const FIXTURE_ACCESS: &str = "SYNTHETIC_ACCESS_TOKEN";
    const FIXTURE_REFRESH: &str = "SYNTHETIC_REFRESH_TOKEN";
    const RESPONSE_ACCESS: &str = "REFRESH_RESULT_RESPONSE_ACCESS_PRIVATE_3b71";
    const RESPONSE_REFRESH: &str = "REFRESH_RESULT_RESPONSE_REFRESH_PRIVATE_6d20";

    let home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{RESPONSE_ACCESS}","refresh_token":"{RESPONSE_REFRESH}","public":"rotated"}}"#
        ),
    );
    let (host, catalog) = native_host(&home, transport.clone());
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let observed = invoke(
        &mut vm,
        "issue_and_send_result",
        &[
            Value::string("fixture-codex"),
            Value::Int(4),
            policy.clone(),
        ],
    )
    .expect("guest callable returns a public outcome");

    // Exactly one native request must leave the host across both guest sends.
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "first send only, replay sends nothing");
    assert_eq!(sent[0].url, "https://auth.example.test/oauth/token");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/x-www-form-urlencoded")
    );
    assert!(sent[0].body.contains("grant_type=refresh_token"));
    assert!(
        sent[0].body.contains(FIXTURE_REFRESH),
        "host injected the one-shot refresh secret"
    );

    assert_eq!(field(&observed, "ok"), &Value::Bool(true));
    assert_eq!(field(&observed, "first_status"), &Value::Int(200));
    assert_eq!(
        field(&observed, "first_body"),
        &Value::string(r#"{"public":"rotated"}"#)
    );
    assert_eq!(
        field(&observed, "replay_ok"),
        &Value::Bool(false),
        "replay does not succeed"
    );
    // Actual native/Core code observed when the live typed request/usage is
    // reused after the one-use refresh resource was consumed by the first send.
    assert_eq!(
        field(&observed, "replay_code"),
        &Value::string("resource_invalid"),
        "observed native replay code"
    );
    let rendered = format!("{observed:?}");
    for secret in [
        FIXTURE_REFRESH,
        FIXTURE_ACCESS,
        RESPONSE_ACCESS,
        RESPONSE_REFRESH,
    ] {
        assert!(!rendered.contains(secret), "RSS output leaked {secret}");
    }
}
