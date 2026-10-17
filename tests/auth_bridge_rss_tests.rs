#![cfg(feature = "config-fixture")]

use rustscript_agent::{
    RunCancellation,
    auth::host::{AuthHost, auth_host_catalog},
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
        "auth-bridge-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&home).expect("private home");
    #[cfg(unix)]
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("config fixture");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("auth fixture")
        .replace("1788440000000", "1900000000000");
    fs::write(home.join("auth.yaml"), auth).expect("auth fixture copy");
    #[cfg(unix)]
    for name in ["config.yaml", "auth.yaml"] {
        fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600)).expect("file mode");
    }
    home
}

fn bridge_vm() -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/bridge_contract.rss");
    let source = fs::read_to_string(&path).expect("real RSS bridge entry must exist");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real RSS bridge entry");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host");
    host.register(&mut registry, catalog.as_ref())
        .expect("register exact catalog");
    registry.bind_vm_cached(&mut vm).expect("bind registry");
    assert!(matches!(vm.run().expect("run root"), VmStatus::Halted));
    vm
}

fn host_home(context: Value) -> Value {
    field(&context, "host_home").clone()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected map")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn invoke(vm: &mut Vm, home: Value, id: &str) -> rustscript_vm::VmResult<Value> {
    let callable = vm.resolve_exported_callable("run")?;
    vm.invoke_callable(callable, &[home, Value::string(id)])
}

fn assert_no_secrets(text: &str) {
    for secret in ["SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_REFRESH_TOKEN"] {
        assert!(!text.contains(secret), "secret in bridge output or error");
    }
}

#[test]
fn admitted_credential_returns_only_public_metadata_summary() {
    let mut vm = bridge_vm();
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = host_home(host.bind_vm(&mut vm).expect("trusted home"));
    let result = invoke(&mut vm, home, "fixture-codex").expect("admitted metadata");
    let Value::Map(fields) = &result else {
        panic!("expected public summary")
    };
    let mut keys: Vec<_> = fields
        .iter()
        .map(|(key, _)| match key {
            Value::String(key) => key.to_string(),
            _ => panic!("expected string key"),
        })
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "credential_generation",
            "credential_id",
            "has_refresh_token",
            "ok",
            "policy_generation"
        ]
    );
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(field(&result, "policy_generation"), &Value::Int(1));
    assert_eq!(
        field(&result, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&result, "credential_generation"), &Value::Int(4));
    assert_eq!(field(&result, "has_refresh_token"), &Value::Bool(true));
    let rendered = format!("{result:?}");
    assert_no_secrets(&rendered);
}

#[test]
fn unadmitted_credential_is_denied_by_real_entry() {
    let mut vm = bridge_vm();
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = host_home(host.bind_vm(&mut vm).expect("trusted home"));
    let admitted = invoke(&mut vm, home.clone(), "fixture-codex").expect("positive control");
    assert_eq!(field(&admitted, "ok"), &Value::Bool(true));
    let failure =
        invoke(&mut vm, home, "unadmitted-synthetic-id").expect_err("unadmitted ID must be denied");
    let rendered = failure.to_string();
    assert!(
        rendered.contains("credential_not_admitted"),
        "unexpected rejection: {rendered}"
    );
    assert_no_secrets(&rendered);
}

#[test]
fn foreign_and_forged_home_resources_are_denied() {
    let mut origin = bridge_vm();
    let origin_host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("origin host");
    let foreign = host_home(origin_host.bind_vm(&mut origin).expect("origin bind"));
    assert_eq!(
        field(
            &invoke(&mut origin, foreign.clone(), "fixture-codex").expect("origin control"),
            "ok"
        ),
        &Value::Bool(true)
    );

    let mut target = bridge_vm();
    let unbound = invoke(&mut target, foreign.clone(), "fixture-codex")
        .expect_err("foreign home in unbound VM must be denied");
    assert_no_secrets(&unbound.to_string());
    let target_host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("target host");
    let local = host_home(target_host.bind_vm(&mut target).expect("target bind"));
    assert_eq!(
        field(
            &invoke(&mut target, local, "fixture-codex").expect("target control"),
            "ok"
        ),
        &Value::Bool(true)
    );
    let cross_vm = invoke(&mut target, foreign, "fixture-codex")
        .expect_err("foreign home from another VM must be denied");
    assert_no_secrets(&cross_vm.to_string());
    let forged = invoke(&mut target, Value::Int(i64::MAX), "fixture-codex")
        .expect_err("fabricated home must be denied");
    assert_no_secrets(&forged.to_string());
}
