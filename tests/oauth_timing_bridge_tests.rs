use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustscript_agent::auth::host::{AuthHost, auth_host_catalog};
use rustscript_agent::auth::oauth::{
    OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport,
};
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryRunner, RunCancellation};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, HostParamPassing, HostTypeSchema,
    ResourceTypeKey, SourceFlavor, Value, Vm, VmError, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};

const TIMING_SOURCE: &str = include_str!("../rss/auth/timing_contract.rss");

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let base =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
        let path = base.join(format!(
            "oauth-timing-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private auth home");
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixtures.join("config.yaml"), path.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixtures.join("auth.yaml"))
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

impl AsRef<Path> for TempHome {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn timing_vm() -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/timing_contract.rss");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        TIMING_SOURCE,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real timing RSS against its runtime catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = TempHome::new("registration");
    AuthHost::new(
        registration_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host")
    .register(&mut registry, catalog.as_ref())
    .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind exact catalog");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS map, got {value:?}");
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    try_invoke(vm, name, args).expect("RSS call")
}

fn try_invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

#[test]
fn timing_rss_contract_compiles_against_the_exact_catalog() {
    let catalog = auth_host_catalog();
    let functions = catalog.functions();
    assert!(
        functions
            .iter()
            .any(|function| function.name == "oauth::now_ms"),
        "auth catalog is missing oauth::now_ms"
    );
    assert!(
        functions
            .iter()
            .any(|function| function.name == "oauth::wait_ms"),
        "auth catalog is missing oauth::wait_ms"
    );
    let now = functions
        .iter()
        .find(|function| function.name == "oauth::now_ms")
        .expect("clock schema");
    assert_eq!(now.params.len(), 1);
    assert_eq!(now.params[0].name, "policy_handle");
    assert_eq!(now.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(
        now.params[0].ty,
        HostTypeSchema::Resource(ResourceTypeKey::new("auth.policy").expect("policy key"))
    );
    assert_eq!(now.return_type, HostTypeSchema::Int);
    let wait = functions
        .iter()
        .find(|function| function.name == "oauth::wait_ms")
        .expect("wait schema");
    assert_eq!(wait.params.len(), 2);
    assert_eq!(wait.params[0].name, "policy_handle");
    assert_eq!(wait.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(
        wait.params[0].ty,
        HostTypeSchema::Resource(ResourceTypeKey::new("auth.policy").expect("policy key"))
    );
    assert_eq!(wait.params[1].name, "millis");
    assert_eq!(wait.params[1].passing, HostParamPassing::Value);
    assert_eq!(wait.params[1].ty, HostTypeSchema::Int);
    assert_eq!(wait.return_type, HostTypeSchema::Null);
    compile_source_at_path_with_flavor_and_options(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/timing_contract.rss"),
        TIMING_SOURCE,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog),
    )
    .expect("typed timing RSS contract must compile against the auth catalog");
}

#[test]
fn real_rss_clock_reads_the_injected_oauth_clock_and_its_progression() {
    const START_MS: u64 = 1_900_000_000_123;
    let home = TempHome::new("injected-clock");
    let mut vm = timing_vm();
    let clock = Arc::new(ScriptedClock::new(START_MS));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock.clone(),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth);
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let host_home = field(&bound, "host_home").clone();
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    assert_eq!(
        invoke(&mut vm, "now", std::slice::from_ref(&policy)),
        Value::Int(START_MS as i64)
    );
    clock.expire();
    assert_eq!(
        invoke(&mut vm, "now", std::slice::from_ref(&policy)),
        Value::Int((START_MS + 86_400_000) as i64)
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_rss_positive_wait_sleeps_until_its_monotonic_target() {
    const WAIT_MS: u64 = 35;
    let home = TempHome::new("positive-wait");
    let mut vm = timing_vm();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    let started = Instant::now();
    let returned =
        try_invoke(&mut vm, "wait", &[policy, Value::Int(WAIT_MS as i64)]).expect("bounded wait");
    assert_eq!(returned, Value::Null);
    assert!(
        started.elapsed() >= Duration::from_millis(WAIT_MS),
        "wait returned before its monotonic target"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_rss_wait_rejects_negative_duration_with_fixed_code() {
    let home = TempHome::new("negative-wait");
    let mut vm = timing_vm();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    let failure = try_invoke(&mut vm, "wait", &[policy, Value::Int(-1)])
        .expect_err("negative wait must be rejected");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "wait_out_of_range"),
        "unexpected error: {failure}"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_rss_clock_without_oauth_matches_the_measured_system_time_window() {
    let home = TempHome::new("system-clock");
    let mut vm = timing_vm();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    let before_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis();
    let returned = invoke(&mut vm, "now", std::slice::from_ref(&policy));
    let after_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis();
    let Value::Int(returned_ms) = returned else {
        panic!("clock returns int, got {returned:?}");
    };
    assert!(
        i64::try_from(before_ms).expect("before fits int") <= returned_ms
            && returned_ms <= i64::try_from(after_ms).expect("after fits int"),
        "returned time must lie within the measured interval"
    );
}

#[test]
fn real_rss_clock_rejects_checked_integer_overflow() {
    let home = TempHome::new("clock-overflow");
    let mut vm = timing_vm();
    let clock = Arc::new(ScriptedClock::new(u64::MAX));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock,
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth);
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    let failure = try_invoke(&mut vm, "now", std::slice::from_ref(&policy))
        .expect_err("unrepresentable clock must fail");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "clock_unavailable"),
        "unexpected error: {failure}"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn auth_entry_runner_executes_timing_and_returns_a_redacted_command_envelope() {
    let source = r#"
        use config;
        use auth;
        use oauth;

        struct TimingCommand {
            operation: string,
            provider: string?,
            credential_id: string?
        }

        struct TimingEnvelope {
            ok: bool,
            operation: string,
            credential_id: string?,
            generation: int,
            status: string,
            error: string?
        }

        pub fn run(home: resource<auth.host_home>, command: TimingCommand) -> TimingEnvelope {
            let snapshot = config::load_snapshot(&home);
            let policy = snapshot.policy_handle;
            let observed_ms: int = oauth::now_ms(&policy);
            oauth::wait_ms(&policy, 0);
            {
                ok: snapshot.ok && observed_ms >= 0,
                operation: command.operation,
                credential_id: command.credential_id,
                generation: snapshot.policy_generation,
                status: "timing_complete",
                error: null
            }
        }
    "#;
    let runner = AuthEntryRunner::from_source(source).expect("typed timing entry compiles");
    let home = TempHome::new("auth-entry-runner");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = runner
        .run(
            home.0.clone(),
            AuthCommandInput {
                operation: "timing-check".to_string(),
                provider: None,
                credential_id: None,
            },
            &cancellation,
            None,
        )
        .expect("AuthEntryRunner result");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(field(&result, "operation"), &Value::string("timing-check"));
    assert_eq!(field(&result, "generation"), &Value::Int(1));
    assert_eq!(field(&result, "status"), &Value::string("timing_complete"));
    assert!(optional_field(&result, "error").is_none_or(|value| matches!(value, Value::Null)));
    assert!(
        optional_field(&result, "credential_id").is_none_or(|value| matches!(value, Value::Null))
    );
    assert!(!format!("{result:?}").contains("SYNTHETIC"));
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn real_rss_wait_rejects_value_above_per_call_cap() {
    let home = TempHome::new("wait-over-cap");
    let mut vm = timing_vm();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    let failure = try_invoke(&mut vm, "wait", &[policy, Value::Int(60_001)])
        .expect_err("wait above native cap must fail");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "wait_out_of_range"),
        "unexpected error: {failure}"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_rss_wait_rejects_target_past_deadline_before_sleeping() {
    let home = TempHome::new("wait-deadline");
    let mut vm = timing_vm();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(3)),
    )
    .expect("auth host");
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    let started = Instant::now();
    let failure = try_invoke(&mut vm, "wait", &[policy, Value::Int(60_000)])
        .expect_err("target beyond owner deadline must be rejected");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "wait_deadline_exceeded"),
        "unexpected error: {failure}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "deadline rejection must happen before any wait"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_rss_zero_wait_checks_active_owner_and_allocates_nothing() {
    let home = TempHome::new("zero-wait");
    let mut vm = timing_vm();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let bound = auth.bind_vm(&mut vm).expect("bind host home");
    let policy = invoke(&mut vm, "snapshot", &[field(&bound, "host_home").clone()]);
    for _ in 0..64 {
        assert_eq!(
            invoke(&mut vm, "wait", &[policy.clone(), Value::Int(0)]),
            Value::Null
        );
        assert_eq!(vm.host_context().resource_count(), 2);
    }
    auth.revoke();
    let failure = try_invoke(&mut vm, "wait", &[policy, Value::Int(0)])
        .expect_err("zero wait still checks owner activity");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "policy_inactive"),
        "unexpected error: {failure}"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}
