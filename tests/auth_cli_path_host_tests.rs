use rustscript_agent::auth::host::{ConfigPathHost, auth_host_catalog};
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::resource::{CloseProgress, HostResource, ResourceCloseReason, ResourceResult};
use rustscript_vm::{
    CapabilityProfile, CompileSourceFileOptions, HostFunctionRegistry, HostResourceType,
    ResourceTypeKey, SourceFlavor, Value, Vm, VmStatus, compile_source_with_flavor_and_options,
};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

struct WrongPathResource;

impl HostResource for WrongPathResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new("test.wrong_path_resource").expect("test resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for WrongPathResource {
    const KEY: &'static str = "test.wrong_path_resource";
    const DESCRIPTION: &'static str = "Real wrong-type entry for path resource validation";
}

const RSS: &str = r#"
use config;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

pub fn run(home: resource<config.path_home>, command: AuthCommandInput) -> ConfigPathResultEnvelope {
    config::resolved_path_result(&home)
}
"#;

fn runner_from(source: &str) -> AuthEntryRunner {
    let catalog = auth_host_catalog();
    compile_source_with_flavor_and_options(
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog),
    )
    .unwrap_or_else(|error| panic!("raw RSS diagnostic: {error:?}"));
    AuthEntryRunner::from_source(source)
        .unwrap_or_else(|error| panic!("path ABI source must pass admission: {error:?}"))
}

const PATH_ENTRY_PATH: &str = "rss/config/path.rss";
const PATH_SOURCES: &[(&str, &str)] = &[(PATH_ENTRY_PATH, include_str!("../rss/config/path.rss"))];

fn runner() -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(PATH_ENTRY_PATH, PATH_SOURCES)
        .expect("compile the production closed path bundle")
}

fn command() -> AuthCommandInput {
    AuthCommandInput {
        operation: "config.path".into(),
        provider: None,
        credential_id: None,
    }
}

fn temp_path(label: &str) -> PathBuf {
    PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp")).join(
        format!(
            "scope-h-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ),
    )
}

fn run_path(runner: &AuthEntryRunner, home: PathBuf) -> Result<Value, AuthEntryError> {
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    runner.run_with_path_host_factory(command(), &cancellation, move |child| {
        ConfigPathHost::new(home, child)
    })
}

fn path_program() -> (rustscript_vm::Program, Arc<rustscript_vm::HostApiCatalog>) {
    let catalog = auth_host_catalog();
    let program = compile_source_with_flavor_and_options(
        RSS,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile real path RSS against the production catalog")
    .program;
    (program, catalog)
}

fn native_path_vm(
    home: PathBuf,
    cancellation: RunCancellation,
) -> (Vm, ConfigPathHost, Value, Value) {
    let (program, catalog) = path_program();
    native_path_vm_for_program(program, catalog, home, cancellation)
}

fn native_path_vm_for_program(
    program: rustscript_vm::Program,
    catalog: Arc<rustscript_vm::HostApiCatalog>,
    home: PathBuf,
    cancellation: RunCancellation,
) -> (Vm, ConfigPathHost, Value, Value) {
    let mut vm = Vm::try_new(program).expect("create fresh native VM");
    let host = ConfigPathHost::new(home, cancellation).expect("create no-store path host");
    let mut registry = HostFunctionRegistry::empty();
    registry.set_capability_profile(CapabilityProfile::deny_all());
    host.register(&mut registry, catalog.as_ref())
        .expect("install path-only module against the same catalog snapshot");
    registry.set_capability_profile(CapabilityProfile::deny_all());
    registry.authorize_registered_builtin_import("config::resolved_path_result");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind exact config-path capability registry");
    let bound = host
        .bind_vm(&mut vm)
        .expect("publish real typed path resource");
    assert_eq!(vm.run().expect("run RSS root frame"), VmStatus::Halted);
    let callable = vm
        .resolve_exported_callable("run")
        .expect("resolve compiled RSS entry");
    (vm, host, callable, bound)
}

fn invoke_native_path(
    vm: &mut Vm,
    callable: &Value,
    bound: &Value,
) -> Result<Value, rustscript_vm::VmError> {
    invoke_native_path_value(vm, callable, field(bound, "host_home").clone())
}

fn invoke_native_path_value(
    vm: &mut Vm,
    callable: &Value,
    home: Value,
) -> Result<Value, rustscript_vm::VmError> {
    vm.invoke_callable(callable.clone(), &[home, command_value()])
}

fn command_value() -> Value {
    Value::map(vec![
        (Value::string("operation"), Value::string("config.path")),
        (Value::string("provider"), Value::Null),
        (Value::string("credential_id"), Value::Null),
    ])
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected result map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing result field {name}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        panic!("expected result map, got {value:?}");
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn assert_absent_or_null(value: &Value, name: &str) {
    assert!(
        optional_field(value, name).is_none_or(|value| matches!(value, Value::Null)),
        "field {name} must be absent or null in {value:?}"
    );
}

fn assert_path_error(value: &Value, code: &str) {
    assert_eq!(field(value, "ok"), &Value::Bool(false));
    assert_eq!(field(value, "status"), &Value::string(""));
    assert_eq!(field(value, "error"), &Value::string(code));
    assert_eq!(field(value, "generation"), &Value::Int(0));
    assert_absent_or_null(value, "credential_id");
}

fn assert_path_status(value: &Value, expected: &str) {
    assert_eq!(field(value, "ok"), &Value::Bool(true));
    assert_eq!(field(value, "status"), &Value::string(expected));
    assert_eq!(field(value, "operation"), &Value::string("config.path"));
    assert_eq!(field(value, "generation"), &Value::Int(0));
    assert_absent_or_null(value, "credential_id");
    assert_absent_or_null(value, "error");
}

#[test]
fn rss_native_path_invocation_reads_no_config_or_auth_files() {
    let root = temp_path("read-only");
    let real_home = root.join("actual home");
    let linked_home = root.join("home alias");
    fs::create_dir_all(real_home.join("opaque-directory")).expect("create existing home");
    fs::write(real_home.join("config.yaml"), b"invalid: [config bytes\xff")
        .expect("write corrupt config");
    fs::write(
        real_home.join("auth.yaml"),
        b"invalid: [credential bytes\xfe",
    )
    .expect("write corrupt auth");
    fs::write(real_home.join("opaque-directory/secret"), b"opaque content")
        .expect("write opaque content");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_home, &linked_home).expect("create home symlink");
    #[cfg(not(unix))]
    let linked_home = real_home.clone();

    let config_before = fs::read(real_home.join("config.yaml")).expect("read config bytes");
    let auth_before = fs::read(real_home.join("auth.yaml")).expect("read auth bytes");
    let opaque_before =
        fs::read(real_home.join("opaque-directory/secret")).expect("read opaque bytes");
    #[cfg(unix)]
    let symlink_before = fs::read_link(&linked_home).expect("read home symlink");

    let output = run_path(&runner(), linked_home.clone()).expect("path-only RSS run");
    assert_path_status(
        &output,
        linked_home
            .join("config.yaml")
            .to_str()
            .expect("UTF-8 expected path"),
    );
    assert_eq!(
        fs::read(real_home.join("config.yaml")).expect("config remains readable"),
        config_before
    );
    assert_eq!(
        fs::read(real_home.join("auth.yaml")).expect("auth remains readable"),
        auth_before
    );
    assert_eq!(
        fs::read(real_home.join("opaque-directory/secret")).expect("opaque remains readable"),
        opaque_before
    );
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(&linked_home).expect("symlink remains readable"),
        symlink_before
    );
    assert!(!format!("{output:?}").contains("credential bytes"));
    fs::remove_dir_all(root).expect("remove test files");
}

#[test]
fn missing_nested_home_is_reported_lexically_without_creation() {
    let base = temp_path("missing");
    let missing_home = base.join("nested").join("absent home");
    let output = run_path(&runner(), missing_home.clone()).expect("missing home remains valid");
    assert_path_status(&output, missing_home.join("config.yaml").to_str().unwrap());
    assert!(
        !base.exists(),
        "path lookup must not create the missing home or parents"
    );
}

#[test]
fn legal_path_bytes_are_preserved_and_invalid_paths_return_static_failures() {
    let root = temp_path("legal");
    let legal_home = root.join(r#"space "quoted" and \backslash"#);
    let output = run_path(&runner(), legal_home.clone()).expect("legal path run");
    assert_path_status(&output, legal_home.join("config.yaml").to_str().unwrap());

    let control_home = root.join(format!("line{}break", '\n'));
    let output = run_path(&runner(), control_home.clone()).expect("control path envelope");
    assert_path_error(&output, "invalid_path");
    assert!(!format!("{output:?}").contains("line\nbreak"));

    let long_home = (0..11).fold(root.clone(), |path, _| path.join("x".repeat(220)));
    assert!(long_home.join("config.yaml").as_os_str().len() > 2048);
    let output = run_path(&runner(), long_home).expect("long path envelope");
    assert_path_error(&output, "invalid_path");

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = root.as_os_str().as_encoded_bytes().to_vec();
        bytes.extend_from_slice(b"/invalid-\xff-home");
        let invalid_utf8 = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        let output = run_path(&runner(), invalid_utf8).expect("non-UTF-8 path envelope");
        assert_path_error(&output, "invalid_path");
    }
}

#[test]
fn invalid_home_paths_follow_agent_path_validation_without_disclosure() {
    let invalid_homes = [
        PathBuf::from("relative-home"),
        PathBuf::from("/root/../outside"),
    ];
    for home in invalid_homes {
        let error = run_path(&runner(), home.clone()).expect_err("invalid home must be rejected");
        assert_eq!(error, AuthEntryError::HostSetup);
        assert!(!format!("{error:?}").contains(&home.to_string_lossy().to_string()));
    }
}

#[test]
fn invocation_rejects_invalid_cancellation_before_path_factory_effects() {
    let runner = runner();
    let called = std::cell::Cell::new(false);
    let unbounded = RunCancellation::new();
    let error = runner
        .run_with_path_host_factory(command(), &unbounded, |child| {
            called.set(true);
            ConfigPathHost::new(temp_path("unbounded"), child)
        })
        .expect_err("unbounded cancellation must be rejected");
    assert_eq!(error, AuthEntryError::DeadlineRequired);
    assert!(!called.get());

    let expired = RunCancellation::with_deadline(Instant::now() - Duration::from_secs(1));
    let error = runner
        .run_with_path_host_factory(command(), &expired, |child| {
            called.set(true);
            ConfigPathHost::new(temp_path("expired"), child)
        })
        .expect_err("expired cancellation must be rejected");
    assert_eq!(
        error,
        AuthEntryError::Cancelled(CancellationReason::Deadline)
    );
    assert!(!called.get());

    let requested = RunCancellation::with_timeout(Duration::from_secs(10));
    requested.request(CancellationReason::Requested);
    let error = runner
        .run_with_path_host_factory(command(), &requested, |child| {
            called.set(true);
            ConfigPathHost::new(temp_path("requested"), child)
        })
        .expect_err("requested cancellation must be rejected");
    assert_eq!(
        error,
        AuthEntryError::Cancelled(CancellationReason::Requested)
    );
    assert!(!called.get());
}

#[test]
fn json_builtin_is_granted_only_for_bundle_path_execution() {
    let production = include_str!("../rss/config/path.rss");
    let json_source = production.replacen(
        "    if operation.copy() == \"config.path\" => {",
        "    let encoded: string = json::encode(command.operation.copy());\n    if operation.copy() == \"config.path\" => {",
        1,
    );
    let json_source = json_source.replacen("use config;", "use config;\nuse json;", 1);
    assert_ne!(
        json_source, production,
        "production path.rss must carry the scoped JSON insertion anchor"
    );
    assert!(matches!(
        AuthEntryRunner::from_source(&json_source),
        Err(AuthEntryError::ImportDenied)
    ));
    let bundled = AuthEntryRunner::from_bundle("main.rss", &[("main.rss", &json_source)])
        .expect("the existing bundle JSON opt-in compiles");
    let missing_home = temp_path("bundle-json");
    let output = run_path(&bundled, missing_home.clone()).expect("bundle path with JSON builtin");
    assert_path_status(&output, missing_home.join("config.yaml").to_str().unwrap());
    assert!(!missing_home.exists());
}

#[test]
fn path_registry_does_not_install_http_host_functions() {
    let source = r#"
use config;
use http;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

pub fn run(
    home: resource<config.path_home>,
    command: AuthCommandInput
) -> ConfigPathResultEnvelope {
    let request = http::request::new("GET", "https://example.invalid/path");
    config::resolved_path_result(&home)
}
"#;
    let catalog = auth_host_catalog();
    let compiled = compile_source_with_flavor_and_options(
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("the broad RSS compile catalog contains the HTTP host schema");
    let mut vm = Vm::try_new(compiled.program).expect("fresh raw-Core VM");
    let missing_home = temp_path("denied-http");
    let path_host = ConfigPathHost::new(
        missing_home.clone(),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
    .expect("no-store path host");
    let mut registry = HostFunctionRegistry::empty();
    registry.set_capability_profile(CapabilityProfile::deny_all());
    path_host
        .register(&mut registry, catalog.as_ref())
        .expect("install only config path adapter");
    registry.set_capability_profile(CapabilityProfile::deny_all());
    registry.authorize_registered_builtin_import("config::resolved_path_result");
    let bind_error = registry
        .bind_vm_cached(&mut vm)
        .expect_err("path-only registry must reject the broad HTTP import");
    assert!(format!("{bind_error:?}").contains("http::request::new"));
    assert_eq!(vm.host_context().resource_count(), 0);
    assert!(
        !missing_home.exists(),
        "registry rejection precedes guest effects"
    );
}

#[test]
fn path_registry_rejects_snapshot_and_credential_mutation_imports() {
    let snapshot_source = r#"
use config;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

pub fn inspect(home: resource<auth.host_home>) -> int {
    config::load_snapshot(&home).policy_generation
}

pub fn run(
    home: resource<config.path_home>,
    command: AuthCommandInput
) -> ConfigPathResultEnvelope {
    config::resolved_path_result(&home)
}
"#;
    for source in [
        snapshot_source,
        r#"
use auth;
use config;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

pub fn delete_one(policy: resource<auth.policy>) -> int {
    auth::delete("fixture", &policy);
    1
}

pub fn run(
    home: resource<config.path_home>,
    command: AuthCommandInput
) -> ConfigPathResultEnvelope {
    config::resolved_path_result(&home)
}
"#,
    ] {
        let missing_home = temp_path("denied-auth-import");
        let error = run_path(&runner_from(source), missing_home.clone())
            .expect_err("path-only registry must not admit snapshot or auth mutation imports");
        assert_eq!(error, AuthEntryError::RegistrySetup);
        assert!(!missing_home.exists());
    }
}

#[test]
fn foreign_and_wrong_type_real_resources_fail_without_affecting_peer_bindings() {
    let mut peer = native_path_vm(
        temp_path("peer-a"),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    );
    let mut other = native_path_vm(
        temp_path("peer-b"),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    );

    let foreign =
        invoke_native_path_value(&mut other.0, &other.2, field(&peer.3, "host_home").clone());
    assert!(
        foreign.is_err(),
        "Core must reject a resource from a peer VM"
    );

    let wrong_handle = {
        let token = other
            .0
            .host_context()
            .push_resource(WrongPathResource)
            .expect("publish a real wrong-type arena resource");
        Value::Int(token.handle().raw() as i64)
    };
    let wrong = invoke_native_path_value(&mut other.0, &other.2, wrong_handle);
    assert!(
        wrong.is_err(),
        "Core must reject a real resource with another type key"
    );
    assert_eq!(other.0.host_context().resource_count(), 2);

    let peer_result = invoke_native_path(&mut peer.0, &peer.2, &peer.3)
        .expect("valid peer resource remains usable");
    assert_eq!(field(&peer_result, "ok"), &Value::Bool(true));
    let other_result = invoke_native_path(&mut other.0, &other.2, &other.3)
        .expect("valid local resource remains usable");
    assert_eq!(field(&other_result, "ok"), &Value::Bool(true));
    peer.1.revoke();
    other.1.revoke();
}

#[test]
fn bound_resource_rejects_rebind_and_reports_revocation_flags() {
    let mut native = native_path_vm(
        temp_path("rebind"),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    );
    let rebind = native
        .1
        .bind_vm(&mut native.0)
        .expect_err("one VM cannot be rebound");
    assert!(format!("{rebind:?}").contains("already_bound"));
    assert_eq!(native.0.host_context().resource_count(), 1);
    let live =
        invoke_native_path(&mut native.0, &native.2, &native.3).expect("peer path stays live");
    assert_eq!(field(&live, "ok"), &Value::Bool(true));

    native.1.revoke();
    let result = invoke_native_path(&mut native.0, &native.2, &native.3)
        .expect("revocation is returned as a typed failure envelope");
    assert_owner_failure(&result, false, false, true);
}

#[test]
fn cancellation_and_elapsed_deadline_flags_are_independent() {
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut cancelled = native_path_vm(temp_path("cancelled"), cancellation.clone());
    cancellation.request(CancellationReason::Requested);
    let result = invoke_native_path(&mut cancelled.0, &cancelled.2, &cancelled.3)
        .expect("cancellation is returned as a typed failure envelope");
    assert_owner_failure(&result, true, false, false);
    cancelled.1.revoke();

    let (program, catalog) = path_program();
    let deadline = RunCancellation::with_timeout(Duration::from_secs(2));
    let mut expired =
        native_path_vm_for_program(program, catalog, temp_path("elapsed"), deadline.clone());
    thread::sleep(
        deadline.remaining_deadline().expect("deadline remains") + Duration::from_millis(10),
    );
    let result = invoke_native_path(&mut expired.0, &expired.2, &expired.3)
        .expect("elapsed deadline is returned as a typed failure envelope");
    assert_owner_failure(&result, false, true, false);
    expired.1.revoke();
}

#[test]
fn path_cpu_loop_cancellation_is_bounded_for_root_and_exported_entry() {
    let executable = std::env::current_exe().expect("test executable path");
    for case in ["root", "entry"] {
        let mut child = Command::new(&executable)
            .arg("--exact")
            .arg("path_cpu_loop_cancellation_child")
            .arg("--nocapture")
            .env("RUSTSCRIPT_PATH_CPU_CASE", case)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start finite-rescue CPU-loop subprocess");
        let rescue = Instant::now() + Duration::from_secs(8);
        loop {
            match child.try_wait().expect("poll CPU-loop subprocess") {
                Some(status) => {
                    let output = child.wait_with_output().expect("collect child output");
                    assert!(
                        status.success(),
                        "{case} CPU-loop subprocess failed: {}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    break;
                }
                None if Instant::now() < rescue => thread::sleep(Duration::from_millis(10)),
                None => {
                    child.kill().expect("kill child after finite rescue");
                    let output = child
                        .wait_with_output()
                        .expect("collect rescued child output");
                    panic!(
                        "{case} CPU-loop subprocess exceeded finite rescue: {}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

#[test]
fn path_cpu_loop_cancellation_child() {
    let Ok(case) = std::env::var("RUSTSCRIPT_PATH_CPU_CASE") else {
        return;
    };
    let source = match case.as_str() {
        "root" => {
            r#"
use config;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

while true { 1; }

pub fn run(
    home: resource<config.path_home>,
    command: AuthCommandInput
) -> ConfigPathResultEnvelope {
    config::resolved_path_result(&home)
}
"#
        }
        "entry" => {
            r#"
use config;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

pub fn run(
    home: resource<config.path_home>,
    command: AuthCommandInput
) -> ConfigPathResultEnvelope {
    while true { 1; }
    config::resolved_path_result(&home)
}
"#
        }
        _ => panic!("unknown finite-rescue case {case}"),
    };
    let runner = runner_from(source);
    let parent = RunCancellation::with_timeout(Duration::from_secs(5));
    let home = temp_path("cpu-loop");
    let watched_child = Arc::new(Mutex::new(None));
    let observer = Arc::new(Mutex::new(None));
    let child_result = Arc::clone(&watched_child);
    let observer_result = Arc::clone(&observer);
    let result = runner.run_with_path_host_factory(command(), &parent, move |child| {
        let request = child.clone();
        let observer_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !request.watcher_is_armed() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            assert!(
                request.watcher_is_armed(),
                "invocation watcher must arm before guest run"
            );
            thread::sleep(Duration::from_millis(15));
            request.request(CancellationReason::Requested);
        });
        *observer_result.lock().expect("observer slot") = Some(observer_thread);
        *child_result.lock().expect("child cancellation slot") = Some(child.clone());
        ConfigPathHost::new(home, child)
    });
    if let Some(observer) = observer.lock().expect("observer slot").take() {
        observer
            .join()
            .expect("request cancellation from live watcher observer");
    }
    assert_eq!(
        result,
        Err(AuthEntryError::Cancelled(CancellationReason::Requested)),
        "real RSS {case} loop must preserve the requested cancellation reason"
    );
    assert!(
        !watched_child
            .lock()
            .expect("child cancellation slot")
            .as_ref()
            .expect("invocation cancellation captured")
            .watcher_is_armed(),
        "invocation watcher must be joined on cancellation"
    );
}

#[test]
fn closing_and_reusing_vm_invalidates_the_old_resource_generation() {
    let mut native = native_path_vm(
        temp_path("reuse"),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    );
    let old_home = field(&native.3, "host_home").clone();
    let first =
        invoke_native_path(&mut native.0, &native.2, &native.3).expect("first real path call");
    assert_eq!(field(&first, "ok"), &Value::Bool(true));

    native
        .0
        .reset_for_reuse()
        .expect("close the current VM scope");
    let rescue_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut context = Context::from_waker(Waker::noop());
        match native.0.poll_reset_for_reuse(&mut context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(error)) => panic!("VM close failed: {error:?}"),
            Poll::Pending if Instant::now() < rescue_deadline => {
                thread::sleep(Duration::from_millis(1))
            }
            Poll::Pending => panic!("VM close did not finish before finite rescue"),
        }
    }
    assert_eq!(native.0.host_context().resource_count(), 0);

    let new_bound = native
        .1
        .bind_vm(&mut native.0)
        .expect("reuse host after resource close");
    assert_eq!(native.0.run().expect("restart RSS root"), VmStatus::Halted);
    let new_callable = native
        .0
        .resolve_exported_callable("run")
        .expect("resolve entry after VM reset");
    assert!(
        invoke_native_path_value(&mut native.0, &new_callable, old_home).is_err(),
        "old resource generation must remain closed after reuse"
    );
    let reused = invoke_native_path(&mut native.0, &new_callable, &new_bound)
        .expect("fresh resource remains valid after reuse");
    assert_eq!(field(&reused, "ok"), &Value::Bool(true));
    native.1.revoke();
}

fn assert_owner_failure(value: &Value, cancelled: bool, deadline_exceeded: bool, revoked: bool) {
    assert_eq!(field(value, "ok"), &Value::Bool(false));
    assert_eq!(
        field(field(value, "error"), "code"),
        &Value::string("policy_inactive")
    );
    assert_eq!(
        field(field(value, "error"), "cancelled"),
        &Value::Bool(cancelled)
    );
    assert_eq!(
        field(field(value, "error"), "deadline_exceeded"),
        &Value::Bool(deadline_exceeded)
    );
    assert_eq!(
        field(field(value, "error"), "revoked"),
        &Value::Bool(revoked)
    );
}
