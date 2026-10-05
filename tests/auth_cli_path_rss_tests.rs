use rustscript_agent::auth::host::{AuthHost, ConfigPathHost, auth_host_catalog};
use rustscript_agent::cli::{CliOutput, execute_config_path_cli};
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::{
    CapabilityProfile, CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm,
    compile_source_with_flavor_and_options,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ENTRY_PATH: &str = "rss/config/path.rss";
const SOURCES: &[(&str, &str)] = &[(ENTRY_PATH, include_str!("../rss/config/path.rss"))];

struct TempArea(PathBuf);

impl TempArea {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 test temp"),
        );
        let area = root.join(format!("path-rss-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&area).expect("create isolated area");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&area, fs::Permissions::from_mode(0o700)).expect("private area");
        }
        Self(area)
    }
}

impl Drop for TempArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn runner() -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES).expect("compile production path bundle")
}

fn command(
    operation: &str,
    provider: Option<&str>,
    credential_id: Option<&str>,
) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: provider.map(str::to_owned),
        credential_id: credential_id.map(str::to_owned),
    }
}

fn run_path(runner: &AuthEntryRunner, home: &Path) -> Result<Value, AuthEntryError> {
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    runner.run_with_path_host_factory(command("config.path", None, None), &cancellation, {
        let home = home.to_path_buf();
        move |child| ConfigPathHost::new(home, child)
    })
}

fn run_path_once(
    runner: &AuthEntryRunner,
    home: &Path,
    input: AuthCommandInput,
) -> Result<Value, AuthEntryError> {
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    runner.run_with_path_host_factory(input, &cancellation, {
        let home = home.to_path_buf();
        move |child| ConfigPathHost::new(home, child)
    })
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected typed report map, got {value:?}");
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(fields) = value else {
        panic!("expected typed report map, got {value:?}");
    };
    fields.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn assert_report_error(value: &Value, operation: &str, code: &str) {
    assert_eq!(field(value, "ok"), &Value::Bool(false), "{value:?}");
    assert_eq!(field(value, "operation"), &Value::string(operation));
    assert_eq!(field(value, "status"), &Value::string(""));
    assert_eq!(field(value, "error"), &Value::string(code));
    assert_eq!(field(value, "generation"), &Value::Int(0));
    assert!(optional_field(value, "credential_id").is_none_or(|v| matches!(v, Value::Null)));
}

#[test]
fn production_path_bundle_reports_the_common_auth_entry_wire() {
    let area = TempArea::new("common-wire");
    let home = area.0.join("home");
    fs::create_dir(&home).expect("existing home");
    let output = run_path(&runner(), &home).expect("run production path bundle");
    assert_eq!(field(&output, "ok"), &Value::Bool(true), "{output:?}");
    assert_eq!(field(&output, "operation"), &Value::string("config.path"));
    assert_eq!(field(&output, "generation"), &Value::Int(0));
    assert!(optional_field(&output, "credential_id").is_none_or(|v| matches!(v, Value::Null)));
    assert!(optional_field(&output, "error").is_none_or(|v| matches!(v, Value::Null)));
    assert_eq!(
        field(&output, "status"),
        &Value::string(home.join("config.yaml").to_str().unwrap())
    );
}

#[test]
fn missing_and_existing_homes_are_reported_lexically_without_creation() {
    let area = TempArea::new("lexical");
    let existing = area.0.join("existing");
    fs::create_dir(&existing).expect("existing home");
    let before = fs::read_dir(&existing).expect("read home").count();
    let existing_result = run_path(&runner(), &existing).expect("existing home run");
    assert_eq!(
        field(&existing_result, "status"),
        &Value::string(existing.join("config.yaml").to_str().unwrap())
    );
    assert_eq!(fs::read_dir(&existing).expect("read home").count(), before);

    let missing = area.0.join("nested").join("absent home");
    let missing_result = run_path(&runner(), &missing).expect("missing home run");
    assert_eq!(
        field(&missing_result, "status"),
        &Value::string(missing.join("config.yaml").to_str().unwrap())
    );
    assert!(!missing.exists(), "path lookup must not create the home");
    assert!(
        !missing.parent().expect("parent").exists(),
        "path lookup must not create parents"
    );
}

#[test]
fn corrupt_config_and_auth_bytes_are_ignored_by_the_path_branch() {
    let area = TempArea::new("opaque");
    let home = area.0.join("home");
    fs::create_dir(&home).expect("home");
    fs::write(home.join("config.yaml"), b"invalid: [config bytes\xff").expect("corrupt config");
    fs::write(home.join("auth.yaml"), b"invalid: [auth bytes\xfe").expect("corrupt auth");
    let config_before = fs::read(home.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(home.join("auth.yaml")).expect("auth bytes");

    let output = run_path(&runner(), &home).expect("path branch ignores config bytes");
    assert_eq!(
        field(&output, "status"),
        &Value::string(home.join("config.yaml").to_str().unwrap())
    );
    assert!(!format!("{output:?}").contains("config bytes"));
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(home.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(fs::read_dir(&home).expect("read home").count(), 2);
}

#[test]
fn legal_path_bytes_are_preserved_and_invalid_paths_are_redacted() {
    let area = TempArea::new("legal");
    let legal_home = area.0.join(r#"space "quoted" and \backslash"#);
    let output = run_path(&runner(), &legal_home).expect("legal path run");
    assert_eq!(
        field(&output, "status"),
        &Value::string(legal_home.join("config.yaml").to_str().unwrap())
    );

    let control_home = area.0.join(format!("line{}break", '\n'));
    let control = run_path(&runner(), &control_home).expect("control path report");
    assert_report_error(&control, "config.path", "invalid_path");
    assert!(
        !format!("{control:?}").contains("line"),
        "invalid path bytes must not be echoed: {control:?}"
    );

    let long_home = (0..11).fold(area.0.clone(), |path, _| path.join("x".repeat(220)));
    assert!(long_home.join("config.yaml").as_os_str().len() > 2048);
    let long = run_path(&runner(), &long_home).expect("over-bound path report");
    assert_report_error(&long, "config.path", "invalid_path");

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = area.0.as_os_str().as_encoded_bytes().to_vec();
        bytes.extend_from_slice(b"/invalid-\xff-home");
        let invalid_utf8 = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        let report = run_path(&runner(), &invalid_utf8).expect("non-UTF-8 path report");
        assert_report_error(&report, "config.path", "invalid_path");
        assert!(!format!("{report:?}").contains("invalid-"));
    }
}

#[test]
fn rss_owns_operation_and_selector_validation_for_the_path_branch() {
    let area = TempArea::new("business-validation");
    let home = area.0.join("home");
    fs::create_dir(&home).expect("home");

    let unsupported = run_path_once(&runner(), &home, command("config.check", None, None))
        .expect("unsupported operation report");
    assert_report_error(&unsupported, "config.check", "unsupported_operation");

    let with_provider = run_path_once(
        &runner(),
        &home,
        command("config.path", Some("vendor"), None),
    )
    .expect("selector rejection report");
    assert_report_error(&with_provider, "config.path", "invalid_command");

    let with_credential = run_path_once(
        &runner(),
        &home,
        command("config.path", None, Some("credential")),
    )
    .expect("credential rejection report");
    assert_report_error(&with_credential, "config.path", "invalid_command");

    assert_eq!(fs::read_dir(&home).expect("read home").count(), 0);
}

#[test]
fn invalid_home_stays_a_static_setup_failure_without_disclosure() {
    for home in [
        PathBuf::from("relative-home"),
        PathBuf::from("/root/../outside"),
    ] {
        let error = run_path(&runner(), &home).expect_err("invalid home must be rejected");
        assert_eq!(error, AuthEntryError::HostSetup);
        assert!(!format!("{error:?}").contains(&home.to_string_lossy().to_string()));
    }
}

#[test]
fn missing_expired_and_requested_cancellations_precede_host_effects() {
    let runner = runner();
    let called = std::cell::Cell::new(false);

    let unbounded = RunCancellation::new();
    let error = runner
        .run_with_path_host_factory(command("config.path", None, None), &unbounded, |child| {
            called.set(true);
            ConfigPathHost::new(PathBuf::from("/nonexistent-home"), child)
        })
        .expect_err("unbounded cancellation must be rejected");
    assert_eq!(error, AuthEntryError::DeadlineRequired);
    assert!(!called.get());

    let expired = RunCancellation::with_deadline(Instant::now() - Duration::from_secs(1));
    let error = runner
        .run_with_path_host_factory(command("config.path", None, None), &expired, |child| {
            called.set(true);
            ConfigPathHost::new(PathBuf::from("/nonexistent-home"), child)
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
        .run_with_path_host_factory(command("config.path", None, None), &requested, |child| {
            called.set(true);
            ConfigPathHost::new(PathBuf::from("/nonexistent-home"), child)
        })
        .expect_err("requested cancellation must be rejected");
    assert_eq!(
        error,
        AuthEntryError::Cancelled(CancellationReason::Requested)
    );
    assert!(!called.get());
}

#[test]
fn malformed_guest_reports_are_rejected_by_the_shared_report_validator() {
    let area = TempArea::new("malformed");
    let home = area.0.join("home");
    fs::create_dir(&home).expect("home");

    // The former raw primitive envelope is no longer a valid runner report.
    let primitive = r#"
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
    let primitive_runner = AuthEntryRunner::from_bundle("main.rss", &[("main.rss", primitive)])
        .expect("raw primitive bundle compiles");
    let error = run_path_once(&primitive_runner, &home, command("config.path", None, None))
        .expect_err("raw primitive envelope is not a valid report wire");
    assert_eq!(error, AuthEntryError::OutputInvalid);

    // A guest report that omits required fields is rejected without partial output.
    let truncated = r#"
struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}

pub fn run(home: int, command: AuthCommandInput) -> map {
    {ok: true, status: "incomplete"}
}
"#;
    let truncated_runner = AuthEntryRunner::from_bundle("main.rss", &[("main.rss", truncated)])
        .expect("truncated bundle compiles");
    let error = run_path_once(&truncated_runner, &home, command("config.path", None, None))
        .expect_err("truncated report is rejected");
    assert!(
        matches!(
            error,
            AuthEntryError::OutputInvalid
                | AuthEntryError::HomeBind
                | AuthEntryError::HomeCarrier
                | AuthEntryError::EntryArity
                | AuthEntryError::NoEntry
        ),
        "unexpected truncated-report error: {error:?}"
    );
}

#[test]
fn cli_adapter_renders_success_and_bounded_business_failure() {
    let area = TempArea::new("cli-adapter");
    let home = area.0.join("home");
    fs::create_dir(&home).expect("home");

    let runner = runner();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let home_path = home.clone();
    let success = execute_config_path_cli(
        &runner,
        command("config.path", None, None),
        &cancellation,
        move |child| ConfigPathHost::new(home_path, child),
    );
    assert_eq!(
        success,
        CliOutput {
            exit_code: 0,
            stdout: format!("{}\n", home.join("config.yaml").to_string_lossy()),
            stderr: String::new(),
        }
    );
    assert!(!cancellation.watcher_is_armed());

    let control_home = area.0.join(format!("bad{}path", '\x1b'));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let failure = execute_config_path_cli(
        &runner,
        command("config.path", None, None),
        &cancellation,
        move |child| ConfigPathHost::new(control_home, child),
    );
    assert_eq!(failure.exit_code, 1);
    assert!(failure.stdout.is_empty(), "stdout={:?}", failure.stdout);
    assert_eq!(failure.stderr, "invalid_path\n");
    assert!(!cancellation.watcher_is_armed());

    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let unsupported = execute_config_path_cli(
        &runner,
        command("config.check", None, None),
        &cancellation,
        {
            let home = home.clone();
            move |child| ConfigPathHost::new(home, child)
        },
    );
    assert_eq!(unsupported.exit_code, 1);
    assert!(unsupported.stdout.is_empty());
    assert_eq!(unsupported.stderr, "unsupported_operation\n");
}

#[test]
fn valid_auth_entry_report_wire_is_shared_with_the_path_validator() {
    // Compile the real auth command bundle and confirm the shared validator still
    // accepts its AuthEntryResult shape through the auth host factory.
    let area = TempArea::new("shared-wire");
    let home = area.0.join("home");
    fs::create_dir(&home).expect("home");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("copy config");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("read auth fixture")
        .replace("1788440000000", "1900000000000")
        .replace("1788436400000", "1899996400000");
    fs::write(home.join("auth.yaml"), auth).expect("write auth fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("private home");
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                .expect("private fixture");
        }
    }

    let auth_runner = AuthEntryRunner::from_bundle(
        "rss/auth/commands.rss",
        &[
            (
                "rss/auth/commands.rss",
                include_str!("../rss/auth/commands.rss"),
            ),
            (
                "rss/config/selection.rss",
                include_str!("../rss/config/selection.rss"),
            ),
        ],
    )
    .expect("compile real auth bundle");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let report = auth_runner
        .run_with_host_factory(command("config.check", None, None), &cancellation, {
            let home = home.clone();
            move |child| AuthHost::new_for_commands(home, child)
        })
        .expect("shared validator accepts the real auth report");
    assert_eq!(field(&report, "operation"), &Value::string("config.check"));
    assert!(optional_field(&report, "status").is_some());
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn native_path_bridge_remains_reachable_for_direct_primitive_compilation() {
    // The native descriptor still returns ConfigPathResultEnvelope inside RSS; it is
    // never printed as a business result but must still compile against the catalog.
    let source = r#"
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
    let catalog = auth_host_catalog();
    let compiled = compile_source_with_flavor_and_options(
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("native path descriptor compiles in real RSS");
    let mut vm = Vm::try_new(compiled.program).expect("fresh VM");
    let home = TempArea::new("native-bridge").0.join("home");
    let host = ConfigPathHost::new(home, RunCancellation::with_timeout(Duration::from_secs(10)))
        .expect("path host");
    let mut registry = HostFunctionRegistry::empty();
    registry.set_capability_profile(CapabilityProfile::deny_all());
    host.register(&mut registry, catalog.as_ref())
        .expect("register path module");
    registry.set_capability_profile(CapabilityProfile::deny_all());
    registry.authorize_registered_builtin_import("config::resolved_path_result");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind path registry");
    let bound = host.bind_vm(&mut vm).expect("publish path resource");
    assert_eq!(
        vm.run().expect("run RSS root"),
        rustscript_vm::VmStatus::Halted
    );
    let callable = vm.resolve_exported_callable("run").expect("resolve entry");
    let native = vm
        .invoke_callable(
            callable,
            &[
                field(&bound, "host_home").clone(),
                Value::map(vec![
                    (Value::string("operation"), Value::string("config.path")),
                    (Value::string("provider"), Value::Null),
                    (Value::string("credential_id"), Value::Null),
                ]),
            ],
        )
        .expect("invoke native path primitive");
    assert_eq!(field(&native, "ok"), &Value::Bool(true));
    assert!(matches!(field(&native, "value"), Value::String(_)));
    host.revoke();
}
