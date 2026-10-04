use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustscript_agent::auth::host::AuthHost;
use rustscript_agent::cli::{
    CliError, CliInvocation, CliOutput, cli_usage, execute_auth_cli, parse_cli_args,
    resolve_cli_paths,
};
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryRunner, RunCancellation};
use rustscript_agent::{
    AgentConfig, AgentRunner, CancellationReason, RunDeliveryError, RunEventSink,
};
use rustscript_vm::Value;
use std::time::Duration;

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!("auth-cli-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create isolated test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn parse(values: &[&str]) -> Result<CliInvocation, CliError> {
    parse_cli_args(values.iter().map(OsString::from))
}

#[derive(Default)]
struct RecordingSink(Vec<Value>);

impl RunEventSink for RecordingSink {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        self.0.push(value);
        Ok(())
    }
}

fn run_agent(invocation: CliInvocation) -> (Vec<String>, Value, Vec<Value>) {
    let CliInvocation::Run {
        script,
        allowed_hosts,
    } = invocation
    else {
        panic!("expected run invocation");
    };
    let runner = AgentRunner::from_file(
        script,
        AgentConfig::for_hosts(allowed_hosts.iter().map(String::as_str)),
    )
    .expect("compile forwarded RSS file");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut sink = RecordingSink::default();
    let value = runner
        .run_with_context_and_events(Value::map(vec![]), &mut sink, &cancellation)
        .expect("execute forwarded RSS file and collect events");
    assert!(!cancellation.watcher_is_armed());
    (allowed_hosts, value, sink.0)
}

#[test]
fn legacy_and_explicit_run_forward_the_same_real_rss_script_and_hosts() {
    let dir = TestDir::new("argv");
    let script = dir.0.join("forward.rss");
    fs::write(
        &script,
        "use stream; pub fn run(input: map) -> string { stream::emit(\"shell-event\"); \"shell-forwarded\" }",
    )
    .expect("write inline RSS source");
    let script_text = script.to_string_lossy().into_owned();
    let hosts = ["fixture.invalid", "fixture.invalid"];

    let legacy = parse_cli_args(
        [
            "--script",
            script_text.as_str(),
            "--allow-host",
            hosts[0],
            "--allow-host",
            hosts[1],
        ]
        .into_iter()
        .map(OsString::from),
    )
    .expect("parse legacy invocation");
    let explicit = parse_cli_args(
        [
            "run",
            "--script",
            script_text.as_str(),
            "--allow-host",
            hosts[0],
            "--allow-host",
            hosts[1],
        ]
        .into_iter()
        .map(OsString::from),
    )
    .expect("parse explicit invocation");

    let (legacy_hosts, legacy_value, legacy_events) = run_agent(legacy);
    let (explicit_hosts, explicit_value, explicit_events) = run_agent(explicit);
    assert_eq!(legacy_hosts, hosts);
    assert_eq!(explicit_hosts, hosts);
    assert_eq!(legacy_value, Value::string("shell-forwarded"));
    assert_eq!(explicit_value, legacy_value);
    assert_eq!(legacy_events, [Value::string("shell-event")]);
    assert_eq!(explicit_events, legacy_events);
}

#[test]
fn last_script_value_wins_without_reordering_hosts() {
    let dir = TestDir::new("last-script");
    let first = dir.0.join("first.rss");
    let last = dir.0.join("last.rss");
    fs::write(&first, "pub fn run(input: map) -> string { \"first\" }").expect("write first RSS");
    fs::write(&last, "pub fn run(input: map) -> string { \"last\" }").expect("write last RSS");
    let first = first.to_string_lossy().into_owned();
    let last = last.to_string_lossy().into_owned();
    let invocation = parse_cli_args(
        [
            "--script",
            first.as_str(),
            "--allow-host",
            "host-a.invalid",
            "--script",
            last.as_str(),
            "--allow-host",
            "host-b.invalid",
        ]
        .into_iter()
        .map(OsString::from),
    )
    .expect("parse compatible repeated script option");
    let (hosts, result, events) = run_agent(invocation);
    assert_eq!(hosts, ["host-a.invalid", "host-b.invalid"]);
    assert_eq!(result, Value::string("last"));
    assert!(events.is_empty());
}

type AuthCliGrammarCase<'a> = (&'a [&'a str], &'a str, Option<&'a str>, Option<&'a str>);

#[test]
fn admin_commands_map_to_the_exact_generic_auth_envelope() {
    let cases: &[AuthCliGrammarCase<'_>] = &[
        (
            &["auth", "login", "provider/name:Case"],
            "auth.login",
            Some("provider/name:Case"),
            None,
        ),
        (&["auth", "status"], "auth.status", None, None),
        (
            &["auth", "status", "unlisted-provider"],
            "auth.status",
            Some("unlisted-provider"),
            None,
        ),
        (
            &["auth", "logout", "opaque-id/unchanged"],
            "auth.logout",
            None,
            Some("opaque-id/unchanged"),
        ),
        (&["config", "path"], "config.path", None, None),
        (&["config", "check"], "config.check", None, None),
    ];

    for (args, operation, provider, credential_id) in cases {
        let invocation = parse(args).expect("parse syntax-only command");
        let CliInvocation::Auth(input) = invocation else {
            panic!("expected generic AuthCommandInput");
        };
        assert_eq!(
            input,
            AuthCommandInput {
                operation: (*operation).to_owned(),
                provider: provider.map(str::to_owned),
                credential_id: credential_id.map(str::to_owned),
            }
        );
    }
}

#[test]
fn malformed_and_unsafe_argv_is_rejected_without_echoing_values() {
    for args in [
        &[][..],
        &["unknown"][..],
        &["unknown", "--help"][..],
        &["run"][..],
        &["run", "auth", "login", "provider-name"][..],
        &["--script"][..],
        &["--script", "--allow-host", "host.invalid"][..],
        &["--script", "path.rss"][..],
        &["--script", "path.rss", "--allow-host"][..],
        &["--script", "path.rss", "--allow-host", ""][..],
        &["auth"][..],
        &["auth", "login"][..],
        &["auth", "login", ""][..],
        &["auth", "status", "", "extra"][..],
        &["auth", "login", "provider-name", "--help"][..],
        &["auth", "logout"][..],
        &["config", "path", "extra"][..],
        &["config", "check", "-h"][..],
        &["config", "other"][..],
        &["auth", "login", "bad\u{7f}provider"][..],
    ] {
        assert!(matches!(parse(args), Err(CliError::InvalidArguments)));
    }
    assert!(parse(&["--help"]).is_ok());
    assert!(parse(&["-h"]).is_ok());
    assert!(parse(&["run", "--help"]).is_ok());
    assert!(matches!(
        parse(&[
            "--script",
            "opaque-path-marker",
            "--allow-host",
            "host.invalid",
            "-h"
        ]),
        Ok(CliInvocation::Help)
    ));
    let error = parse(&["--opaque-secret-marker"]).expect_err("unknown argv must fail");
    assert_eq!(error.code(), "cli_arguments_invalid");
    assert_eq!(error.to_string(), "cli_arguments_invalid");
    assert!(!error.to_string().contains("opaque-secret-marker"));
}

#[cfg(unix)]
#[test]
fn run_script_path_preserves_non_utf8_os_strings() {
    use std::os::unix::ffi::OsStringExt;

    let script = OsString::from_vec(b"/assigned/temp/script-\xff.rss".to_vec());
    let invocation = parse_cli_args([
        OsString::from("--script"),
        script.clone(),
        OsString::from("--allow-host"),
        OsString::from("host.invalid"),
    ])
    .expect("script path accepts native OsString bytes");
    assert!(matches!(
        invocation,
        CliInvocation::Run { script: path, .. } if path.as_os_str() == script.as_os_str()
    ));

    let invalid_selector = OsString::from_vec(b"provider-\xff".to_vec());
    assert!(matches!(
        parse_cli_args([
            OsString::from("auth"),
            OsString::from("login"),
            invalid_selector
        ]),
        Err(CliError::InvalidArguments)
    ));
    let invalid_host = OsString::from_vec(b"host-\xff".to_vec());
    assert!(matches!(
        parse_cli_args([
            OsString::from("--script"),
            OsString::from("valid.rss"),
            OsString::from("--allow-host"),
            invalid_host,
        ]),
        Err(CliError::InvalidArguments)
    ));
}

#[test]
fn dash_prefixed_legacy_values_remain_values_not_new_flag_policy() {
    let invocation = parse_cli_args([
        OsString::from("--script"),
        OsString::from("-legacy-script.rss"),
        OsString::from("--allow-host"),
        OsString::from("-legacy-host"),
    ])
    .expect("legacy parser consumes supplied argv values verbatim");
    assert_eq!(
        invocation,
        CliInvocation::Run {
            script: PathBuf::from("-legacy-script.rss"),
            allowed_hosts: vec!["-legacy-host".to_owned()],
        }
    );
}

#[test]
fn run_host_value_is_not_limited_by_admin_selector_size() {
    let host = format!("host-{}", "x".repeat(2048));
    let invocation = parse_cli_args([
        OsString::from("--script"),
        OsString::from("script.rss"),
        OsString::from("--allow-host"),
        OsString::from(&host),
    ])
    .expect("run host value uses the legacy argv forwarding contract");
    assert_eq!(
        invocation,
        CliInvocation::Run {
            script: PathBuf::from("script.rss"),
            allowed_hosts: vec![host],
        }
    );
}

#[test]
fn usage_describes_legacy_run_and_admin_syntax() {
    let usage = cli_usage();
    for grammar in [
        "--script PATH",
        "run --script PATH",
        "auth login PROVIDER",
        "auth status [PROVIDER]",
        "auth logout ID",
        "config path",
        "config check",
    ] {
        assert!(usage.contains(grammar), "usage missing {grammar}");
    }
}

fn populated_home(label: &str) -> TestDir {
    let home = TestDir::new(label);
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.0.join("config.yaml")).expect("copy config fixture");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("read synthetic auth fixture")
        .replace("1788440000000", "1900000000000")
        .replace("1788436400000", "1899996400000");
    fs::write(home.0.join("auth.yaml"), auth).expect("write synthetic auth fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home.0, fs::Permissions::from_mode(0o700)).expect("private test home");
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(home.0.join(name), fs::Permissions::from_mode(0o600))
                .expect("private fixture file");
        }
    }
    home
}

fn command_input(operation: &str, provider: Option<&str>) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: provider.map(str::to_owned),
        credential_id: None,
    }
}

fn inline_command_runner() -> AuthEntryRunner {
    let source = r#"use config;
struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}
struct AuthEntryResult {
    ok: bool,
    operation: string,
    credential_id: string?,
    generation: int,
    status: string,
    error: string?
}
pub fn run(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {
    let snapshot = config::load_snapshot(&home);
    {
        ok: snapshot.ok,
        operation: command.operation,
        credential_id: command.provider,
        generation: snapshot.policy_generation,
        status: "rss-row\nsecond-row",
        error: snapshot.error
    }
}
"#;
    AuthEntryRunner::from_bundle(
        "rss/auth/runner_entry.rss",
        &[("rss/auth/runner_entry.rss", source)],
    )
    .expect("compile inline typed RSS command entry")
}

fn rss_string_literal(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => {
                write!(&mut escaped, "\\x{:02x}", control as u32).expect("write escape");
            }
            other => escaped.push(other),
        }
    }
    escaped.insert(0, '"');
    escaped.push('"');
    escaped
}

fn inline_result_runner(ok: bool, status: &str, error: Option<&str>) -> AuthEntryRunner {
    let ok = if ok { "true" } else { "false" };
    let status = rss_string_literal(status);
    let error = error
        .map(rss_string_literal)
        .unwrap_or_else(|| "null".to_owned());
    let source = format!(
        r#"use config;
struct AuthCommandInput {{
    operation: string,
    provider: string?,
    credential_id: string?
}}
struct AuthEntryResult {{
    ok: bool,
    operation: string,
    credential_id: string?,
    generation: int,
    status: string,
    error: string?
}}
pub fn run(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {{
    let snapshot = config::load_snapshot(&home);
    {{
        ok: {ok} && snapshot.ok,
        operation: command.operation,
        credential_id: command.provider,
        generation: snapshot.policy_generation,
        status: {status},
        error: {error}
    }}
}}
"#
    );
    AuthEntryRunner::from_bundle(
        "rss/auth/runner_entry.rss",
        &[("rss/auth/runner_entry.rss", &source)],
    )
    .unwrap_or_else(|error| {
        panic!(
            "compile bounded inline RSS result ({} bytes): {}",
            source.len(),
            error.code()
        )
    })
}

fn assert_child_watcher_disarmed(child: &Arc<Mutex<Option<RunCancellation>>>) {
    let child = child.lock().expect("child cancellation capture");
    assert!(
        !child
            .as_ref()
            .expect("captured child token")
            .watcher_is_armed()
    );
}

fn value_field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected typed RSS result map");
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing typed RSS field {name}"))
}

#[test]
fn rss_status_is_rendered_after_real_native_command_host_execution() {
    let home = populated_home("native-render");
    let runner = inline_command_runner();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let CliInvocation::Auth(input) =
        parse(&["auth", "status", "provider-arbitrary"]).expect("parse auth status")
    else {
        panic!("expected generic auth invocation");
    };
    let output = execute_auth_cli(&runner, input, &cancellation, move |child| {
        AuthHost::new_for_commands(home.0.clone(), child)
    });

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "rss-row\nsecond-row\n");
    assert!(output.stderr.is_empty());
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn parsed_admin_envelope_reaches_real_rss_and_native_snapshot_unchanged() {
    let home = populated_home("forwarded-envelope");
    let runner = inline_command_runner();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let CliInvocation::Auth(input) =
        parse(&["auth", "status", "unlisted/vendor-arbitrary"]).expect("parse auth status")
    else {
        panic!("expected generic auth invocation");
    };
    let value = runner
        .run_with_host_factory(input, &cancellation, move |child| {
            AuthHost::new_for_commands(home.0.clone(), child)
        })
        .expect("execute parsed envelope through actual native host");

    assert_eq!(value_field(&value, "ok"), &Value::Bool(true));
    assert_eq!(
        value_field(&value, "operation"),
        &Value::string("auth.status")
    );
    assert_eq!(
        value_field(&value, "credential_id"),
        &Value::string("unlisted/vendor-arbitrary")
    );
    assert_eq!(value_field(&value, "generation"), &Value::Int(1));
    assert_eq!(
        value_field(&value, "status"),
        &Value::string("rss-row\nsecond-row")
    );
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn cli_error_display_is_only_a_static_redacted_code() {
    let error = CliError::InvalidHome;
    assert_eq!(error.code(), "cli_home_invalid");
    assert_eq!(error.to_string(), "cli_home_invalid");
}

#[test]
fn isolated_home_child_process() {
    let Ok(mode) = std::env::var("AUTH_CLI_HOME_CHILD") else {
        return;
    };
    if mode == "isolated" {
        let selected = std::env::var_os("RUSTSCRIPT_AGENT_HOME").expect("selected home");
        let default_home = std::env::var_os("HOME").expect("isolated default home");
        let paths = resolve_cli_paths().expect("resolve selected home");
        assert_eq!(paths.home, PathBuf::from(&selected));
        assert_ne!(paths.home, PathBuf::from(&default_home));

        let runner = inline_command_runner();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let selected_home = paths.home.clone();
        let output = execute_auth_cli(
            &runner,
            command_input("config.check", None),
            &cancellation,
            move |child| AuthHost::new_for_commands(selected_home, child),
        );
        assert_eq!(output.exit_code, 0);
        assert!(
            !output
                .stdout
                .contains(&paths.home.to_string_lossy().to_string())
        );
        assert!(
            !output
                .stderr
                .contains(&paths.home.to_string_lossy().to_string())
        );
        assert!(!PathBuf::from(default_home).exists());
    } else if mode == "default" {
        let home = PathBuf::from(std::env::var_os("HOME").expect("default home"));
        let paths = resolve_cli_paths().expect("resolve HOME default");
        assert_eq!(paths.home, home.join(".rustscript-agent"));
        assert!(!paths.home.exists());
    } else if mode == "invalid" {
        let default_home = std::env::var_os("HOME").expect("sentinel default home");
        let error = resolve_cli_paths().expect_err("empty trusted override must fail");
        assert_eq!(error.code(), "cli_home_invalid");
        assert_eq!(error.to_string(), "cli_home_invalid");
        assert!(
            !error
                .to_string()
                .contains(&PathBuf::from(&default_home).display().to_string())
        );
        assert!(!PathBuf::from(default_home).exists());
    } else {
        panic!("unknown child mode");
    }
}

#[test]
fn home_resolution_and_native_execution_use_only_child_selected_home() {
    let selected = populated_home("selected-home");
    let sentinel = selected.0.join("default-home-not-used");
    assert!(!sentinel.exists());

    for mode in ["isolated", "default", "invalid"] {
        let mut child = Command::new(std::env::current_exe().expect("test executable"));
        child
            .args(["--exact", "isolated_home_child_process", "--nocapture"])
            .env("AUTH_CLI_HOME_CHILD", mode)
            .env(
                "RUSTSCRIPT_AGENT_TEST_TMP",
                std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"),
            );
        if mode == "isolated" {
            child
                .env("RUSTSCRIPT_AGENT_HOME", &selected.0)
                .env("HOME", &sentinel)
                .env_remove("USERPROFILE");
        } else if mode == "default" {
            child
                .env_remove("RUSTSCRIPT_AGENT_HOME")
                .env("HOME", &sentinel)
                .env_remove("USERPROFILE");
        } else {
            child
                .env("RUSTSCRIPT_AGENT_HOME", "")
                .env("HOME", &sentinel)
                .env_remove("USERPROFILE");
        }
        let output = child.output().expect("run environment-isolated child");
        assert!(
            output.status.success(),
            "child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains(&selected.0.to_string_lossy().to_string()));
        assert!(!stderr.contains(&selected.0.to_string_lossy().to_string()));
    }
    assert!(!sentinel.exists());
    assert!(!sentinel.join(".rustscript-agent").exists());
}

#[test]
fn negative_rss_result_uses_business_exit_and_bounded_error_category() {
    let home = populated_home("negative-output");
    let runner = inline_result_runner(false, "negative-row", Some("credential_unavailable"));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let output = execute_auth_cli(
        &runner,
        command_input("auth.status", None),
        &cancellation,
        move |child| AuthHost::new_for_commands(home.0.clone(), child),
    );

    assert_eq!(
        output,
        CliOutput {
            exit_code: 1,
            stdout: "negative-row\n".to_owned(),
            stderr: "credential_unavailable\n".to_owned(),
        }
    );
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn output_bounds_and_controls_fail_closed_without_partial_stdout() {
    let home = populated_home("output-boundaries");
    let home_path = home.0.clone();
    let boundary = inline_result_runner(true, &"x".repeat(256 * 1024 - 1), None);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let boundary_child = Arc::new(Mutex::new(None));
    let captured_boundary = Arc::clone(&boundary_child);
    let output = execute_auth_cli(
        &boundary,
        command_input("config.check", None),
        &cancellation,
        {
            let home_path = home_path.clone();
            move |child| {
                *captured_boundary
                    .lock()
                    .expect("child cancellation capture") = Some(child.clone());
                AuthHost::new_for_commands(home_path, child)
            }
        },
    );
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout.len(), 256 * 1024);
    assert!(output.stdout.ends_with('\n'));
    assert!(output.stderr.is_empty());
    assert_child_watcher_disarmed(&boundary_child);

    let cases = [
        (
            inline_result_runner(true, &"x".repeat(256 * 1024 + 1), None),
            "cli_output_too_large\n",
        ),
        (
            inline_result_runner(true, "valid-row", Some(&"e".repeat(2048))),
            "cli_output_too_large\n",
        ),
        (
            inline_result_runner(true, "valid-row", Some("bad\ncategory")),
            "cli_output_invalid\n",
        ),
    ];
    for (runner, expected_error) in cases {
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let child_cancellation = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&child_cancellation);
        let output = execute_auth_cli(
            &runner,
            command_input("config.check", None),
            &cancellation,
            {
                let home_path = home_path.clone();
                move |child| {
                    *captured.lock().expect("child cancellation capture") = Some(child.clone());
                    AuthHost::new_for_commands(home_path, child)
                }
            },
        );
        assert_eq!(output.exit_code, 1);
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, expected_error);
        assert!(!cancellation.watcher_is_armed());
        assert_child_watcher_disarmed(&child_cancellation);
    }

    for control in ['\0', '\x01', '\x1b', '\x7f'] {
        let runner = inline_result_runner(true, &format!("unsafe{control}report"), None);
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let child_cancellation = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&child_cancellation);
        let output = execute_auth_cli(
            &runner,
            command_input("config.check", None),
            &cancellation,
            {
                let home_path = home_path.clone();
                move |child| {
                    *captured.lock().expect("child cancellation capture") = Some(child.clone());
                    AuthHost::new_for_commands(home_path, child)
                }
            },
        );
        assert_eq!(output.exit_code, 1);
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, "cli_output_invalid\n");
        assert_child_watcher_disarmed(&child_cancellation);
    }
}

#[test]
fn native_factory_failures_and_pre_cancelled_inputs_are_redacted_and_typed() {
    let runner = inline_command_runner();
    let marker = "PRIVATE_FACTORY_SECRET_MARKER";
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let output = execute_auth_cli(
        &runner,
        command_input("config.check", None),
        &cancellation,
        move |_| Err(marker.to_owned()),
    );
    assert_eq!(
        output,
        CliOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "auth_host_setup_failed\n".to_owned(),
        }
    );
    assert!(!output.stdout.contains(marker));
    assert!(!output.stderr.contains(marker));
    assert!(!cancellation.watcher_is_armed());

    for (reason, exit_code) in [
        (CancellationReason::Requested, 130),
        (CancellationReason::Deadline, 124),
    ] {
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        cancellation.request(reason);
        let called = Arc::new(AtomicBool::new(false));
        let output = execute_auth_cli(
            &runner,
            command_input("config.check", None),
            &cancellation,
            {
                let called = Arc::clone(&called);
                move |_| {
                    called.store(true, Ordering::SeqCst);
                    Err("must-not-run".to_owned())
                }
            },
        );
        assert_eq!(output.exit_code, exit_code);
        assert_eq!(output.stdout, "");
        assert_eq!(output.stderr, "auth_cancelled\n");
        assert!(!called.load(Ordering::SeqCst));
        assert!(!cancellation.watcher_is_armed());
    }

    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let called = Arc::new(AtomicBool::new(false));
    let output = execute_auth_cli(
        &runner,
        command_input(&"x".repeat(2049), None),
        &cancellation,
        {
            let called = Arc::clone(&called);
            move |_| {
                called.store(true, Ordering::SeqCst);
                Err("must-not-run".to_owned())
            }
        },
    );
    assert_eq!(output.exit_code, 1);
    assert_eq!(output.stderr, "auth_input_invalid\n");
    assert!(!called.load(Ordering::SeqCst));
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn in_run_deadline_maps_to_timeout_and_disarms_native_watcher() {
    let source = "use auth; while true { 1; } pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }";
    let runner = AuthEntryRunner::from_source(source).expect("compile RSS loop for cancellation");
    let home = populated_home("deadline-loop");
    let cancellation = RunCancellation::with_timeout(Duration::from_millis(300));
    let child_cancellation = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&child_cancellation);
    let output = execute_auth_cli(
        &runner,
        command_input("config.check", None),
        &cancellation,
        move |child| {
            *captured.lock().expect("child cancellation capture") = Some(child.clone());
            AuthHost::new_for_commands(home.0.clone(), child)
        },
    );

    assert_eq!(output.exit_code, 124);
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, "auth_cancelled\n");
    assert!(!cancellation.watcher_is_armed());
    let child = child_cancellation
        .lock()
        .expect("child cancellation capture");
    assert!(
        !child
            .as_ref()
            .expect("captured child token")
            .watcher_is_armed()
    );
}
