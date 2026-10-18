use rustscript_agent::auth::host::AuthHost;
use rustscript_agent::auth::host::{PublicDeviceInstruction, device_instruction_channel};
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext, PreparedHttpsRequest,
    RawHttpsResponse, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport,
};
use rustscript_agent::runtime::{
    AuthCommandInput, AuthEntryError, AuthEntryRunner, MAX_AGENT_SOURCE_BYTES,
};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::Value;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const ENTRY_PATH: &str = "rss/auth/runner_entry.rss";
const SOURCES: &[(&str, &str)] = &[
    (
        ENTRY_PATH,
        r#"use auth;
use self::commands as commands;
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
    commands::dispatch(home, command)
}
"#,
    ),
    (
        "rss/auth/commands.rss",
        r#"use self::metadata as metadata;
use super::shared::types as types;
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
pub fn dispatch(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {
    metadata::load(home, command, types::initial_generation())
}
"#,
    ),
    (
        "rss/auth/metadata.rss",
        r#"use auth;
use config;
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
fn metadata_result(operation: string, snapshot_ok: bool, loaded: AuthMetadataEnvelope) -> AuthEntryResult {
    {
        ok: snapshot_ok && loaded.ok,
        operation: operation,
        credential_id: loaded.metadata.credential_id,
        generation: loaded.metadata.generation,
        status: loaded.metadata.status,
        error: loaded.error
    }
}
pub fn load(home: resource<auth.host_home>, command: AuthCommandInput, initial_generation: int) -> AuthEntryResult {
    let snapshot = config::load_snapshot(&home);
    if command.operation == "snapshot" => {
        let generation: int = initial_generation;
        {
            ok: snapshot.ok,
            operation: command.operation,
            credential_id: null,
            generation: generation,
            status: "snapshot_empty",
            error: snapshot.error
        }
    } else if command.credential_id != null => {
        let credential_id: string = command.credential_id;
        let loaded = auth::load_metadata(credential_id, &snapshot.policy_handle);
        metadata_result(command.operation, snapshot.ok, loaded)
    } else => {
        {
            ok: false,
            operation: command.operation,
            credential_id: null,
            generation: 0,
            status: "credential_id_required",
            error: "credential_id_required"
        }
    }
}
"#,
    ),
    (
        "rss/shared/types.rss",
        r#"struct AuthCommandInput {
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
pub fn initial_generation() -> int { 0 }
"#,
    ),
];

fn input(operation: &str, credential_id: Option<&str>) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: None,
        credential_id: credential_id.map(str::to_owned),
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected result record");
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
        panic!("expected result record");
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new(label: &str, empty_auth: bool) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
        let path = root.join(format!("auth-bundle-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create auth fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy config fixture");
        if empty_auth {
            fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
                .expect("empty auth store");
        } else {
            let auth = fs::read_to_string(fixture.join("auth.yaml"))
                .expect("read auth fixture")
                .replace("1788440000000", "1900000000000");
            fs::write(path.join("auth.yaml"), auth).expect("write auth fixture");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private home");
            for name in ["config.yaml", "auth.yaml"] {
                if path.join(name).exists() {
                    fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                        .expect("private fixture file");
                }
            }
        }
        Self(path)
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cleanup_home(home: &Path) {
    let _ = fs::remove_dir_all(home);
}

fn make_bundle(path: &str, source: &str) -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(path, &[(path, source)]).expect("compile in-memory bundle")
}

fn bundle_error(result: Result<AuthEntryRunner, AuthEntryError>, reason: &str) -> AuthEntryError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected bundle rejection: {reason}"),
    }
}

#[test]
fn in_memory_bundle_resolves_nested_imports_and_executes_typed_auth_business_calls() {
    let runner = AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES)
        .expect("closed virtual module bundle compiles without checkout files");
    let home = FixtureHome::new("metadata", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let value = runner
        .run_with_host_factory(input("metadata", Some("fixture-codex")), &cancellation, {
            let home = home.0.clone();
            move |child| AuthHost::new(home, child)
        })
        .expect("run typed config and auth host calls");
    assert_eq!(field(&value, "ok"), &Value::Bool(true));
    assert_eq!(field(&value, "operation"), &Value::string("metadata"));
    assert_eq!(
        field(&value, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&value, "generation"), &Value::Int(4));
    assert_eq!(field(&value, "status"), &Value::string("active"));
    assert!(!format!("{value:?}").contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn relative_auth_and_config_host_root_names_resolve_inside_the_supplied_tree() {
    let sources = [
        (
            "rss/auth/runner.rss",
            r#"use auth;
use self::auth as local_auth;
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
    local_auth::metadata(home, command)
}
"#,
        ),
        (
            "rss/auth/auth.rss",
            r#"use auth;
use super::config as local_config;
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
pub fn metadata(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {
    let snapshot = local_config::load(home);
    let loaded = auth::load_metadata("fixture-codex", &snapshot.policy_handle);
    let metadata = loaded.metadata.copy();
    {
        ok: snapshot.ok && loaded.ok,
        operation: command.operation,
        credential_id: metadata.credential_id,
        generation: metadata.generation,
        status: metadata.status,
        error: loaded.error
    }
}
"#,
        ),
        (
            "rss/config.rss",
            r#"use config;
pub fn load(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}
"#,
        ),
    ];
    let result = AuthEntryRunner::from_bundle("rss/auth/runner.rss", &sources);
    assert!(
        result.is_ok(),
        "nested relative imports were rejected: {:?}",
        result.err().map(|error| error.code())
    );
    let runner = result.expect("nested source modules compile from supplied bytes");
    let home = FixtureHome::new("relative-host-root", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let value = runner
        .run_with_host_factory(input("metadata", Some("fixture-codex")), &cancellation, {
            let home = home.0.clone();
            move |child| AuthHost::new(home, child)
        })
        .expect("execute actual config and auth host calls through source modules");
    assert_eq!(field(&value, "ok"), &Value::Bool(true));
    assert_eq!(
        field(&value, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&value, "generation"), &Value::Int(4));
    assert_eq!(field(&value, "status"), &Value::string("active"));
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn enrollment_factory_runs_bundle_against_generation_zero_without_provider_selection() {
    let runner = AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES).expect("compile command bundle");
    let home = FixtureHome::new("enrollment", true);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let value = runner
        .run_with_host_factory(input("snapshot", None), &cancellation, {
            let home = home.0.clone();
            move |child| AuthHost::new_for_enrollment(home, child, "fixture-codex")
        })
        .expect("new-for-enrollment host permits a real snapshot run");
    assert_eq!(field(&value, "ok"), &Value::Bool(true));
    assert_eq!(field(&value, "generation"), &Value::Int(0));
    assert_eq!(field(&value, "status"), &Value::string("snapshot_empty"));
    assert!(
        optional_field(&value, "credential_id").is_none_or(|value| matches!(value, Value::Null))
    );
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn bundle_json_encode_handles_public_data_without_granting_other_builtins() {
    let source = r#"use json;
// use io;
pub fn run(home: resource<auth.host_home>, command: map) -> map {
    let source_marker: string = "use io; ../outside.rss";
    let encoded: string = json::encode({"label": "public", "count": 2});
    {
        ok: true,
        operation: "json",
        credential_id: null,
        generation: 0,
        status: encoded,
        error: null
    }
}
"#;
    let runner = make_bundle("public_json.rss", source);
    let home = FixtureHome::new("json", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let value = runner
        .run_with_host_factory(input("json", None), &cancellation, {
            let home = home.0.clone();
            move |child| AuthHost::new(home, child)
        })
        .expect("only json::encode is admitted for ordinary public data");
    assert_eq!(
        field(&value, "status"),
        &Value::string(r#"{"count":2,"label":"public"}"#)
    );
    let denied = bundle_error(
        AuthEntryRunner::from_bundle(
            "bad_builtin.rss",
            &[(
                "bad_builtin.rss",
                "use io; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
            )],
        ),
        "unrelated builtin import is denied before a runner exists",
    );
    assert_eq!(denied.code(), "auth_import_denied");
}

#[test]
fn bundle_does_not_bind_json_decode() {
    let source = r#"use json;
pub fn run(home: resource<auth.host_home>, command: map) -> map {
    let decoded = json::decode::<map>("{\"public\":true}");
    let encoded: string = json::encode(decoded);
    {
        ok: true,
        operation: "decode",
        credential_id: null,
        generation: 0,
        status: encoded,
        error: null
    }
}
"#;
    let runner = make_bundle("json_decode.rss", source);
    let home = FixtureHome::new("json-decode", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = runner.run_with_host_factory(input("decode", None), &cancellation, {
        let home = home.0.clone();
        move |child| AuthHost::new(home, child)
    });
    let error = result.expect_err("restricted registry must reject json::decode");
    assert_eq!(error.code(), "auth_registry_setup_failed");
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn bundle_cannot_serialize_an_opaque_policy_resource() {
    let source = r#"use config;
use json;
pub fn run(home: resource<auth.host_home>, command: map) -> map {
    let snapshot = config::load_snapshot(&home);
    let encoded: string = json::encode(snapshot.policy_handle);
    {
        ok: true,
        operation: "opaque",
        credential_id: null,
        generation: 0,
        status: encoded,
        error: null
    }
}
"#;
    let runner =
        match AuthEntryRunner::from_bundle("opaque_json.rss", &[("opaque_json.rss", source)]) {
            Ok(runner) => runner,
            Err(error) => {
                assert_eq!(error.code(), "auth_compile_failed");
                return;
            }
        };
    let home = FixtureHome::new("opaque", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = runner.run_with_host_factory(input("opaque", None), &cancellation, {
        let home = home.0.clone();
        move |child| AuthHost::new(home, child)
    });
    assert!(
        result.is_err(),
        "opaque resource JSON encoding must fail closed"
    );
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn preflight_rejects_unreachable_transitive_edges_escape_and_host_shadowing() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            "main.rss",
            &[
                (
                    "main.rss",
                    "pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
                ),
                ("unused.rss", "use io; pub fn unused() -> int { 2 }"),
            ],
        ),
        (
            "app/main.rss",
            &[(
                "app/main.rss",
                "use super::super::outside; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
            )],
        ),
        (
            "main.rss",
            &[
                (
                    "main.rss",
                    "use auth::helper; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
                ),
                ("auth/helper.rss", "pub fn side_effect() -> int { 7 }"),
            ],
        ),
        (
            "main.rss",
            &[
                (
                    "main.rss",
                    "use auth; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
                ),
                ("auth.rss", "pub fn shadow() -> int { 7 }"),
            ],
        ),
        (
            "main.rss",
            &[(
                "main.rss",
                "use missing::nested; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
            )],
        ),
        (
            "main.rss",
            &[(
                "main.rss",
                "use missing::{value}; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
            )],
        ),
        (
            "main.rss",
            &[(
                "main.rss",
                "use auth::{load_metadata}; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
            )],
        ),
        (
            "main.rss",
            &[
                (
                    "main.rss",
                    "pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
                ),
                ("unused.rss", "pub fn broken( {"),
            ],
        ),
    ];
    for (index, (entry, sources)) in cases.iter().enumerate() {
        let error = bundle_error(
            AuthEntryRunner::from_bundle(entry, sources),
            "deny closed graph violation",
        );
        assert_eq!(
            error.code(),
            if index == cases.len() - 1 {
                "auth_source_invalid"
            } else {
                "auth_import_denied"
            }
        );
        assert!(!error.to_string().contains("side_effect"));
    }
}

#[test]
fn bundle_rejects_duplicate_paths_and_missing_entry() {
    let source = "pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }";
    let duplicate = bundle_error(
        AuthEntryRunner::from_bundle("main.rss", &[("main.rss", source), ("main.rss", source)]),
        "duplicate canonical path",
    );
    assert_eq!(duplicate.code(), "auth_import_denied");
    let missing = bundle_error(
        AuthEntryRunner::from_bundle("absent.rss", &[("main.rss", source)]),
        "entry must be supplied",
    );
    assert_eq!(missing.code(), "auth_import_denied");
}

#[test]
fn bundle_bounds_file_count_total_bytes_and_canonical_paths_before_compile() {
    let oversized = "x".repeat(MAX_AGENT_SOURCE_BYTES + 1);
    let error = bundle_error(
        AuthEntryRunner::from_bundle("main.rss", &[("main.rss", &oversized)]),
        "per-file limit",
    );
    assert_eq!(error.code(), "auth_source_too_large");

    let body = format!("//{}\npub fn value() -> int {{ 1 }}", "x".repeat(900_000));
    let owned: Vec<(String, String)> = (0..5)
        .map(|index| (format!("unit{index}.rss"), body.clone()))
        .collect();
    let refs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect();
    let error = bundle_error(
        AuthEntryRunner::from_bundle("unit0.rss", &refs),
        "aggregate byte limit",
    );
    assert_eq!(error.code(), "auth_source_too_large");

    let many: Vec<(String, String)> = (0..65)
        .map(|index| {
            (
                format!("unit{index}.rss"),
                "pub fn value() -> int { 1 }".to_owned(),
            )
        })
        .collect();
    let refs: Vec<(&str, &str)> = many
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect();
    let error = bundle_error(
        AuthEntryRunner::from_bundle("unit0.rss", &refs),
        "file count limit",
    );
    assert_eq!(error.code(), "auth_source_too_large");

    for path in [
        "/main.rss",
        "a//main.rss",
        "a/./main.rss",
        "a/../main.rss",
        "a\\main.rss",
        "main.txt",
        "",
        "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/main.rss",
    ] {
        let error = bundle_error(
            AuthEntryRunner::from_bundle(path, &[(path, "pub fn run() -> int { 1 }")]),
            "noncanonical path denied",
        );
        assert_eq!(error.code(), "auth_import_denied");
    }
}

#[test]
fn source_bytes_are_taken_from_the_closed_bundle_not_checkout_neighbors() {
    let runner = AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES)
        .expect("same relative path as checked-in RSS is still an in-memory override");
    let home = FixtureHome::new("virtual-path", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let value = runner
        .run_with_host_factory(
            input("bundle-byte-sentinel", Some("fixture-codex")),
            &cancellation,
            {
                let home = home.0.clone();
                move |child| AuthHost::new(home, child)
            },
        )
        .expect("execute supplied entry bytes");
    assert_eq!(
        field(&value, "operation"),
        &Value::string("bundle-byte-sentinel")
    );
    assert_eq!(field(&value, "status"), &Value::string("active"));
    assert_eq!(field(&value, "generation"), &Value::Int(4));
}

#[test]
fn factory_validation_redacts_failures_and_disarms_cancellation() {
    let runner = AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES).expect("compile bundle");
    let invalid = RunCancellation::with_timeout(Duration::from_secs(10));
    let called = Arc::new(Mutex::new(false));
    let error = runner
        .run_with_host_factory(input(&"x".repeat(2049), None), &invalid, {
            let called = Arc::clone(&called);
            move |_| {
                *called.lock().expect("factory call marker") = true;
                Err("private host setup detail".to_owned())
            }
        })
        .expect_err("input rejected before host factory");
    assert_eq!(error.code(), "auth_input_invalid");
    assert!(!*called.lock().expect("factory call marker"));
    assert!(!invalid.watcher_is_armed());

    let expired = RunCancellation::with_timeout(Duration::ZERO);
    let error = runner
        .run_with_host_factory(input("snapshot", None), &expired, {
            let called = Arc::clone(&called);
            move |_| {
                *called.lock().expect("factory call marker") = true;
                Err("private host setup detail".to_owned())
            }
        })
        .expect_err("expired cancellation is rejected before factory effects");
    assert!(matches!(
        error,
        AuthEntryError::Cancelled(CancellationReason::Deadline)
    ));
    assert!(!*called.lock().expect("factory call marker"));
    assert!(!expired.watcher_is_armed());

    let failed_setup = RunCancellation::with_timeout(Duration::from_secs(10));
    let error = runner
        .run_with_host_factory(input("snapshot", None), &failed_setup, |_| {
            Err("private host setup detail".to_owned())
        })
        .expect_err("host setup maps to redacted category");
    assert_eq!(error.code(), "auth_host_setup_failed");
    assert!(!error.to_string().contains("private host setup detail"));
    assert!(!failed_setup.watcher_is_armed());
}

const AUTH_BUNDLE_OBSERVER_MARKER_ENV: &str = "AUTH_BUNDLE_OBSERVER_CHILD_MARKER";
const AUTH_BUNDLE_OBSERVER_COMPLETION_PREFIX: &str = "AUTH_BUNDLE_OBSERVER_CHILD_COMPLETED:";
const AUTH_BUNDLE_OBSERVER_OUTPUT_LIMIT: usize = 16 * 1024;

fn auth_bundle_observer_case_key(test_name: &str) -> &'static str {
    match test_name {
        "imported_entry_cancellation_uses_child_token_and_cleans_the_epoch_watcher" => {
            "child-token"
        }
        "imported_entry_cancels_during_native_oauth_wait_and_cleans_up" => "native-wait",
        _ => panic!("unknown isolated auth bundle observer test"),
    }
}

fn run_isolated_auth_bundle_observer(test_name: &str) -> Option<String> {
    match std::env::var(AUTH_BUNDLE_OBSERVER_MARKER_ENV) {
        Ok(marker) => {
            assert!(marker.len() <= 128, "observer marker is bounded");
            let mut fields = marker.splitn(4, ':');
            assert_eq!(fields.next(), Some("auth-bundle-observer"));
            let parent_id = fields
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .expect("observer marker has a parent process id");
            assert_eq!(
                fields.next(),
                Some(auth_bundle_observer_case_key(test_name))
            );
            let nonce = fields.next().expect("observer marker has a nonce");
            assert!(
                uuid::Uuid::parse_str(nonce).is_ok(),
                "observer nonce is owned"
            );
            assert_ne!(parent_id, std::process::id());
            Some(marker)
        }
        Err(std::env::VarError::NotPresent) => {
            run_auth_bundle_observer_child(test_name);
            None
        }
        Err(_) => panic!("observer marker must be valid UTF-8"),
    }
}

fn run_auth_bundle_observer_child(test_name: &str) {
    let fixture_temp = std::env::var("RUSTSCRIPT_AGENT_TEST_TMP")
        .expect("assigned fixture temp is required by FixtureHome");
    assert!(
        !fixture_temp.is_empty(),
        "assigned fixture temp is nonempty"
    );
    let parent_id = std::process::id();
    let marker = format!(
        "auth-bundle-observer:{parent_id}:{}:{}",
        auth_bundle_observer_case_key(test_name),
        uuid::Uuid::new_v4()
    );
    assert!(marker.len() <= 128, "observer marker is bounded");

    let executable = std::env::current_exe().expect("test executable path");
    let mut child = Command::new(executable)
        .args(["--exact", test_name, "--nocapture"])
        .env_clear()
        .env(AUTH_BUNDLE_OBSERVER_MARKER_ENV, &marker)
        .env("RUSTSCRIPT_AGENT_TEST_TMP", fixture_temp)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn exact isolated auth bundle observer test");
    let stdout = child.stdout.take().expect("child stdout pipe");
    let stderr = child.stderr.take().expect("child stderr pipe");
    let stdout_reader = thread::spawn(move || drain_bounded_child_stream(stdout));
    let stderr_reader = thread::spawn(move || drain_bounded_child_stream(stderr));

    let rescue = Instant::now() + Duration::from_secs(12);
    let mut rescued = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < rescue => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                rescued = true;
                let _ = child.kill();
                break;
            }
        }
    }
    let status = child.wait().expect("reap exact isolated auth bundle child");
    let stdout = stdout_reader
        .join()
        .expect("join child stdout drainer")
        .expect("drain child stdout");
    let stderr = stderr_reader
        .join()
        .expect("join child stderr drainer")
        .expect("drain child stderr");

    assert!(
        !rescued,
        "isolated auth bundle child exceeded its rescue bound"
    );
    assert!(
        status.success(),
        "isolated auth bundle child exited successfully"
    );
    assert!(stdout.len() <= AUTH_BUNDLE_OBSERVER_OUTPUT_LIMIT);
    assert!(stderr.len() <= AUTH_BUNDLE_OBSERVER_OUTPUT_LIMIT);

    let stdout = String::from_utf8_lossy(&stdout);
    let test_line = format!("test {test_name} ...");
    assert_eq!(
        stdout.matches(&test_line).count(),
        1,
        "child ran the exact named test"
    );
    let completion = format!("{AUTH_BUNDLE_OBSERVER_COMPLETION_PREFIX}{marker}");
    assert_eq!(
        stdout.matches(&completion).count(),
        1,
        "child returned its parent-owned marker"
    );
    let summary = stdout
        .lines()
        .find(|line| line.starts_with("test result:"))
        .map(str::trim)
        .expect("exact child test emitted a result summary");
    assert!(
        summary.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
            && summary.contains(" filtered out; finished in "),
        "exact child test must report exactly one passing test"
    );
    let control_summary = if test_name
        == "imported_entry_cancels_during_native_oauth_wait_and_cleans_up"
    {
        assert!(
                stdout.contains(
                    "auth-bundle observer control: live_count=1, zero_while_live=false, zero_after_join=true"
                ),
                "native-wait child must verify the live-watcher negative control"
            );
        "; live-watcher control verified (1/false/true)"
    } else {
        ""
    };
    println!(
        "isolated auth bundle child verified: test={test_name}; status=success; {summary}; owned marker verified{control_summary}"
    );
}

fn drain_bounded_child_stream(mut stream: impl Read) -> io::Result<Vec<u8>> {
    let mut captured = Vec::with_capacity(AUTH_BUNDLE_OBSERVER_OUTPUT_LIMIT);
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(captured);
        }
        let remaining = AUTH_BUNDLE_OBSERVER_OUTPUT_LIMIT - captured.len();
        captured.extend_from_slice(&buffer[..read.min(remaining)]);
    }
}

#[test]
fn imported_entry_cancellation_uses_child_token_and_cleans_the_epoch_watcher() {
    let Some(observer_marker) = run_isolated_auth_bundle_observer(
        "imported_entry_cancellation_uses_child_token_and_cleans_the_epoch_watcher",
    ) else {
        return;
    };
    let sources = [
        (
            "main.rss",
            "use self::worker as worker; pub fn run(home: resource<auth.host_home>, command: map) -> int { worker::spin() }",
        ),
        ("worker.rss", "pub fn spin() -> int { while true { 1; } 1 }"),
    ];
    let runner = AuthEntryRunner::from_bundle("main.rss", &sources).expect("compile loop bundle");
    let home = FixtureHome::new("cancel", false);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let child_slot = Arc::new(Mutex::new(None::<RunCancellation>));
    let child_capture = Arc::clone(&child_slot);
    let request = cancellation.clone();
    let observer = thread::spawn(move || {
        let observed = wait_for_epoch_watcher(Duration::from_secs(3));
        request.request(CancellationReason::Requested);
        assert!(
            observed.expect("read epoch watcher task table"),
            "bundle run arms a finite watcher"
        );
    });
    let result = runner.run_with_host_factory(input("spin", None), &cancellation, {
        let home = home.0.clone();
        move |child: RunCancellation| {
            assert!(
                child.deadline_instant().is_some(),
                "factory receives a finite child token"
            );
            *child_capture.lock().expect("child token slot") = Some(child.clone());
            AuthHost::new(home, child)
        }
    });
    observer.join().expect("cancellation observer");
    assert!(matches!(
        result,
        Err(AuthEntryError::Cancelled(CancellationReason::Requested))
    ));
    assert!(
        child_slot
            .lock()
            .expect("child token slot")
            .as_ref()
            .is_some_and(|child| { child.requested() == Some(CancellationReason::Requested) })
    );
    assert!(!cancellation.watcher_is_armed());
    assert!(
        wait_for_no_epoch_watchers(Duration::from_secs(3))
            .expect("read epoch watcher task table after join"),
        "joined epoch watcher becomes invisible within the bounded observation"
    );
    assert_eq!(
        epoch_watcher_count().expect("read epoch watcher count after join"),
        0
    );
    cleanup_home(&home.0);
    println!("{AUTH_BUNDLE_OBSERVER_COMPLETION_PREFIX}{observer_marker}");
}

struct CancellationAwareTransport {
    started: Arc<AtomicBool>,
}

impl BoundedHttpsTransport for CancellationAwareTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.started.store(true, Ordering::Release);
        loop {
            context.check()?;
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn imported_entry_cancels_during_native_oauth_wait_and_cleans_up() {
    let Some(observer_marker) = run_isolated_auth_bundle_observer(
        "imported_entry_cancels_during_native_oauth_wait_and_cleans_up",
    ) else {
        return;
    };
    let sources = [
        (
            "main.rss",
            "use auth; use self::transport as transport; pub fn run(home: resource<auth.host_home>, command: map) -> map { transport::wait(home) }",
        ),
        (
            "transport.rss",
            r#"use auth;
use config;
use oauth;
pub fn wait(home: resource<auth.host_home>) -> map {
    let snapshot = config::load_snapshot(&home);
    let request = {
        policy_handle: snapshot.policy_handle,
        credential_id: "fixture-codex",
        method: "GET",
        path: "/oauth/token",
        public_headers: [],
        public_body: ""
    };
    let usage = {kind: "none"};
    let response = oauth::transport(&request, &usage);
    {
        ok: response.ok,
        operation: "native_wait",
        credential_id: null,
        generation: 0,
        status: "returned",
        error: null
    }
}
"#,
        ),
    ];
    let runner = AuthEntryRunner::from_bundle("main.rss", &sources).expect("compile OAuth bundle");
    let home = FixtureHome::new("native-wait", false);
    let started = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(CancellationAwareTransport {
        started: Arc::clone(&started),
    });
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let request = cancellation.clone();
    let started_by_transport = Arc::clone(&started);
    let observer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let observed = loop {
            if started_by_transport.load(Ordering::Acquire) {
                match epoch_watcher_count() {
                    Ok(count) if count > 0 => break Ok(true),
                    Ok(_) => {}
                    Err(error) => break Err(error),
                }
            }
            if Instant::now() >= deadline {
                break Ok(false);
            }
            thread::sleep(Duration::from_millis(2));
        };
        request.request(CancellationReason::Requested);
        observed
    });
    let result = runner.run_with_host_factory(input("native-wait", None), &cancellation, {
        let home = home.0.clone();
        move |child| AuthHost::new(home, child).map(|host| host.with_oauth_host(oauth))
    });
    assert!(
        observer
            .join()
            .expect("native-wait observer")
            .expect("read epoch watcher task table in native-wait observer")
    );
    assert!(
        started.load(Ordering::Acquire),
        "native transport reached its cancellable wait"
    );
    assert!(matches!(
        result,
        Err(AuthEntryError::Cancelled(CancellationReason::Requested))
    ));
    assert!(!cancellation.watcher_is_armed());
    assert!(
        wait_for_no_epoch_watchers(Duration::from_secs(3))
            .expect("read epoch watcher task table after join"),
        "joined epoch watcher becomes invisible within the bounded observation"
    );
    assert_eq!(
        epoch_watcher_count().expect("read epoch watcher count after join"),
        0
    );
    #[cfg(target_os = "linux")]
    assert_live_epoch_watcher_observer_control();
    cleanup_home(&home.0);
    println!("{AUTH_BUNDLE_OBSERVER_COMPLETION_PREFIX}{observer_marker}");
}

fn wait_for_epoch_watcher(timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if epoch_watcher_count()? > 0 {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn wait_for_no_epoch_watchers(timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if epoch_watcher_count()? == 0 {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(target_os = "linux")]
fn epoch_watcher_count() -> io::Result<usize> {
    let mut count = 0;
    for task in fs::read_dir("/proc/self/task")? {
        let task = task?;
        let task_path = task.path();
        match fs::read_to_string(task_path.join("comm")) {
            Ok(name) if name.starts_with("run-epoch") => count += 1,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if task_path.try_exists()? {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(count)
}

#[cfg(not(target_os = "linux"))]
fn epoch_watcher_count() -> io::Result<usize> {
    Ok(0)
}

#[cfg(target_os = "linux")]
fn assert_live_epoch_watcher_observer_control() {
    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let watcher = thread::Builder::new()
        .name("run-epoch-watcher".to_owned())
        .spawn(move || {
            started_sender
                .send(())
                .expect("signal named watcher control readiness");
            release_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded release for named watcher control");
        })
        .expect("spawn named watcher observer control");

    let started = started_receiver.recv_timeout(Duration::from_secs(3));
    let live_count = epoch_watcher_count();
    let zero_while_live = wait_for_no_epoch_watchers(Duration::from_secs(3));
    let released = release_sender.send(());
    let joined = watcher.join();

    assert!(started.is_ok(), "named watcher control must start");
    let live_count = live_count.expect("read live named watcher count");
    assert_eq!(live_count, 1, "a live named watcher must be counted");
    let zero_while_live = zero_while_live.expect("read live watcher during bounded zero check");
    assert!(
        !zero_while_live,
        "bounded zero observer must reject a genuinely live named watcher"
    );
    assert!(
        released.is_ok(),
        "release the bounded named watcher control"
    );
    joined.expect("join named watcher observer control");
    let zero_after_join = wait_for_no_epoch_watchers(Duration::from_secs(3))
        .expect("read epoch watcher task table after join");
    assert!(
        zero_after_join,
        "bounded zero observer must succeed after named watcher termination and join"
    );
    println!(
        "auth-bundle observer control: live_count={live_count}, zero_while_live={zero_while_live}, zero_after_join={zero_after_join}"
    );
}

#[test]
fn aliased_public_login_run_executes_in_the_closed_bundle_and_returns_auth_metadata() {
    const ACCESS: &str = "SYNTHETIC_BUNDLE_ACCESS_TOKEN";
    const REFRESH: &str = "SYNTHETIC_BUNDLE_REFRESH_TOKEN";
    const DEVICE: &str = "SYNTHETIC_BUNDLE_DEVICE_ID";
    const CODE: &str = "SYNTHETIC_BUNDLE_AUTH_CODE";
    const VERIFIER: &str = "synthetic-bundle-verifier-abcdefghijklmnopqrstuvwxyz";
    const USER_CODE: &str = "PUBLIC-BUNDLE-7QK";
    const NOW_MS: u64 = 1_900_000_000_000;
    const ENTRY: &str = "rss/auth/commands.rss";
    const SOURCES: &[(&str, &str)] = &[
        (ENTRY, include_str!("../rss/auth/commands.rss")),
        (
            "rss/config/selection.rss",
            include_str!("../rss/config/selection.rss"),
        ),
        ("rss/auth/login.rss", include_str!("../rss/auth/login.rss")),
        (
            "rss/auth/codex_device.rss",
            include_str!("../rss/auth/codex_device.rss"),
        ),
        ("rss/auth/types.rss", include_str!("../rss/auth/types.rss")),
        (
            "rss/auth/pkce_login.rss",
            include_str!("../rss/auth/pkce_login.rss"),
        ),
        (
            "rss/auth/pkce_instruction_session.rss",
            include_str!("../rss/auth/pkce_instruction_session.rss"),
        ),
        (
            "rss/auth/pkce_session.rss",
            include_str!("../rss/auth/pkce_session.rss"),
        ),
        (
            "rss/auth/token_metadata.rss",
            include_str!("../rss/auth/token_metadata.rss"),
        ),
        (
            "rss/auth/token_save.rss",
            include_str!("../rss/auth/token_save.rss"),
        ),
    ];

    let runner = AuthEntryRunner::from_bundle(ENTRY, SOURCES)
        .expect("the real aliased login sibling compiles in the supplied bundle");
    let admin_home = FixtureHome::new("entry-run-with-login-sibling", false);
    let admin_cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let admin_value = runner
        .run_with_host_factory(input("auth.status", None), &admin_cancellation, {
            let home = admin_home.0.clone();
            move |child| AuthHost::new_for_commands(home, child)
        })
        .expect("the bundle entry run remains callable beside the sibling run export");
    assert_eq!(field(&admin_value, "ok"), &Value::Bool(true));
    assert_eq!(
        field(&admin_value, "operation"),
        &Value::string("auth.status")
    );
    assert!(!admin_cancellation.watcher_is_armed());

    let home = FixtureHome::new("real-login-bundle", false);
    let configured_login =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex_device/config.yaml");
    fs::copy(configured_login, home.0.join("config.yaml"))
        .expect("install configured device-login fixture");
    fs::remove_file(home.0.join("auth.yaml")).expect("start without credential store");
    let config_before = fs::read(home.0.join("config.yaml")).expect("snapshot config bytes");

    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE}","code_verifier":"{VERIFIER}","public":"poll-ok"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{ACCESS}","refresh_token":"{REFRESH}","token_type":"Bearer","expires_in":3600,"public":"exchange-ok"}}"#
        ),
    );
    let sent_transport = Arc::clone(&transport);
    let inspect_transport = Arc::clone(&transport);
    let home_path = home.0.clone();
    let (sender, receiver) = device_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let value = runner
        .run_with_host_factory(
            AuthCommandInput {
                operation: "auth.login".to_owned(),
                provider: Some("openai-codex".to_owned()),
                credential_id: None,
            },
            &cancellation,
            move |child| {
                let oauth = Arc::new(OAuthHost::new(
                    sent_transport,
                    Arc::new(ScriptedCallback::new()),
                    Arc::new(ScriptedBrowser::new()),
                    Arc::new(ScriptedClock::new(NOW_MS)),
                    Arc::new(ScriptedCancel::new()),
                ));
                Ok(AuthHost::new_for_login(home_path, child)?
                    .with_oauth_host(oauth)
                    .with_device_instruction_sender(sender))
            },
        )
        .expect("run the typed aliased auth.login entry through its native host");

    assert_eq!(field(&value, "ok"), &Value::Bool(true));
    assert_eq!(field(&value, "operation"), &Value::string("auth.login"));
    assert_eq!(
        field(&value, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&value, "generation"), &Value::Int(1));
    let status = match field(&value, "status") {
        Value::String(status) => {
            serde_json::from_str::<serde_json::Value>(status).expect("serialized login metadata")
        }
        other => panic!("expected serialized login metadata, got {other:?}"),
    };
    assert_eq!(
        status,
        serde_json::json!({
            "credential_id": "fixture-codex",
            "generation": 1,
            "provider": "openai-codex",
            "source": "codex-device",
            "status": "active"
        })
    );
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    let auth = fs::read_to_string(home.0.join("auth.yaml")).expect("native factory saved auth");
    assert!(auth.contains(ACCESS));
    assert!(auth.contains(REFRESH));
    for secret in [ACCESS, REFRESH, DEVICE, CODE, VERIFIER] {
        assert!(!format!("{value:?}").contains(secret));
    }
    let instruction: PublicDeviceInstruction = receiver.try_recv().expect("native instruction");
    assert_eq!(instruction.user_code, USER_CODE);
    assert_eq!(
        instruction.verification_url,
        "https://auth.example.test/codex/device"
    );
    assert_eq!(inspect_transport.take_sent().len(), 3);
    assert!(!cancellation.watcher_is_armed());
}

fn bundle_with_sibling_deleting_run(root_functions: &str) -> AuthEntryRunner {
    const ENTRY: &str = "rss/auth/commands.rss";
    const SIBLING: &str = "rss/auth/sibling.rss";
    const SIBLING_SOURCE: &str = r#"use auth;
use config;
pub fn run(home: resource<auth.host_home>, command: map) -> int {
    let policy = config::load_snapshot(&home).policy_handle;
    auth::delete("fixture-codex", &policy);
    17
}
"#;
    let entry_source = format!("use self::sibling::{{run as sibling_run}};\n{root_functions}");
    AuthEntryRunner::from_bundle(ENTRY, &[(ENTRY, &entry_source), (SIBLING, SIBLING_SOURCE)])
        .expect("closed bundle with root and sibling run exports")
}

fn run_and_expect_entry_error(
    runner: &AuthEntryRunner,
    label: &str,
    expected: AuthEntryError,
    expected_code: &str,
) {
    let home = FixtureHome::new(label, false);
    let initial_auth = fs::read(home.0.join("auth.yaml")).expect("read initial auth bytes");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let error = runner
        .run_with_host_factory(input("auth.status", None), &cancellation, {
            let home = home.0.clone();
            move |child| AuthHost::new_for_commands(home, child)
        })
        .expect_err("a sibling export cannot serve as the root auth entry");
    assert_eq!(error, expected);
    assert_eq!(error.code(), expected_code);
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("read auth after failed entry selection"),
        initial_auth,
        "sibling business effects must not run"
    );
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn missing_or_private_root_run_never_invokes_sibling_business_effects() {
    for (label, root_functions) in [
        ("missing-root-run", "pub fn helper() -> int { 1 }"),
        (
            "private-root-run",
            "fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
        ),
    ] {
        let runner = bundle_with_sibling_deleting_run(root_functions);
        run_and_expect_entry_error(
            &runner,
            label,
            AuthEntryError::NoEntry,
            "auth_entry_missing",
        );
    }
}

#[test]
fn wrong_arity_root_run_is_reported_before_sibling_business_effects() {
    let runner = bundle_with_sibling_deleting_run("pub fn run() -> int { 1 }");
    run_and_expect_entry_error(
        &runner,
        "wrong-arity-root-run",
        AuthEntryError::EntryArity,
        "auth_entry_arity",
    );
}

#[test]
fn named_imports_remain_bounded_by_closed_tree_preflight() {
    const ROOT: &str = "pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }";
    let missing_sibling = [(
        "main.rss",
        "use self::missing::{run as missing_run}; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
    )];
    let root_escape = [(
        "main.rss",
        "use super::outside::{run as escaped_run}; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
    )];
    let host_named = [(
        "main.rss",
        "use auth::{load_metadata as host_load}; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
    )];
    let unreachable_transitive = [
        ("main.rss", ROOT),
        (
            "unused.rss",
            "use self::missing::{run as missing_run}; pub fn unused() -> int { 2 }",
        ),
    ];

    for (entry, sources) in [
        ("main.rss", &missing_sibling[..]),
        ("main.rss", &root_escape[..]),
        ("main.rss", &host_named[..]),
        ("main.rss", &unreachable_transitive[..]),
    ] {
        let error = bundle_error(
            AuthEntryRunner::from_bundle(entry, sources),
            "named imports still require explicit in-bundle targets and cannot reach host roots",
        );
        assert_eq!(error.code(), "auth_import_denied");
    }
}

#[test]
fn named_import_of_private_sibling_export_fails_core_compilation() {
    let sources = [
        (
            "main.rss",
            "use self::private::{hidden as hidden_run}; pub fn run(home: resource<auth.host_home>, command: map) -> int { hidden_run() }",
        ),
        ("private.rss", "fn hidden() -> int { 7 }"),
    ];
    let error = bundle_error(
        AuthEntryRunner::from_bundle("main.rss", &sources),
        "private sibling functions are not made public by named-import admission",
    );
    assert_eq!(error.code(), "auth_compile_failed");
}
