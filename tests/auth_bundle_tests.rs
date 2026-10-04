use rustscript_agent::auth::host::AuthHost;
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext, PreparedHttpsRequest,
    RawHttpsResponse, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
};
use rustscript_agent::runtime::{
    AuthCommandInput, AuthEntryError, AuthEntryRunner, MAX_AGENT_SOURCE_BYTES,
};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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
                    "use auth::shadow; pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }",
                ),
                ("auth/shadow.rss", "pub fn side_effect() -> int { 7 }"),
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

#[test]
fn imported_entry_cancellation_uses_child_token_and_cleans_the_epoch_watcher() {
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
        assert!(
            wait_for_epoch_watcher(Duration::from_secs(3)),
            "bundle run arms a finite watcher"
        );
        request.request(CancellationReason::Requested);
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
    assert_eq!(epoch_watcher_count(), 0);
    cleanup_home(&home.0);
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
            if started_by_transport.load(Ordering::Acquire) && epoch_watcher_count() > 0 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
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
    assert!(observer.join().expect("native-wait observer"));
    assert!(
        started.load(Ordering::Acquire),
        "native transport reached its cancellable wait"
    );
    assert!(matches!(
        result,
        Err(AuthEntryError::Cancelled(CancellationReason::Requested))
    ));
    assert!(!cancellation.watcher_is_armed());
    assert_eq!(epoch_watcher_count(), 0);
    cleanup_home(&home.0);
}

fn wait_for_epoch_watcher(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if epoch_watcher_count() > 0 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn epoch_watcher_count() -> usize {
    let Ok(tasks) = fs::read_dir("/proc/self/task") else {
        return 0;
    };
    tasks
        .filter_map(Result::ok)
        .filter(|task| {
            fs::read_to_string(task.path().join("comm"))
                .is_ok_and(|name| name.starts_with("run-epoch"))
        })
        .count()
}
