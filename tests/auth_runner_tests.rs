use rustscript_agent::auth::host::auth_host_catalog;
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::{
    CompileSourceFileOptions, SourceFlavor, Value, compile_source_at_path_with_flavor_and_options,
    compile_source_with_flavor_and_options,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

fn compile_raw_at(path: &PathBuf, source: &str) -> Result<rustscript_vm::Program, String> {
    compile_source_at_path_with_flavor_and_options(
        path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .map(|compiled| compiled.program)
    .map_err(|error| error.to_string())
}

#[test]
fn raw_core_file_import_resolves_existing_rss_module() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/raw_entry.rss");
    let error = compile_raw_at(&path, "use bridge_contract;\npub fn run() -> int { 1 }\n")
        .expect_err("the existing module exports the conflicting run binding");
    assert!(
        error.contains("run"),
        "expected imported run binding conflict: {error}"
    );
    assert!(
        error.to_ascii_lowercase().contains("conflict"),
        "expected conflict diagnostic: {error}"
    );
}

#[test]
fn structured_preflight_rejects_existing_and_nonexistent_file_imports() {
    let cases = [
        "use bridge_contract;\npub fn run() -> int { 1 }",
        "use super::rss::auth::bridge_contract as leaked;\npub fn run() -> int { 1 }",
        "use self::not_present;\npub fn run() -> int { 1 }",
        "use not_present;\npub fn run() -> int { 1 }",
        "use auth::not_present;\npub fn run() -> int { 1 }",
        "use not_present::{value};\npub fn run() -> int { 1 }",
    ];
    for source in cases {
        let error = match AuthEntryRunner::from_source(source) {
            Err(error) => error,
            Ok(_) => panic!("non-root or grouped module path must be denied before compilation"),
        };
        assert_eq!(error.code(), "auth_import_denied", "{source}: {error}");
        let rendered = error.to_string();
        assert!(
            !rendered.contains(source),
            "source leaked in error: {rendered}"
        );
        assert!(
            !rendered.contains("bridge_contract"),
            "path leaked in error: {rendered}"
        );
    }
}

#[test]
fn structured_preflight_allows_only_single_host_roots_and_ignores_text_literals() {
    let source = r#"
        // use super::comment_only;
        use config;
        use auth::{load_metadata};
        pub fn run() -> string {
            let marker: string = "use self::literal_only;";
            marker
        }
    "#;
    AuthEntryRunner::from_source(source)
        .expect("host imports compile and comments/string literals are not directives");
}

#[test]
fn source_limit_is_checked_before_parser_and_compiler() {
    let source = "x".repeat(rustscript_agent::MAX_AGENT_SOURCE_BYTES + 1);
    let error = match AuthEntryRunner::from_source(&source) {
        Err(error) => error,
        Ok(_) => panic!("oversized source must be rejected"),
    };
    assert_eq!(error.code(), "auth_source_too_large");
    assert!(!error.to_string().contains(&source));
}

fn checked_in_runner() -> AuthEntryRunner {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/runner_entry.rss"),
    )
    .expect("checked-in auth runner RSS entry");
    AuthEntryRunner::from_source(&source).expect("compile checked-in auth runner entry")
}

fn fixture_home(label: &str, generation: u64) -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
    let home = root.join(format!(
        "auth-runner-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&home).expect("private auth home");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("copy config fixture");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("read auth fixture")
        .replace("1788440000000", "1900000000000")
        .replace("generation: 4", &format!("generation: {generation}"));
    fs::write(home.join("auth.yaml"), auth).expect("write auth fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                .expect("file mode");
        }
    }
    home
}

fn cleanup_home(home: &Path) {
    fs::remove_dir_all(home).expect("remove test auth home");
}

fn command(operation: &str, credential_id: Option<&str>) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: None,
        credential_id: credential_id.map(str::to_owned),
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected scalar result map")
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
        panic!("expected scalar result map")
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

#[test]
fn checked_in_entry_compiles_host_roots_without_loading_same_named_file_modules() {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/runner_entry.rss"),
    )
    .expect("checked-in auth runner RSS entry");
    let catalog = auth_host_catalog();
    let compiled = compile_source_with_flavor_and_options(
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("host imports compile from in-memory source");
    let imports: Vec<&str> = compiled
        .program
        .imports
        .iter()
        .map(|import| import.name.as_str())
        .collect();
    assert!(imports.contains(&"config::load_snapshot"), "{imports:?}");
    assert!(imports.contains(&"auth::load_metadata"), "{imports:?}");
    assert_eq!(
        imports.len(),
        2,
        "only the intended auth host imports: {imports:?}"
    );
    let host_schemas = compiled.program.host_import_schemas();
    assert_eq!(host_schemas.len(), compiled.program.imports.len());
    assert!(host_schemas.iter().all(Option::is_some));
    assert!(
        host_schemas
            .iter()
            .flatten()
            .all(|schema| schema.fingerprint == catalog.fingerprint())
    );
    let debug_source = compiled
        .program
        .debug
        .as_ref()
        .and_then(|debug| debug.source.as_deref());
    assert_eq!(debug_source, Some(source.as_str()), "entry source only");
}

#[test]
fn checked_in_rss_entry_runs_metadata_and_snapshot_against_injected_home() {
    let runner = checked_in_runner();
    let home = fixture_home("metadata", 4);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let metadata = runner
        .run(
            home.clone(),
            command("metadata", Some("fixture-codex")),
            &cancellation,
            None,
        )
        .expect("metadata command");
    assert_eq!(field(&metadata, "ok"), &Value::Bool(true));
    assert_eq!(field(&metadata, "operation"), &Value::string("metadata"));
    assert_eq!(
        field(&metadata, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&metadata, "generation"), &Value::Int(4));
    assert_eq!(field(&metadata, "status"), &Value::string("active"));
    assert!(optional_field(&metadata, "error").is_none_or(|value| matches!(value, Value::Null)));

    let snapshot = runner
        .run(home.clone(), command("snapshot", None), &cancellation, None)
        .expect("snapshot command uses sanitized refs");
    assert_eq!(field(&snapshot, "ok"), &Value::Bool(true));
    assert_eq!(field(&snapshot, "operation"), &Value::string("snapshot"));
    assert_eq!(
        field(&snapshot, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&snapshot, "generation"), &Value::Int(4));
    assert_eq!(field(&snapshot, "status"), &Value::string("active"));
    let rendered = format!("{metadata:?}{snapshot:?}");
    assert!(!rendered.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!rendered.contains("SYNTHETIC_REFRESH_TOKEN"));
    assert!(!cancellation.watcher_is_armed());
    cleanup_home(&home);
}

#[test]
fn repeated_runs_use_new_home_and_never_treat_provider_as_a_home_override() {
    let runner = checked_in_runner();
    let first_home = fixture_home("first", 4);
    let second_home = fixture_home("second", 9);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut input = command("metadata", Some("fixture-codex"));
    input.provider = Some(second_home.to_string_lossy().into_owned());
    let first = runner
        .run(first_home.clone(), input, &cancellation, None)
        .expect("first injected home");
    let second = runner
        .run(
            second_home.clone(),
            command("metadata", Some("fixture-codex")),
            &cancellation,
            None,
        )
        .expect("second injected home");
    assert_eq!(field(&first, "generation"), &Value::Int(4));
    assert_eq!(field(&second, "generation"), &Value::Int(9));
    assert!(!cancellation.watcher_is_armed());
    cleanup_home(&first_home);
    cleanup_home(&second_home);
}

#[test]
fn command_fields_are_bounded_and_control_free() {
    let runner = checked_in_runner();
    let home = fixture_home("input-bounds", 4);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    for input in [
        AuthCommandInput {
            operation: "x".repeat(2049),
            provider: None,
            credential_id: None,
        },
        AuthCommandInput {
            operation: "snapshot".into(),
            provider: Some("x".repeat(2049)),
            credential_id: None,
        },
        AuthCommandInput {
            operation: "snapshot".into(),
            provider: None,
            credential_id: Some("bad\nvalue".into()),
        },
    ] {
        let error = match runner.run(home.clone(), input, &cancellation, None) {
            Err(error) => error,
            Ok(_) => panic!("invalid bounded command input must fail"),
        };
        assert_eq!(error.code(), "auth_input_invalid");
    }
    let mut at_limit = command("snapshot", None);
    at_limit.provider = Some("p".repeat(2048));
    assert!(
        runner
            .run(home.clone(), at_limit, &cancellation, None)
            .is_ok()
    );
    assert!(!cancellation.watcher_is_armed());
    cleanup_home(&home);
}

#[test]
fn missing_and_wrong_arity_entries_fail_with_fixed_errors_and_cleanup() {
    let home = fixture_home("arity", 4);
    for (source, expected) in [
        ("pub fn other() -> int { 1 }", "auth_entry_missing"),
        ("pub fn run() -> int { 1 }", "auth_entry_arity"),
    ] {
        let runner = AuthEntryRunner::from_source(source).expect("compile runner source");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let error = match runner.run(home.clone(), command("snapshot", None), &cancellation, None) {
            Err(error) => error,
            Ok(_) => panic!("entry mismatch must fail"),
        };
        assert_eq!(error.code(), expected);
        assert!(!cancellation.watcher_is_armed());
    }
    cleanup_home(&home);
}

#[test]
fn expired_and_unbounded_cancellation_are_rejected_without_watcher_leaks() {
    let runner = checked_in_runner();
    let home = fixture_home("deadlines", 4);
    let no_deadline = RunCancellation::new();
    let error = match runner.run(home.clone(), command("snapshot", None), &no_deadline, None) {
        Err(error) => error,
        Ok(_) => panic!("finite deadline is required"),
    };
    assert_eq!(error.code(), "auth_deadline_required");
    assert!(!no_deadline.watcher_is_armed());

    let expired = RunCancellation::with_timeout(Duration::ZERO);
    let error = match runner.run(home.clone(), command("snapshot", None), &expired, None) {
        Err(error) => error,
        Ok(_) => panic!("expired deadline must stop before root execution"),
    };
    assert!(matches!(
        error,
        AuthEntryError::Cancelled(CancellationReason::Deadline)
    ));
    assert!(!expired.watcher_is_armed());
    cleanup_home(&home);
}

#[test]
fn cpu_loops_cancel_with_exact_reason_and_disarm_each_watcher() {
    for case in [
        "requested-root",
        "requested-entry",
        "deadline-root",
        "deadline-entry",
    ] {
        run_cancellation_helper(case);
    }
}

#[test]
fn reused_parent_keeps_a_fresh_watcher_for_a_later_cpu_loop() {
    run_cancellation_helper("reuse-requested-root");
}

#[test]
fn concurrent_invocations_keep_independent_epoch_watchers() {
    run_cancellation_helper("concurrent-request");
}

#[test]
fn cpu_loop_cancellation_helper_process() {
    let Ok(case) = std::env::var("AUTH_RUNNER_CPU_CASE") else {
        return;
    };
    run_cpu_case_in_helper(&case);
}

fn run_cancellation_helper(case: &str) {
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "cpu_loop_cancellation_helper_process",
            "--nocapture",
        ])
        .env("AUTH_RUNNER_CPU_CASE", case)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bounded CPU-loop helper process");
    let child_pid = child.id();
    let rescue = Instant::now() + Duration::from_secs(12);
    loop {
        if child.try_wait().expect("poll helper process").is_some() {
            break;
        }
        if Instant::now() >= rescue {
            child.kill().expect("kill stuck helper process");
            let output = child
                .wait_with_output()
                .expect("collect killed helper output");
            cleanup_cpu_helper_homes(child_pid);
            panic!(
                "CPU-loop helper exceeded finite rescue for {case}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect helper output");
    cleanup_cpu_helper_homes(child_pid);
    assert!(
        output.status.success(),
        "CPU-loop helper failed for {case}; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cleanup_cpu_helper_homes(process_id: u32) {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
    for label in ["cpu-child", "reuse"] {
        let prefix = format!("auth-runner-{label}-{process_id}-");
        let Ok(entries) = fs::read_dir(&root) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

fn run_cpu_case_in_helper(case: &str) {
    let root_loop = "use auth; while true { 1; } pub fn run(home: resource<auth.host_home>, command: map) -> int { 1 }";
    let entry_loop = "use auth; pub fn run(home: resource<auth.host_home>, command: map) -> int { while true { 1; } 1 }";
    let concurrent = case == "concurrent-request";
    let reuses_parent = case == "reuse-requested-root";
    let source = if case.ends_with("entry") {
        entry_loop
    } else {
        root_loop
    };
    // Compile the real root/entry infinite CPU-loop source and create its fixture home
    // BEFORE constructing the parent cancellation, so the 750ms deadline budget below
    // measures execution (watcher arm + run) and not fixture compile/I/O setup. The
    // reused-parent branch stays after parent creation and keeps sharing this parent.
    let runner = Arc::new(AuthEntryRunner::from_source(source).expect("compile CPU loop"));
    let home = fixture_home("cpu-child", 4);
    let parent = if case.starts_with("deadline-") {
        RunCancellation::with_deadline(Instant::now() + Duration::from_millis(750))
    } else {
        RunCancellation::with_timeout(Duration::from_secs(10))
    };

    if reuses_parent {
        let success_runner = checked_in_runner();
        let home = fixture_home("reuse", 4);
        for _ in 0..2 {
            success_runner
                .run(
                    home.clone(),
                    command("metadata", Some("fixture-codex")),
                    &parent,
                    None,
                )
                .expect("success run under shared parent");
            assert!(!parent.watcher_is_armed());
            assert_eq!(epoch_watcher_count(), 0);
        }
        cleanup_home(&home);
    }

    if concurrent {
        run_concurrent_cpu_cases(runner, home, parent);
        return;
    }

    let request_cancellation = parent.clone();
    let requests = case.starts_with("requested-") || reuses_parent;
    let observer = thread::spawn(move || {
        let observed = wait_for_epoch_watcher_count(1, Duration::from_secs(3));
        if requests {
            if observed {
                thread::sleep(Duration::from_millis(10));
            }
            request_cancellation.request(CancellationReason::Requested);
        }
        observed
    });

    let result = runner.run(home.clone(), command("snapshot", None), &parent, None);
    let observer_saw_watcher = observer.join().expect("watcher observer");
    cleanup_home(&home);

    assert!(
        observer_saw_watcher,
        "cancellation test must observe an armed watcher: {case}"
    );
    assert!(
        matches!(
            result,
            Err(AuthEntryError::Cancelled(CancellationReason::Requested))
                if requests
        ) || matches!(
            result,
            Err(AuthEntryError::Cancelled(CancellationReason::Deadline))
                if !requests
        ),
        "unexpected cancellation result for {case}: {result:?}"
    );
    assert!(
        !parent.watcher_is_armed(),
        "parent watcher must remain untouched"
    );
    assert_eq!(
        epoch_watcher_count(),
        0,
        "invocation watcher must be joined"
    );
}

fn run_concurrent_cpu_cases(runner: Arc<AuthEntryRunner>, home: PathBuf, parent: RunCancellation) {
    let entry_runner = Arc::new(
        AuthEntryRunner::from_source(
            "use auth; pub fn run(home: resource<auth.host_home>, command: map) -> int { while true { 1; } 1 }",
        )
        .expect("compile concurrent entry loop"),
    );
    let runners = [runner, entry_runner];
    let gate = Arc::new(Barrier::new(3));
    let (result_sender, result_receiver) = mpsc::channel();
    let mut workers = Vec::new();
    for (index, runner) in runners.into_iter().enumerate() {
        let gate = Arc::clone(&gate);
        let cancellation = parent.clone();
        let run_home = home.clone();
        let sender = result_sender.clone();
        workers.push(thread::spawn(move || {
            gate.wait();
            let result = runner.run(run_home, command("snapshot", None), &cancellation, None);
            let _ = sender.send((index, result));
        }));
    }
    drop(result_sender);
    gate.wait();
    let observed = wait_for_epoch_watcher_count(2, Duration::from_secs(3));
    parent.request(CancellationReason::Requested);

    let receive_deadline = Instant::now() + Duration::from_secs(9);
    let mut results = Vec::new();
    while results.len() < workers.len() {
        let remaining = receive_deadline.saturating_duration_since(Instant::now());
        match result_receiver.recv_timeout(remaining) {
            Ok(result) => results.push(result),
            Err(_) => break,
        }
    }
    if results.len() != workers.len() {
        cleanup_home(&home);
        eprintln!(
            "only {} concurrent CPU loops completed after cancellation",
            results.len()
        );
        std::process::exit(1);
    }
    for worker in workers {
        worker.join().expect("concurrent runner thread");
    }
    cleanup_home(&home);

    assert!(
        observed,
        "both invocation-local watchers must be armed before request"
    );
    assert_eq!(results.len(), 2, "both CPU loops must finish after request");
    assert!(
        results.iter().all(|(_, result)| matches!(
            result,
            Err(AuthEntryError::Cancelled(CancellationReason::Requested))
        )),
        "both invocations must preserve the exact request reason: {results:?}"
    );
    assert!(
        !parent.watcher_is_armed(),
        "the shared request root owns no invocation watcher"
    );
    assert_eq!(
        epoch_watcher_count(),
        0,
        "both invocation watchers must be joined"
    );
}

fn wait_for_epoch_watcher_count(expected: usize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if epoch_watcher_count() >= expected {
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

#[test]
fn non_auth_builtin_imports_are_rejected_before_compilation() {
    let error = match AuthEntryRunner::from_source(
        "use json; pub fn run() -> string { json::encode(1) }",
    ) {
        Err(error) => error,
        Ok(_) => panic!("standard builtin import must not enter auth runner"),
    };
    assert_eq!(error.code(), "auth_import_denied");
}
