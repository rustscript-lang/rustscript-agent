use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustscript_agent::config::ProcessToolConfig;
use rustscript_agent::tools::{
    NativeToolExecutor, ProcessOwner, ProcessTable, TerminalExecutor, TerminalRequest, ToolResult,
};
use rustscript_vm::CancellationToken;
use serde_json::json;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const TEMP_ROOT: &str =
    "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-tools-agent-integration-c77be280";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(TEMP_ROOT).join(format!(
            "terminal-{}-{}-{}",
            std::process::id(),
            sequence,
            std::thread::current().name().unwrap_or("test")
        ));
        fs::create_dir_all(&root).expect("create terminal fixture root");
        Self { root }
    }

    fn config(&self) -> ProcessToolConfig {
        ProcessToolConfig::for_workspace(&self.root)
    }

    fn executor(&self) -> TerminalExecutor {
        let config = self.config();
        let table = Arc::new(ProcessTable::new(config.clone()).expect("process table"));
        TerminalExecutor::new(config, table, owner()).expect("terminal executor")
    }

    fn executor_with_config(&self, mut config: ProcessToolConfig) -> TerminalExecutor {
        config.workspace_root = self.root.clone();
        let table = Arc::new(ProcessTable::new(config.clone()).expect("process table"));
        TerminalExecutor::new(config, table, owner()).expect("terminal executor")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn owner() -> ProcessOwner {
    ProcessOwner::new("profile-test", "session-test", "run-test").expect("owner")
}

fn error_code(result: &ToolResult) -> &str {
    result
        .error
        .as_ref()
        .expect("tool result should contain an error")
        .code
        .as_str()
}

fn assert_invalid_cwd_without_raw_path(result: &ToolResult, leaked: &[&str]) {
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(result), "invalid_cwd");
    let message = &result
        .error
        .as_ref()
        .expect("invalid_cwd should include a message")
        .message;
    let encoded = serde_json::to_string(result).expect("serialize invalid_cwd");
    for token in leaked {
        assert!(
            !message.contains(token),
            "invalid_cwd message leaked {token:?}: {message}"
        );
        assert!(
            !encoded.contains(token),
            "invalid_cwd envelope leaked {token:?}: {encoded}"
        );
    }
}

fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let Some(close) = stat.rfind(')') else {
                return true;
            };
            let state = stat[close + 1..].split_whitespace().next().unwrap_or("");
            state != "Z"
        }
        Err(_) => false,
    }
}

fn wait_until_dead(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("pid {pid} is still alive");
}

#[test]
fn terminal_executor_matches_the_frozen_registry_contract() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    assert_eq!(executor.slot(), NativeToolExecutor::Terminal);
    let descriptor = executor.descriptor();
    assert_eq!(descriptor.name, "terminal");
    assert_eq!(descriptor.toolset, "process");
    assert_eq!(descriptor.risk_class, "execute");
    assert_eq!(executor.slot().contract().tool_name, "terminal");
}

#[test]
fn foreground_argv_echo_returns_a_typed_terminal_result() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/echo".to_string(), "hello-terminal".to_string()],
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    assert!(result.content.contains("hello-terminal"));
    assert_eq!(result.data["exit_code"], 0);
    assert_eq!(result.data["background"], false);
    assert!(!result.truncated);
    let wire = serde_json::to_value(&result).expect("serialize");
    for key in ["ok", "content", "data", "error", "truncated", "artifacts"] {
        assert!(wire.get(key).is_some(), "missing {key}");
    }
}

#[test]
fn json_execute_uses_argv_only_and_rejects_a_shell_command_string() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    let ok = executor.execute(&json!({
        "argv": ["/bin/echo", "from-json"]
    }));
    assert!(ok.ok, "{ok:?}");
    assert!(ok.content.contains("from-json"));

    let missing = executor.execute(&json!({"command": "echo hi"}));
    assert!(!missing.ok);
    assert_eq!(error_code(&missing), "invalid_argv");
}

#[test]
fn argv_metacharacters_are_literal_and_never_reach_a_shell() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("should-not-exist");
    let executor = fixture.executor();
    let payload = format!("literal; touch {}", marker.display());
    let result = executor.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            payload.clone(),
        ],
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    assert_eq!(result.content, payload);
    assert!(!marker.exists(), "argv must not be interpreted by a shell");
}

#[test]
fn single_argv_entry_containing_spaces_is_the_program_name() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    let result = executor.run(TerminalRequest {
        argv: vec!["echo hello && true".to_string()],
        ..TerminalRequest::default()
    });
    assert!(!result.ok);
    assert_eq!(error_code(&result), "spawn_failed");
}

#[test]
fn relative_cwd_is_resolved_inside_the_workspace_and_escape_is_denied() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("sub")).expect("subdir");
    let executor = fixture.executor();
    let inside = executor.run(TerminalRequest {
        argv: vec!["/bin/pwd".to_string()],
        cwd: Some("sub".to_string()),
        ..TerminalRequest::default()
    });
    assert!(inside.ok, "{inside:?}");
    assert!(inside.content.contains("sub"));

    let escape = executor.run(TerminalRequest {
        argv: vec!["/bin/pwd".to_string()],
        cwd: Some("..".to_string()),
        ..TerminalRequest::default()
    });
    assert_invalid_cwd_without_raw_path(&escape, &[fixture.root.to_string_lossy().as_ref(), ".."]);
}

#[test]
fn nested_cwd_runs_in_the_retained_leaf_directory() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("nested/leaf")).expect("nested leaf");
    fs::write(fixture.root.join("root-marker"), b"root").expect("root marker");
    fs::write(fixture.root.join("nested/leaf/marker"), b"nested").expect("nested marker");
    let executor = fixture.executor();

    let nested = executor.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string(), "marker".to_string()],
        cwd: Some("nested/leaf".to_string()),
        ..TerminalRequest::default()
    });
    assert!(nested.ok, "{nested:?}");
    assert_eq!(nested.content, "nested");

    let default_root = executor.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string(), "root-marker".to_string()],
        cwd: None,
        ..TerminalRequest::default()
    });
    assert!(default_root.ok, "{default_root:?}");
    assert_eq!(default_root.content, "root");

    let empty_root = executor.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string(), "root-marker".to_string()],
        cwd: Some(String::new()),
        ..TerminalRequest::default()
    });
    assert!(empty_root.ok, "{empty_root:?}");
    assert_eq!(empty_root.content, "root");
}

#[cfg(unix)]
#[test]
fn symlink_cwd_is_denied_without_following_or_leaking_paths() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("sub")).expect("subdir");
    fs::write(fixture.root.join("sub/marker"), b"inside").expect("inside marker");
    symlink("sub", fixture.root.join("link")).expect("cwd symlink");
    let executor = fixture.executor();

    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string(), "marker".to_string()],
        cwd: Some("link".to_string()),
        ..TerminalRequest::default()
    });
    assert_invalid_cwd_without_raw_path(
        &result,
        &[fixture.root.to_string_lossy().as_ref(), "inside"],
    );
}

#[test]
fn absolute_cwd_is_denied_even_when_it_points_inside_the_workspace() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("sub")).expect("subdir");
    let executor = fixture.executor();
    let absolute = fixture.root.join("sub");
    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/pwd".to_string()],
        cwd: Some(absolute.to_string_lossy().into_owned()),
        ..TerminalRequest::default()
    });
    assert_invalid_cwd_without_raw_path(
        &result,
        &[
            fixture.root.to_string_lossy().as_ref(),
            absolute.to_string_lossy().as_ref(),
        ],
    );
}

#[cfg(unix)]
#[test]
fn root_binding_swap_fail_closes_without_redirecting_outside() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let workspace = fixture.root.join("workspace");
    let aside = fixture.root.join("workspace-aside");
    let outside = fixture.root.join("outside");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir(&outside).expect("outside");
    fs::write(workspace.join("marker"), b"inside").expect("inside marker");
    fs::write(outside.join("marker"), b"outside").expect("outside marker");

    let mut config = ProcessToolConfig::for_workspace(&workspace);
    config.workspace_root = workspace.clone();
    let table = Arc::new(ProcessTable::new(config.clone()).expect("process table"));
    let executor = TerminalExecutor::new(config, table, owner()).expect("terminal executor");

    fs::rename(&workspace, &aside).expect("move workspace aside");
    symlink(&outside, &workspace).expect("replace workspace with outside symlink");

    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string(), "marker".to_string()],
        ..TerminalRequest::default()
    });
    let outside_path = outside.to_string_lossy().into_owned();
    assert_invalid_cwd_without_raw_path(
        &result,
        &[workspace.to_string_lossy().as_ref(), outside_path.as_str()],
    );
    assert_eq!(
        fs::read(outside.join("marker")).expect("outside marker intact"),
        b"outside"
    );
    assert_eq!(
        fs::read(aside.join("marker")).expect("original workspace intact"),
        b"inside"
    );
}

#[cfg(unix)]
#[test]
fn synchronized_parent_and_leaf_swap_between_open_and_spawn_cannot_redirect_outside() {
    use std::os::unix::fs::symlink;

    use rustscript_vm::{BoundedProcessRequest, ConfinedFsRoot, exec_bounded};

    let fixture = Fixture::new();
    let outside = fixture.root.join("outside");
    fs::create_dir_all(fixture.root.join("parent/leaf")).expect("leaf");
    fs::create_dir(&outside).expect("outside");
    fs::write(fixture.root.join("parent/leaf/marker"), b"inside").expect("inside marker");
    fs::write(outside.join("marker"), b"outside").expect("outside marker");

    let root = ConfinedFsRoot::new(&fixture.root).expect("workspace root capability");
    let directory = root
        .open_directory("parent/leaf")
        .expect("retained leaf directory");

    fs::rename(
        fixture.root.join("parent/leaf"),
        fixture.root.join("leaf-moved"),
    )
    .expect("rename leaf");
    symlink(&outside, fixture.root.join("parent/leaf")).expect("leaf symlink");
    fs::rename(
        fixture.root.join("parent"),
        fixture.root.join("parent-moved"),
    )
    .expect("rename parent");
    symlink(&outside, fixture.root.join("parent")).expect("parent symlink");

    match exec_bounded(
        BoundedProcessRequest::new(vec!["/bin/cat".to_string(), "marker".to_string()])
            .with_confined_cwd(directory)
            .with_timeout(Duration::from_secs(5)),
    ) {
        Ok(output) => {
            assert_ne!(
                output.stdout.as_slice(),
                b"outside",
                "retained cwd must not follow a swapped path"
            );
            assert_eq!(output.stdout, b"inside");
            assert!(output.status.is_success());
        }
        Err(error) => {
            let text = error.to_string();
            assert!(
                !text.contains("outside") && !text.contains(outside.to_string_lossy().as_ref()),
                "fail-closed spawn must stay path-free: {text}"
            );
        }
    }
}

#[test]
fn path_based_cwd_is_absent_from_agent_production() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let production = [
        "src/tools/terminal.rs",
        "src/tools/process.rs",
        "src/tools/mod.rs",
    ];
    for relative in production {
        let source = fs::read_to_string(manifest.join(relative)).expect("read production source");
        assert!(
            !source.contains(".with_cwd("),
            "{relative} must not pass a path cwd"
        );
        assert!(
            !source.contains("with_workspace_root("),
            "{relative} must not pass a workspace path cwd"
        );
        assert!(
            !source.contains("current_dir("),
            "{relative} must not set a user-derived current_dir"
        );
    }
    let terminal = fs::read_to_string(manifest.join("src/tools/terminal.rs")).expect("terminal");
    assert!(
        terminal.contains("with_confined_cwd"),
        "terminal must retain a confined cwd capability"
    );
    assert!(
        terminal.contains("open_directory"),
        "terminal must open cwd through ConfinedFsRoot"
    );
    assert!(
        !terminal.contains("canonicalize"),
        "terminal must not canonicalize cwd paths"
    );
    assert!(
        !terminal.contains("strip_prefix"),
        "terminal must not check cwd with strip_prefix"
    );
    assert!(
        !terminal.contains("fn resolve_cwd"),
        "terminal must not keep a path-based resolve_cwd helper"
    );
}

#[test]
fn explicit_env_is_allowlisted_and_host_environment_is_not_inherited() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    unsafe {
        std::env::set_var("RUSTSCRIPT_AGENT_SHOULD_NOT_LEAK", "secret-host-env");
    }
    let result = executor.run(TerminalRequest {
        argv: vec!["/usr/bin/env".to_string()],
        env: [("BOUNDED_ENV".to_string(), "literal-value".to_string())].into(),
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    assert_eq!(result.content.trim(), "BOUNDED_ENV=literal-value");
    assert!(!result.content.contains("RUSTSCRIPT_AGENT_SHOULD_NOT_LEAK"));
    unsafe {
        std::env::remove_var("RUSTSCRIPT_AGENT_SHOULD_NOT_LEAK");
    }
}

#[test]
fn foreground_writes_stdin_then_closes_it() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string()],
        stdin: Some(b"from-stdin\n".to_vec()),
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    assert_eq!(result.content, "from-stdin\n");
}

#[test]
fn foreground_timeout_is_typed_and_kills_the_child() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("timeout.pid");
    let executor = fixture.executor();
    let started = Instant::now();
    let result = executor.run(TerminalRequest {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo $$ > \"$1\"; sleep 60".to_string(),
            "timeout-child".to_string(),
            marker.to_string_lossy().into_owned(),
        ],
        timeout_ms: Some(80),
        ..TerminalRequest::default()
    });
    assert!(!result.ok);
    assert_eq!(error_code(&result), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid: u32 = fs::read_to_string(&marker)
        .expect("pid marker")
        .trim()
        .parse()
        .expect("pid");
    wait_until_dead(pid);
}

#[test]
fn output_is_bounded_with_truncation_and_gap_metadata() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.max_stream_bytes = 64;
    config.max_output_bytes = 800;
    let executor = fixture.executor_with_config(config);
    let result = executor.run(TerminalRequest {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "i=0; while [ $i -lt 4000 ]; do printf o; i=$((i+1)); done".to_string(),
        ],
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    assert!(result.truncated);
    let encoded = serde_json::to_vec(&result).expect("serialize bounded output");
    assert!(
        encoded.len() <= 800,
        "envelope {} exceeds cap",
        encoded.len()
    );
    assert_eq!(result.data["stdout_truncated"], true);
    assert!(result.data["stdout_next_offset"].as_u64().unwrap() > 32);
    assert!(result.artifacts.is_empty());
}

#[test]
fn serialized_terminal_envelope_stays_within_max_output_bytes() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.max_stream_bytes = 256;
    config.max_output_bytes = 800;
    let executor = fixture.executor_with_config(config);
    let result = executor.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            "x".repeat(256),
        ],
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    let encoded = serde_json::to_vec(&result).expect("serialize terminal result");
    assert!(
        encoded.len() <= 800,
        "envelope {} exceeds cap: {}",
        encoded.len(),
        String::from_utf8_lossy(&encoded)
    );
    assert!(result.truncated);
}

#[test]
fn terminal_metadata_overflow_returns_typed_bounded_error() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.max_output_bytes = 128;
    let executor = fixture.executor_with_config(config);
    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/echo".to_string(), "hello-terminal".to_string()],
        ..TerminalRequest::default()
    });
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "output_truncated");
    let encoded = serde_json::to_vec(&result).expect("serialize bounded error");
    assert!(
        encoded.len() <= 128,
        "bounded error {} exceeds cap: {}",
        encoded.len(),
        String::from_utf8_lossy(&encoded)
    );
}

#[test]
fn background_mode_creates_an_opaque_owned_process_record() {
    let fixture = Fixture::new();
    let executor = fixture.executor();
    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(2_000),
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    assert_eq!(result.data["background"], true);
    let process_id = result.data["process_id"].as_str().expect("process_id");
    assert!(process_id.len() >= 32);
    assert!(process_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_ne!(process_id, "1");
    executor
        .table()
        .cleanup_owner(&owner())
        .expect("cleanup background process");
}

#[test]
fn dropping_the_table_reaps_background_children() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("drop.pid");
    let config = fixture.config();
    let table = Arc::new(ProcessTable::new(config.clone()).expect("table"));
    let executor =
        TerminalExecutor::new(config, Arc::clone(&table), owner()).expect("terminal executor");
    let spawned = executor.run(TerminalRequest {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo $$ > \"$1\"; sleep 60".to_string(),
            "drop-child".to_string(),
            marker.to_string_lossy().into_owned(),
        ],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let started = Instant::now();
    while !marker.exists() && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let pid: u32 = fs::read_to_string(&marker)
        .expect("pid marker")
        .trim()
        .parse()
        .expect("pid");
    drop(executor);
    drop(table);
    wait_until_dead(pid);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn config_rejects_zero_and_over_large_process_budgets() {
    let fixture = Fixture::new();
    let base = fixture.config();
    base.validate()
        .expect("default process config should validate");

    let mut invalid = base.clone();
    invalid.max_timeout = Duration::ZERO;
    assert!(invalid.validate().is_err());

    let mut invalid = base.clone();
    invalid.max_output_bytes = 0;
    assert!(invalid.validate().is_err());

    let mut invalid = base.clone();
    invalid.max_stream_bytes = 0;
    assert!(invalid.validate().is_err());

    let mut invalid = base.clone();
    invalid.max_processes = 0;
    assert!(invalid.validate().is_err());

    let mut invalid = base.clone();
    invalid.workspace_root = PathBuf::from("relative-workspace");
    assert!(invalid.validate().is_err());

    let mut invalid = base;
    invalid.max_timeout = Duration::from_secs(60 * 60 + 1);
    assert!(invalid.validate().is_err());
}

fn tight_timeout_config(fixture: &Fixture) -> ProcessToolConfig {
    let mut config = fixture.config();
    config.default_timeout = Duration::from_millis(40);
    config.max_timeout = Duration::from_millis(400);
    config
}

#[test]
fn no_controls_wrappers_accept_timeout_above_default_up_to_max() {
    let fixture = Fixture::new();
    let executor = fixture.executor_with_config(tight_timeout_config(&fixture));

    let run = executor.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "0.12".to_string()],
        timeout_ms: Some(300),
        ..TerminalRequest::default()
    });
    assert!(run.ok, "{run:?}");
    assert_eq!(run.data["exit_code"], 0);

    let execute = executor.execute(&json!({
        "argv": ["/bin/sleep", "0.12"],
        "timeout_ms": 300
    }));
    assert!(execute.ok, "{execute:?}");
    assert_eq!(execute.data["exit_code"], 0);

    let over_max = executor.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "0.12".to_string()],
        timeout_ms: Some(401),
        ..TerminalRequest::default()
    });
    assert!(!over_max.ok, "{over_max:?}");
    assert_eq!(error_code(&over_max), "invalid_timeout");
}

#[test]
fn omitted_timeout_still_uses_default_internally() {
    let fixture = Fixture::new();
    let executor = fixture.executor_with_config(tight_timeout_config(&fixture));
    let started = Instant::now();
    let result = executor.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "1".to_string()],
        ..TerminalRequest::default()
    });
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "deadline_elapsed");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "omitted timeout used {:?} instead of default_timeout",
        started.elapsed()
    );

    let started = Instant::now();
    let execute = executor.execute(&json!({
        "argv": ["/bin/sleep", "1"]
    }));
    assert!(!execute.ok, "{execute:?}");
    assert_eq!(error_code(&execute), "deadline_elapsed");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "omitted execute timeout used {:?} instead of default_timeout",
        started.elapsed()
    );
}

#[test]
fn explicit_external_deadline_still_clamps_timeout_above_default() {
    let fixture = Fixture::new();
    let executor = fixture.executor_with_config(tight_timeout_config(&fixture));
    let started = Instant::now();
    let result = executor.execute_with_controls(
        &json!({
            "argv": ["/bin/sleep", "1"],
            "timeout_ms": 300
        }),
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(20),
    );
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_millis(200));

    let started = Instant::now();
    let run = executor.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "1".to_string()],
        timeout_ms: Some(300),
        deadline: Some(Instant::now() + Duration::from_millis(20)),
        ..TerminalRequest::default()
    });
    assert!(!run.ok, "{run:?}");
    assert_eq!(error_code(&run), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_millis(200));
}
