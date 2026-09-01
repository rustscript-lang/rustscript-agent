use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::config::{MAX_PROCESS_TOOL_TIMEOUT, ProcessToolConfig};
use rustscript_agent::tools::{
    NativeToolExecutor, ProcessAction, ProcessArtifactSink, ProcessExecutor, ProcessOwner,
    ProcessRequest, ProcessTable, TerminalExecutor, TerminalRequest, ToolResult,
};
use rustscript_vm::CancellationToken;
use serde_json::json;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const TEMP_ROOT: &str = "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-t4-process2-905efdd1";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(TEMP_ROOT).join(format!(
            "process-{}-{}-{}",
            std::process::id(),
            sequence,
            std::thread::current().name().unwrap_or("test")
        ));
        fs::create_dir_all(&root).expect("create process fixture root");
        Self { root }
    }

    fn config(&self) -> ProcessToolConfig {
        ProcessToolConfig::for_workspace(&self.root)
    }

    fn pair(&self) -> (TerminalExecutor, ProcessExecutor, Arc<ProcessTable>) {
        self.pair_for(owner())
    }

    fn pair_for(
        &self,
        owner: ProcessOwner,
    ) -> (TerminalExecutor, ProcessExecutor, Arc<ProcessTable>) {
        self.pair_with_config_for(self.config(), owner)
    }

    fn pair_with_config(
        &self,
        config: ProcessToolConfig,
    ) -> (TerminalExecutor, ProcessExecutor, Arc<ProcessTable>) {
        self.pair_with_config_for(config, owner())
    }

    fn pair_with_config_for(
        &self,
        mut config: ProcessToolConfig,
        owner: ProcessOwner,
    ) -> (TerminalExecutor, ProcessExecutor, Arc<ProcessTable>) {
        config.workspace_root = self.root.clone();
        let table = Arc::new(ProcessTable::new(config.clone()).expect("process table"));
        let terminal = TerminalExecutor::new(config.clone(), Arc::clone(&table), owner.clone())
            .expect("terminal");
        let process = ProcessExecutor::new(config, Arc::clone(&table), owner).expect("process");
        (terminal, process, table)
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

fn other_owner() -> ProcessOwner {
    ProcessOwner::new("other-profile", "other-session", "other-run").expect("other owner")
}

fn error_code(result: &ToolResult) -> &str {
    result
        .error
        .as_ref()
        .expect("tool result should contain an error")
        .code
        .as_str()
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

fn wait_for_file(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return text;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {}", path.display());
}

fn spawn_sleep(terminal: &TerminalExecutor, seconds: &str, timeout_ms: u64) -> String {
    let result = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), seconds.to_string()],
        background: true,
        timeout_ms: Some(timeout_ms),
        ..TerminalRequest::default()
    });
    assert!(result.ok, "{result:?}");
    result.data["process_id"]
        .as_str()
        .expect("process_id")
        .to_string()
}

#[test]
fn process_executor_matches_the_frozen_registry_contract() {
    let fixture = Fixture::new();
    let (_, process, _) = fixture.pair();
    assert_eq!(process.slot(), NativeToolExecutor::Process);
    assert_eq!(process.descriptor().name, "process");
    assert_eq!(process.descriptor().toolset, "process");
    assert_eq!(process.slot().contract().tool_name, "process");
}

#[test]
fn process_timeout_ms_schema_advertises_stable_millisecond_maximum() {
    let fixture = Fixture::new();
    let (_, process, _) = fixture.pair();
    let timeout = &process.descriptor().schema["properties"]["timeout_ms"];
    assert_eq!(timeout["type"], "integer");
    assert_eq!(timeout["minimum"], 1);
    let maximum = u64::try_from(MAX_PROCESS_TOOL_TIMEOUT.as_millis()).expect("max timeout fits ms");
    assert_eq!(timeout["maximum"], maximum);
}

#[test]
fn background_lifecycle_supports_poll_wait_log_write_close_and_kill() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();

    let poll = process.run(ProcessRequest {
        action: ProcessAction::Poll,
        process_id: process_id.clone(),
        ..ProcessRequest::default()
    });
    assert!(poll.ok, "{poll:?}");
    assert_eq!(poll.data["status"], "running");

    let written = process.run(ProcessRequest {
        action: ProcessAction::Write,
        process_id: process_id.clone(),
        data: Some("hello-cat\n".to_string()),
        ..ProcessRequest::default()
    });
    assert!(written.ok, "{written:?}");

    let closed = process.run(ProcessRequest {
        action: ProcessAction::Close,
        process_id: process_id.clone(),
        ..ProcessRequest::default()
    });
    assert!(closed.ok, "{closed:?}");

    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id: process_id.clone(),
        timeout_ms: Some(2_000),
        ..ProcessRequest::default()
    });
    assert!(waited.ok, "{waited:?}");
    assert_eq!(waited.data["exit_code"], 0);

    let log = process.run(ProcessRequest {
        action: ProcessAction::Log,
        process_id: process_id.clone(),
        offset: Some(0),
        limit: Some(64),
        ..ProcessRequest::default()
    });
    assert!(log.ok, "{log:?}");
    assert!(log.content.contains("hello-cat"));
    assert_eq!(log.data["stdout_gap"], false);

    let killed = process.run(ProcessRequest {
        action: ProcessAction::Kill,
        process_id: process_id.clone(),
        ..ProcessRequest::default()
    });
    assert!(killed.ok, "{killed:?}");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn json_execute_dispatches_process_actions() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let process_id = spawn_sleep(&terminal, "30", 2_000);
    let poll = process.execute(&json!({
        "action": "poll",
        "process_id": process_id,
    }));
    assert!(poll.ok, "{poll:?}");
    assert_eq!(poll.data["status"], "running");
    let killed = process.execute(&json!({
        "action": "kill",
        "process_id": process_id,
    }));
    assert!(killed.ok, "{killed:?}");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn owner_denial_is_indistinguishable_from_missing() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let process_id = spawn_sleep(&terminal, "30", 5_000);
    let (_, stranger, _) = fixture.pair_for(other_owner());

    let missing = process.run(ProcessRequest {
        action: ProcessAction::Poll,
        process_id: "ffffffffffffffffffffffffffffffff".to_string(),
        ..ProcessRequest::default()
    });
    let denied = stranger.run(ProcessRequest {
        action: ProcessAction::Poll,
        process_id: process_id.clone(),
        ..ProcessRequest::default()
    });
    assert!(!missing.ok);
    assert!(!denied.ok);
    assert_eq!(error_code(&missing), "process_not_found");
    assert_eq!(error_code(&denied), "process_not_found");
    assert_eq!(
        missing.error.as_ref().unwrap().message,
        denied.error.as_ref().unwrap().message
    );

    let numeric = process.run(ProcessRequest {
        action: ProcessAction::Kill,
        process_id: "1".to_string(),
        ..ProcessRequest::default()
    });
    assert_eq!(error_code(&numeric), "process_not_found");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn kill_rejects_numeric_pids_and_does_not_signal_the_os_process() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("kill.pid");
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo $$ > \"$1\"; sleep 60".to_string(),
            "kill-child".to_string(),
            marker.to_string_lossy().into_owned(),
        ],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let pid: u32 = wait_for_file(&marker).trim().parse().expect("pid");
    assert!(pid_alive(pid));

    let numeric = process.run(ProcessRequest {
        action: ProcessAction::Kill,
        process_id: pid.to_string(),
        ..ProcessRequest::default()
    });
    assert_eq!(error_code(&numeric), "process_not_found");
    assert!(
        pid_alive(pid),
        "numeric pid must not be used as a kill target"
    );

    let killed = process.run(ProcessRequest {
        action: ProcessAction::Kill,
        process_id,
        ..ProcessRequest::default()
    });
    assert!(killed.ok, "{killed:?}");
    wait_until_dead(pid);
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn wait_timeout_cannot_extend_the_spawn_deadline() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let process_id = spawn_sleep(&terminal, "30", 120);
    let started = Instant::now();
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id,
        timeout_ms: Some(5_000),
        ..ProcessRequest::default()
    });
    assert!(!waited.ok);
    assert_eq!(error_code(&waited), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_secs(2));
    table.cleanup_owner(&owner()).expect("cleanup");
}

fn tight_timeout_config(fixture: &Fixture) -> ProcessToolConfig {
    let mut config = fixture.config();
    config.default_timeout = Duration::from_millis(40);
    config.max_timeout = Duration::from_millis(400);
    config
}

#[test]
fn no_controls_wait_accepts_timeout_above_default_up_to_max() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair_with_config(tight_timeout_config(&fixture));
    let process_id = spawn_sleep(&terminal, "0.12", 300);
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id,
        timeout_ms: Some(300),
        ..ProcessRequest::default()
    });
    assert!(waited.ok, "{waited:?}");
    assert_eq!(waited.data["status"], "exited");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn no_controls_execute_wait_is_not_prematurely_deadline_elapsed() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair_with_config(tight_timeout_config(&fixture));
    let process_id = spawn_sleep(&terminal, "0.12", 300);
    let waited = process.execute(&json!({
        "action": "wait",
        "process_id": process_id,
        "timeout_ms": 300
    }));
    assert!(waited.ok, "{waited:?}");
    assert_eq!(waited.data["status"], "exited");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn omitted_wait_timeout_is_not_clamped_to_default() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair_with_config(tight_timeout_config(&fixture));
    let process_id = spawn_sleep(&terminal, "0.12", 300);
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id,
        timeout_ms: None,
        ..ProcessRequest::default()
    });
    assert!(waited.ok, "{waited:?}");
    assert_eq!(waited.data["status"], "exited");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn explicit_external_deadline_still_clamps_wait_above_default() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair_with_config(tight_timeout_config(&fixture));
    let process_id = spawn_sleep(&terminal, "1", 300);
    let started = Instant::now();
    let waited = process.run_with_controls(
        ProcessRequest {
            action: ProcessAction::Wait,
            process_id: process_id.clone(),
            timeout_ms: Some(300),
            ..ProcessRequest::default()
        },
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(20),
    );
    assert!(!waited.ok, "{waited:?}");
    assert_eq!(error_code(&waited), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_millis(200));

    let started = Instant::now();
    let execute = process.execute_with_controls(
        &json!({
            "action": "wait",
            "process_id": process_id,
            "timeout_ms": 300
        }),
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(20),
    );
    assert!(!execute.ok, "{execute:?}");
    assert_eq!(error_code(&execute), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_millis(200));
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn stdin_close_is_idempotent_and_races_stay_bounded() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/cat".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let barrier = Arc::new(Barrier::new(3));
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut joins = Vec::new();
    for action in [ProcessAction::Write, ProcessAction::Close] {
        let process = process.clone();
        let process_id = process_id.clone();
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            let result = process.run(ProcessRequest {
                action,
                process_id,
                data: Some("x".repeat(64 * 1024)),
                ..ProcessRequest::default()
            });
            results
                .lock()
                .unwrap()
                .push(result.ok || result.error.is_some());
        }));
    }
    barrier.wait();
    for join in joins {
        join.join().expect("race thread");
    }
    let closed = process.run(ProcessRequest {
        action: ProcessAction::Close,
        process_id: process_id.clone(),
        ..ProcessRequest::default()
    });
    assert!(closed.ok, "{closed:?}");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn concurrent_poll_wait_and_kill_complete_within_a_bound() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let process_id = spawn_sleep(&terminal, "30", 5_000);
    let barrier = Arc::new(Barrier::new(4));
    let started = Instant::now();
    let mut joins = Vec::new();
    for action in [
        ProcessAction::Poll,
        ProcessAction::Wait,
        ProcessAction::Kill,
    ] {
        let process = process.clone();
        let process_id = process_id.clone();
        let barrier = Arc::clone(&barrier);
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            process.run(ProcessRequest {
                action,
                process_id,
                timeout_ms: Some(1_000),
                ..ProcessRequest::default()
            })
        }));
    }
    barrier.wait();
    for join in joins {
        let result = join.join().expect("race thread");
        assert!(result.ok || result.error.is_some(), "{result:?}");
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn kill_reaps_child_tree_residue() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("tree.pid");
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 60 & echo $! > \"$1\"; wait".to_string(),
            "tree-root".to_string(),
            marker.to_string_lossy().into_owned(),
        ],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let descendant: u32 = wait_for_file(&marker)
        .trim()
        .parse()
        .expect("descendant pid");
    let killed = process.run(ProcessRequest {
        action: ProcessAction::Kill,
        process_id,
        ..ProcessRequest::default()
    });
    assert!(killed.ok, "{killed:?}");
    wait_until_dead(descendant);
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn owner_cleanup_terminates_on_stop_session_deletion_and_shutdown() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("cleanup.pid");
    let (terminal, _, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo $$ > \"$1\"; sleep 60".to_string(),
            "cleanup-child".to_string(),
            marker.to_string_lossy().into_owned(),
        ],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let pid: u32 = wait_for_file(&marker).trim().parse().expect("pid");
    assert_eq!(
        table.cleanup_run("profile-test", "session-test", "run-test"),
        1
    );
    wait_until_dead(pid);

    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    assert_eq!(table.cleanup_session("profile-test", "session-test"), 1);

    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    assert_eq!(table.cleanup_profile("profile-test"), 1);
    table.shutdown();
    assert_eq!(table.len(), 0);
}

#[test]
fn artifact_sink_is_optional_and_overflow_stays_bounded() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.max_stream_bytes = 256;
    config.max_output_bytes = 600;
    let table = Arc::new(ProcessTable::new(config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(config.clone(), Arc::clone(&table), owner())
        .expect("terminal")
        .with_artifact_sink(Arc::new(RejectingSink));
    let overflow = terminal.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            "abcdefghijklmnopqrstuvwxyz".repeat(8),
        ],
        ..TerminalRequest::default()
    });
    assert!(overflow.ok, "{overflow:?}");
    assert!(overflow.truncated);
    let encoded = serde_json::to_vec(&overflow).expect("serialize overflow");
    assert!(
        encoded.len() <= 600,
        "envelope {} exceeds cap",
        encoded.len()
    );
    assert!(overflow.artifacts.is_empty());
    assert_eq!(overflow.data["overflow"], true);
    assert_eq!(overflow.data["overflow_reason"], "artifact_unavailable");

    let stored = terminal
        .with_artifact_sink(Arc::new(MemorySink::default()))
        .run(TerminalRequest {
            argv: vec![
                "/usr/bin/printf".to_string(),
                "%s".to_string(),
                "abcdefghijklmnopqrstuvwxyz".repeat(8),
            ],
            ..TerminalRequest::default()
        });
    assert!(stored.ok, "{stored:?}");
    assert_eq!(stored.artifacts.len(), 1);
    assert!(!stored.artifacts[0].contains('/'));
    let encoded = serde_json::to_vec(&stored).expect("serialize stored");
    assert!(
        encoded.len() <= 600,
        "envelope {} exceeds cap",
        encoded.len()
    );
    table.shutdown();
}

#[test]
fn log_limit_advances_next_offset_so_follow_up_returns_unread_bytes() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            "0123456789ABCDEF".to_string(),
        ],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id: process_id.clone(),
        timeout_ms: Some(2_000),
        ..ProcessRequest::default()
    });
    assert!(waited.ok, "{waited:?}");

    let first = process.run(ProcessRequest {
        action: ProcessAction::Log,
        process_id: process_id.clone(),
        offset: Some(0),
        limit: Some(4),
        ..ProcessRequest::default()
    });
    assert!(first.ok, "{first:?}");
    assert_eq!(first.data["stdout"].as_str().unwrap(), "0123");
    let start = first.data["stdout_offset"].as_u64().unwrap();
    let next = first.data["stdout_next_offset"].as_u64().unwrap();
    assert_eq!(next, start + 4);
    assert_eq!(first.data["stdout_gap"], false);

    let second = process.run(ProcessRequest {
        action: ProcessAction::Log,
        process_id: process_id.clone(),
        offset: Some(next),
        limit: Some(4),
        ..ProcessRequest::default()
    });
    assert!(second.ok, "{second:?}");
    assert_eq!(second.data["stdout"].as_str().unwrap(), "4567");
    assert_eq!(
        second.data["stdout_next_offset"].as_u64().unwrap(),
        second.data["stdout_offset"].as_u64().unwrap() + 4
    );
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn write_timeout_ms_caps_a_full_pipe_and_returns_typed_timeout() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let started = Instant::now();
    let written = process.run(ProcessRequest {
        action: ProcessAction::Write,
        process_id: process_id.clone(),
        data: Some("x".repeat(1024 * 1024)),
        timeout_ms: Some(80),
        ..ProcessRequest::default()
    });
    let elapsed = started.elapsed();
    assert!(!written.ok, "{written:?}");
    assert_eq!(error_code(&written), "deadline_elapsed");
    assert!(
        elapsed < Duration::from_millis(800),
        "write timeout blocked for {elapsed:?}"
    );
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn wait_timeout_ms_rejects_u64_max_without_panic() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let process_id = spawn_sleep(&terminal, "30", 5_000);
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id: process_id.clone(),
        timeout_ms: Some(u64::MAX),
        ..ProcessRequest::default()
    });
    assert!(!waited.ok, "{waited:?}");
    assert_eq!(error_code(&waited), "invalid_timeout");

    let execute = process.execute(&json!({
        "action": "wait",
        "process_id": process_id,
        "timeout_ms": u64::MAX
    }));
    assert!(!execute.ok, "{execute:?}");
    assert_eq!(error_code(&execute), "invalid_timeout");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn wait_timeout_ms_above_max_is_invalid() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair_with_config(tight_timeout_config(&fixture));
    let process_id = spawn_sleep(&terminal, "1", 300);
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id,
        timeout_ms: Some(401),
        ..ProcessRequest::default()
    });
    assert!(!waited.ok, "{waited:?}");
    assert_eq!(error_code(&waited), "invalid_timeout");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn write_timeout_ms_rejects_u64_max_without_panic() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let written = process.run(ProcessRequest {
        action: ProcessAction::Write,
        process_id: process_id.clone(),
        data: Some("x".to_string()),
        timeout_ms: Some(u64::MAX),
        ..ProcessRequest::default()
    });
    assert!(!written.ok, "{written:?}");
    assert_eq!(error_code(&written), "invalid_timeout");

    let execute = process.execute(&json!({
        "action": "write",
        "process_id": process_id,
        "data": "x",
        "timeout_ms": u64::MAX
    }));
    assert!(!execute.ok, "{execute:?}");
    assert_eq!(error_code(&execute), "invalid_timeout");
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn write_timeout_ms_above_max_is_invalid() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair_with_config(tight_timeout_config(&fixture));
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "1".to_string()],
        background: true,
        timeout_ms: Some(300),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let written = process.run(ProcessRequest {
        action: ProcessAction::Write,
        process_id,
        data: Some("x".to_string()),
        timeout_ms: Some(401),
        ..ProcessRequest::default()
    });
    assert!(!written.ok, "{written:?}");
    assert_eq!(error_code(&written), "invalid_timeout");
    table.cleanup_owner(&owner()).expect("cleanup");
}

fn spawn_blocking_write(
    process: &ProcessExecutor,
    process_id: String,
    cancellation: CancellationToken,
    deadline: Instant,
    timeout_ms: Option<u64>,
) -> std::thread::JoinHandle<ToolResult> {
    let process = process.clone();
    std::thread::spawn(move || {
        process.run_with_controls(
            ProcessRequest {
                action: ProcessAction::Write,
                process_id,
                data: Some("x".repeat(1024 * 1024)),
                timeout_ms,
                ..ProcessRequest::default()
            },
            &cancellation,
            deadline,
        )
    })
}

fn wait_until_write_blocks(join: &std::thread::JoinHandle<ToolResult>) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(40) {
        assert!(
            !join.is_finished(),
            "write completed before the pipe could fill"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !join.is_finished(),
        "write completed before cancellation/deadline"
    );
}

#[test]
fn write_cancellation_interrupts_a_full_pipe() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let cancellation = CancellationToken::new();
    let started = Instant::now();
    let join = spawn_blocking_write(
        &process,
        process_id,
        cancellation.clone(),
        Instant::now() + Duration::from_secs(5),
        Some(5_000),
    );
    wait_until_write_blocks(&join);
    cancellation.cancel();
    let written = join.join().expect("write thread");
    let elapsed = started.elapsed();
    assert!(!written.ok, "{written:?}");
    assert_eq!(error_code(&written), "cancelled");
    assert!(
        elapsed < Duration::from_millis(800),
        "cancelled write blocked for {elapsed:?}"
    );
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn write_caller_deadline_interrupts_a_full_pipe() {
    let fixture = Fixture::new();
    let (terminal, process, table) = fixture.pair();
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let started = Instant::now();
    let written = process.run_with_controls(
        ProcessRequest {
            action: ProcessAction::Write,
            process_id,
            data: Some("x".repeat(1024 * 1024)),
            timeout_ms: Some(5_000),
            ..ProcessRequest::default()
        },
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(50),
    );
    let elapsed = started.elapsed();
    assert!(!written.ok, "{written:?}");
    assert_eq!(error_code(&written), "deadline_elapsed");
    assert!(
        elapsed < Duration::from_millis(800),
        "deadline write blocked for {elapsed:?}"
    );
    table.cleanup_owner(&owner()).expect("cleanup");
}

#[test]
fn serialized_process_envelope_stays_within_max_output_bytes() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.max_stream_bytes = 256;
    config.max_output_bytes = 800;
    let table = Arc::new(ProcessTable::new(config.clone()).expect("table"));
    let terminal =
        TerminalExecutor::new(config.clone(), Arc::clone(&table), owner()).expect("terminal");
    let process = ProcessExecutor::new(config, Arc::clone(&table), owner()).expect("process");
    let spawned = terminal.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            "y".repeat(256),
        ],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let waited = process.run(ProcessRequest {
        action: ProcessAction::Wait,
        process_id: process_id.clone(),
        timeout_ms: Some(2_000),
        ..ProcessRequest::default()
    });
    let encoded = serde_json::to_vec(&waited).expect("serialize process result");
    assert!(
        encoded.len() <= 800,
        "envelope {} exceeds cap: {}",
        encoded.len(),
        String::from_utf8_lossy(&encoded)
    );
    assert!(waited.ok, "{waited:?}");
    assert!(waited.truncated);
    let log = process.run(ProcessRequest {
        action: ProcessAction::Log,
        process_id,
        offset: Some(0),
        limit: Some(256),
        ..ProcessRequest::default()
    });
    let encoded = serde_json::to_vec(&log).expect("serialize process log");
    assert!(
        encoded.len() <= 800,
        "log envelope {} exceeds cap: {}",
        encoded.len(),
        String::from_utf8_lossy(&encoded)
    );
    table.shutdown();
}

#[test]
fn cleanup_cancels_in_flight_foreground_before_background_reap() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("foreground.pid");
    let (terminal, _, table) = fixture.pair();
    let started = Instant::now();
    let join = std::thread::spawn(move || {
        terminal.run(TerminalRequest {
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo $$ > \"$1\"; sleep 8".to_string(),
                "foreground-child".to_string(),
                marker.to_string_lossy().into_owned(),
            ],
            timeout_ms: Some(8_000),
            ..TerminalRequest::default()
        })
    });
    let pid: u32 = wait_for_file(&fixture.root.join("foreground.pid"))
        .trim()
        .parse()
        .expect("pid");
    assert!(pid_alive(pid));
    assert_eq!(
        table.cleanup_run("profile-test", "session-test", "run-test"),
        0
    );
    let result = join.join().expect("foreground thread");
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "cancelled");
    wait_until_dead(pid);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "foreground cleanup blocked for {:?}",
        started.elapsed()
    );
}

#[test]
fn cleanup_timeout_bounds_hostile_children_without_waiting_spawn_deadline() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.cleanup_timeout = Duration::from_millis(120);
    config.max_processes = 8;
    let table = Arc::new(ProcessTable::new(config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(config, Arc::clone(&table), owner()).expect("terminal");
    let mut pids = Vec::new();
    for index in 0..3 {
        let marker = fixture.root.join(format!("hostile-{index}.pid"));
        let spawned = terminal.run(TerminalRequest {
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "trap \"\" TERM INT HUP QUIT; echo $$ > \"$1\"; sleep 30".to_string(),
                format!("hostile-{index}"),
                marker.to_string_lossy().into_owned(),
            ],
            background: true,
            timeout_ms: Some(30_000),
            ..TerminalRequest::default()
        });
        assert!(spawned.ok, "{spawned:?}");
        let pid: u32 = wait_for_file(&marker).trim().parse().expect("pid");
        pids.push(pid);
    }
    let started = Instant::now();
    assert_eq!(
        table.cleanup_run("profile-test", "session-test", "run-test"),
        3
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(800),
        "cleanup waited {elapsed:?} instead of honoring cleanup_timeout"
    );
    for pid in pids {
        wait_until_dead(pid);
    }
    assert_eq!(table.len(), 0);
}

#[test]
fn write_during_cleanup_does_not_escape_and_foreground_register_fails_closed() {
    let fixture = Fixture::new();
    let (terminal, _, table) = fixture.pair();
    table.shutdown();
    let started = Instant::now();
    let foreground = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "8".to_string()],
        timeout_ms: Some(8_000),
        ..TerminalRequest::default()
    });
    assert!(!foreground.ok, "{foreground:?}");
    assert_eq!(error_code(&foreground), "cancelled");
    let background = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "8".to_string()],
        background: true,
        timeout_ms: Some(8_000),
        ..TerminalRequest::default()
    });
    assert!(!background.ok, "{background:?}");
    assert_eq!(error_code(&background), "cancelled");
    assert!(started.elapsed() < Duration::from_millis(800));
}

#[derive(Default)]
struct MemorySink {
    stored: Mutex<Vec<(String, Vec<u8>)>>,
}

impl ProcessArtifactSink for MemorySink {
    fn store(&self, _owner: &ProcessOwner, bytes: &[u8]) -> Result<String, String> {
        let id = format!("artifact-{:02}", self.stored.lock().unwrap().len() + 1);
        self.stored
            .lock()
            .unwrap()
            .push((id.clone(), bytes.to_vec()));
        Ok(id)
    }
}

struct RejectingSink;

impl ProcessArtifactSink for RejectingSink {
    fn store(&self, _owner: &ProcessOwner, _bytes: &[u8]) -> Result<String, String> {
        Err("unavailable".to_string())
    }
}
