use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use rustscript_agent::config::{
    FileToolConfig, MAX_ARTIFACT_OBJECT_BYTES, MAX_ARTIFACT_TOTAL_BYTES, MAX_TOOL_OUTPUT_BYTES,
    ProcessToolConfig, RunLimits,
};
use rustscript_agent::tools::{
    ArtifactOwner, ArtifactStore, FileTools, NativeToolExecutor, ProcessAction,
    ProcessArtifactSink, ProcessExecutor, ProcessOwner, ProcessRequest, ProcessTable,
    ReadFileRequest, SearchFilesRequest, TerminalExecutor, TerminalRequest, ToolOwner, ToolResult,
};
use rustscript_vm::CancellationToken;
use serde_json::json;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const TEMP_ROOT: &str =
    "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-tools-agent-integration-c77be280";

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let parent = Path::new(TEMP_ROOT).join(format!(
            "exec-{}-{}-{}",
            std::process::id(),
            sequence,
            std::thread::current().name().unwrap_or("test")
        ));
        let root = parent.join("workspace");
        fs::create_dir_all(&root).expect("create integration fixture root");
        Self { root, parent }
    }

    fn file_config(&self) -> FileToolConfig {
        let mut config = FileToolConfig::for_workspace(&self.root);
        config.artifact_store.root = self.parent.join("artifacts");
        config
    }

    fn process_config(&self) -> ProcessToolConfig {
        ProcessToolConfig::for_workspace(&self.root)
    }

    fn tools(&self) -> FileTools {
        FileTools::new(self.file_config()).expect("file tools")
    }

    fn tools_with_config(&self, mut config: FileToolConfig) -> FileTools {
        config.workspace_root = self.root.clone();
        config.artifact_store.root = self.parent.join(format!(
            "artifacts-{}",
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        FileTools::new(config).expect("configured file tools")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

fn tool_owner() -> ToolOwner {
    ToolOwner::new("profile-test", "session-test", "run-test").expect("tool owner")
}

fn other_tool_owner() -> ToolOwner {
    ToolOwner::new("other-profile", "other-session", "other-run").expect("other tool owner")
}

fn error_code(result: &ToolResult) -> &str {
    result
        .error
        .as_ref()
        .expect("tool result should contain an error")
        .code
        .as_str()
}

fn encoded_len(result: &ToolResult) -> usize {
    serde_json::to_vec(result)
        .expect("tool result must serialize")
        .len()
}

fn assert_within_cap(result: &ToolResult, cap: usize) {
    let encoded = encoded_len(result);
    assert!(
        encoded <= cap,
        "envelope {encoded} exceeds cap {cap}: {}",
        String::from_utf8_lossy(&serde_json::to_vec(result).unwrap())
    );
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

#[test]
fn shared_serialized_cap_covers_file_terminal_and_process() {
    let fixture = Fixture::new();
    let payload = "0123456789abcdef\n".repeat(64);

    let mut file_config = fixture.file_config();
    file_config.max_output_bytes = 512;
    file_config.max_read_bytes = 4096;
    file_config.max_search_output_bytes = 512;
    file_config.artifact_store.max_object_bytes = 4096;
    file_config.artifact_store.max_total_bytes = 8192;
    let files = fixture
        .tools_with_config(file_config)
        .with_owner(ArtifactOwner::from(tool_owner()));
    fs::write(fixture.root.join("large.txt"), &payload).expect("write large file");
    let read = files.read_file(ReadFileRequest::new("large.txt"));
    assert_within_cap(&read, 512);
    assert!(read.truncated || error_code_if_any(&read) == Some("output_truncated"));
    if read.ok {
        assert_eq!(read.artifacts.len(), 1);
        files
            .artifact_store()
            .retrieve(&ArtifactOwner::from(tool_owner()), &read.artifacts[0])
            .expect("owner can retrieve published file payload");
    }

    let mut process_config = fixture.process_config();
    process_config.max_stream_bytes = 256;
    process_config.max_output_bytes = 800;
    let table = Arc::new(ProcessTable::new(process_config.clone()).expect("table"));
    let sink: Arc<dyn ProcessArtifactSink> = files.artifact_store_arc();
    let terminal = TerminalExecutor::new(
        process_config.clone(),
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("terminal")
    .with_artifact_sink(Arc::clone(&sink));
    let process = ProcessExecutor::new(
        process_config,
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("process")
    .with_artifact_sink(sink);

    let terminal_result = terminal.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            "x".repeat(256),
        ],
        ..TerminalRequest::default()
    });
    assert_within_cap(&terminal_result, 800);
    assert!(
        terminal_result.truncated
            || error_code_if_any(&terminal_result) == Some("output_truncated")
    );

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
        process_id,
        timeout_ms: Some(2_000),
        ..ProcessRequest::default()
    });
    assert_within_cap(&waited, 800);
    assert!(waited.truncated || error_code_if_any(&waited) == Some("output_truncated"));
    table.shutdown();
}

fn error_code_if_any(result: &ToolResult) -> Option<&str> {
    result.error.as_ref().map(|error| error.code.as_str())
}

#[test]
fn metadata_only_overflow_fails_closed_with_output_truncated() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("tiny.txt"), "hello\n").expect("write tiny file");
    let mut file_config = fixture.file_config();
    file_config.max_output_bytes = 32;
    file_config.max_read_bytes = 1024;
    file_config.max_search_output_bytes = 32;
    file_config.artifact_store.max_object_bytes = 1024;
    file_config.artifact_store.max_total_bytes = 2048;
    let files = fixture.tools_with_config(file_config);
    let read = files.read_file(ReadFileRequest::new("tiny.txt"));
    assert!(!read.ok, "{read:?}");
    assert_eq!(error_code(&read), "output_truncated");
    assert!(read.truncated);
    assert!(
        encoded_len(&read) < 512,
        "fail-closed envelope should stay compact"
    );

    let mut process_config = fixture.process_config();
    process_config.max_output_bytes = 128;
    let table = Arc::new(ProcessTable::new(process_config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(process_config, table, ProcessOwner::from(tool_owner()))
        .expect("terminal");
    let result = terminal.run(TerminalRequest {
        argv: vec!["/bin/echo".to_string(), "hello-terminal".to_string()],
        ..TerminalRequest::default()
    });
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "output_truncated");
    assert_within_cap(&result, 128);
}

#[test]
fn owner_validation_is_identical_across_tool_artifact_and_process() {
    let too_long = "x".repeat(129);
    let max = "y".repeat(128);
    let cases: &[(&str, &str, &str)] = &[
        ("", "session", "run"),
        ("profile", "", "run"),
        ("profile", "session", ""),
        ("pro\0file", "session", "run"),
        ("profile", "ses\0sion", "run"),
        ("profile", "session", "ru\0n"),
        (too_long.as_str(), "session", "run"),
        ("profile", too_long.as_str(), "run"),
        ("profile", "session", too_long.as_str()),
    ];
    for &(profile, session, run) in cases {
        let tool = ToolOwner::new(profile, session, run);
        let artifact = ArtifactOwner::new(profile, session, run);
        let process = ProcessOwner::new(profile, session, run);
        assert_eq!(tool.as_ref().err(), artifact.as_ref().err());
        assert_eq!(tool.as_ref().err(), process.as_ref().err());
        assert!(
            tool.is_err(),
            "invalid owner {profile:?}/{session:?}/{run:?}"
        );
    }

    let owner = ToolOwner::new(&max, &max, &max).expect("128-byte labels are accepted");
    let artifact = ArtifactOwner::from(owner.clone());
    let process = ProcessOwner::from(owner.clone());
    assert_eq!(artifact.profile(), owner.profile());
    assert_eq!(artifact.session(), owner.session());
    assert_eq!(artifact.run(), owner.run());
    assert_eq!(process.profile_id(), owner.profile());
    assert_eq!(process.session_id(), owner.session());
    assert_eq!(process.run_id(), owner.run());
    assert_eq!(ToolOwner::from(artifact.clone()).profile(), owner.profile());
    assert_eq!(ToolOwner::from(process.clone()).run(), owner.run());
    assert_eq!(ArtifactOwner::from(process), artifact);
}

#[test]
fn workspace_validation_is_shared_across_file_process_and_run_limits() {
    let fixture = Fixture::new();
    let file = FileToolConfig::for_workspace(&fixture.root);
    let process = ProcessToolConfig::for_workspace(&fixture.root);
    file.validate().expect("file workspace");
    process.validate().expect("process workspace");
    RunLimits::new(1, 1, 1024, &fixture.root).expect("run limits workspace");

    assert_eq!(file.max_output_bytes, process.max_output_bytes);
    assert!(file.max_output_bytes <= MAX_TOOL_OUTPUT_BYTES);
    assert!(process.max_output_bytes <= MAX_TOOL_OUTPUT_BYTES);
    assert!(file.max_output_bytes as u64 <= RunLimits::MAX_TOOL_OUTPUT_BYTES);
    assert_eq!(
        MAX_TOOL_OUTPUT_BYTES as u64,
        RunLimits::MAX_TOOL_OUTPUT_BYTES
    );

    let relative = PathBuf::from("relative-workspace");
    let mut invalid_file = file.clone();
    invalid_file.workspace_root = relative.clone();
    let mut invalid_process = process.clone();
    invalid_process.workspace_root = relative;
    let file_err = invalid_file
        .validate()
        .expect_err("relative file workspace");
    let process_err = invalid_process
        .validate()
        .expect_err("relative process workspace");
    assert_eq!(file_err, process_err);
    assert!(RunLimits::new(1, 1, 1024, Path::new("relative-workspace")).is_err());

    let missing = fixture.parent.join("missing-workspace");
    let mut invalid_file = file.clone();
    invalid_file.workspace_root = missing.clone();
    let mut invalid_process = process.clone();
    invalid_process.workspace_root = missing.clone();
    let file_err = invalid_file.validate().expect_err("missing file workspace");
    let process_err = invalid_process
        .validate()
        .expect_err("missing process workspace");
    assert_eq!(file_err, process_err);
    assert!(RunLimits::new(1, 1, 1024, &missing).is_err());

    let mut oversize_file = file;
    oversize_file.max_output_bytes = MAX_TOOL_OUTPUT_BYTES + 1;
    oversize_file.max_search_output_bytes = oversize_file
        .max_search_output_bytes
        .min(oversize_file.max_output_bytes);
    oversize_file.artifact_store.max_object_bytes = MAX_ARTIFACT_OBJECT_BYTES;
    oversize_file.artifact_store.max_total_bytes = MAX_ARTIFACT_TOTAL_BYTES;
    assert!(oversize_file.validate().is_err());
    let mut oversize_process = process;
    oversize_process.max_output_bytes = MAX_TOOL_OUTPUT_BYTES + 1;
    assert!(oversize_process.validate().is_err());
}

#[test]
fn artifact_store_is_process_artifact_sink_and_owner_cleanup_is_scoped() {
    let fixture = Fixture::new();
    let mut file_config = fixture.file_config();
    file_config.max_output_bytes = 2048;
    file_config.max_read_bytes = 4096;
    file_config.max_search_output_bytes = 2048;
    file_config.artifact_store.max_object_bytes = 4096;
    file_config.artifact_store.max_total_bytes = 16_384;
    let files = fixture
        .tools_with_config(file_config)
        .with_owner(ArtifactOwner::from(tool_owner()));
    let store = files.artifact_store_arc();

    let mut process_config = fixture.process_config();
    process_config.max_stream_bytes = 256;
    process_config.max_output_bytes = 800;
    let table = Arc::new(ProcessTable::new(process_config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(
        process_config,
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("terminal")
    .with_artifact_sink(Arc::clone(&store) as Arc<dyn ProcessArtifactSink>);

    let result = terminal.run(TerminalRequest {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            "z".repeat(256),
        ],
        ..TerminalRequest::default()
    });
    assert_within_cap(&result, 800);
    assert!(!result.artifacts.is_empty(), "{result:?}");
    let artifact_id = result.artifacts[0].clone();
    store
        .retrieve(&ArtifactOwner::from(tool_owner()), &artifact_id)
        .expect("owning process can retrieve overflow artifact");
    assert!(
        store
            .retrieve(&ArtifactOwner::from(other_tool_owner()), &artifact_id)
            .is_err(),
        "foreign owner must not retrieve overflow artifact"
    );

    let other = ArtifactOwner::from(other_tool_owner());
    let kept = store.put(&other, b"keep-me").expect("foreign artifact").id;
    let removed = store
        .cleanup_owner(&ArtifactOwner::from(tool_owner()))
        .expect("owner cleanup");
    assert!(removed >= 1);
    assert!(
        store
            .retrieve(&ArtifactOwner::from(tool_owner()), &artifact_id)
            .is_err()
    );
    store
        .retrieve(&other, &kept)
        .expect("TTL-unrelated foreign artifact remains after owner cleanup");
    table.shutdown();
}

#[test]
fn shared_cancellation_and_deadline_stop_file_search_terminal_and_process() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("hit.txt"), "needle\n").expect("write search fixture");
    let files = fixture.tools();
    let cancelled = CancellationToken::new();
    cancelled.cancel();

    let search = files.search_files_with_controls(
        SearchFilesRequest::new("needle"),
        &cancelled,
        far_deadline(),
    );
    assert!(!search.ok, "{search:?}");
    assert_eq!(error_code(&search), "cancelled");

    let write = files.write_file_with_controls("new.txt", "payload\n", &cancelled, far_deadline());
    assert!(!write.ok, "{write:?}");
    assert_eq!(error_code(&write), "cancelled");
    assert!(!fixture.root.join("new.txt").exists());

    let read =
        files.read_file_with_controls(ReadFileRequest::new("hit.txt"), &cancelled, far_deadline());
    assert!(!read.ok, "{read:?}");
    assert_eq!(error_code(&read), "cancelled");

    let elapsed = Instant::now();
    let deadline = files.search_files_with_controls(
        SearchFilesRequest::new("needle"),
        &CancellationToken::new(),
        elapsed,
    );
    assert!(!deadline.ok, "{deadline:?}");
    assert_eq!(error_code(&deadline), "deadline_elapsed");

    let process_config = fixture.process_config();
    let table = Arc::new(ProcessTable::new(process_config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(
        process_config.clone(),
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("terminal");
    let process = ProcessExecutor::new(
        process_config,
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("process");

    let terminal_cancelled = terminal.run_with_controls(
        TerminalRequest {
            argv: vec!["/bin/echo".to_string(), "should-not-run".to_string()],
            ..TerminalRequest::default()
        },
        &cancelled,
        far_deadline(),
    );
    assert!(!terminal_cancelled.ok, "{terminal_cancelled:?}");
    assert_eq!(error_code(&terminal_cancelled), "cancelled");

    let terminal_deadline = terminal.run_with_controls(
        TerminalRequest {
            argv: vec!["/bin/echo".to_string(), "should-not-run".to_string()],
            ..TerminalRequest::default()
        },
        &CancellationToken::new(),
        Instant::now(),
    );
    assert!(!terminal_deadline.ok, "{terminal_deadline:?}");
    assert_eq!(error_code(&terminal_deadline), "deadline_elapsed");

    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let waited = process.run_with_controls(
        ProcessRequest {
            action: ProcessAction::Wait,
            process_id,
            timeout_ms: Some(5_000),
            ..ProcessRequest::default()
        },
        &cancelled,
        far_deadline(),
    );
    assert!(!waited.ok, "{waited:?}");
    assert_eq!(error_code(&waited), "cancelled");
    table
        .cleanup_owner(&ProcessOwner::from(tool_owner()))
        .expect("cleanup");
}

#[test]
fn json_terminal_execute_honors_caller_deadline_instead_of_hard_coded_none() {
    let fixture = Fixture::new();
    let process_config = fixture.process_config();
    let table = Arc::new(ProcessTable::new(process_config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(process_config, table, ProcessOwner::from(tool_owner()))
        .expect("terminal");
    let result = terminal.execute_with_controls(
        &json!({
            "argv": ["/bin/echo", "from-json"]
        }),
        &CancellationToken::new(),
        Instant::now(),
    );
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "deadline_elapsed");
}

#[test]
fn no_controls_wrappers_keep_default_timeout_from_clamping_request_timeouts() {
    let fixture = Fixture::new();
    let mut process_config = fixture.process_config();
    process_config.default_timeout = Duration::from_millis(40);
    process_config.max_timeout = Duration::from_millis(400);
    let table = Arc::new(ProcessTable::new(process_config.clone()).expect("table"));
    let terminal = TerminalExecutor::new(
        process_config.clone(),
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("terminal");
    let process = ProcessExecutor::new(
        process_config,
        Arc::clone(&table),
        ProcessOwner::from(tool_owner()),
    )
    .expect("process");

    let run = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "0.12".to_string()],
        timeout_ms: Some(300),
        ..TerminalRequest::default()
    });
    assert!(run.ok, "{run:?}");

    let execute = terminal.execute(&json!({
        "argv": ["/bin/sleep", "0.12"],
        "timeout_ms": 300
    }));
    assert!(execute.ok, "{execute:?}");

    let started = Instant::now();
    let omitted = terminal.execute(&json!({
        "argv": ["/bin/sleep", "1"]
    }));
    assert!(!omitted.ok, "{omitted:?}");
    assert_eq!(error_code(&omitted), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_millis(300));

    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "0.12".to_string()],
        background: true,
        timeout_ms: Some(300),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let waited = process.execute(&json!({
        "action": "wait",
        "process_id": process_id,
        "timeout_ms": 300
    }));
    assert!(waited.ok, "{waited:?}");
    assert_eq!(waited.data["status"], "exited");

    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "1".to_string()],
        background: true,
        timeout_ms: Some(300),
        ..TerminalRequest::default()
    });
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();
    let started = Instant::now();
    let clamped = process.execute_with_controls(
        &json!({
            "action": "wait",
            "process_id": process_id,
            "timeout_ms": 300
        }),
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(20),
    );
    assert!(!clamped.ok, "{clamped:?}");
    assert_eq!(error_code(&clamped), "deadline_elapsed");
    assert!(started.elapsed() < Duration::from_millis(200));
    table
        .cleanup_owner(&ProcessOwner::from(tool_owner()))
        .expect("cleanup");
}

#[test]
fn owner_cleanup_and_retrieve_race_without_sleep() {
    let fixture = Fixture::new();
    let store = ArtifactStore::with_config(fixture.file_config().artifact_store).expect("store");
    let owner = ArtifactOwner::from(tool_owner());
    let id = store.put(&owner, b"race-payload").expect("put").id;
    let barrier = Arc::new(Barrier::new(2));
    let store = Arc::new(store);

    let cleanup_store = Arc::clone(&store);
    let cleanup_owner = owner.clone();
    let cleanup_barrier = Arc::clone(&barrier);
    let cleanup = std::thread::spawn(move || {
        cleanup_barrier.wait();
        cleanup_store.cleanup_owner(&cleanup_owner)
    });

    let retrieve_store = Arc::clone(&store);
    let retrieve_owner = owner;
    let retrieve_id = id;
    let retrieve_barrier = barrier;
    let retrieve = std::thread::spawn(move || {
        retrieve_barrier.wait();
        retrieve_store.retrieve(&retrieve_owner, &retrieve_id)
    });

    cleanup.join().expect("cleanup thread").expect("cleanup");
    let _ = retrieve.join().expect("retrieve thread");
}

#[test]
fn file_execute_with_controls_rejects_cancelled_patch_before_effect() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("patch.txt"), "old\n").expect("write patch fixture");
    let files = fixture.tools();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let result = files.execute_with_controls(
        &NativeToolExecutor::Patch,
        &json!({
            "path": "patch.txt",
            "old_string": "old",
            "new_string": "new"
        }),
        &cancelled,
        far_deadline(),
    );
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "cancelled");
    assert_eq!(
        fs::read_to_string(fixture.root.join("patch.txt")).expect("read patch fixture"),
        "old\n"
    );
}
