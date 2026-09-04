//! Generic confined filesystem, process, and artifact capabilities.
//!
//! These tests drive native primitives that later RSS tools will consume.
//! Capability code must not know model-visible tool names.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner,
    capabilities::{
        ApprovalGate, ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityError,
        CapabilityLifecycle, CapabilityOwner, CapabilityRisk, DurableStarted, DurableToolLifecycle,
        FilesystemCapability, FilesystemLimits, LifecycleClock, LifecycleError, LifecycleLimits,
        NeverCancelled, PrepareMetadata, PrepareOutcome, ProcessCapability, ProcessLimits,
        SystemClock, TokenIssuer,
    },
};
use rustscript_vm::{HostTypeSchema, Value as VmValue};
use serde_json::{Value, json};

struct ScriptedClock {
    now_ms: Mutex<u64>,
    instant: Mutex<Instant>,
}

impl ScriptedClock {
    fn new(now_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            now_ms: Mutex::new(now_ms),
            instant: Mutex::new(Instant::now()),
        })
    }

    fn set_now_ms(&self, now_ms: u64) {
        *self.now_ms.lock().expect("clock ms") = now_ms;
    }
}

impl LifecycleClock for ScriptedClock {
    fn now_ms(&self) -> u64 {
        *self.now_ms.lock().expect("clock ms")
    }

    fn now(&self) -> Instant {
        *self.instant.lock().expect("clock instant")
    }
}

struct SequenceIssuer {
    next: Mutex<u64>,
}

impl SequenceIssuer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: Mutex::new(1),
        })
    }
}

impl TokenIssuer for SequenceIssuer {
    fn issue(&self) -> String {
        let mut next = self.next.lock().expect("issuer");
        let id = *next;
        *next += 1;
        format!("tok-{id}")
    }
}

struct MemoryDurable {
    active: Mutex<bool>,
    results: Mutex<HashMap<String, Value>>,
}

impl MemoryDurable {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(true),
            results: Mutex::new(HashMap::new()),
        })
    }
}

impl DurableToolLifecycle for MemoryDurable {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        if *self.active.lock().expect("active") {
            Ok(())
        } else {
            Err(LifecycleError::InactiveRun)
        }
    }

    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        Ok(())
    }

    fn replay_result(
        &self,
        _run_id: &str,
        call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(self.results.lock().expect("results").get(call_id).cloned())
    }

    fn commit_started(&self, _record: &DurableStarted) -> Result<(), LifecycleError> {
        Ok(())
    }

    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
        self.results
            .lock()
            .expect("results")
            .insert(call_id.to_string(), result.clone());
        Ok(result.clone())
    }

    fn interrupt(&self, _call_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct AllowAll;

impl ApprovalGate for AllowAll {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Ok(metadata.risk_class)
    }
}

struct FlagCancel {
    cancelled: AtomicBool,
}

impl FlagCancel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
        })
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl CancellationFlag for FlagCancel {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

struct Fixture {
    root: PathBuf,
    lifecycle: CapabilityLifecycle,
    owner: CapabilityOwner,
    clock: Arc<ScriptedClock>,
    cancel: Arc<FlagCancel>,
    next_call: AtomicU64,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn tmp_root(label: &str) -> PathBuf {
    let unique = format!(
        "cap-{}-{}-{}",
        label.replace('/', "-"),
        std::process::id(),
        NEXT_CAP_TMP.fetch_add(1, Ordering::Relaxed)
    );
    let root = std::env::temp_dir().join(unique);
    fs::create_dir_all(&root).expect("create workspace");
    root
}

static NEXT_CAP_TMP: AtomicU64 = AtomicU64::new(0);

fn owner() -> CapabilityOwner {
    CapabilityOwner::new("profile-a", "session-a", "run-a").expect("owner")
}

fn metadata(call_id: &str, risk: CapabilityRisk) -> PrepareMetadata {
    PrepareMetadata {
        run_id: "run-a".to_string(),
        call_id: call_id.to_string(),
        tool_name: "fixture_capability".to_string(),
        argument_digest: "digest-a".to_string(),
        registry_identity: "registry-a".to_string(),
        risk_class: risk,
        summary: "capability fixture".to_string(),
    }
}

fn token_of(outcome: PrepareOutcome) -> String {
    match outcome {
        PrepareOutcome::Execute {
            execution_token, ..
        } => execution_token,
        other => panic!("expected execute token, got {other:?}"),
    }
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = tmp_root(label);
        let owner = owner();
        let clock = ScriptedClock::new(1_000);
        let cancel = FlagCancel::new();
        let lifecycle = CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity("registry-a")
            .workspace(&root)
            .limits(LifecycleLimits {
                max_tool_calls: 32,
                max_output_bytes: 64 * 1024,
                max_summary_bytes: 256,
            })
            .deadline_ms(60_000)
            .clock(Arc::clone(&clock) as Arc<dyn LifecycleClock>)
            .tokens(SequenceIssuer::new() as Arc<dyn TokenIssuer>)
            .durable(MemoryDurable::new() as Arc<dyn DurableToolLifecycle>)
            .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
            .cancellation(Arc::clone(&cancel) as Arc<dyn CancellationFlag>)
            .generation(1)
            .build()
            .expect("lifecycle");
        Self {
            root,
            lifecycle,
            owner,
            clock,
            cancel,
            next_call: AtomicU64::new(1),
        }
    }

    fn token(&self, risk: CapabilityRisk) -> String {
        let call = self.next_call.fetch_add(1, Ordering::SeqCst);
        token_of(
            self.lifecycle
                .prepare(&self.owner, metadata(&format!("call-{call}"), risk))
                .expect("prepare"),
        )
    }

    fn filesystem(&self) -> FilesystemCapability {
        FilesystemCapability::new(
            self.lifecycle.clone(),
            self.owner.clone(),
            FilesystemLimits {
                max_read_bytes: 64,
                max_write_bytes: 64,
                max_list_entries: 4,
            },
        )
        .expect("filesystem")
    }

    fn processes(&self) -> ProcessCapability {
        ProcessCapability::new(
            self.lifecycle.clone(),
            self.owner.clone(),
            ProcessLimits::default(),
        )
        .expect("processes")
    }

    fn processes_with(&self, host_limits: ProcessLimits) -> ProcessCapability {
        ProcessCapability::new(self.lifecycle.clone(), self.owner.clone(), host_limits)
            .expect("processes")
    }

    fn artifacts(&self, limits: ArtifactLimits) -> ArtifactCapability {
        ArtifactCapability::new(self.lifecycle.clone(), self.owner.clone(), limits)
            .expect("artifacts")
    }
}

fn error_code(error: &CapabilityError) -> &str {
    error.code()
}

fn run_cap_source(
    fixture: &Fixture,
    filesystem: Option<Arc<FilesystemCapability>>,
    processes: Option<Arc<ProcessCapability>>,
    artifacts: Option<Arc<ArtifactCapability>>,
    source: &str,
) -> VmValue {
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(fixture.lifecycle.clone())),
        capability_owner: Some(fixture.owner.clone()),
        filesystem,
        processes,
        artifacts,
        ..AgentHostBridges::default()
    };
    AgentRunner::from_source(source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run")
}

fn envelope_error_code(value: &VmValue) -> String {
    let VmValue::Map(fields) = value else {
        panic!("expected map envelope, got {value:?}");
    };
    assert_eq!(
        fields.get(&VmValue::string("ok")),
        Some(&VmValue::Bool(false)),
        "expected typed failure, got {value:?}"
    );
    let Some(VmValue::Map(error)) = fields.get(&VmValue::string("error")) else {
        panic!("expected error map, got {value:?}");
    };
    match error.get(&VmValue::string("code")) {
        Some(VmValue::String(code)) => code.to_string(),
        other => panic!("expected error code string, got {other:?}"),
    }
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn wait_until_pid_gone(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    !pid_alive(pid)
}

#[test]
fn forged_and_cross_owner_tokens_are_rejected_before_fs_effect() {
    let fixture = Fixture::new("forged");
    fs::write(fixture.root.join("secret.txt"), b"keep").expect("write");
    let fs_cap = fixture.filesystem();
    let error = fs_cap
        .metadata("forged-token", "secret.txt")
        .expect_err("forged token");
    assert_eq!(error_code(&error), "token_unknown");
    assert!(
        !error
            .message()
            .contains(fixture.root.to_string_lossy().as_ref())
    );

    let other = CapabilityOwner::new("profile-b", "session-b", "run-b").expect("other");
    let other_lifecycle = CapabilityLifecycle::builder()
        .owner(other.clone())
        .registry_identity("registry-a")
        .workspace(&fixture.root)
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(60_000)
        .clock(ScriptedClock::new(1_000) as Arc<dyn LifecycleClock>)
        .tokens(SequenceIssuer::new() as Arc<dyn TokenIssuer>)
        .durable(MemoryDurable::new() as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("other lifecycle");
    let foreign = token_of(
        other_lifecycle
            .prepare(&other, {
                let mut meta = metadata("call-x", CapabilityRisk::Read);
                meta.run_id = "run-b".to_string();
                meta
            })
            .expect("foreign prepare"),
    );
    let error = fs_cap
        .metadata(&foreign, "secret.txt")
        .expect_err("cross-owner token");
    assert!(
        error_code(&error) == "owner_mismatch" || error_code(&error) == "token_unknown",
        "unexpected {}",
        error_code(&error)
    );
}

#[test]
fn read_token_cannot_escalate_to_write() {
    let fixture = Fixture::new("escalate");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let error = fs_cap
        .write_atomic(&token, "out.txt", "", b"hello")
        .expect_err("read token must not write");
    assert_eq!(error_code(&error), "approval_ceiling");
    assert!(!fixture.root.join("out.txt").exists());
}

#[test]
fn traversal_and_symlink_escape_are_denied() {
    let fixture = Fixture::new("escape");
    let outside = fixture
        .root
        .parent()
        .unwrap()
        .join(format!("outside-secret-{}", std::process::id()));
    fs::write(&outside, b"outside-secret").expect("outside");
    fs::create_dir(fixture.root.join("nested")).expect("nested");
    std::os::unix::fs::symlink(&outside, fixture.root.join("link.txt")).expect("file symlink");
    std::os::unix::fs::symlink(
        outside.parent().unwrap(),
        fixture.root.join("nested/outside-dir"),
    )
    .expect("dir symlink");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    for path in [
        "../outside.txt",
        "/tmp/outside.txt",
        "nested/../../outside.txt",
        "link.txt",
        "nested/outside-dir",
    ] {
        let error = fs_cap.metadata(&token, path).expect_err("escape must fail");
        assert_eq!(error_code(&error), "path_denied", "path {path}");
        assert!(!error.message().contains("outside-secret"));
        assert!(!error.message().contains(outside.to_string_lossy().as_ref()));
        let error = fs_cap
            .read_range(&token, path, 0, 16)
            .expect_err("read escape must fail");
        assert_eq!(error_code(&error), "path_denied", "read {path}");
    }
    let _ = fs::remove_file(&outside);
}

#[test]
fn read_write_and_list_respect_explicit_bounds() {
    let fixture = Fixture::new("bounds");
    fs::write(fixture.root.join("big.txt"), vec![b'a'; 80]).expect("big");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    for name in ["a", "b", "c"] {
        fs::write(fixture.root.join("dir").join(name), name.as_bytes()).expect("entry");
    }
    let fs_cap = fixture.filesystem();
    let read_token = fixture.token(CapabilityRisk::Read);
    let error = fs_cap
        .read_range(&read_token, "big.txt", 0, 128)
        .expect_err("oversize read");
    assert_eq!(error_code(&error), "budget_exceeded");

    let window = fs_cap
        .read_range(&read_token, "big.txt", 10, 8)
        .expect("windowed read");
    assert_eq!(window.bytes, b"aaaaaaaa");
    assert_eq!(window.offset, 10);
    assert!(window.truncated);

    let listed = fs_cap.list(&read_token, "dir", 0, 2).expect("list");
    assert_eq!(listed.entries.len(), 2);
    assert!(listed.truncated);
    assert_eq!(listed.next_cursor, 2);

    let write_token = fixture.token(CapabilityRisk::Write);
    let error = fs_cap
        .write_atomic(&write_token, "too-big.txt", "", &[b'x'; 80])
        .expect_err("oversize write");
    assert_eq!(error_code(&error), "budget_exceeded");
    assert!(!fixture.root.join("too-big.txt").exists());
}

#[test]
fn atomic_write_rejects_cas_mismatch_and_symlink_race() {
    let fixture = Fixture::new("cas");
    fs::write(fixture.root.join("target.txt"), b"old").expect("seed");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Write);
    let error = fs_cap
        .write_atomic(&token, "target.txt", "sha256:deadbeef", b"new")
        .expect_err("bad hash");
    assert_eq!(error_code(&error), "cas_mismatch");
    assert_eq!(
        fs::read(fixture.root.join("target.txt")).expect("unchanged"),
        b"old"
    );

    let current = fs_cap
        .read_range(&fixture.token(CapabilityRisk::Read), "target.txt", 0, 64)
        .expect("read current");
    let ok = fs_cap
        .write_atomic(&token, "target.txt", &current.hash.expect("hash"), b"new")
        .expect("cas write");
    assert_eq!(ok.len, 3);
    assert_eq!(
        fs::read(fixture.root.join("target.txt")).expect("replaced"),
        b"new"
    );

    let outside = fixture
        .root
        .parent()
        .unwrap()
        .join(format!("cas-outside-{}", std::process::id()));
    fs::write(&outside, b"outside").expect("outside");
    std::os::unix::fs::symlink(&outside, fixture.root.join("racy.txt")).expect("symlink");
    let error = fs_cap
        .write_atomic(&token, "racy.txt", "", b"replacement")
        .expect_err("symlink race");
    assert_eq!(error_code(&error), "path_denied");
    assert_eq!(fs::read(&outside).expect("outside intact"), b"outside");
    let _ = fs::remove_file(&outside);
}

#[test]
fn atomic_write_unconditional_sentinel_overwrites_and_reports_publication() {
    let fixture = Fixture::new("uncond");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Write);
    let created = fs_cap
        .write_atomic(&token, "fresh.txt", "*", b"hello")
        .expect("create");
    assert_eq!(created.len, 5);
    assert!(created.durable);
    assert!(created.staging_cleaned);
    assert_eq!(
        fs::read(fixture.root.join("fresh.txt")).expect("created"),
        b"hello"
    );

    fs::write(fixture.root.join("target.txt"), b"old").expect("seed");
    let replaced = fs_cap
        .write_atomic(&token, "target.txt", "*", b"new!")
        .expect("overwrite");
    assert_eq!(replaced.len, 4);
    assert!(replaced.durable);
    assert!(replaced.staging_cleaned);
    assert_eq!(
        fs::read(fixture.root.join("target.txt")).expect("replaced"),
        b"new!"
    );
}

#[test]
fn process_spawn_is_isolated_by_owner_and_rejects_forged_handles() {
    let fixture = Fixture::new("proc-own");
    let processes = fixture.processes();
    let token = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &token,
            &["/bin/echo".to_string(), "hello-cap".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 2_000,
                stdout_limit: 64,
                stderr_limit: 64,
                total_limit: 64,
                ..ProcessLimits::default()
            },
        )
        .expect("spawn");
    let polled = processes
        .wait(&token, &spawned.handle, Some(2_000))
        .expect("wait");
    assert!(polled.stdout.contains("hello-cap") || polled.exit_code == Some(0));

    let error = processes
        .poll(&token, "forged-handle", 0, 16)
        .expect_err("forged handle");
    assert_eq!(error_code(&error), "process_not_found");

    let other = Fixture::new("proc-other");
    let other_token = other.token(CapabilityRisk::Execute);
    let error = other
        .processes()
        .poll(&other_token, &spawned.handle, 0, 16)
        .expect_err("cross-owner handle");
    assert!(
        error_code(&error) == "process_not_found" || error_code(&error) == "owner_mismatch",
        "{}",
        error_code(&error)
    );
}

#[test]
fn process_deadline_and_cancel_apply_before_and_during_execution() {
    let fixture = Fixture::new("proc-ctrl");
    let processes = fixture.processes();
    let token = fixture.token(CapabilityRisk::Execute);
    fixture.clock.set_now_ms(60_000);
    let error = processes
        .spawn(
            &token,
            &["/bin/sleep".to_string(), "30".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 30_000,
                stdout_limit: 32,
                stderr_limit: 32,
                total_limit: 32,
                ..ProcessLimits::default()
            },
        )
        .expect_err("deadline before spawn");
    assert_eq!(error_code(&error), "deadline_elapsed");

    fixture.clock.set_now_ms(1_000);
    let live = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &live,
            &["/bin/sleep".to_string(), "30".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 30_000,
                stdout_limit: 32,
                stderr_limit: 32,
                total_limit: 32,
                ..ProcessLimits::default()
            },
        )
        .expect("spawn sleep");
    let pid = spawned.pid;
    fixture.cancel.cancel();
    let error = processes
        .wait(&live, &spawned.handle, Some(2_000))
        .expect_err("cancelled during wait");
    assert_eq!(error_code(&error), "cancelled");
    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(2)),
        "run cancellation left pid {pid} alive"
    );
}

#[test]
fn process_output_is_truncated_and_handles_clean_up_on_drop() {
    let fixture = Fixture::new("proc-out");
    let processes = fixture.processes();
    let token = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &token,
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf '%200s' | tr ' ' x".to_string(),
            ],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 2_000,
                stdout_limit: 16,
                stderr_limit: 16,
                total_limit: 16,
                ..ProcessLimits::default()
            },
        )
        .expect("spawn oversized output");
    let snapshot = processes
        .wait(&token, &spawned.handle, Some(2_000))
        .expect("wait oversized output");
    assert!(snapshot.truncated);
    assert!(snapshot.stdout.len() <= 16);

    let live = processes
        .spawn(
            &token,
            &["/bin/sleep".to_string(), "30".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 30_000,
                stdout_limit: 8,
                stderr_limit: 8,
                total_limit: 8,
                ..ProcessLimits::default()
            },
        )
        .expect("spawn live");
    let pid = live.pid;
    drop(processes);
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if fs::read_to_string(format!("/proc/{pid}/status")).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("dropped process capability left pid {pid} alive");
}

#[test]
fn process_list_spawn_stdin_and_log_cursors_are_owner_scoped() {
    let fixture = Fixture::new("proc-list");
    let processes = fixture.processes();
    let token = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &token,
            &["/bin/cat".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 2_000,
                stdout_limit: 64,
                stderr_limit: 64,
                total_limit: 64,
                stdin_limit: 64,
                log_limit: 64,
            },
        )
        .expect("spawn");
    let listed = processes.list(&token).expect("list");
    assert_eq!(listed, vec![spawned.handle.clone()]);
    let wrote = processes
        .write_stdin(&token, &spawned.handle, b"hello-cursor\n")
        .expect("write");
    assert_eq!(wrote, 13);
    processes
        .close_stdin(&token, &spawned.handle)
        .expect("close");
    let snapshot = processes
        .wait(&token, &spawned.handle, Some(2_000))
        .expect("wait");
    assert!(snapshot.stdout.contains("hello-cursor"));
    assert_eq!(snapshot.stdout_cursor.offset, 0);
    assert!(snapshot.stdout_cursor.next_offset > 0);
    assert!(snapshot.stdout_cursor.eof);
    let log = processes.log(&token, &spawned.handle, 0, 64).expect("log");
    assert_eq!(log.stdout_cursor.offset, 0);
    processes.kill(&token, &spawned.handle).expect("kill");
}

#[test]
fn dropping_execution_lease_reaps_token_owned_process() {
    let fixture = Fixture::new("lease-reap");
    let processes = fixture.processes();
    let token = fixture.token(CapabilityRisk::Execute);
    let lease = fixture.lifecycle.lease(&token).expect("lease");
    let spawned = processes
        .spawn(
            &token,
            &["/bin/sleep".to_string(), "30".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 30_000,
                stdout_limit: 8,
                stderr_limit: 8,
                total_limit: 8,
                ..ProcessLimits::default()
            },
        )
        .expect("spawn");
    let pid = spawned.pid;
    assert!(pid_alive(pid));
    drop(lease);
    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(2)),
        "dropping the execution lease left pid {pid} alive"
    );
}

#[test]
fn artifact_put_get_and_reference_enforce_quota_and_ownership() {
    let fixture = Fixture::new("arts");
    let artifacts = fixture.artifacts(ArtifactLimits {
        max_object_bytes: 16,
        max_total_bytes: 24,
        max_objects: 2,
    });
    let write = fixture.token(CapabilityRisk::Write);
    let first = artifacts
        .put(&write, b"one", &json!({"kind": "log"}))
        .expect("put one");
    let got = artifacts
        .get(&fixture.token(CapabilityRisk::Read), &first.id)
        .expect("get");
    assert_eq!(got, b"one");
    let referred = artifacts
        .reference(&fixture.token(CapabilityRisk::Read), &first.id)
        .expect("reference");
    assert_eq!(referred.id, first.id);
    assert_eq!(referred.len, 3);

    let error = artifacts
        .put(&write, &[b'z'; 32], &json!({}))
        .expect_err("object quota");
    assert_eq!(error_code(&error), "artifact_too_large");

    artifacts
        .put(&write, b"two-bytes!!", &json!({}))
        .expect("put two");
    let error = artifacts
        .put(&write, b"three", &json!({}))
        .expect_err("store quota");
    assert!(
        error_code(&error) == "artifact_store_exhausted" || error_code(&error) == "artifact_quota",
        "{}",
        error_code(&error)
    );

    let other = Fixture::new("arts-other");
    let error = other
        .artifacts(ArtifactLimits {
            max_object_bytes: 16,
            max_total_bytes: 24,
            max_objects: 2,
        })
        .get(&other.token(CapabilityRisk::Read), &first.id)
        .expect_err("cross-owner artifact");
    assert!(
        error_code(&error) == "artifact_not_found" || error_code(&error) == "owner_mismatch",
        "{}",
        error_code(&error)
    );
}

#[test]
fn read_token_cannot_put_generic_artifact_but_can_publish_one_result() {
    let fixture = Fixture::new("result-pub");
    let artifacts = fixture.artifacts(ArtifactLimits {
        max_object_bytes: 16,
        max_total_bytes: 32,
        max_objects: 2,
    });
    let read = fixture.token(CapabilityRisk::Read);
    let denied = artifacts
        .put(&read, b"nope", &json!({}))
        .expect_err("read token must not use generic put");
    assert_eq!(error_code(&denied), "approval_ceiling");

    let malformed = artifacts
        .put_result(&read, b"ok", &json!("not-an-object"))
        .expect_err("non-object metadata");
    assert_eq!(error_code(&malformed), "invalid_request");

    let unknown = artifacts
        .put_result(&read, b"ok", &json!({"purpose": "result"}))
        .expect_err("unknown metadata field");
    assert_eq!(error_code(&unknown), "invalid_request");

    let mismatched = artifacts
        .put_result(&read, b"ok", &json!({"call_id": "other-call"}))
        .expect_err("mismatched call_id");
    assert_eq!(error_code(&mismatched), "invalid_request");

    let published = artifacts
        .put_result(&read, b"payload", &json!({}))
        .expect("valid result publication");
    assert_eq!(published.len, 7);
    assert_eq!(published.metadata["run"], json!("run-a"));
    assert_eq!(published.metadata["call_id"], json!("call-1"));

    let second = artifacts
        .put_result(&read, b"again", &json!({}))
        .expect_err("second result");
    assert_eq!(error_code(&second), "artifact_already_published");

    let quota = fixture.artifacts(ArtifactLimits {
        max_object_bytes: 4,
        max_total_bytes: 4,
        max_objects: 1,
    });
    let read2 = fixture.token(CapabilityRisk::Read);
    let exhausted = quota
        .put_result(&read2, b"too-big", &json!({}))
        .expect_err("quota");
    assert_eq!(error_code(&exhausted), "artifact_too_large");
}

#[test]
fn clock_monotonic_ms_requires_read_token_and_cannot_be_forged() {
    let fixture = Fixture::new("clock");
    fixture.clock.set_now_ms(4_000);
    let read = fixture.token(CapabilityRisk::Read);
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(fixture.lifecycle.clone())),
        capability_owner: Some(fixture.owner.clone()),
        filesystem: Some(Arc::new(fixture.filesystem())),
        ..AgentHostBridges::default()
    };
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::clock_monotonic_ms("{read}")
        }}
    "#
    );
    let result = AgentRunner::from_source(&source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    let json = match result {
        VmValue::Map(fields) => fields,
        other => panic!("expected map, got {other:?}"),
    };
    match json.get(&VmValue::string("ms")) {
        Some(VmValue::Int(ms)) => assert_eq!(*ms, 4_000),
        other => panic!("expected host clock ms, got {other:?}"),
    }

    let forged = r#"
        pub fn run(input: map) -> map {
            cap::clock_monotonic_ms("forged-token")
        }
    "#;
    let denied = run_cap_source(&fixture, None, None, None, forged);
    assert_ne!(envelope_error_code(&denied), "");
}

#[test]
fn host_catalog_registers_cap_functions_with_typed_bounds() {
    let catalog = rustscript_agent::agent_host_catalog();
    let names: Vec<&str> = catalog
        .functions()
        .iter()
        .map(|schema| schema.name.as_str())
        .collect();
    for required in [
        "cap::fs_metadata",
        "cap::fs_read_range",
        "cap::fs_list",
        "cap::fs_write_atomic",
        "cap::process_spawn",
        "cap::process_poll",
        "cap::process_wait",
        "cap::process_log",
        "cap::process_write",
        "cap::process_close",
        "cap::process_kill",
        "cap::artifact_put",
        "cap::artifact_put_result",
        "cap::artifact_get",
        "cap::artifact_reference",
        "cap::clock_monotonic_ms",
        "agent::tool_dispatch",
    ] {
        assert!(
            names.contains(&required),
            "missing host function {required}; have {names:?}"
        );
    }
    let metadata = catalog
        .functions()
        .iter()
        .find(|schema| schema.name == "cap::fs_metadata")
        .expect("fs_metadata schema");
    assert_eq!(metadata.params.len(), 2);
    assert!(matches!(metadata.params[0].ty, HostTypeSchema::String));
    assert!(matches!(metadata.return_type, HostTypeSchema::Map(_)));
}

#[test]
fn host_cap_envelope_rejects_invalid_types_without_host_paths() {
    let fixture = Fixture::new("host-env");
    fs::write(fixture.root.join("ok.txt"), b"hello").expect("seed");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(fixture.lifecycle.clone())),
        capability_owner: Some(fixture.owner.clone()),
        filesystem: Some(Arc::new(fs_cap)),
        processes: Some(Arc::new(fixture.processes())),
        artifacts: Some(Arc::new(fixture.artifacts(ArtifactLimits {
            max_object_bytes: 32,
            max_total_bytes: 64,
            max_objects: 4,
        }))),
        ..AgentHostBridges::default()
    };
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::fs_metadata("{token}", "../escape")
        }}
    "#
    );
    let result = AgentRunner::from_source(&source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]));
    match result {
        Ok(VmValue::Map(fields)) => {
            let ok = fields.get(&VmValue::string("ok")).expect("ok");
            assert_eq!(ok, &VmValue::Bool(false));
            let error = fields.get(&VmValue::string("error")).expect("error");
            let VmValue::Map(error) = error else {
                panic!("expected error map");
            };
            let message = error
                .get(&VmValue::string("message"))
                .and_then(|value| match value {
                    VmValue::String(text) => Some(text.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            assert!(!message.contains(fixture.root.to_string_lossy().as_ref()));
        }
        Ok(other) => panic!("expected map envelope, got {other:?}"),
        Err(error) => panic!("expected envelope, got run error {error}"),
    }
}

#[test]
fn committed_token_is_rejected_by_cap_primitives() {
    let fixture = Fixture::new("committed");
    fs::write(fixture.root.join("secret.txt"), b"keep").expect("seed");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    fixture
        .lifecycle
        .commit(
            &fixture.owner,
            &token,
            json!({"ok": true, "content": "done"}),
        )
        .expect("commit");
    let error = fs_cap
        .read_range(&token, "secret.txt", 0, 4)
        .expect_err("committed");
    assert_eq!(error_code(&error), "duplicate_close");
}

#[test]
fn generation_after_recover_rejects_old_process_handles_and_kills_pid() {
    let fixture = Fixture::new("recover-gen");
    let processes = fixture.processes();
    let token = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &token,
            &["/bin/sleep".to_string(), "30".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 30_000,
                stdout_limit: 8,
                stderr_limit: 8,
                total_limit: 8,
                ..ProcessLimits::default()
            },
        )
        .expect("spawn");
    assert!(pid_alive(spawned.pid));
    let recovered = fixture.lifecycle.recover_open_tokens().expect("recover");
    assert_eq!(recovered.len(), 1);
    let error = processes
        .wait(&token, &spawned.handle, Some(1_000))
        .expect_err("interrupted");
    assert_eq!(error_code(&error), "interrupted");
    assert!(wait_until_pid_gone(spawned.pid, Duration::from_secs(2)));
    let fresh = fixture.token(CapabilityRisk::Execute);
    let error = processes
        .poll(&fresh, &spawned.handle, 0, 8)
        .expect_err("stale generation");
    assert_eq!(error_code(&error), "process_not_found");
}

#[test]
fn listing_enumeration_is_bounded_and_overflow_safe() {
    let fixture = Fixture::new("list-bound");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    for name in ["a", "b", "c"] {
        fs::write(fixture.root.join("dir").join(name), name.as_bytes()).expect("entry");
    }
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let listed = fs_cap.list(&token, "dir", 0, 2).expect("page");
    assert_eq!(listed.entries.len(), 2);
    assert!(listed.truncated);
    let overflow = fs_cap
        .list(&token, "dir", u64::MAX, 2)
        .expect("overflow cursor");
    assert!(overflow.entries.is_empty());
    assert!(!overflow.truncated);
}

#[test]
fn listing_paginates_by_cursor_without_materializing_directory() {
    let fixture = Fixture::new("list-pages");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    let mut expected = Vec::new();
    for index in 0..12 {
        let name = format!("f{index:02}");
        fs::write(fixture.root.join("dir").join(&name), name.as_bytes()).expect("entry");
        expected.push(name);
    }
    expected.sort();
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let mut cursor = 0_u64;
    let mut seen = Vec::new();
    let mut pages = 0_usize;
    loop {
        let page = fs_cap.list(&token, "dir", cursor, 2).expect("bounded page");
        pages += 1;
        assert!(
            page.entries.len() <= 2,
            "page must respect limit=2, got {}",
            page.entries.len()
        );
        assert!(
            pages <= 8,
            "cursor pagination must finish without a global directory dump"
        );
        for entry in &page.entries {
            seen.push(entry.name.clone());
        }
        if !page.truncated {
            break;
        }
        assert_eq!(page.entries.len(), 2);
        assert!(page.next_cursor > cursor);
        cursor = page.next_cursor;
    }
    let mut ordered = seen.clone();
    ordered.sort();
    assert_eq!(ordered, expected);
    assert_eq!(seen.len(), expected.len());
    let overflow = fs_cap
        .list(&token, "dir", u64::MAX, 2)
        .expect("overflow cursor");
    assert!(overflow.entries.is_empty());
    assert!(!overflow.truncated);
    let huge = fs_cap
        .list(&token, "dir", 1 << 40, 2)
        .expect("very large cursor");
    assert!(huge.entries.is_empty());
    assert!(!huge.truncated);
}

#[test]
fn concurrent_cas_writers_serialize_to_one_success() {
    let fixture = Fixture::new("cas-race");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Write);
    fs_cap
        .write_atomic(&token, "race.txt", "", b"seed")
        .expect("create");
    let current = fixture
        .filesystem()
        .read_range(&fixture.token(CapabilityRisk::Read), "race.txt", 0, 64)
        .expect("hash");
    let expected = current.hash.expect("hash");
    let left = fs_cap.clone();
    let right = fs_cap.clone();
    let expected_left = expected.clone();
    let expected_right = expected;
    let token_left = token.clone();
    let token_right = token.clone();
    let first =
        thread::spawn(move || left.write_atomic(&token_left, "race.txt", &expected_left, b"left"));
    let second = thread::spawn(move || {
        right.write_atomic(&token_right, "race.txt", &expected_right, b"right")
    });
    let results = [first.join().expect("left"), second.join().expect("right")];
    let wins = results.iter().filter(|result| result.is_ok()).count();
    let losses = results
        .iter()
        .filter(|result| {
            result
                .as_ref()
                .err()
                .is_some_and(|error| error_code(error) == "cas_mismatch")
        })
        .count();
    assert_eq!(wins, 1);
    assert_eq!(losses, 1);
    let body = fs::read(fixture.root.join("race.txt")).expect("body");
    assert!(body == b"left" || body == b"right");

    let create_left = fs_cap.clone();
    let create_right = fs_cap.clone();
    let token_a = token.clone();
    let token_b = token;
    let first = thread::spawn(move || create_left.write_atomic(&token_a, "absent.txt", "", b"one"));
    let second =
        thread::spawn(move || create_right.write_atomic(&token_b, "absent.txt", "", b"two"));
    let results = [first.join().expect("a"), second.join().expect("b")];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .err()
                .is_some_and(|error| error_code(error) == "cas_mismatch"))
            .count(),
        1
    );
}

#[test]
fn frozen_workspace_root_does_not_follow_replacement_tree() {
    let fixture = Fixture::new("frozen-root");
    fs::write(fixture.root.join("marker.txt"), b"admitted").expect("seed");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let old = fixture.root.with_extension("admitted");
    fs::rename(&fixture.root, &old).expect("rename admitted");
    fs::create_dir(&fixture.root).expect("replacement dir");
    fs::write(fixture.root.join("marker.txt"), b"replacement").expect("replacement");
    let result = fs_cap.read_range(&token, "marker.txt", 0, 16);
    let _ = fs::remove_dir_all(&old);
    match result {
        Ok(read) => assert_eq!(read.bytes, b"admitted"),
        Err(error) => {
            assert_eq!(error_code(&error), "path_denied");
            assert!(!error.message().contains("replacement"));
        }
    }
}

#[test]
fn read_range_permits_window_from_file_larger_than_default_ceiling() {
    let fixture = Fixture::new("large-range");
    let size = 8 * 1024 * 1024 + 32;
    let mut body = vec![0u8; size];
    body[16..24].copy_from_slice(b"windowed");
    fs::write(fixture.root.join("huge.bin"), &body).expect("huge");
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let window = fs_cap
        .read_range(&token, "huge.bin", 16, 8)
        .expect("bounded window");
    assert_eq!(window.bytes, b"windowed");
    assert_eq!(window.offset, 16);
    assert!(window.truncated);
    assert_eq!(window.bytes.len(), 8);
}

#[test]
fn read_range_of_sparse_file_beyond_64mib_stays_bounded() {
    use std::os::unix::fs::FileExt;
    let fixture = Fixture::new("sparse-range");
    let offset = 64 * 1024 * 1024 + 4096;
    let path = fixture.root.join("huge.bin");
    let file = fs::File::create(&path).expect("create sparse");
    file.set_len(offset + 16).expect("sparse size");
    file.write_at(b"windowed", offset)
        .expect("poke high offset");
    drop(file);
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let window = fs_cap
        .read_range(&token, "huge.bin", offset, 8)
        .expect("bounded high-offset window");
    assert_eq!(window.bytes, b"windowed");
    assert_eq!(window.offset, offset);
    assert!(window.truncated);
    let hash = window.hash.expect("range identity");
    assert!(
        hash.starts_with("range:"),
        "range read must use a range/version identity, got {hash}"
    );
    assert!(
        !hash.starts_with("sha256:"),
        "must not label a bounded window as a whole-file hash: {hash}"
    );
}

#[test]
fn host_process_ceilings_clamp_caller_timeout() {
    let fixture = Fixture::new("host-ceil");
    let processes = fixture.processes_with(ProcessLimits {
        timeout_ms: 80,
        stdout_limit: 32,
        stderr_limit: 32,
        total_limit: 32,
        stdin_limit: 8,
        log_limit: 16,
    });
    let token = fixture.token(CapabilityRisk::Execute);
    let started = Instant::now();
    let spawned = processes
        .spawn(
            &token,
            &["/bin/sleep".to_string(), "5".to_string()],
            "",
            &[],
            ProcessLimits {
                timeout_ms: 30_000,
                stdout_limit: 64 * 1024,
                stderr_limit: 64 * 1024,
                total_limit: 64 * 1024,
                stdin_limit: 64 * 1024,
                log_limit: 64 * 1024,
            },
        )
        .expect("spawn");
    let snapshot = processes
        .wait(&token, &spawned.handle, Some(5_000))
        .expect("wait");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!snapshot.running);
    let error = processes
        .write_stdin(&token, &spawned.handle, &[0; 16])
        .expect_err("stdin ceiling");
    assert_eq!(error_code(&error), "budget_exceeded");
}

#[test]
fn host_binary_round_trips_fs_and_artifact_bytes() {
    let fixture = Fixture::new("binary");
    let payload = vec![0xff, 0x00, 0xfe, b'A'];
    fs::write(fixture.root.join("bin.dat"), &payload).expect("bin");
    let fs_cap = fixture.filesystem();
    let artifacts = fixture.artifacts(ArtifactLimits {
        max_object_bytes: 32,
        max_total_bytes: 64,
        max_objects: 4,
    });
    let read_token = fixture.token(CapabilityRisk::Read);
    let write_token = fixture.token(CapabilityRisk::Write);
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(fixture.lifecycle.clone())),
        capability_owner: Some(fixture.owner.clone()),
        filesystem: Some(Arc::new(fs_cap)),
        processes: Some(Arc::new(fixture.processes())),
        artifacts: Some(Arc::new(artifacts)),
        ..AgentHostBridges::default()
    };
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            let read = cap::fs_read_range("{read_token}", "bin.dat", 0, 8);
            let put = cap::artifact_put("{write_token}", read.bytes, {{}});
            cap::artifact_get("{read_token}", put.id)
        }}
    "#
    );
    let result = AgentRunner::from_source(&source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    let VmValue::Map(fields) = result else {
        panic!("expected map");
    };
    match fields.get(&VmValue::string("bytes")) {
        Some(VmValue::Bytes(bytes)) => assert_eq!(bytes.as_ref(), payload.as_slice()),
        other => panic!("expected lossless bytes, got {other:?}"),
    }
}

#[test]
fn host_negative_offset_cannot_read_byte_zero() {
    let fixture = Fixture::new("neg-off");
    fs::write(fixture.root.join("bin.dat"), b"ABC").expect("seed");
    let fs_cap = Arc::new(fixture.filesystem());
    let token = fixture.token(CapabilityRisk::Read);
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::fs_read_range("{token}", "bin.dat", -1, 1)
        }}
    "#
    );
    let result = run_cap_source(
        &fixture,
        Some(Arc::clone(&fs_cap)),
        Some(Arc::new(fixture.processes())),
        None,
        &source,
    );
    assert_eq!(envelope_error_code(&result), "invalid_request");
    if let VmValue::Map(fields) = &result
        && let Some(VmValue::Bytes(bytes)) = fields.get(&VmValue::string("bytes"))
    {
        panic!("negative offset must not return file bytes, got {bytes:?}");
    }
}

#[test]
fn host_malformed_write_payload_does_not_create_or_modify_file() {
    let fixture = Fixture::new("bad-write");
    let path = fixture.root.join("out.bin");
    fs::write(&path, b"keep").expect("seed");
    let fs_cap = Arc::new(fixture.filesystem());
    let token = fixture.token(CapabilityRisk::Write);
    for payload in ["{}", "\"hello\"", "1"] {
        let source = format!(
            r#"
            pub fn run(input: map) -> map {{
                cap::fs_write_atomic("{token}", "out.bin", "", {payload})
            }}
        "#
        );
        let result = run_cap_source(
            &fixture,
            Some(Arc::clone(&fs_cap)),
            Some(Arc::new(fixture.processes())),
            None,
            &source,
        );
        assert_eq!(
            envelope_error_code(&result),
            "invalid_request",
            "payload {payload}"
        );
        assert_eq!(
            fs::read(&path).expect("unchanged"),
            b"keep",
            "payload {payload}"
        );
    }
    assert!(!fixture.root.join("created.bin").exists());
    let create = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::fs_write_atomic("{token}", "created.bin", "", {{}})
        }}
    "#
    );
    let result = run_cap_source(
        &fixture,
        Some(fs_cap),
        Some(Arc::new(fixture.processes())),
        None,
        &create,
    );
    assert_eq!(envelope_error_code(&result), "invalid_request");
    assert!(!fixture.root.join("created.bin").exists());
}

#[test]
fn host_malformed_process_and_artifact_values_fail_without_effects() {
    let fixture = Fixture::new("bad-cap-vals");
    let artifacts = Arc::new(fixture.artifacts(ArtifactLimits {
        max_object_bytes: 32,
        max_total_bytes: 64,
        max_objects: 4,
    }));
    let processes = Arc::new(fixture.processes());
    let write = fixture.token(CapabilityRisk::Write);
    let execute = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &execute,
            &["/bin/cat".to_string()],
            "",
            &[],
            ProcessLimits::default(),
        )
        .expect("spawn");

    let put = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::artifact_put("{write}", {{}}, {{}})
        }}
    "#
    );
    let put_result = run_cap_source(
        &fixture,
        None,
        Some(Arc::clone(&processes)),
        Some(Arc::clone(&artifacts)),
        &put,
    );
    assert_eq!(envelope_error_code(&put_result), "invalid_request");
    if let VmValue::Map(fields) = &put_result
        && let Some(VmValue::String(id)) = fields.get(&VmValue::string("id"))
    {
        panic!("malformed artifact put must not mint an id, got {id}");
    }

    let stdin = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::process_write("{execute}", "{}", {{}})
        }}
    "#,
        spawned.handle
    );
    let write_result = run_cap_source(
        &fixture,
        None,
        Some(Arc::clone(&processes)),
        Some(Arc::clone(&artifacts)),
        &stdin,
    );
    assert_eq!(envelope_error_code(&write_result), "invalid_request");

    let spawn = r#"
        pub fn run(input: map) -> map {
            cap::process_spawn(input.token, input.argv, "", [], {timeout_ms: -1})
        }
    "#;
    let spawn_host = AgentHostBridges {
        lifecycle: Some(Arc::new(fixture.lifecycle.clone())),
        capability_owner: Some(fixture.owner.clone()),
        processes: Some(Arc::clone(&processes)),
        artifacts: Some(artifacts),
        ..AgentHostBridges::default()
    };
    let spawn_result = AgentRunner::from_source(spawn, AgentConfig::default())
        .expect("compile")
        .with_host(spawn_host)
        .run_with_context(VmValue::map(vec![
            (VmValue::string("token"), VmValue::string(&execute)),
            (
                VmValue::string("argv"),
                VmValue::array(vec![VmValue::string("/bin/true")]),
            ),
        ]))
        .expect("run");
    assert_eq!(envelope_error_code(&spawn_result), "invalid_request");

    processes.kill(&execute, &spawned.handle).expect("kill");
}

#[test]
fn zero_limit_pagination_is_invalid_and_cannot_loop() {
    let fixture = Fixture::new("zero-limit");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    for name in ["a", "b", "c"] {
        fs::write(fixture.root.join("dir").join(name), name.as_bytes()).expect("entry");
    }
    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let error = fs_cap
        .list(&token, "dir", 0, 0)
        .expect_err("zero list limit");
    assert_eq!(error_code(&error), "invalid_request");
    let error = fs_cap
        .read_range(&token, "dir/a", 0, 0)
        .expect_err("zero read limit");
    assert_eq!(error_code(&error), "invalid_request");

    let processes = fixture.processes();
    let execute = fixture.token(CapabilityRisk::Execute);
    let spawned = processes
        .spawn(
            &execute,
            &["/bin/echo".to_string(), "hello".to_string()],
            "",
            &[],
            ProcessLimits::default(),
        )
        .expect("spawn");
    let _ = processes
        .wait(&execute, &spawned.handle, Some(5_000))
        .expect("wait");
    let error = processes
        .log(&execute, &spawned.handle, 0, 0)
        .expect_err("zero log limit");
    assert_eq!(error_code(&error), "invalid_request");
    let error = processes
        .poll(&execute, &spawned.handle, 0, 0)
        .expect_err("zero poll limit");
    assert_eq!(error_code(&error), "invalid_request");

    let host_fs = Arc::new(fixture.filesystem());
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::fs_list("{token}", "dir", 0, 0)
        }}
    "#
    );
    let result = run_cap_source(
        &fixture,
        Some(host_fs),
        Some(Arc::new(fixture.processes())),
        None,
        &source,
    );
    assert_eq!(envelope_error_code(&result), "invalid_request");
    if let VmValue::Map(fields) = &result {
        assert_ne!(
            (
                fields.get(&VmValue::string("truncated")),
                fields.get(&VmValue::string("next_cursor")),
                fields.get(&VmValue::string("cursor"))
            ),
            (
                Some(&VmValue::Bool(true)),
                Some(&VmValue::Int(0)),
                Some(&VmValue::Int(0))
            ),
            "clients must not receive truncated=true with an unchanged cursor"
        );
    }

    let mut cursor = 0_u64;
    let mut pages = 0_usize;
    loop {
        pages += 1;
        assert!(pages <= 8, "pagination must not loop");
        let page = fs_cap.list(&token, "dir", cursor, 2).expect("page");
        if page.truncated {
            assert_ne!(
                page.next_cursor, cursor,
                "truncated pages must advance next_cursor"
            );
            cursor = page.next_cursor;
            continue;
        }
        break;
    }
}

#[test]
fn system_clock_monotonic_ms_is_instant_origin_not_unix_wall_clock() {
    let clock = SystemClock;
    let ms = clock.monotonic_ms().expect("monotonic");
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("unix")
        .as_millis() as u64;
    assert!(
        ms < unix / 1_000,
        "monotonic {ms} must not be unix wall {unix}"
    );
    let later = clock.monotonic_ms().expect("later");
    assert!(later >= ms);
}

struct OverflowClock;

impl LifecycleClock for OverflowClock {
    fn now_ms(&self) -> u64 {
        1_000
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn monotonic_ms(&self) -> Option<u64> {
        None
    }
}

#[test]
fn cap_clock_monotonic_ms_overflow_is_fail_closed() {
    let root = tmp_root("clock-overflow");
    let owner = owner();
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity("registry-a")
        .workspace(&root)
        .limits(LifecycleLimits {
            max_tool_calls: 32,
            max_output_bytes: 64 * 1024,
            max_summary_bytes: 256,
        })
        .deadline_ms(60_000)
        .clock(Arc::new(OverflowClock) as Arc<dyn LifecycleClock>)
        .tokens(SequenceIssuer::new() as Arc<dyn TokenIssuer>)
        .durable(MemoryDurable::new() as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .cancellation(Arc::new(NeverCancelled) as Arc<dyn CancellationFlag>)
        .generation(1)
        .build()
        .expect("lifecycle");
    let token = token_of(
        lifecycle
            .prepare(&owner, metadata("call-overflow", CapabilityRisk::Read))
            .expect("prepare"),
    );
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner),
        ..AgentHostBridges::default()
    };
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::clock_monotonic_ms("{token}")
        }}
    "#
    );
    let result = AgentRunner::from_source(&source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    assert_eq!(envelope_error_code(&result), "internal_error");
    let _ = fs::remove_dir_all(&root);
}

struct FailCommitDurable;

impl DurableToolLifecycle for FailCommitDurable {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }

    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        Ok(())
    }

    fn replay_result(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(None)
    }

    fn commit_started(&self, _record: &DurableStarted) -> Result<(), LifecycleError> {
        Ok(())
    }

    fn commit_result(&self, _call_id: &str, _result: &Value) -> Result<Value, LifecycleError> {
        Err(LifecycleError::ResultCommitFailed(
            "injected result failure".to_string(),
        ))
    }

    fn interrupt(&self, _call_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

fn artifact_lifecycle(
    root: &Path,
    durable: Arc<dyn DurableToolLifecycle>,
) -> (CapabilityLifecycle, CapabilityOwner) {
    let owner = owner();
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity("registry-a")
        .workspace(root)
        .limits(LifecycleLimits {
            max_tool_calls: 32,
            max_output_bytes: 64 * 1024,
            max_summary_bytes: 256,
        })
        .deadline_ms(60_000)
        .clock(ScriptedClock::new(1_000) as Arc<dyn LifecycleClock>)
        .tokens(SequenceIssuer::new() as Arc<dyn TokenIssuer>)
        .durable(durable)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .cancellation(Arc::new(NeverCancelled) as Arc<dyn CancellationFlag>)
        .generation(1)
        .build()
        .expect("lifecycle");
    (lifecycle, owner)
}

fn default_artifact_limits() -> ArtifactLimits {
    ArtifactLimits {
        max_object_bytes: 1024,
        max_total_bytes: 4096,
        max_objects: 8,
    }
}

#[test]
fn result_artifact_is_retracted_on_commit_storage_failure() {
    let root = tmp_root("artifact-commit-fail");
    let (lifecycle, owner) = artifact_lifecycle(&root, Arc::new(FailCommitDurable));
    let token = token_of(
        lifecycle
            .prepare(&owner, metadata("call-art-fail", CapabilityRisk::Read))
            .expect("prepare"),
    );
    let artifacts =
        ArtifactCapability::new(lifecycle.clone(), owner.clone(), default_artifact_limits())
            .expect("artifacts");
    let published = artifacts
        .put_result(&token, b"payload", &json!({}))
        .expect("put");
    assert_eq!(artifacts.stored_len(), 1);
    let error = lifecycle
        .commit(&owner, &token, json!({"ok": true, "content": "done"}))
        .expect_err("commit storage");
    assert!(matches!(error, LifecycleError::ResultCommitFailed(_)));
    assert!(artifacts.stored(&published.id).is_none());
    assert_eq!(artifacts.stored_len(), 0);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn result_artifact_is_retracted_on_interrupt_and_reservation_is_released() {
    let fixture = Fixture::new("artifact-interrupt");
    let artifacts = fixture.artifacts(default_artifact_limits());
    let token = fixture.token(CapabilityRisk::Read);
    let published = artifacts
        .put_result(&token, b"payload", &json!({}))
        .expect("put");
    assert!(artifacts.stored(&published.id).is_some());
    fixture.lifecycle.recover_open_tokens().expect("recover");
    assert!(artifacts.stored(&published.id).is_none());
    assert_eq!(artifacts.stored_len(), 0);
    let token2 = fixture.token(CapabilityRisk::Read);
    let again = artifacts
        .put_result(&token2, b"again", &json!({}))
        .expect("republish");
    assert!(artifacts.stored(&again.id).is_some());
}

#[test]
fn result_artifact_is_retracted_on_cancel_after_publication() {
    let fixture = Fixture::new("artifact-cancel");
    let artifacts = fixture.artifacts(default_artifact_limits());
    let token = fixture.token(CapabilityRisk::Read);
    let published = artifacts
        .put_result(&token, b"payload", &json!({}))
        .expect("put");
    fixture.cancel.cancel();
    let error = fixture
        .lifecycle
        .commit(
            &fixture.owner,
            &token,
            json!({"ok": true, "content": "done"}),
        )
        .expect_err("cancelled");
    assert!(matches!(error, LifecycleError::Cancelled));
    assert!(artifacts.stored(&published.id).is_none());
    assert_eq!(artifacts.stored_len(), 0);
}

#[test]
fn successful_commit_retains_result_artifact_for_replay() {
    let fixture = Fixture::new("artifact-keep");
    let artifacts = fixture.artifacts(default_artifact_limits());
    let token = fixture.token(CapabilityRisk::Read);
    let published = artifacts
        .put_result(&token, b"keep-me", &json!({}))
        .expect("put");
    fixture
        .lifecycle
        .commit(
            &fixture.owner,
            &token,
            json!({"ok": true, "content": "done"}),
        )
        .expect("commit");
    let (bytes, _) = artifacts.stored(&published.id).expect("retained");
    assert_eq!(bytes, b"keep-me");
    fixture.lifecycle.recover_open_tokens().expect("recover");
    let (bytes, _) = artifacts.stored(&published.id).expect("still retained");
    assert_eq!(bytes, b"keep-me");
}

#[test]
fn concurrent_result_artifacts_rollback_only_failed_call() {
    let fixture = Fixture::new("artifact-concurrent");
    let artifacts = Arc::new(fixture.artifacts(default_artifact_limits()));
    let token_ok = fixture.token(CapabilityRisk::Read);
    let token_fail = fixture.token(CapabilityRisk::Read);
    thread::scope(|scope| {
        let artifacts_ok = Arc::clone(&artifacts);
        let artifacts_fail = Arc::clone(&artifacts);
        let token_ok = token_ok.clone();
        let token_fail = token_fail.clone();
        scope.spawn(move || {
            artifacts_ok
                .put_result(&token_ok, b"ok-payload", &json!({}))
                .expect("put ok");
        });
        scope.spawn(move || {
            artifacts_fail
                .put_result(&token_fail, b"fail-payload", &json!({}))
                .expect("put fail");
        });
    });
    assert_eq!(artifacts.stored_len(), 2);
    fixture
        .lifecycle
        .commit(
            &fixture.owner,
            &token_ok,
            json!({"ok": true, "content": "done"}),
        )
        .expect("commit ok");
    fixture.cancel.cancel();
    fixture
        .lifecycle
        .commit(
            &fixture.owner,
            &token_fail,
            json!({"ok": true, "content": "done"}),
        )
        .expect_err("cancelled fail call");
    assert_eq!(artifacts.stored_len(), 1);
}

#[cfg(unix)]
#[test]
fn list_omits_non_utf8_names() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("list-non-utf8");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    fs::write(fixture.root.join("dir").join("keep.txt"), "ok").expect("keep");
    fs::write(
        fixture
            .root
            .join("dir")
            .join(OsString::from_vec(vec![0xff, 0x80])),
        "secret",
    )
    .expect("invalid name");
    let listed = fixture
        .filesystem()
        .list(&fixture.token(CapabilityRisk::Read), "dir", 0, 4)
        .expect("list");
    assert!(listed.entries.iter().any(|entry| entry.name == "keep.txt"));
    assert!(
        listed
            .entries
            .iter()
            .all(|entry| !entry.name.contains('\u{FFFD}')),
        "replacement-character names must not be listed: {:?}",
        listed
            .entries
            .iter()
            .map(|entry| &entry.name)
            .collect::<Vec<_>>()
    );
}

#[cfg(unix)]
#[test]
fn list_examination_budget_counts_non_utf8_slots() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("list-exam-slots");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    fs::write(
        fixture
            .root
            .join("dir")
            .join(OsString::from_vec(vec![0xff, 0x80])),
        "secret",
    )
    .expect("invalid-a");
    fs::write(
        fixture
            .root
            .join("dir")
            .join(OsString::from_vec(vec![0xff, 0x81])),
        "secret",
    )
    .expect("invalid-b");
    fs::write(fixture.root.join("dir").join("keep.txt"), "ok").expect("keep");

    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let mut cursor = 0_u64;
    let mut pages = 0_usize;
    let mut seen_keep = false;
    loop {
        pages += 1;
        assert!(pages <= 8, "pagination must not loop");
        let page = fs_cap.list(&token, "dir", cursor, 1).expect("page");
        let examined = page.next_cursor.saturating_sub(page.cursor);
        assert!(
            examined <= 1,
            "limit must bound physical dirents examined, got examined={examined} page={page:?}"
        );
        assert!(
            page.entries.len() <= 1,
            "page must not emit more names than the examination budget"
        );
        assert!(
            page.entries
                .iter()
                .all(|entry| !entry.name.contains('\u{FFFD}')),
            "lossy names must not be listed: {:?}",
            page.entries
                .iter()
                .map(|entry| &entry.name)
                .collect::<Vec<_>>()
        );
        assert!(
            !page.entries.iter().any(|entry| entry.name == "secret"),
            "invalid-byte contents must not leak through the name slot"
        );
        if page.entries.iter().any(|entry| entry.name == "keep.txt") {
            seen_keep = true;
        }
        if page.truncated {
            assert_ne!(
                page.next_cursor, cursor,
                "truncated pages must advance next_cursor"
            );
            cursor = page.next_cursor;
            continue;
        }
        break;
    }
    assert!(seen_keep, "valid keep.txt must remain reachable by cursor");

    let host_fs = Arc::new(fixture.filesystem());
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::fs_list("{token}", "dir", 0, 1)
        }}
    "#
    );
    let result = run_cap_source(&fixture, Some(host_fs), None, None, &source);
    let VmValue::Map(fields) = &result else {
        panic!("expected list envelope, got {result:?}");
    };
    assert_eq!(
        fields.get(&VmValue::string("ok")),
        Some(&VmValue::Bool(true))
    );
    let Some(VmValue::Int(next_cursor)) = fields.get(&VmValue::string("next_cursor")) else {
        panic!("expected next_cursor, got {result:?}");
    };
    assert!(
        *next_cursor <= 1,
        "host list must charge examined slots, got {result:?}"
    );
    if let Some(VmValue::Array(entries)) = fields.get(&VmValue::string("entries")) {
        for entry in entries.iter() {
            let VmValue::Map(entry) = entry else {
                panic!("expected entry map, got {entry:?}");
            };
            if let Some(VmValue::String(name)) = entry.get(&VmValue::string("name")) {
                assert!(
                    !name.contains('\u{FFFD}'),
                    "host list must not expose lossy names: {name}"
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn list_consumed_non_utf8_only_page_advances_next_cursor() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("list-non-utf8-only");
    fs::create_dir(fixture.root.join("dir")).expect("dir");
    fs::write(
        fixture
            .root
            .join("dir")
            .join(OsString::from_vec(vec![0xff, 0x80])),
        "secret",
    )
    .expect("invalid name");
    let listed = fixture
        .filesystem()
        .list(&fixture.token(CapabilityRisk::Read), "dir", 0, 1)
        .expect("list");
    assert!(
        listed.entries.is_empty(),
        "omitted invalid-byte names must not appear: {:?}",
        listed.entries
    );
    assert!(
        listed.next_cursor > listed.cursor,
        "consumed-but-omitted dirents must advance next_cursor: {listed:?}"
    );
    assert!(
        !listed.truncated,
        "a single consumed-omitted dirent must not claim leftover pages: {listed:?}"
    );
}

#[cfg(unix)]
#[test]
fn list_rejects_regular_hardlinks_and_preserves_dirs_and_files() {
    let fixture = Fixture::new("list-hardlink");
    fs::create_dir(fixture.root.join("keep-dir")).expect("dir");
    fs::write(fixture.root.join("keep.txt"), "ok").expect("keep");
    let outside = fixture.root.parent().unwrap().join(format!(
        "outside-shared-{}-{}",
        std::process::id(),
        NEXT_CAP_TMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&outside, "shared").expect("outside");
    fs::hard_link(&outside, fixture.root.join("linked")).expect("hard link");

    let fs_cap = fixture.filesystem();
    let token = fixture.token(CapabilityRisk::Read);
    let error = fs_cap
        .list(&token, "", 0, 4)
        .expect_err("listing a regular hardlink must fail");
    assert_eq!(error_code(&error), "path_denied");
    assert_eq!(
        error.message(),
        "regular files with multiple hard links are not permitted"
    );

    let nested = fixture.root.join("keep-dir");
    fs::write(nested.join("inner.txt"), "inner").expect("inner");
    let listed = fs_cap
        .list(&token, "keep-dir", 0, 4)
        .expect("ordinary directory listing must succeed");
    assert!(
        listed
            .entries
            .iter()
            .any(|entry| entry.name == "inner.txt" && entry.file_type == "file")
    );
    assert!(
        listed.entries.iter().all(|entry| entry.name != "linked"),
        "hardlinked names must not leak through a nested listing: {:?}",
        listed.entries
    );

    let host_fs = Arc::new(fixture.filesystem());
    let source = format!(
        r#"
        pub fn run(input: map) -> map {{
            cap::fs_list("{token}", "", 0, 4)
        }}
    "#
    );
    let result = run_cap_source(&fixture, Some(host_fs), None, None, &source);
    assert_eq!(envelope_error_code(&result), "path_denied");
    let VmValue::Map(fields) = &result else {
        panic!("expected map envelope, got {result:?}");
    };
    let Some(VmValue::Map(error)) = fields.get(&VmValue::string("error")) else {
        panic!("expected error map, got {result:?}");
    };
    assert_eq!(
        error.get(&VmValue::string("message")),
        Some(&VmValue::string(
            "regular files with multiple hard links are not permitted"
        ))
    );
    let _ = fs::remove_file(&outside);
}
