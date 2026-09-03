//! Generic confined filesystem, process, and artifact capabilities.
//!
//! These tests drive native primitives that later RSS tools will consume.
//! Capability code must not know model-visible tool names.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::capabilities::{
    ApprovalGate, ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityError,
    CapabilityLifecycle, CapabilityOwner, CapabilityRisk, DurableStarted, DurableToolLifecycle,
    FilesystemCapability, FilesystemLimits, LifecycleClock, LifecycleError, LifecycleLimits,
    PrepareMetadata, PrepareOutcome, ProcessCapability, ProcessLimits, TokenIssuer,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner};
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
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );
    let root = Path::new(
        "/mnt/TEMP/workspace/rustscript-agent/tmp/prod-agent-task-0c-capabilities-272f7bb4",
    )
    .join(unique);
    fs::create_dir_all(&root).expect("create workspace");
    root
}

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
        ProcessCapability::new(self.lifecycle.clone(), self.owner.clone()).expect("processes")
    }

    fn artifacts(&self, limits: ArtifactLimits) -> ArtifactCapability {
        ArtifactCapability::new(self.lifecycle.clone(), self.owner.clone(), limits)
            .expect("artifacts")
    }
}

fn error_code(error: &CapabilityError) -> &str {
    error.code()
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
    for name in ["a", "b", "c", "d", "e"] {
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
            },
        )
        .expect("spawn sleep");
    fixture.cancel.cancel();
    let error = processes
        .wait(&live, &spawned.handle, Some(2_000))
        .expect_err("cancelled during wait");
    assert_eq!(error_code(&error), "cancelled");
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
        "cap::artifact_get",
        "cap::artifact_reference",
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
