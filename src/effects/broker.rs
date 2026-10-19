//! Host-private authority, immutable object preparation and per-call fences.
//! Managed cwd mapping does not isolate arbitrary program effects outside the tree.
use super::authority::{
    ManagedNativeOperation, ManagedPolicyClass, ManagedToolPolicyCatalog, SealedManagedCallPolicy,
};
use super::retention::{
    ManagedCallReservation, ManagedObjectLease, ManagedObjectLeaseRegistry, ManagedObjectTicket,
};
use super::{
    journal::*,
    tree_store,
    types::{EffectCancellation, EffectDeadline},
};
use crate::registry::ToolRegistrySnapshot;
use crate::{
    capabilities::vm_io::ConfinedFsRoot,
    capabilities::{
        CapabilityOwner, CapabilityRisk, FilesystemCapability, FilesystemLimits, ProcessCapability,
        ProcessLimits, TokenClaims, lifecycle::CapabilityLifecycle,
    },
    config::ManagedWorkspaceConfig,
    gateway::store::GatewayPersistence,
    runtime::{RunCancellation, rss_runner::WorkspaceAuthority},
};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
#[cfg(all(test, feature = "workspace-io-fault"))]
#[path = "managed_authority_tests.rs"]
mod managed_authority_tests;

#[derive(Clone)]
pub(crate) struct ManagedEntryContract {
    pub(crate) trust: crate::plugins::PackageTrust,
    pub(crate) effects: Vec<ManagedEffectRequirement>,
    pub(crate) single_builtin_graph: bool,
}

#[derive(Clone)]
pub(crate) struct ManagedEffectRequirement {
    pub(crate) kind: String,
    pub(crate) scope: String,
    pub(crate) recovery: String,
}

#[cfg(test)]
type ManagedNativeWriteObserver = Arc<dyn Fn(Arc<ManagedCallContext>) + Send + Sync>;
pub(crate) struct ManagedEffectRuntime {
    #[cfg(test)]
    pub(crate) canonical_observation_fixture: Mutex<Option<Value>>,
    #[cfg(test)]
    native_write_observer: Mutex<Option<ManagedNativeWriteObserver>>,
    #[cfg(test)]
    native_ready_observer: Mutex<Option<ManagedNativeWriteObserver>>,
    #[cfg(test)]
    close_after_native_spawn: AtomicBool,
    #[cfg(feature = "workspace-io-fault")]
    fault: Mutex<Option<ManagedEffectFault>>,
    #[cfg(feature = "workspace-io-fault")]
    prepare_gate: Mutex<Option<Arc<ManagedPrepareGate>>>,
    config: ManagedWorkspaceConfig,
    pub(crate) repository: ManagedEffectRepository,
    root: ConfinedFsRoot,
    directories: Vec<ConfinedFsRoot>,
    path: PathBuf,
    store_id: String,
    _lock: File,
    marker: File,
    marker_identity: (u64, u64),
    leases: Arc<ManagedObjectLeaseRegistry>,
    pub(crate) tree_sync: tree_store::DirectorySync,
    initialized: Mutex<Option<ManagedWorkspaceRecord>>,
}

/// Per-store, one-shot deterministic managed protocol cuts.
#[cfg(feature = "workspace-io-fault")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedEffectFault {
    BeforeIntent,
    BeginAfterFirstEvent,
    AfterIntent,
    AfterOperationBeforePrepare,
    AfterObjectsSynced,
    PrepareAfterObjectRegistry,
    AfterPrepared,
    CommitAfterDecision,
    CommitAfterHead,
    CommitAfterReceipt,
    CommitAfterFirstEvent,
    CommitAfterMessage,
    AfterDurableBeforeLive,
    ResultPartialWrite,
    ResultFileFsync,
    TreeRename,
    SealedMetadata,
    TreeDirectoryFsync,
    OwnedCleanup,
    ObjectReferenceUnavailable,
    WriterReap,
    WriterDrain,
}

#[cfg(feature = "workspace-io-fault")]
impl ManagedEffectRuntime {
    pub(crate) fn arm_fault(&self, fault: ManagedEffectFault) {
        *self.fault.lock() = Some(fault);
    }
    pub(crate) fn take_fault(&self, fault: ManagedEffectFault) -> bool {
        let mut armed = self.fault.lock();
        if *armed == Some(fault) {
            armed.take();
            true
        } else {
            false
        }
    }
    pub(crate) fn take_sql_fault(&self) -> String {
        use ManagedEffectFault::*;
        let mut armed = self.fault.lock();
        match *armed {
            Some(
                cut @ (CommitAfterDecision
                | CommitAfterHead
                | CommitAfterReceipt
                | CommitAfterFirstEvent
                | CommitAfterMessage),
            ) => {
                armed.take();
                format!("{cut:?}")
            }
            _ => String::new(),
        }
    }
}

#[cfg(feature = "workspace-io-fault")]
struct ManagedPrepareGate {
    state: std::sync::Mutex<(usize, bool, bool)>,
    cv: std::sync::Condvar,
    deadline: std::time::Instant,
    call_id: Option<String>,
}
#[cfg(feature = "workspace-io-fault")]
pub struct ManagedPrepareGateGuard {
    gate: Arc<ManagedPrepareGate>,
}
#[cfg(feature = "workspace-io-fault")]
impl ManagedEffectRuntime {
    pub(crate) fn arm_prepare_gate(&self, call_id: Option<&str>) -> ManagedPrepareGateGuard {
        let gate = Arc::new(ManagedPrepareGate {
            state: std::sync::Mutex::new((0, false, false)),
            cv: std::sync::Condvar::new(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(20),
            call_id: call_id.map(str::to_owned),
        });
        *self.prepare_gate.lock() = Some(Arc::clone(&gate));
        ManagedPrepareGateGuard { gate }
    }
}
#[cfg(feature = "workspace-io-fault")]
impl ManagedPrepareGateGuard {
    pub fn wait_arrived(&self, count: usize) -> Result<(), String> {
        let mut state = self
            .gate
            .state
            .lock()
            .map_err(|_| "managed fixture gate poisoned")?;
        while state.0 < count && !state.2 {
            let remaining = self
                .gate
                .deadline
                .saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("managed fixture arrival deadline".into());
            }
            state = self
                .gate
                .cv
                .wait_timeout(state, remaining)
                .map_err(|_| "managed fixture gate poisoned")?
                .0;
        }
        if state.2 {
            Err("managed fixture gate aborted".into())
        } else {
            Ok(())
        }
    }
    pub fn release(&self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|p| p.into_inner());
        state.1 = true;
        self.gate.cv.notify_all();
    }
}
#[cfg(feature = "workspace-io-fault")]
impl Drop for ManagedPrepareGateGuard {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|p| p.into_inner());
        state.2 = true;
        self.gate.cv.notify_all();
    }
}
#[cfg(feature = "workspace-io-fault")]
impl ManagedPrepareGate {
    fn arrive(&self, deadline: std::time::Instant) -> Result<(), String> {
        let deadline = deadline.min(self.deadline);
        let mut state = self
            .state
            .lock()
            .map_err(|_| "managed fixture gate poisoned")?;
        if state.1 {
            return Ok(());
        }
        if state.2 {
            return Err("managed fixture gate aborted".into());
        }
        state.0 += 1;
        self.cv.notify_all();
        while !state.1 && !state.2 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("managed fixture preparation deadline".into());
            }
            state = self
                .cv
                .wait_timeout(state, remaining)
                .map_err(|_| "managed fixture gate poisoned")?
                .0;
        }
        if state.2 && !state.1 {
            Err("managed fixture gate aborted".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "workspace-io-fault"))]
mod managed_native_tests {
    use super::*;
    use crate::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ScriptedProvider};
    #[tokio::test(flavor = "multi_thread")]
    async fn real_rss_write_remains_inflight_and_closing_denies_new_native_operations() {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(
            format!("managed-inflight-{}", uuid::Uuid::new_v4().simple()),
        );
        let workspace = root.join("workspace");
        let home = root.join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        for path in [&root, &workspace, &home] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
        let mut config = AgentGatewayConfig {
            managed_workspace: Some(ManagedWorkspaceConfig {
                source_root: workspace.clone(),
                quota: super::super::ResourceQuota::new(1000, 1048576, 16).unwrap(),
                retention: crate::config::ManagedRetentionLimits::default(),
            }),
            ..Default::default()
        };
        config.approvals.write = "allow".into();
        let state =
            AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
                .unwrap()
                .with_workspace_home(&home);
        let service = state.service();
        let runtime = service.managed_runtime_for_test().unwrap();
        let gate = Arc::new(ManagedPrepareGate {
            state: std::sync::Mutex::new((0, false, false)),
            cv: std::sync::Condvar::new(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(20),
            call_id: None,
        });
        let release = ManagedPrepareGateGuard {
            gate: Arc::clone(&gate),
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        *runtime.native_write_observer.lock() = Some(Arc::new(move |call| {
            tx.send(Arc::clone(&call)).unwrap();
            gate.arrive(call.binding().unwrap().cancel.deadline_instant().unwrap())
                .unwrap();
        }));
        let provider = Arc::new(ScriptedProvider::new());
        provider.push_ok(json!({"text":"","tool_calls":[{"id":"inflight","name":"write_file","arguments":{"path":"during.txt","content":"actual original RSS bytes"}}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
        service.inject_provider_host(provider);
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"write under an observed Native operation"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let worker = tokio::spawn(
            service
                .clone()
                .run_worker(run.run_id.clone(), "ignored".into()),
        );
        let call = rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
        release.wait_arrived(1).unwrap();
        let active = call.active_native_operations();
        call.fence_for_prepare().unwrap();
        let adapter = call.adapters.lock().clone().unwrap();
        let late = adapter
            .filesystem
            .write_atomic(&adapter.token, "late.txt", "*", b"denied");
        release.release();
        worker.await.unwrap();
        drop(release);
        let view = fs::read_dir(root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::read(view.join("during.txt")).unwrap(),
            b"actual original RSS bytes"
        );
        assert!(!view.join("late.txt").exists());
        assert!(late.is_err());
        assert!(!workspace.join("during.txt").exists());
        assert_eq!(
            active, 1,
            "an admitted actual Native write must remain counted until its IO returns"
        );
        assert_eq!(call.active_native_operations(), 0);
        let request = ManagedEffectGetRequest {
            owner: call.identity.owner.clone(),
            call_id: call.identity.call_id.clone(),
        };
        drop(adapter);
        drop(call);
        drop(runtime);
        service.shutdown().await.unwrap();
        drop(service);
        drop(state);
        let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
            .unwrap()
            .with_workspace_home(&home);
        assert!(matches!(
            reopened.service().replay_managed_call(request).unwrap(),
            ManagedCallReplay::Indeterminate { .. }
        ));
        reopened.service().shutdown().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn actual_spawn_closed_before_table_insertion_still_requires_owned_writer_settlement() {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(
            format!("managed-owned-child-{}", uuid::Uuid::new_v4().simple()),
        );
        let workspace = root.join("workspace");
        let home = root.join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        for path in [&root, &workspace, &home] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
        let mut config = AgentGatewayConfig {
            managed_workspace: Some(ManagedWorkspaceConfig {
                source_root: workspace,
                quota: super::super::ResourceQuota::new(1000, 1048576, 16).unwrap(),
                retention: crate::config::ManagedRetentionLimits::default(),
            }),
            ..Default::default()
        };
        config.approvals.process = "allow".into();
        let state =
            AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
                .unwrap()
                .with_workspace_home(&home);
        let service = state.service();
        service
            .managed_runtime_for_test()
            .unwrap()
            .close_after_native_spawn
            .store(true, Ordering::SeqCst);
        let provider = Arc::new(ScriptedProvider::new());
        provider.push_ok(json!({"text":"","tool_calls":[{"id":"spawn","name":"terminal","arguments":{"argv":["/bin/sh","-c","exit 0"],"timeout_ms":1000}}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
        provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
        service.inject_provider_host(provider);
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"actual child close fence"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        service
            .clone()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        let request = ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id.clone(),
                run_id: run.run_id.clone(),
            },
            call_id: "spawn".into(),
        };
        let record = state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert_eq!(
            record.prepared.as_ref().unwrap().writer_state,
            ManagedWriterState::Settled,
            "an actual spawned child cannot be certified by an empty process table"
        );
        assert_eq!(
            record.outcome.as_ref().unwrap().disposition,
            ManagedPublicationStatus::NotPublished
        );
        service.shutdown().await.unwrap();
        drop(service);
        drop(state);
        let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
            .unwrap()
            .with_workspace_home(&home);
        assert_eq!(
            reopened
                .persistence()
                .unwrap()
                .managed_effect_get(&request)
                .unwrap()
                .unwrap(),
            record
        );
        reopened.service().shutdown().await.unwrap();
    }
}

fn error(value: impl std::fmt::Debug) -> String {
    format!("{value:?}")
}
pub(crate) fn fresh(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}
fn private(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(error)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err("managed store directory ownership/mode/type invalid".into());
    }
    Ok(())
}
fn file_identity(file: &File) -> Result<(u64, u64), String> {
    let meta = file.metadata().map_err(error)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
    {
        return Err("managed store file ownership/mode/type invalid".into());
    }
    Ok((meta.dev(), meta.ino()))
}
fn open_private_file(path: &Path, create: bool) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(create)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("managed private file open (create={create}): {e}"))
}
impl ManagedEffectRuntime {
    pub(crate) fn open(
        config: ManagedWorkspaceConfig,
        database: &Path,
        persistence: Arc<GatewayPersistence>,
    ) -> Result<Arc<Self>, String> {
        config.validate()?;
        if database == Path::new(":memory:") || !database.is_absolute() {
            return Err("managed workspace requires an absolute persistent database".into());
        }
        let source = fs::canonicalize(&config.source_root).map_err(error)?;
        if !config.source_root.is_absolute() || source == Path::new("/") {
            return Err("managed source must be an absolute non-root directory".into());
        }
        let parent = database.parent().ok_or("database parent missing")?;
        let filename = database
            .file_name()
            .ok_or("database filename missing")?
            .to_str()
            .ok_or("database filename invalid")?;
        let path = parent.join(format!(".{filename}.effects"));
        let packages = parent.join(format!(".{filename}.tool-packages"));
        for excluded in [database, path.as_path(), packages.as_path()] {
            if excluded.starts_with(&source) || source.starts_with(excluded) {
                return Err("managed source overlaps persistent state".into());
            }
        }
        let created = match fs::create_dir(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(error(e)),
        };
        if created {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(error)?;
        }
        private(&path)?;
        let root = ConfinedFsRoot::new(&path).map_err(error)?;
        let lockpath = path.join("lease");
        let lock = if created {
            open_private_file(&lockpath, true)?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lockpath)
                .map_err(error)?
        };
        file_identity(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("managed_store_in_use".into());
        }
        let markerpath = path.join("store-id");
        let mut marker = open_private_file(&markerpath, created)?;
        let store_id = if created {
            let id = fresh("store");
            marker.write_all(id.as_bytes()).map_err(error)?;
            marker.sync_all().map_err(error)?;
            id
        } else {
            let mut id = String::new();
            Read::by_ref(&mut marker)
                .take(128)
                .read_to_string(&mut id)
                .map_err(error)?;
            id
        };
        validate_id("store", &store_id)?;
        let mut directories = Vec::new();
        for name in ["trees", "results", "details", "views", "staging"] {
            let child = path.join(name);
            if created {
                fs::create_dir(&child).map_err(error)?;
                fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).map_err(error)?;
            }
            private(&child)?;
            tree_store::fsync_dir(&child).map_err(error)?;
            directories.push(root.subroot(name, root.limits()).map_err(error)?);
        }
        tree_store::fsync_dir(&path).map_err(error)?;
        if created {
            tree_store::fsync_dir(parent).map_err(error)?;
        }
        let marker_identity = file_identity(&marker)?;
        let leases = ManagedObjectLeaseRegistry::open(
            &config,
            &root,
            persistence.as_ref(),
            &store_id,
            &super::retention::StartupCensus::new(),
        )?;
        Ok(Arc::new(Self {
            #[cfg(test)]
            canonical_observation_fixture: Mutex::new(None),
            #[cfg(test)]
            native_write_observer: Mutex::new(None),
            #[cfg(test)]
            native_ready_observer: Mutex::new(None),
            #[cfg(test)]
            close_after_native_spawn: AtomicBool::new(false),
            #[cfg(feature = "workspace-io-fault")]
            fault: Mutex::new(None),
            #[cfg(feature = "workspace-io-fault")]
            prepare_gate: Mutex::new(None),
            config,
            repository: ManagedEffectRepository::new(persistence),
            root,
            directories,
            path,
            store_id,
            _lock: lock,
            marker,
            marker_identity,
            leases,
            tree_sync: tree_store::DirectorySync::default(),
            initialized: Mutex::new(None),
        }))
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        if !self.root.revalidate_binding() {
            return Err("managed store root replaced".into());
        }
        if self
            .directories
            .iter()
            .any(|directory| !directory.revalidate_binding())
        {
            return Err("managed store object namespace replaced".into());
        }
        let marker = open_private_file(&self.path.join("store-id"), false)?;
        if file_identity(&marker)? != self.marker_identity
            || file_identity(&self.marker)? != self.marker_identity
        {
            return Err("managed store marker replaced".into());
        }
        Ok(())
    }
    fn prepare_tree(
        &self,
        source: &ConfinedFsRoot,
        cancel: &RunCancellation,
        seal: bool,
        reservation: Option<&ManagedCallReservation>,
    ) -> Result<NativePreparedObject, String> {
        self.check()?;
        if cancel.requested().is_some() {
            return Err("managed effect cancelled".into());
        }
        let deadline = EffectDeadline::at(
            cancel
                .deadline_instant()
                .ok_or("managed deadline missing")?,
        );
        let mut ticket = match reservation {
            Some(reservation) => reservation.take_object(self.config.quota.max_bytes)?,
            None => self.leases.single(self.config.quota.max_bytes)?,
        };
        let id = fresh("tree");
        ticket.start(&id)?;
        let staging = self.path.join("staging").join(&id);
        let original = cancel.clone();
        let cancellation = EffectCancellation::linked(move || {
            original.requested().is_some() || original.deadline_passed()
        });
        let copied = tree_store::copy_tree_from_fd_with_sync(
            &source.duplicate_descriptor().map_err(error)?,
            &staging,
            &self.config.quota,
            &cancellation,
            &deadline,
            seal,
            &self.tree_sync,
        )
        .map_err(error)?;
        let final_path = self.path.join("trees").join(&id);
        #[cfg(feature = "workspace-io-fault")]
        if reservation.is_some() && self.take_fault(ManagedEffectFault::TreeRename) {
            return Err("managed IO rename: EIO".into());
        }
        fs::rename(&staging, &final_path)
            .map_err(|e| format!("managed sealed tree rename: {e}"))?;
        #[cfg(feature = "workspace-io-fault")]
        if reservation.is_some() && self.take_fault(ManagedEffectFault::SealedMetadata) {
            return Err("managed IO sealed metadata: EIO".into());
        }
        if seal {
            tree_store::chmod_dir(&final_path, 0o555).map_err(error)?;
            tree_store::fsync_dir(&final_path).map_err(error)?;
        }
        tree_store::fsync_dir(&self.path.join("staging")).map_err(error)?;
        #[cfg(feature = "workspace-io-fault")]
        if reservation.is_some() && self.take_fault(ManagedEffectFault::TreeDirectoryFsync) {
            return Err("managed IO post-rename directory fsync: EIO".into());
        }
        tree_store::fsync_dir(&self.path.join("trees")).map_err(error)?;
        let root = self
            .root
            .subroot(&format!("trees/{id}"), self.root.limits())
            .map_err(error)?;
        if !root.revalidate_binding() {
            return Err("managed secure reopen failed".into());
        }
        self.check()?;
        let lease = ticket.seal(copied.bytes)?;
        Ok(NativePreparedObject {
            reference: ManagedObjectRef {
                store_id: self.store_id.clone(),
                object_id: id,
                object_kind: ManagedObjectKind::Tree,
                byte_count: copied.bytes.to_string(),
                entry_count: copied.entries.to_string(),
                object_format: "agent.managed-tree/v1".into(),
            },
            _lease: lease,
            handle: ManagedReadyHandle::Tree(root),
        })
    }
    fn result_object(
        &self,
        result: &CanonicalToolResultJson,
        budget: usize,
        reservation: &ManagedCallReservation,
    ) -> Result<NativePreparedObject, String> {
        self.blob_object(
            ManagedObjectKind::CanonicalResult,
            result.as_str().as_bytes(),
            budget,
            reservation,
        )
    }
    fn blob_object(
        &self,
        kind: ManagedObjectKind,
        bytes: &[u8],
        budget: usize,
        reservation: &ManagedCallReservation,
    ) -> Result<NativePreparedObject, String> {
        self.check()?;
        if bytes.len() > budget {
            return Err("managed canonical output exceeds original limit".into());
        }
        let (prefix, namespace, format) = match kind {
            ManagedObjectKind::CanonicalResult => {
                ("result", "results", "agent.canonical-tool-result/v1")
            }
            ManagedObjectKind::IntentDetails => ("intent", "details", "agent.intent-details/v1"),
            ManagedObjectKind::Tree => return Err("managed blob kind invalid".into()),
        };
        let mut ticket = reservation.take_object(bytes.len() as u64)?;
        let id = fresh(prefix);
        let staging = self.path.join("staging").join(&id);
        ticket.start(&id)?;
        let mut file = open_private_file(&staging, true)?;
        #[cfg(feature = "workspace-io-fault")]
        if kind == ManagedObjectKind::CanonicalResult
            && self.take_fault(ManagedEffectFault::ResultPartialWrite)
        {
            file.write_all(&bytes[..bytes.len() / 2]).map_err(error)?;
            return Err("managed IO partial canonical result write: EIO".into());
        }
        file.write_all(bytes).map_err(error)?;
        #[cfg(feature = "workspace-io-fault")]
        if kind == ManagedObjectKind::CanonicalResult
            && self.take_fault(ManagedEffectFault::ResultFileFsync)
        {
            return Err("managed IO canonical result file fsync: EIO".into());
        }
        file.sync_all().map_err(error)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(error)?;
        file.sync_all().map_err(error)?;
        fs::rename(&staging, self.path.join(namespace).join(&id)).map_err(error)?;
        tree_store::fsync_dir(&self.path.join("staging")).map_err(error)?;
        tree_store::fsync_dir(&self.path.join(namespace)).map_err(error)?;
        let reopened = open_private_file(&self.path.join(namespace).join(&id), false)?;
        if file_identity(&file)? != file_identity(&reopened)? {
            return Err("managed result identity changed".into());
        }
        self.check()?;
        let lease = ticket.seal(bytes.len() as u64)?;
        Ok(NativePreparedObject {
            reference: ManagedObjectRef {
                store_id: self.store_id.clone(),
                object_id: id,
                object_kind: kind,
                byte_count: bytes.len().to_string(),
                entry_count: "1".into(),
                object_format: format.into(),
            },
            _lease: lease,
            handle: ManagedReadyHandle::Blob(reopened),
        })
    }
    fn open_result(&self, object: &ManagedObjectRef) -> Result<(File, u64), String> {
        self.open_blob(object, ManagedObjectKind::CanonicalResult)
    }
    fn open_blob(
        &self,
        object: &ManagedObjectRef,
        kind: ManagedObjectKind,
    ) -> Result<(File, u64), String> {
        let (prefix, namespace, format) = match kind {
            ManagedObjectKind::CanonicalResult => {
                ("result", "results", "agent.canonical-tool-result/v1")
            }
            ManagedObjectKind::IntentDetails => ("intent", "details", "agent.intent-details/v1"),
            ManagedObjectKind::Tree => return Err("managed blob kind invalid".into()),
        };
        self.check()?;
        validate_id(prefix, &object.object_id)?;
        if object.store_id != self.store_id
            || object.object_kind != kind
            || object.object_format != format
            || object.entry_count != "1"
        {
            return Err("managed_object_unavailable".into());
        }
        let directory = self.root.open_directory(namespace).map_err(error)?;
        let name = std::ffi::CString::new(object.object_id.as_bytes()).map_err(error)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("managed_object_unavailable".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        file_identity(&file)?;
        let size = object.byte_count.parse::<u64>().map_err(error)?;
        let metadata = file.metadata().map_err(error)?;
        if size > crate::config::MAX_TOOL_OUTPUT_BYTES as u64
            || metadata.len() != size
            || metadata.mode() & 0o222 != 0
        {
            return Err("managed result size/mode invalid".into());
        }
        self.check()?;
        Ok((file, size))
    }
    fn original_arguments(&self, identity: &ManagedArgumentIdentity) -> Result<String, String> {
        match identity {
            ManagedArgumentIdentity::Inline {
                canonical_arguments,
            } => Ok(canonical_arguments.clone()),
            ManagedArgumentIdentity::Object { details } => {
                let (mut file, size) = self.open_blob(details, ManagedObjectKind::IntentDetails)?;
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take(size + 1)
                    .read_to_end(&mut bytes)
                    .map_err(error)?;
                if bytes.len() as u64 != size {
                    return Err("managed intent details changed".into());
                }
                self.check()?;
                String::from_utf8(bytes)
                    .map_err(|_| "managed intent details encoding invalid".into())
            }
        }
    }
    pub(crate) fn read_result_chunk(
        &self,
        object: &ManagedObjectRef,
        offset: u64,
        limit: usize,
    ) -> Result<ManagedResultChunk, String> {
        if limit == 0 || limit > 131072 {
            return Err("managed result chunk limit must be 1..=131072".into());
        }
        let (file, size) = self.open_result(object)?;
        if offset > size {
            return Err("managed result offset exceeds total bytes".into());
        }
        let want = usize::try_from((size - offset).min(limit as u64)).map_err(error)?;
        let mut bytes = vec![0; want];
        let mut received = 0;
        while received < want {
            let count = file
                .read_at(&mut bytes[received..], offset + received as u64)
                .map_err(error)?;
            if count == 0 {
                return Err("managed immutable result unexpectedly shortened".into());
            }
            received += count;
        }
        self.check()?;
        file_identity(&file)?;
        let next_offset = offset + received as u64;
        Ok(ManagedResultChunk {
            bytes,
            next_offset,
            eof: next_offset == size,
            total_bytes: size,
        })
    }
    pub(crate) fn read_result(&self, object: &ManagedObjectRef) -> Result<Value, String> {
        let (mut file, size) = self.open_result(object)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(size + 1)
            .read_to_end(&mut bytes)
            .map_err(error)?;
        let result: Value = serde_json::from_slice(&bytes).map_err(error)?;
        CanonicalToolResultJson::from_value(&result)?;
        self.check()?;
        Ok(result)
    }
    pub(crate) fn authorize_query(
        &self,
        authority: &WorkspaceAuthority,
        identity: &ManagedWorkspaceIdentity,
    ) -> Result<(), String> {
        authority.check().map_err(error)?;
        self.check()?;
        if identity.store_id != self.store_id
            || fs::canonicalize(&self.config.source_root).map_err(error)?
                != Path::new(authority.canonical_path())
        {
            return Err("managed query unavailable".into());
        }
        let (device, inode) = authority
            .grant()
            .held()
            .root()
            .binding_identity()
            .map_err(error)?;
        if device.to_string() != identity.source_identity.device_decimal
            || inode.to_string() != identity.source_identity.inode_decimal
        {
            return Err("managed source replaced".into());
        }
        Ok(())
    }

    pub(crate) fn authorize_workspace_query(
        &self,
        authority: &WorkspaceAuthority,
        profile: &str,
        workspace_id: &str,
        cancellation: &RunCancellation,
    ) -> Result<(), String> {
        validate_id("ws", workspace_id)?;
        let (device, inode) = authority
            .grant()
            .held()
            .root()
            .binding_identity()
            .map_err(error)?;
        let source = DirectoryIdentity {
            device_decimal: device.to_string(),
            inode_decimal: inode.to_string(),
        };
        let record = self
            .repository
            .workspace(&self.store_id, profile, &source, cancellation)?
            .ok_or("managed configured workspace unavailable")?;
        if record.identity.workspace_id != workspace_id {
            return Err("managed configured workspace mismatch".into());
        }
        self.authorize_query(authority, &record.identity)
    }

    pub(crate) fn verify_tree(&self, tree: &str) -> Result<(), String> {
        self.check()?;
        validate_id("tree", tree)?;
        self.root
            .subroot(&format!("trees/{tree}"), self.root.limits())
            .map_err(error)?;
        Ok(())
    }

    pub(crate) fn prepare_run_binding(
        self: &Arc<Self>,
        authority: Arc<WorkspaceAuthority>,
        owner: ManagedOwnerScope,
        code: ManagedCodeIdentity,
        contract: ManagedEntryContract,
        captured_policy: (Arc<ManagedToolPolicyCatalog>, Arc<ToolRegistrySnapshot>),
        cancel: RunCancellation,
    ) -> Result<Arc<ManagedRunBinding>, String> {
        let (policy_catalog, registry_snapshot) = captured_policy;
        authority.check().map_err(error)?;
        self.check()?;
        if !contract.single_builtin_graph
            || contract.trust != crate::plugins::PackageTrust::EmbeddingOwnedBuiltin
        {
            return Err("managed graph must be captured embedding-owned single builtin".into());
        }
        if !policy_catalog.matches_code(&code)
            || code.registry_identity != registry_snapshot.identity()
        {
            return Err("managed captured catalog/snapshot mismatch".into());
        }
        let configured = fs::canonicalize(&self.config.source_root).map_err(error)?;
        if configured != Path::new(authority.canonical_path()) {
            return Err("managed_workspace_mismatch".into());
        }
        let source = authority.grant();
        let (device, inode) = source.held().root().binding_identity().map_err(error)?;
        let configured_root = ConfinedFsRoot::new(&configured).map_err(error)?;
        if configured_root.binding_identity().map_err(error)? != (device, inode) {
            return Err("managed source binding mismatch".into());
        }
        let identity = DirectoryIdentity {
            device_decimal: device.to_string(),
            inode_decimal: inode.to_string(),
        };
        let cached = self.initialized.lock().clone();
        let workspace = match cached {
            Some(record) => record,
            None => {
                let existing = self.repository.workspace(
                    &self.store_id,
                    &owner.profile,
                    &identity,
                    &cancel,
                )?;
                let record = match existing {
                    Some(record) => record,
                    None => {
                        let seed = self.prepare_tree(source.held().root(), &cancel, true, None)?;
                        let record = ManagedWorkspaceRecord {
                            format: WORKSPACE_FORMAT.into(),
                            schema_version: 1,
                            identity: ManagedWorkspaceIdentity {
                                store_id: self.store_id.clone(),
                                workspace_id: fresh("ws"),
                                branch_id: fresh("br"),
                                source_identity: identity.clone(),
                            },
                            profile: owner.profile.clone(),
                            seed_root: seed.reference.clone(),
                            max_entries: self.config.quota.max_entries,
                            max_bytes: self.config.quota.max_bytes,
                            max_depth: self.config.quota.max_depth,
                        };
                        self.repository.command_with_cancellation("effect.workspace_register",&json!({"store_id":self.store_id,"profile":owner.profile,"source_device":identity.device_decimal,"source_inode":identity.inode_decimal,"workspace_json":serde_json::to_string(&record).map_err(error)?}),&cancel)?;
                        self.repository
                            .workspace(&self.store_id, &owner.profile, &identity, &cancel)?
                            .ok_or("workspace registration missing")?
                    }
                };
                *self.initialized.lock() = Some(record.clone());
                record
            }
        };
        if workspace.identity.source_identity != identity {
            return Err("managed source identity replaced".into());
        }
        if workspace.max_entries != self.config.quota.max_entries
            || workspace.max_bytes != self.config.quota.max_bytes
            || workspace.max_depth != self.config.quota.max_depth
        {
            return Err("managed configured quota differs from durable workspace".into());
        }
        validate_id("tree", &workspace.seed_root.object_id)?;
        self.root
            .subroot(
                &format!("trees/{}", workspace.seed_root.object_id),
                self.root.limits(),
            )
            .map_err(error)?;
        authority.check().map_err(error)?;
        Ok(Arc::new(ManagedRunBinding {
            runtime: Arc::clone(self),
            authority,
            owner,
            code,
            contract,
            policy_catalog,
            registry_snapshot,
            cancel,
            workspace,
            calls: Mutex::new(HashMap::new()),
            admitted_limits: Mutex::new(None),
        }))
    }
}
pub(crate) fn validate_id(prefix: &str, id: &str) -> Result<(), String> {
    if id.strip_prefix(&format!("{prefix}-")).is_none_or(|rest| {
        rest.len() != 32
            || !rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        Err("managed identifier malformed".into())
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq)]
struct ManagedAdapterLimits {
    filesystem: FilesystemLimits,
    process: ProcessLimits,
    output_budget: usize,
}
pub(crate) struct ManagedRunBinding {
    pub(crate) runtime: Arc<ManagedEffectRuntime>,
    pub(crate) authority: Arc<WorkspaceAuthority>,
    pub(crate) owner: ManagedOwnerScope,
    pub(crate) code: ManagedCodeIdentity,
    contract: ManagedEntryContract,
    policy_catalog: Arc<ManagedToolPolicyCatalog>,
    registry_snapshot: Arc<ToolRegistrySnapshot>,
    pub(crate) cancel: RunCancellation,
    pub(crate) workspace: ManagedWorkspaceRecord,
    calls: Mutex<HashMap<String, Arc<ManagedCallContext>>>,
    admitted_limits: Mutex<Option<ManagedAdapterLimits>>,
}
pub(crate) struct ManagedLiveReplay {
    pub(crate) outcome: ManagedCommitOutcome,
    pub(crate) result: Value,
}
impl ManagedRunBinding {
    #[cfg(test)]
    pub(crate) fn with_cancellation_for_test(&self, cancel: RunCancellation) -> Arc<Self> {
        Arc::new(Self {
            runtime: Arc::clone(&self.runtime),
            authority: Arc::clone(&self.authority),
            owner: self.owner.clone(),
            code: self.code.clone(),
            contract: self.contract.clone(),
            policy_catalog: Arc::clone(&self.policy_catalog),
            registry_snapshot: Arc::clone(&self.registry_snapshot),
            cancel,
            workspace: self.workspace.clone(),
            calls: Mutex::new(HashMap::new()),
            admitted_limits: Mutex::new(*self.admitted_limits.lock()),
        })
    }
    pub(crate) fn matches_contract(&self, contract: Option<&ManagedEntryContract>) -> bool {
        contract.is_some_and(|contract| {
            contract.trust == self.contract.trust
                && contract.single_builtin_graph == self.contract.single_builtin_graph
                && contract.effects.len() == self.contract.effects.len()
                && contract
                    .effects
                    .iter()
                    .zip(&self.contract.effects)
                    .all(|(left, right)| {
                        left.kind == right.kind
                            && left.scope == right.scope
                            && left.recovery == right.recovery
                    })
        })
    }
    pub(crate) fn matches_policy_catalog(
        &self,
        catalog: Option<&Arc<ManagedToolPolicyCatalog>>,
    ) -> bool {
        catalog.is_some_and(|catalog| {
            Arc::ptr_eq(catalog, &self.policy_catalog) && catalog.matches_code(&self.code)
        })
    }
    pub(crate) fn seal_call_policy(
        &self,
        name: &str,
        risk: CapabilityRisk,
        arguments: &str,
    ) -> Result<Arc<SealedManagedCallPolicy>, String> {
        self.check()?;
        let policy =
            self.policy_catalog
                .seal(&self.code, &self.registry_snapshot, name, risk, arguments)?;
        let (kind, scope) = policy.class().required_effect()?;
        if !self.contract.effects.iter().any(|effect| {
            effect.kind == kind
                && effect.scope == scope
                && (effect.recovery == "none"
                    || (policy.class() == ManagedPolicyClass::WorkspaceWrite
                        && effect.recovery == "checkpoint"))
        }) {
            return Err("managed undeclared effect".into());
        }
        Ok(policy)
    }
    pub(crate) fn replay_live(
        &self,
        call_id: &str,
        tool_name: &str,
        arguments: Option<&Value>,
        canonical: Option<&str>,
    ) -> Result<Option<ManagedLiveReplay>, String> {
        self.check()?;
        let Some(record) = self.runtime.repository.get(
            &ManagedEffectGetRequest {
                owner: self.owner.clone(),
                call_id: call_id.into(),
            },
            &self.cancel,
        )?
        else {
            return Ok(None);
        };
        let identity = &record.identity;
        if identity.owner != self.owner
            || identity.call_id != call_id
            || identity.tool_name != tool_name
            || identity.code != self.code
            || identity.workspace != self.workspace.identity
            || identity.authorization_generation != self.authority.generation()
        {
            return Err("managed replay identity mismatch".into());
        }
        let head = self
            .runtime
            .repository
            .head(&self.workspace.identity, &self.cancel)?;
        if identity.epoch != head.epoch {
            return Err("managed replay epoch mismatch".into());
        }
        let original = self
            .runtime
            .original_arguments(&identity.argument_identity)?;
        if canonical.is_some_and(|canonical| canonical != original) {
            return Err("managed replay argument identity mismatch".into());
        }
        if let Some(arguments) = arguments {
            let parsed: Value = serde_json::from_str(&original)
                .map_err(|_| "managed original arguments corrupt")?;
            if &parsed != arguments {
                return Err("managed replay original parent mismatch".into());
            }
        }
        let Some(outcome) = record.outcome else {
            return Err(if record.prepared.is_some() {
                "managed_effect_staged"
            } else {
                "managed_effect_indeterminate"
            }
            .into());
        };
        if !matches!(
            outcome.disposition,
            ManagedPublicationStatus::Committed
                | ManagedPublicationStatus::ReadOnly
                | ManagedPublicationStatus::NotPublished
                | ManagedPublicationStatus::Conflict
        ) {
            return Err("managed replay final disposition invalid".into());
        }
        self.runtime.verify_tree(
            outcome
                .publication
                .candidate_head
                .as_deref()
                .unwrap_or(&outcome.publication.base_head),
        )?;
        let result = self.runtime.read_result(&outcome.canonical_result_ref)?;
        self.check()?;
        Ok(Some(ManagedLiveReplay { outcome, result }))
    }
    pub(crate) fn bind_admitted_limits(
        &self,
        filesystem: FilesystemLimits,
        process: ProcessLimits,
        output_budget: usize,
    ) -> Result<(), String> {
        let limits = ManagedAdapterLimits {
            filesystem,
            process,
            output_budget,
        };
        let mut retained = self.admitted_limits.lock();
        if retained.as_ref().is_some_and(|old| *old != limits) {
            return Err("managed admitted ceilings changed".into());
        }
        *retained = Some(limits);
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        self.authority.check().map_err(error)?;
        self.runtime.check()?;
        if self.cancel.requested().is_some() || self.cancel.deadline_passed() {
            return Err("managed original deadline/cancellation".into());
        }
        Ok(())
    }
    pub(crate) fn call(&self, id: &str) -> Option<Arc<ManagedCallContext>> {
        self.calls.lock().get(id).cloned()
    }
    pub(crate) fn register(
        self: &Arc<Self>,
        call_id: &str,
        tool_name: &str,
        arguments: &str,
        policy: Arc<SealedManagedCallPolicy>,
        deadline_ms: u64,
    ) -> Result<Arc<ManagedCallContext>, String> {
        self.check()?;
        if self.calls.lock().contains_key(call_id) {
            return Err("managed exact call already registered".into());
        }
        if !policy.matches(&self.policy_catalog, &self.code, tool_name) {
            return Err("managed policy binding mismatch".into());
        }
        let risk = policy.expected_risk().as_str();
        let head = self
            .runtime
            .repository
            .head(&self.workspace.identity, &self.cancel)?;
        let parent = self
            .runtime
            .repository
            .object_metadata(
                &ManagedObjectReferencesRequest {
                    store_id: self.workspace.identity.store_id.clone(),
                    object_id: head.head_object_id.clone(),
                },
                &self.cancel,
            )?
            .ok_or("managed parent object metadata missing")?;
        if parent.object_kind != ManagedObjectKind::Tree
            || parent.object_format != "agent.managed-tree/v1"
        {
            return Err("managed parent object kind/format invalid".into());
        }
        let limits = self
            .admitted_limits
            .lock()
            .as_ref()
            .copied()
            .ok_or("managed admitted ceilings missing")?;
        let writable = policy.class().writable();
        let multiplier = if writable { 2 } else { 1 };
        let large = serde_json::to_vec(&ManagedArgumentIdentity::Inline {
            canonical_arguments: arguments.into(),
        })
        .map_err(error)?
        .len()
            > 4096;
        if arguments.len() > crate::config::MAX_TOOL_OUTPUT_BYTES {
            return Err("managed original arguments exceed bounded detail storage".into());
        }
        let detail_bytes = if large { arguments.len() as u64 } else { 0 };
        let bytes = self
            .runtime
            .config
            .quota
            .max_bytes
            .checked_mul(multiplier)
            .and_then(|bytes| {
                bytes.checked_add((limits.output_budget as u64).checked_mul(multiplier)?)
            })
            .and_then(|bytes| bytes.checked_add(detail_bytes))
            .ok_or("managed reservation overflow")?;
        let reservation = self
            .runtime
            .leases
            .reserve((if writable { 4 } else { 2 }) + usize::from(large), bytes)?;
        let detail = if large {
            Some(self.runtime.blob_object(
                ManagedObjectKind::IntentDetails,
                arguments.as_bytes(),
                crate::config::MAX_TOOL_OUTPUT_BYTES,
                &reservation,
            )?)
        } else {
            None
        };
        let argument_identity = match &detail {
            Some(object) => ManagedArgumentIdentity::Object {
                details: object.reference.clone(),
            },
            None => ManagedArgumentIdentity::Inline {
                canonical_arguments: arguments.into(),
            },
        };
        let identity = ManagedCallIdentity {
            owner: self.owner.clone(),
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            argument_identity,
            code: self.code.clone(),
            workspace: self.workspace.identity.clone(),
            epoch: head.epoch,
            expected_head: head.head_object_id,
            expected_head_version: head.head_version,
            original_deadline_ms: deadline_ms,
            authorization_generation: self.authority.generation(),
            approved_risk: risk.into(),
            approval_basis: if risk == "read" {
                ManagedApprovalBasis::ReadWithoutAttestation
            } else {
                ManagedApprovalBasis::GuardianAttested
            },
        };
        let call = Arc::new(ManagedCallContext {
            binding: Arc::downgrade(self),
            policy,
            identity,
            effect_id: fresh("effect"),
            receipt_id: fresh("receipt"),
            phase: Mutex::new(CallPhase::Registered),
            adapters: Mutex::new(None),
            prepared: Mutex::new(None),
            outcome: Mutex::new(None),
            closing: AtomicBool::new(false),
            native_operations: Mutex::new(0),
            operation_drained: parking_lot::Condvar::new(),
            reservation,
            parent,
            original_arguments: arguments.into(),
            _detail_object: detail,
        });
        self.calls.lock().insert(call_id.into(), Arc::clone(&call));
        Ok(call)
    }
}
#[derive(Clone, Copy, PartialEq)]
enum CallPhase {
    Registered,
    Executing,
    Preparing,
    Prepared,
    Final,
    Unknown,
}
struct NativePreparedObject {
    reference: ManagedObjectRef,
    _lease: ManagedObjectLease,
    handle: ManagedReadyHandle,
}
enum ManagedReadyHandle {
    Tree(ConfinedFsRoot),
    Blob(File),
}
pub(crate) enum ManagedViewRetention {
    Reclaimed,
    Retained,
}
pub(crate) struct ManagedAdapters {
    lifecycle: CapabilityLifecycle,
    pub(crate) filesystem: Arc<FilesystemCapability>,
    pub(crate) processes: Arc<ProcessCapability>,
    root: Arc<ConfinedFsRoot>,
    work: tree_store::WorkRoot,
    token: String,
    deadline: EffectDeadline,
    output_budget: usize,
    view_id: String,
    view_charge: Mutex<Option<ManagedObjectTicket>>,
}
pub(crate) struct PreparedEffectWitness {
    pub(crate) record: ManagedPreparedRecord,
    pub(crate) original: Value,
    pub(crate) conflict: Value,
    objects: Vec<NativePreparedObject>,
}
impl PreparedEffectWitness {
    pub(crate) fn check_ready(&self, runtime: &ManagedEffectRuntime) -> Result<(), String> {
        for object in &self.objects {
            match &object.handle {
                ManagedReadyHandle::Tree(root) => {
                    if !root.revalidate_binding() {
                        return Err("managed prepared tree identity changed".into());
                    }
                }
                ManagedReadyHandle::Blob(file) => {
                    let (current, _) = runtime
                        .open_blob(&object.reference, object.reference.object_kind.clone())?;
                    if file_identity(file)? != file_identity(&current)? {
                        return Err("managed prepared result identity changed".into());
                    }
                }
            }
        }
        Ok(())
    }
}
/// Unforgeable started binding; no public constructor or deserializer.
pub struct ManagedStartedWitness {
    pub(crate) call: Arc<ManagedCallContext>,
    pub(crate) started: crate::capabilities::DurableStarted,
}
/// Unforgeable prepared execution binding; audit DTOs cannot construct this.
pub struct ManagedFinalWitness {
    pub(crate) call: Arc<ManagedCallContext>,
    pub(crate) prepared: Arc<PreparedEffectWitness>,
}
pub(crate) struct ManagedCallContext {
    binding: Weak<ManagedRunBinding>,
    pub(crate) identity: ManagedCallIdentity,
    pub(crate) policy: Arc<SealedManagedCallPolicy>,
    pub(crate) effect_id: String,
    pub(crate) receipt_id: String,
    phase: Mutex<CallPhase>,
    adapters: Mutex<Option<Arc<ManagedAdapters>>>,
    prepared: Mutex<Option<Arc<PreparedEffectWitness>>>,
    closing: AtomicBool,
    outcome: Mutex<Option<ManagedCommitOutcome>>,
    native_operations: Mutex<usize>,
    operation_drained: parking_lot::Condvar,
    reservation: Arc<ManagedCallReservation>,
    parent: ManagedObjectRef,
    original_arguments: String,
    _detail_object: Option<NativePreparedObject>,
}
pub(crate) struct ManagedOperationEvidence {
    call: Arc<ManagedCallContext>,
}
impl Drop for ManagedOperationEvidence {
    fn drop(&mut self) {
        let mut active = self.call.native_operations.lock();
        *active -= 1;
        if *active == 0 {
            self.call.operation_drained.notify_all();
        }
    }
}
impl ManagedCallContext {
    pub(crate) fn check_current_generation(&self) -> Result<(), String> {
        let adapter = self
            .adapters
            .lock()
            .clone()
            .ok_or("managed view unavailable")?;
        adapter
            .lifecycle
            .ensure_generation(self.identity.authorization_generation)
            .map_err(error)
    }
    pub(crate) fn cleanup_final_view(&self) -> ManagedViewRetention {
        if *self.phase.lock() != CallPhase::Final || *self.native_operations.lock() != 0 {
            return ManagedViewRetention::Retained;
        }
        if !self.outcome.lock().as_ref().is_some_and(|outcome| {
            matches!(
                outcome.disposition,
                ManagedPublicationStatus::Committed
                    | ManagedPublicationStatus::ReadOnly
                    | ManagedPublicationStatus::Conflict
            )
        }) {
            return ManagedViewRetention::Retained;
        }
        let Some(adapter) = self.adapters.lock().clone() else {
            return ManagedViewRetention::Retained;
        };
        let Ok(binding) = self.binding() else {
            return ManagedViewRetention::Retained;
        };
        let Some(ticket) = adapter.view_charge.lock().take() else {
            return ManagedViewRetention::Retained;
        };
        let request = ManagedObjectReferencesRequest {
            store_id: binding.runtime.store_id.clone(),
            object_id: adapter.view_id.clone(),
        };
        #[cfg(feature = "workspace-io-fault")]
        if binding
            .runtime
            .take_fault(ManagedEffectFault::ObjectReferenceUnavailable)
        {
            binding
                .runtime
                .repository
                .inject_reference_transport_failure();
        }
        let can_reclaim = ticket.sole_known_lease()
            && binding
                .runtime
                .repository
                .object_references(&request, &binding.cancel)
                .is_ok_and(|references| references.is_empty())
            && binding.runtime.check().is_ok()
            && adapter.root.revalidate_binding();
        if !can_reclaim {
            *adapter.view_charge.lock() = Some(ticket);
            return ManagedViewRetention::Retained;
        }
        #[cfg(feature = "workspace-io-fault")]
        if binding.runtime.take_fault(ManagedEffectFault::OwnedCleanup) {
            *adapter.view_charge.lock() = Some(ticket);
            return ManagedViewRetention::Retained;
        }
        if tree_store::remove_owned_tree(adapter.work.path()).is_err() {
            *adapter.view_charge.lock() = Some(ticket);
            return ManagedViewRetention::Retained;
        }
        if ticket.retire().is_ok() {
            ManagedViewRetention::Reclaimed
        } else {
            ManagedViewRetention::Retained
        }
    }
    #[cfg(all(test, feature = "workspace-io-fault"))]
    fn active_native_operations(&self) -> usize {
        *self.native_operations.lock()
    }
    fn fence_for_prepare(&self) -> Result<(), String> {
        let _active = self.native_operations.lock();
        let mut phase = self.phase.lock();
        if *phase != CallPhase::Executing {
            return Err("managed preparation already fenced".into());
        }
        *phase = CallPhase::Preparing;
        self.closing.store(true, Ordering::Release);
        Ok(())
    }
    fn wait_operations_drained(&self, deadline: std::time::Instant) -> Result<(), String> {
        let mut active = self.native_operations.lock();
        while *active != 0 {
            if std::time::Instant::now() >= deadline {
                return Err("managed operation drain reached original deadline".into());
            }
            self.operation_drained.wait_until(&mut active, deadline);
        }
        Ok(())
    }
    pub(crate) fn enter_operation(
        self: &Arc<Self>,
        claims: &TokenClaims,
        operation: ManagedNativeOperation,
    ) -> Result<ManagedOperationEvidence, String> {
        if !self.policy.allows_operation(operation) {
            return Err("managed primitive denied by captured class".into());
        }
        self.authorize(claims, operation.required_risk())?;
        let mut active = self.native_operations.lock();
        if self.closing.load(Ordering::Acquire) || *self.phase.lock() != CallPhase::Executing {
            return Err("managed call closing".into());
        }
        if *active >= 32 {
            return Err("managed operation capacity exceeded".into());
        }
        *active += 1;
        Ok(ManagedOperationEvidence {
            call: Arc::clone(self),
        })
    }
    pub(crate) fn record_outcome(&self, outcome: &ManagedCommitOutcome) {
        *self.outcome.lock() = Some(outcome.clone());
    }
    pub(crate) fn publication(&self) -> Option<ManagedPublicationRef> {
        self.outcome
            .lock()
            .as_ref()
            .map(|outcome| outcome.publication.clone())
    }
    pub(crate) fn binding(&self) -> Result<Arc<ManagedRunBinding>, String> {
        self.binding
            .upgrade()
            .ok_or("managed binding unavailable".into())
    }
    pub(crate) fn record(&self) -> ManagedEffectRecord {
        ManagedEffectRecord {
            format: MANAGED_FORMAT.into(),
            effect_id: self.effect_id.clone(),
            schema_version: 1,
            identity: self.identity.clone(),
            state: ManagedPublicationStatus::Indeterminate,
            prepared: None,
            outcome: None,
            recovery: None,
        }
    }
    pub(crate) fn validate_started(
        &self,
        started: &crate::capabilities::DurableStarted,
    ) -> Result<(), String> {
        if started.argument_digest
            != self
                .binding()?
                .runtime
                .original_arguments(&self.identity.argument_identity)?
            || started.tool_name != self.identity.tool_name
            || started.registry_identity != self.identity.code.registry_identity
            || started.risk_class != self.policy.expected_risk()
            || started.risk_class.as_str() != self.identity.approved_risk
        {
            return Err("managed started facts mismatch".into());
        }
        Ok(())
    }
    pub(crate) fn bind_execution(
        self: &Arc<Self>,
        token: &str,
        claims: &TokenClaims,
        lifecycle: CapabilityLifecycle,
        owner: CapabilityOwner,
    ) -> Result<(), String> {
        let binding = self.binding()?;
        binding.check()?;
        let limits = binding
            .admitted_limits
            .lock()
            .as_ref()
            .copied()
            .ok_or("managed admitted ceilings missing")?;
        #[cfg(feature = "workspace-io-fault")]
        if binding.runtime.take_fault(ManagedEffectFault::AfterIntent) {
            return Err("managed fixture cut after durable intent".into());
        }
        self.check_token_binding(claims)?;
        if owner != claims.owner {
            return Err("managed token owner mismatch".into());
        }
        lifecycle
            .ensure_generation(claims.generation)
            .map_err(error)?;
        let (head, version) = (
            &self.identity.expected_head,
            self.identity.expected_head_version,
        );
        let _ = version;
        validate_id("tree", head)?;
        let source = binding
            .runtime
            .root
            .subroot(&format!("trees/{head}"), binding.runtime.root.limits())
            .map_err(error)?;
        let id = fresh("view");
        let path = binding.runtime.path.join("views").join(&id);
        let mut view_charge = self
            .reservation
            .take_object(binding.runtime.config.quota.max_bytes)?;
        view_charge.start(&id)?;
        let original = binding.cancel.clone();
        let cancellation = EffectCancellation::linked(move || {
            original.requested().is_some() || original.deadline_passed()
        });
        let copied = tree_store::copy_tree_from_fd(
            &source.duplicate_descriptor().map_err(error)?,
            &path,
            &binding.runtime.config.quota,
            &cancellation,
            &EffectDeadline::at(claims.deadline),
            false,
        )
        .map_err(error)?;
        let work = tree_store::WorkRoot::open(
            path,
            binding.runtime.config.quota,
            tree_store::Usage {
                entries: copied.entries,
                bytes: copied.bytes,
            },
        )
        .map_err(error)?;
        let root = Arc::new(
            binding
                .runtime
                .root
                .subroot(&format!("views/{id}"), binding.runtime.root.limits())
                .map_err(error)?,
        );
        let filesystem = Arc::new(
            FilesystemCapability::new_managed(
                lifecycle.clone(),
                owner.clone(),
                limits.filesystem,
                Arc::clone(&root),
                binding.authority.grant(),
                Arc::downgrade(self),
            )
            .map_err(error)?,
        );
        #[cfg(test)]
        if let Some(observer) = binding.runtime.native_write_observer.lock().clone() {
            let call = Arc::downgrade(self);
            filesystem.inject_before_write(Arc::new(move |_, _| {
                let call = call.upgrade().ok_or_else(|| {
                    crate::capabilities::CapabilityError::new(
                        "managed_call_unavailable",
                        "managed call unavailable",
                    )
                })?;
                observer(call);
                Ok(())
            }));
        }
        let processes = Arc::new(
            ProcessCapability::new_managed(
                lifecycle.clone(),
                owner,
                limits.process,
                Arc::clone(&root),
                binding.authority.grant(),
                Arc::downgrade(self),
            )
            .map_err(error)?,
        );
        #[cfg(test)]
        if binding
            .runtime
            .close_after_native_spawn
            .swap(false, Ordering::SeqCst)
        {
            let process_owner = Arc::clone(&processes);
            processes.set_after_os_spawn_hook(Arc::new(move || process_owner.shutdown_all()));
        }
        *self.adapters.lock() = Some(Arc::new(ManagedAdapters {
            lifecycle,
            filesystem,
            processes,
            root,
            work,
            token: token.into(),
            deadline: EffectDeadline::at(claims.deadline),
            output_budget: claims.output_budget,
            view_id: id,
            view_charge: Mutex::new(Some(view_charge)),
        }));
        *self.phase.lock() = CallPhase::Executing;
        #[cfg(test)]
        let observer = binding.runtime.native_ready_observer.lock().clone();
        #[cfg(test)]
        if let Some(observer) = observer {
            observer(Arc::clone(self));
        }
        Ok(())
    }
    pub(crate) fn adapters(&self, token: &str) -> Result<Arc<ManagedAdapters>, String> {
        let adapter = self
            .adapters
            .lock()
            .clone()
            .ok_or("managed view unavailable")?;
        if adapter.token != token {
            return Err("managed sibling token denied".into());
        }
        Ok(adapter)
    }
    pub(crate) fn authorize(
        &self,
        claims: &TokenClaims,
        risk: CapabilityRisk,
    ) -> Result<(), String> {
        self.check_token_binding(claims)?;
        if self.closing.load(Ordering::Acquire) || *self.phase.lock() != CallPhase::Executing {
            return Err("managed call closing".into());
        }
        if risk != CapabilityRisk::Read && risk != self.policy.expected_risk() {
            return Err("managed operation ceiling mismatch".into());
        }
        Ok(())
    }
    fn check_token_binding(&self, claims: &TokenClaims) -> Result<(), String> {
        let binding = self.binding()?;
        binding.check()?;
        if !self.policy.matches(
            &binding.policy_catalog,
            &binding.code,
            &self.identity.tool_name,
        ) || claims.risk_ceiling != self.policy.expected_risk()
            || claims.owner.profile() != self.identity.owner.profile
            || claims.owner.session() != self.identity.owner.session_id
            || claims.owner.run() != self.identity.owner.run_id
            || claims.call_id != self.identity.call_id
            || claims.tool_name != self.identity.tool_name
            || claims.argument_digest != self.original_arguments
            || claims.registry_identity != self.identity.code.registry_identity
            || claims.generation != self.identity.authorization_generation
            || claims.deadline_ms != self.identity.original_deadline_ms
            || claims.workspace != Path::new(binding.authority.canonical_path())
            || claims.risk_ceiling.as_str() != self.identity.approved_risk
            || self.identity.code != binding.code
            || self.identity.workspace != binding.workspace.identity
        {
            return Err("managed call closing or identity mismatch".into());
        }
        Ok(())
    }
    pub(crate) fn accounted_write<T, E>(
        &self,
        token: &str,
        path: &str,
        bytes: &[u8],
        publish: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, crate::capabilities::CapabilityError> {
        let binding = self.binding().map_err(|e| {
            crate::capabilities::CapabilityError::new("managed_call_unavailable", e)
        })?;
        let adapter = self.adapters(token).map_err(|e| {
            crate::capabilities::CapabilityError::new("managed_call_unavailable", e)
        })?;
        let original = binding.cancel.clone();
        let cancellation = EffectCancellation::linked(move || {
            original.requested().is_some() || original.deadline_passed()
        });
        adapter
            .work
            .with_accounted_atomic_write(path, bytes, &cancellation, &adapter.deadline, publish)
            .map_err(|e| {
                crate::capabilities::CapabilityError::new("budget_exceeded", e.to_string())
            })
    }
    pub(crate) fn prepare_result(
        &self,
        token: &str,
        result: &Value,
    ) -> Result<Arc<PreparedEffectWitness>, String> {
        let binding = self.binding()?;
        binding.check()?;
        self.fence_for_prepare()?;
        self.wait_operations_drained(
            binding
                .cancel
                .deadline_instant()
                .ok_or("managed original deadline missing")?,
        )?;
        let adapter = self.adapters(token)?;
        let writer = adapter
            .processes
            .settle_managed_call(token)
            .map_err(error)?;
        #[cfg(feature = "workspace-io-fault")]
        if binding
            .runtime
            .take_fault(ManagedEffectFault::AfterOperationBeforePrepare)
        {
            return Err("managed fixture cut after actual operation".into());
        }
        #[cfg(test)]
        let fixture_result = binding.runtime.canonical_observation_fixture.lock().take();
        #[cfg(test)]
        let result = fixture_result.as_ref().unwrap_or(result);
        let canonical = CanonicalToolResultJson::from_value(result)?;
        let parent = self.parent.clone();
        let writable = self.policy.class().writable();
        let ok = result["ok"] == true;
        let candidate = if writable && ok {
            Some(binding.runtime.prepare_tree(
                &adapter.root,
                &binding.cancel,
                true,
                Some(&self.reservation),
            )?)
        } else {
            None
        };
        let original =
            binding
                .runtime
                .result_object(&canonical, adapter.output_budget, &self.reservation)?;
        let conflict = json!({"ok":false,"content":"","data":{},"error":{"code":"effect_head_conflict","message":"managed branch head changed; original observation and candidate remain staged"},"truncated":false,"artifacts":[]});
        let conflict_ref = if candidate.is_some() {
            Some(binding.runtime.result_object(
                &CanonicalToolResultJson::from_value(&conflict)?,
                adapter.output_budget,
                &self.reservation,
            )?)
        } else {
            None
        };
        let record = ManagedPreparedRecord {
            format: MANAGED_FORMAT.into(),
            schema_version: 1,
            effect_id: self.effect_id.clone(),
            identity: self.identity.clone(),
            parent_root: parent,
            candidate_root: candidate.as_ref().map(|object| object.reference.clone()),
            canonical_result: original.reference.clone(),
            conflict_result: conflict_ref.as_ref().map(|object| object.reference.clone()),
            writer_state: writer,
            operation_class: if writable {
                ManagedOperationClass::TreeWrite
            } else {
                ManagedOperationClass::ReadOnly
            },
            prepared_at_ms: crate::domain::timestamp(),
            observation_ok: ok,
            external_effects: self.policy.class().external_effects(),
        };
        self.reservation.release_unspent();
        let mut objects = vec![original];
        if let Some(candidate) = candidate {
            objects.push(candidate);
        }
        if let Some(conflict) = conflict_ref {
            objects.push(conflict);
        }
        #[cfg(feature = "workspace-io-fault")]
        if binding
            .runtime
            .take_fault(ManagedEffectFault::AfterObjectsSynced)
        {
            return Err("managed fixture cut after immutable objects synced".into());
        }
        let cut = {
            #[cfg(feature = "workspace-io-fault")]
            {
                if binding
                    .runtime
                    .take_fault(ManagedEffectFault::PrepareAfterObjectRegistry)
                {
                    "PrepareAfterObjectRegistry"
                } else {
                    ""
                }
            }
            #[cfg(not(feature = "workspace-io-fault"))]
            {
                ""
            }
        };
        binding.runtime.repository.command_with_cancellation("effect.prepare",&json!({"effect_id":self.effect_id,"receipt_id":self.receipt_id,"prepared_json":serde_json::to_string(&record).map_err(error)?,"cut":cut}),&binding.cancel)?;
        let witness = Arc::new(PreparedEffectWitness {
            record,
            original: serde_json::from_str(canonical.as_str()).map_err(error)?,
            conflict,
            objects,
        });
        *self.prepared.lock() = Some(Arc::clone(&witness));
        *self.phase.lock() = CallPhase::Prepared;
        #[cfg(feature = "workspace-io-fault")]
        if binding
            .runtime
            .take_fault(ManagedEffectFault::AfterPrepared)
        {
            return Err("managed fixture cut after durable preparation".into());
        }
        #[cfg(feature = "workspace-io-fault")]
        {
            let gate = binding.runtime.prepare_gate.lock().clone();
            if let Some(gate) = gate
                && gate
                    .call_id
                    .as_deref()
                    .is_none_or(|id| id == self.identity.call_id)
            {
                gate.arrive(
                    binding
                        .cancel
                        .deadline_instant()
                        .ok_or("managed original deadline missing")?,
                )?;
            }
        }
        Ok(witness)
    }
    pub(crate) fn witness(&self) -> Result<Arc<PreparedEffectWitness>, String> {
        self.prepared
            .lock()
            .clone()
            .ok_or("managed prepared witness unavailable".into())
    }
    pub(crate) fn interrupt_unpublished(&self) {
        let mut phase = self.phase.lock();
        if *phase != CallPhase::Final {
            *phase = CallPhase::Unknown;
            self.closing.store(true, Ordering::Release);
        }
        drop(phase);
        // Only unused admission capacity is released. Every started ticket,
        // physical candidate and durable reference keeps its separate charge.
        self.reservation.release_unspent();
    }
    pub(crate) fn finalize(&self, known: bool) {
        *self.phase.lock() = if known {
            CallPhase::Final
        } else {
            CallPhase::Unknown
        };
        self.reservation.release_unspent();
    }
}
