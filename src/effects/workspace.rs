//! Native workspace views, immutable roots, and compare-and-swap publish.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use super::tree_store::{self, Usage, WorkRoot};
#[cfg(feature = "workspace-io-fault")]
use super::tree_store::{
    IoFaultSlot, FAULT_FILE_FSYNC, FAULT_OWNED_CLEANUP, FAULT_PARTIAL_WRITE,
    FAULT_POST_RENAME_CHMOD, FAULT_POST_RENAME_DIR_FSYNC,
};
use super::types::{
    BranchEpoch, BranchId, CapabilitySecret, EffectError, EffectErrorKind, EffectFailure,
    ImportConsistency, ImportWorkspace, JournalEntry, JournalKind, OpenViewRequest, OwnerId,
    PublicWorkspaceRef, Publication, PublishRequest, ResourceQuota, TreeId, WorkspaceId,
};

pub(crate) struct StoreInner {
    pub(crate) root: PathBuf,
    pub(crate) state: Mutex<StoreState>,
    #[cfg(feature = "workspace-io-fault")]
    io_fault: IoFaultSlot,
}

pub(crate) struct StoreState {
    pub(crate) workspaces: HashMap<WorkspaceId, WorkspaceRecord>,
}

pub(crate) struct WorkspaceRecord {
    pub(crate) secret: CapabilitySecret,
    pub(crate) owner_id: OwnerId,
    pub(crate) quota: ResourceQuota,
    pub(crate) import_consistency: ImportConsistency,
    pub(crate) branches: HashMap<BranchId, BranchRecord>,
    pub(crate) lineage: Vec<BranchId>,
    pub(crate) trees: HashSet<TreeId>,
    pub(crate) checkpoints:
        HashMap<super::types::CheckpointId, super::checkpoint::CheckpointRecord>,
    pub(crate) journal: Vec<JournalEntry>,
    pub(crate) revoked: bool,
}

pub(crate) struct BranchRecord {
    pub(crate) epoch: BranchEpoch,
    pub(crate) head: TreeId,
    pub(crate) writers: HashSet<String>,
}

#[derive(Clone)]
pub struct EffectStore {
    inner: Arc<StoreInner>,
}

impl fmt::Debug for EffectStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectStore")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}

impl EffectStore {
    pub fn create(root: impl AsRef<Path>) -> Result<Self, EffectError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir(&root).map_err(|error| {
            EffectError::new(EffectErrorKind::Io, format!("create store failed: {error}"))
        })?;
        for name in ["trees", "views", "checkpoints", "staging"] {
            let path = root.join(name);
            fs::create_dir(&path).map_err(|error| {
                EffectError::new(
                    EffectErrorKind::Io,
                    format!("create {name} failed: {error}"),
                )
            })?;
            tree_store::chmod_dir(&path, 0o700)?;
        }
        tree_store::chmod_dir(&root, 0o700)?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                root,
                state: Mutex::new(StoreState {
                    workspaces: HashMap::new(),
                }),
                #[cfg(feature = "workspace-io-fault")]
                io_fault: IoFaultSlot::new(),
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub fn import_workspace(
        &self,
        request: ImportWorkspace,
    ) -> Result<WorkspaceHandle, EffectError> {
        request.deadline.check()?;
        let tree_id = TreeId::fresh();
        let staging = self.staging_path(&tree_id);
        let copied = tree_store::copy_tree(
            &request.source,
            &staging,
            &request.quota,
            &request.cancellation,
            &request.deadline,
            true,
        )?;
        let published = self.tree_path(&tree_id);
        if let Err(error) = fs::rename(&staging, &published) {
            let _ = tree_store::remove_tree(&staging);
            return Err(EffectError::new(
                EffectErrorKind::Io,
                format!("publish import tree failed: {error}"),
            ));
        }
        if let Err(error) = self.inner.seal_published_tree(&published) {
            return Err(self.inner.cleanup_owned_published(&published, error));
        }
        let _ = copied;
        let workspace_id = WorkspaceId::fresh();
        let owner_id = OwnerId::fresh();
        let branch_id = BranchId::fresh();
        let secret = CapabilitySecret::fresh();
        let epoch = BranchEpoch::initial();
        let mut state = self.inner.state.lock();
        state.workspaces.insert(
            workspace_id.clone(),
            WorkspaceRecord {
                secret: secret.clone(),
                owner_id: owner_id.clone(),
                quota: request.quota,
                import_consistency: ImportConsistency::OrdinaryCopy,
                branches: HashMap::from([(
                    branch_id.clone(),
                    BranchRecord {
                        epoch,
                        head: tree_id.clone(),
                        writers: HashSet::new(),
                    },
                )]),
                lineage: vec![branch_id.clone()],
                trees: HashSet::from([tree_id.clone()]),
                checkpoints: HashMap::new(),
                journal: vec![JournalEntry {
                    kind: JournalKind::Imported,
                    branch_id: branch_id.clone(),
                    head: tree_id,
                    epoch,
                }],
                revoked: false,
            },
        );
        Ok(WorkspaceHandle {
            store: Arc::clone(&self.inner),
            workspace_id,
            owner_id,
            branch_id,
            epoch,
            secret,
        })
    }

    pub fn open_view_from_public_ids(
        &self,
        _workspace: &PublicWorkspaceRef,
    ) -> Result<WritableView, EffectError> {
        Err(EffectError::new(
            EffectErrorKind::AuthorityRequired,
            "public identifiers cannot open a writable view",
        ))
    }

    pub fn revoke(&self, handle: &WorkspaceHandle) -> Result<(), EffectError> {
        handle.revoke()
    }

    fn tree_path(&self, tree: &TreeId) -> PathBuf {
        self.inner.root.join("trees").join(tree.as_str())
    }

    fn staging_path(&self, tree: &TreeId) -> PathBuf {
        self.inner.root.join("staging").join(tree.as_str())
    }
}

#[derive(Clone)]
pub struct WorkspaceHandle {
    pub(crate) store: Arc<StoreInner>,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) owner_id: OwnerId,
    pub(crate) branch_id: BranchId,
    pub(crate) epoch: BranchEpoch,
    pub(crate) secret: CapabilitySecret,
}

impl fmt::Debug for WorkspaceHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceHandle")
            .field("workspace_id", &self.workspace_id)
            .field("owner_id", &self.owner_id)
            .field("branch_id", &self.branch_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl WorkspaceHandle {
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn branch_id(&self) -> &BranchId {
        &self.branch_id
    }

    pub fn epoch(&self) -> BranchEpoch {
        self.epoch
    }

    pub fn head(&self) -> TreeId {
        let state = self.store.state.lock();
        state
            .workspaces
            .get(&self.workspace_id)
            .and_then(|workspace| workspace.branches.get(&self.branch_id))
            .map(|branch| branch.head.clone())
            .unwrap_or_else(TreeId::fresh)
    }

    pub fn public_ref(&self) -> PublicWorkspaceRef {
        PublicWorkspaceRef {
            workspace_id: self.workspace_id.clone(),
            branch_id: self.branch_id.clone(),
            head: self.head(),
            epoch: self.epoch,
        }
    }

    pub fn journal(&self) -> Vec<JournalEntry> {
        let state = self.store.state.lock();
        state
            .workspaces
            .get(&self.workspace_id)
            .filter(|workspace| workspace.secret == self.secret)
            .map(|workspace| workspace.journal.clone())
            .unwrap_or_default()
    }

    pub fn lineage(&self) -> Vec<BranchId> {
        let state = self.store.state.lock();
        state
            .workspaces
            .get(&self.workspace_id)
            .filter(|workspace| workspace.secret == self.secret)
            .map(|workspace| workspace.lineage.clone())
            .unwrap_or_default()
    }

    pub fn immutable_path(&self, tree: &TreeId) -> Result<PathBuf, EffectError> {
        let state = self.store.state.lock();
        let workspace = self.workspace(&state)?;
        if !workspace.trees.contains(tree) {
            return Err(not_found("tree"));
        }
        Ok(self.store.root.join("trees").join(tree.as_str()))
    }

    pub fn checkpoint_path(&self, id: &super::types::CheckpointId) -> Result<PathBuf, EffectError> {
        let state = self.store.state.lock();
        let workspace = self.workspace(&state)?;
        if !workspace.checkpoints.contains_key(id) {
            return Err(not_found("checkpoint"));
        }
        Ok(self
            .store
            .root
            .join("checkpoints")
            .join(format!("{id}.yaml")))
    }

    pub fn read_committed(&self, rel: &str) -> Result<Vec<u8>, EffectError> {
        let path = {
            let state = self.store.state.lock();
            let workspace = self.workspace(&state)?;
            if workspace.revoked {
                return Err(revoked());
            }
            let branch = workspace
                .branches
                .get(&self.branch_id)
                .ok_or_else(|| not_found("branch"))?;
            self.store.root.join("trees").join(branch.head.as_str())
        };
        let dir = open_tree(&path)?;
        tree_store::read_from(&dir, rel)
    }

    pub fn open_view(&self, request: OpenViewRequest) -> Result<WritableView, EffectError> {
        request.deadline.check()?;
        request.cancellation.poll()?;
        let view_id = format!("view-{}", uuid::Uuid::new_v4().simple());
        let quota = {
            let mut state = self.store.state.lock();
            let workspace = self.workspace_mut(&mut state)?;
            if workspace.revoked {
                return Err(revoked());
            }
            let branch = workspace
                .branches
                .get_mut(&self.branch_id)
                .ok_or_else(|| not_found("branch"))?;
            if branch.epoch != self.epoch || request.expected_epoch != branch.epoch {
                return Err(stale());
            }
            if branch.head != request.expected_head {
                return Err(conflict("expected head does not match"));
            }
            branch.writers.insert(view_id.clone());
            workspace.quota
        };
        let view_dir = self.store.root.join("views").join(&view_id);
        let work_path = view_dir.join("work");
        let temp_path = view_dir.join("tmp");
        let opened = (|| {
            fs::create_dir(&view_dir).map_err(|error| {
                EffectError::new(EffectErrorKind::Io, format!("create view failed: {error}"))
            })?;
            tree_store::chmod_dir(&view_dir, 0o700)?;
            fs::create_dir(&temp_path).map_err(|error| {
                EffectError::new(EffectErrorKind::Io, format!("create temp failed: {error}"))
            })?;
            tree_store::chmod_dir(&temp_path, 0o700)?;
            let source = self
                .store
                .root
                .join("trees")
                .join(request.expected_head.as_str());
            let copied = tree_store::copy_tree(
                &source,
                &work_path,
                &quota,
                &request.cancellation,
                &request.deadline,
                false,
            )?;
            WorkRoot::open(
                work_path,
                quota,
                Usage {
                    entries: copied.entries,
                    bytes: copied.bytes,
                },
            )
        })();
        match opened {
            Ok(work) => Ok(WritableView {
                store: Arc::clone(&self.store),
                workspace_id: self.workspace_id.clone(),
                owner_id: self.owner_id.clone(),
                branch_id: self.branch_id.clone(),
                epoch: self.epoch,
                secret: self.secret.clone(),
                view_id,
                view_dir,
                temp_path,
                work,
                released: AtomicBool::new(false),
            }),
            Err(error) => {
                let _ = tree_store::remove_tree(&view_dir);
                self.release_writer(&view_id);
                Err(error)
            }
        }
    }

    // The error carries the live view so the caller can discard or retry it.
    #[allow(clippy::result_large_err)]
    pub fn publish(
        &self,
        view: WritableView,
        request: PublishRequest,
    ) -> Result<Publication, EffectFailure<WritableView>> {
        if let Err(error) = self.prepare_publish(&view, &request) {
            return Err(EffectFailure::new(error, view));
        }
        let tree_id = TreeId::fresh();
        let staging = self.store.root.join("staging").join(tree_id.as_str());
        let quota = {
            let state = self.store.state.lock();
            match self.workspace(&state) {
                Ok(workspace) => workspace.quota,
                Err(error) => return Err(EffectFailure::new(error, view)),
            }
        };
        if let Err(error) = tree_store::copy_tree(
            view.work.path(),
            &staging,
            &quota,
            &request.cancellation,
            &request.deadline,
            true,
        ) {
            let _ = tree_store::remove_tree(&staging);
            return Err(EffectFailure::new(error, view));
        }
        match self.commit_publish(&view, &request, &tree_id, &staging) {
            Ok(publication) => {
                view.detach();
                Ok(publication)
            }
            Err(error) => {
                let _ = tree_store::remove_tree(&staging);
                Err(EffectFailure::new(error, view))
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn discard(&self, view: WritableView) -> Result<(), EffectFailure<WritableView>> {
        if let Err(error) = self.reject_foreign_view(&view) {
            return Err(EffectFailure::new(error, view));
        }
        let head = self.head();
        view.detach();
        self.append_journal(JournalKind::Discarded, head);
        Ok(())
    }

    fn reject_foreign_view(&self, view: &WritableView) -> Result<(), EffectError> {
        if view.secret != self.secret
            || view.owner_id != self.owner_id
            || view.workspace_id != self.workspace_id
        {
            return Err(owner_mismatch());
        }
        if view.branch_id != self.branch_id {
            return Err(conflict("view belongs to another branch"));
        }
        if view.epoch != self.epoch {
            return Err(stale());
        }
        Ok(())
    }

    pub fn revoke(&self) -> Result<(), EffectError> {
        let mut state = self.store.state.lock();
        let workspace = self.workspace_mut(&mut state)?;
        workspace.revoked = true;
        for branch in workspace.branches.values_mut() {
            branch.epoch = branch.epoch.next();
        }
        Ok(())
    }

    pub(crate) fn workspace<'a>(
        &self,
        state: &'a StoreState,
    ) -> Result<&'a WorkspaceRecord, EffectError> {
        let workspace = state
            .workspaces
            .get(&self.workspace_id)
            .ok_or_else(|| not_found("workspace"))?;
        if workspace.secret != self.secret || workspace.owner_id != self.owner_id {
            return Err(authority_required());
        }
        Ok(workspace)
    }

    pub(crate) fn workspace_mut<'a>(
        &self,
        state: &'a mut StoreState,
    ) -> Result<&'a mut WorkspaceRecord, EffectError> {
        let workspace = state
            .workspaces
            .get_mut(&self.workspace_id)
            .ok_or_else(|| not_found("workspace"))?;
        if workspace.secret != self.secret || workspace.owner_id != self.owner_id {
            return Err(authority_required());
        }
        Ok(workspace)
    }

    fn prepare_publish(
        &self,
        view: &WritableView,
        request: &PublishRequest,
    ) -> Result<(), EffectError> {
        request.deadline.check()?;
        request.cancellation.poll()?;
        if view.secret != self.secret
            || view.owner_id != self.owner_id
            || view.workspace_id != self.workspace_id
        {
            return Err(owner_mismatch());
        }
        Ok(())
    }

    fn commit_publish(
        &self,
        view: &WritableView,
        request: &PublishRequest,
        tree_id: &TreeId,
        staging: &Path,
    ) -> Result<Publication, EffectError> {
        {
            let mut state = self.store.state.lock();
            self.validate_publish(&mut state, view, request)?;
        }
        let published = self.store.root.join("trees").join(tree_id.as_str());
        fs::rename(staging, &published).map_err(|error| {
            EffectError::new(
                EffectErrorKind::Io,
                format!("rename published tree failed: {error}"),
            )
        })?;
        if let Err(error) = self.store.seal_published_tree(&published) {
            return Err(self.store.cleanup_owned_published(&published, error));
        }
        let finished = {
            let mut state = self.store.state.lock();
            self.finish_publish(&mut state, view, request, tree_id)
        };
        match finished {
            Ok(publication) => Ok(publication),
            Err(error) => Err(self.store.cleanup_owned_published(&published, error)),
        }
    }

    fn validate_publish(
        &self,
        state: &mut StoreState,
        view: &WritableView,
        request: &PublishRequest,
    ) -> Result<(), EffectError> {
        let workspace = self.workspace_mut(state)?;
        if workspace.revoked {
            return Err(revoked());
        }
        let branch = workspace
            .branches
            .get(&self.branch_id)
            .ok_or_else(|| not_found("branch"))?;
        if branch.epoch != self.epoch || request.expected_epoch != branch.epoch {
            return Err(stale());
        }
        if branch.head != request.expected_head || !branch.writers.contains(&view.view_id) {
            return Err(conflict("head or writer changed before publish"));
        }
        Ok(())
    }

    fn finish_publish(
        &self,
        state: &mut StoreState,
        view: &WritableView,
        request: &PublishRequest,
        tree_id: &TreeId,
    ) -> Result<Publication, EffectError> {
        self.validate_publish(state, view, request)?;
        let workspace = self.workspace_mut(state)?;
        let branch = workspace
            .branches
            .get_mut(&self.branch_id)
            .ok_or_else(|| not_found("branch"))?;
        let previous_head = branch.head.clone();
        branch.head = tree_id.clone();
        branch.writers.remove(&view.view_id);
        let epoch = branch.epoch;
        workspace.trees.insert(tree_id.clone());
        workspace.journal.push(JournalEntry {
            kind: JournalKind::Published,
            branch_id: self.branch_id.clone(),
            head: tree_id.clone(),
            epoch,
        });
        Ok(Publication {
            head: tree_id.clone(),
            epoch,
            previous_head,
        })
    }

    fn release_writer(&self, view_id: &str) {
        let mut state = self.store.state.lock();
        let Ok(workspace) = self.workspace_mut(&mut state) else {
            return;
        };
        let Some(branch) = workspace.branches.get_mut(&self.branch_id) else {
            return;
        };
        branch.writers.remove(view_id);
    }

    fn append_journal(&self, kind: JournalKind, head: TreeId) {
        let mut state = self.store.state.lock();
        if let Ok(workspace) = self.workspace_mut(&mut state) {
            let epoch = workspace
                .branches
                .get(&self.branch_id)
                .map(|branch| branch.epoch)
                .unwrap_or(self.epoch);
            workspace.journal.push(JournalEntry {
                kind,
                branch_id: self.branch_id.clone(),
                head,
                epoch,
            });
        }
    }
}

pub struct WritableView {
    store: Arc<StoreInner>,
    workspace_id: WorkspaceId,
    owner_id: OwnerId,
    branch_id: BranchId,
    epoch: BranchEpoch,
    secret: CapabilitySecret,
    view_id: String,
    view_dir: PathBuf,
    temp_path: PathBuf,
    work: WorkRoot,
    released: AtomicBool,
}

impl fmt::Debug for WritableView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WritableView")
            .field("work", &self.work.path())
            .finish_non_exhaustive()
    }
}

impl WritableView {
    pub fn work_root(&self) -> &Path {
        self.work.path()
    }

    pub fn private_temp(&self) -> &Path {
        &self.temp_path
    }

    pub fn write_file(&self, rel: &str, bytes: &[u8]) -> Result<(), EffectError> {
        self.ensure_live()?;
        self.work.write_file(rel, bytes)
    }

    pub fn read_file(&self, rel: &str) -> Result<Vec<u8>, EffectError> {
        self.work.read_file(rel)
    }

    pub fn delete(&self, rel: &str) -> Result<(), EffectError> {
        self.ensure_live()?;
        self.work.delete(rel)
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), EffectError> {
        self.ensure_live()?;
        self.work.rename(from, to)
    }

    pub fn create_dir(&self, rel: &str) -> Result<(), EffectError> {
        self.ensure_live()?;
        self.work.create_dir(rel)
    }

    pub fn set_executable(&self, rel: &str, executable: bool) -> Result<(), EffectError> {
        self.ensure_live()?;
        self.work.set_executable(rel, executable)
    }

    pub fn list(&self, rel: &str) -> Result<Vec<String>, EffectError> {
        self.work.list(rel)
    }

    fn ensure_live(&self) -> Result<(), EffectError> {
        if self.released.load(Ordering::SeqCst) {
            return Err(stale());
        }
        let state = self.store.state.lock();
        let workspace = state
            .workspaces
            .get(&self.workspace_id)
            .ok_or_else(|| not_found("workspace"))?;
        if workspace.secret != self.secret || workspace.owner_id != self.owner_id {
            return Err(authority_required());
        }
        if workspace.revoked {
            return Err(revoked());
        }
        let branch = workspace
            .branches
            .get(&self.branch_id)
            .ok_or_else(|| not_found("branch"))?;
        if branch.epoch != self.epoch {
            return Err(stale());
        }
        Ok(())
    }

    fn detach(&self) {
        self.finalize();
    }

    fn finalize(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        self.release_originating_writer();
        let _ = tree_store::remove_tree(&self.view_dir);
    }

    fn release_originating_writer(&self) {
        let mut state = self.store.state.lock();
        let Some(workspace) = state.workspaces.get_mut(&self.workspace_id) else {
            return;
        };
        if workspace.secret != self.secret {
            return;
        }
        if let Some(branch) = workspace.branches.get_mut(&self.branch_id) {
            branch.writers.remove(&self.view_id);
        }
    }
}

impl Drop for WritableView {
    fn drop(&mut self) {
        self.finalize();
    }
}

#[cfg(feature = "workspace-io-fault")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedIoFault {
    PartialWrite { errno: i32 },
    FileFsync { errno: i32 },
    PostRenameChmod { errno: i32 },
    PostRenameDirFsync { errno: i32 },
    OwnedCleanup { errno: i32 },
}

#[cfg(feature = "workspace-io-fault")]
impl SimulatedIoFault {
    pub const EIO: i32 = libc::EIO;
    pub const ENOSPC: i32 = libc::ENOSPC;

    fn checked(self) -> Result<(u8, i32), EffectError> {
        let (point, errno) = match self {
            Self::PartialWrite { errno } => (FAULT_PARTIAL_WRITE, errno),
            Self::FileFsync { errno } => (FAULT_FILE_FSYNC, errno),
            Self::PostRenameChmod { errno } => (FAULT_POST_RENAME_CHMOD, errno),
            Self::PostRenameDirFsync { errno } => (FAULT_POST_RENAME_DIR_FSYNC, errno),
            Self::OwnedCleanup { errno } => (FAULT_OWNED_CLEANUP, errno),
        };
        if errno != libc::EIO && errno != libc::ENOSPC {
            return Err(EffectError::new(
                EffectErrorKind::InvalidConfiguration,
                "simulated I/O fault errno must be EIO or ENOSPC",
            ));
        }
        Ok((point, errno))
    }
}

#[cfg(feature = "workspace-io-fault")]
impl EffectStore {
    pub fn arm_simulated_io_fault(&self, fault: SimulatedIoFault) -> Result<(), EffectError> {
        let (point, errno) = fault.checked()?;
        self.inner.io_fault.arm(point, errno);
        Ok(())
    }
}

#[cfg(feature = "workspace-io-fault")]
impl WritableView {
    pub fn arm_simulated_io_fault(&self, fault: SimulatedIoFault) -> Result<(), EffectError> {
        let (point, errno) = fault.checked()?;
        match point {
            FAULT_PARTIAL_WRITE | FAULT_FILE_FSYNC => self.work.arm_io_fault(point, errno),
            _ => self.store.io_fault.arm(point, errno),
        }
        Ok(())
    }

    pub fn accounted_usage(&self) -> (u64, u64) {
        self.work.usage_snapshot()
    }
}

impl StoreInner {
    fn cleanup_owned_published(&self, published: &Path, error: EffectError) -> EffectError {
        let tree_id = published
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if self.tree_is_registered(tree_id) {
            return EffectError::new(
                error.kind(),
                format!("{error}; refusing to remove a registered tree"),
            );
        }
        #[cfg(feature = "workspace-io-fault")]
        if let Some(code) = self.io_fault.take(FAULT_OWNED_CLEANUP) {
            let cleanup = tree_store::simulated_io("cleanup", code);
            return EffectError::new(
                error.kind(),
                format!("{error}; owned tree cleanup failed: {cleanup}"),
            );
        }
        match tree_store::remove_owned_tree(published) {
            Ok(()) => error,
            Err(cleanup) => EffectError::new(
                error.kind(),
                format!("{error}; owned tree cleanup failed: {cleanup}"),
            ),
        }
    }

    fn tree_is_registered(&self, tree_id: &str) -> bool {
        if tree_id.is_empty() {
            return true;
        }
        let state = self.state.lock();
        state.workspaces.values().any(|workspace| {
            workspace
                .trees
                .iter()
                .any(|registered| registered.as_str() == tree_id)
        })
    }

    fn seal_published_tree(&self, published: &Path) -> Result<(), EffectError> {
        #[cfg(feature = "workspace-io-fault")]
        if let Some(code) = self.io_fault.take(FAULT_POST_RENAME_CHMOD) {
            return Err(tree_store::simulated_io("fchmod", code));
        }
        tree_store::chmod_dir(published, 0o555)?;
        #[cfg(feature = "workspace-io-fault")]
        if let Some(code) = self.io_fault.take(FAULT_POST_RENAME_DIR_FSYNC) {
            return Err(tree_store::simulated_io("fsync", code));
        }
        tree_store::fsync_dir(&self.root.join("trees"))
    }
}

fn open_tree(path: &Path) -> Result<std::os::fd::OwnedFd, EffectError> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| EffectError::new(EffectErrorKind::RejectedPath, "tree path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(EffectError::new(
            EffectErrorKind::Io,
            "open immutable tree failed",
        ))
    } else {
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
}

fn not_found(what: &str) -> EffectError {
    EffectError::new(EffectErrorKind::NotFound, format!("{what} was not found"))
}

fn stale() -> EffectError {
    EffectError::new(EffectErrorKind::StaleEpoch, "branch epoch changed")
}

fn conflict(message: &str) -> EffectError {
    EffectError::new(EffectErrorKind::Conflict, message)
}

fn revoked() -> EffectError {
    EffectError::new(EffectErrorKind::Revoked, "workspace capability was revoked")
}

fn authority_required() -> EffectError {
    EffectError::new(
        EffectErrorKind::AuthorityRequired,
        "native capability is required",
    )
}

fn owner_mismatch() -> EffectError {
    EffectError::new(
        EffectErrorKind::OwnerMismatch,
        "view owner does not match the handle",
    )
}
