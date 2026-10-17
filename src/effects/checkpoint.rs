//! Checkpoint documents and branch restore for one Native filesystem workspace.
//!
//! A checkpoint records the immutable root, lineage, and epoch. Plugin state,
//! graph lock, and history cursor stay explicitly out of scope.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
use yaml_rust2::YamlLoader;
use yaml_rust2::parser::{Event, Parser};

use super::types::{
    BranchEpoch, BranchId, CheckpointId, EffectError, EffectErrorKind, ExternalEffectNotice,
    ImportConsistency, JournalEntry, JournalKind, MAX_LINEAGE, OwnerId, PublicCheckpointRef,
    TreeId, WorkspaceId,
};
use super::workspace::{BranchRecord, EffectStore, WorkspaceHandle};

const FORMAT: &str = "rustscript.checkpoint/v1";
const NOT_IN_SCOPE: &str = "not_in_scope";
const MAX_YAML_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRecord {
    format: String,
    checkpoint_id: CheckpointId,
    workspace_id: WorkspaceId,
    owner_id: OwnerId,
    branch_id: BranchId,
    lineage: Vec<BranchId>,
    immutable_root: TreeId,
    epoch: BranchEpoch,
    parent_head: TreeId,
    active_writers: u64,
    import_consistency: ImportConsistency,
    external_effects_not_reverted: Vec<ExternalEffectNotice>,
}

impl CheckpointRecord {
    pub fn checkpoint_id(&self) -> &CheckpointId {
        &self.checkpoint_id
    }

    pub fn immutable_root(&self) -> &TreeId {
        &self.immutable_root
    }

    pub fn active_writers(&self) -> u64 {
        self.active_writers
    }

    pub fn external_effects_not_reverted(&self) -> &[ExternalEffectNotice] {
        &self.external_effects_not_reverted
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(&self.document()).expect("checkpoint document is serializable")
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self.document()).expect("checkpoint document is serializable")
    }

    fn document(&self) -> CheckpointDocument {
        CheckpointDocument {
            format: self.format.clone(),
            checkpoint_id: self.checkpoint_id.as_str().to_string(),
            workspace_id: self.workspace_id.as_str().to_string(),
            owner_id: self.owner_id.as_str().to_string(),
            branch_id: self.branch_id.as_str().to_string(),
            lineage: self
                .lineage
                .iter()
                .map(|branch| branch.as_str().to_string())
                .collect(),
            immutable_root: self.immutable_root.as_str().to_string(),
            epoch: self.epoch.get(),
            parent_head: self.parent_head.as_str().to_string(),
            active_writers: self.active_writers,
            import_consistency: self.import_consistency.as_str().to_string(),
            plugin_state: ScopeStatus {
                availability: NOT_IN_SCOPE.to_string(),
            },
            graph: ScopeStatus {
                availability: NOT_IN_SCOPE.to_string(),
            },
            history: ScopeStatus {
                availability: NOT_IN_SCOPE.to_string(),
            },
            external_effects_not_reverted: self.external_effects_not_reverted.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointDocument {
    format: String,
    checkpoint_id: String,
    workspace_id: String,
    owner_id: String,
    branch_id: String,
    lineage: Vec<String>,
    immutable_root: String,
    epoch: u64,
    parent_head: String,
    active_writers: u64,
    import_consistency: String,
    plugin_state: ScopeStatus,
    graph: ScopeStatus,
    history: ScopeStatus,
    external_effects_not_reverted: Vec<ExternalEffectNotice>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeStatus {
    availability: String,
}

#[derive(Clone, Debug)]
pub struct RestoredBranch {
    pub handle: WorkspaceHandle,
    pub previous_branch: BranchId,
    pub head: TreeId,
    pub epoch: BranchEpoch,
    pub external_effects_not_reverted: Vec<ExternalEffectNotice>,
}

impl WorkspaceHandle {
    pub fn checkpoint(
        &self,
        request: super::types::CheckpointRequest,
    ) -> Result<CheckpointRecord, EffectError> {
        request.deadline.check()?;
        request.cancellation.poll_quiet()?;
        let mut state = self.store.state.lock();
        let workspace = self.workspace_mut(&mut state)?;
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
        if !branch.writers.is_empty() {
            return Err(EffectError::new(
                EffectErrorKind::CheckpointBusy,
                "a writable view is still open",
            ));
        }
        let head = branch.head.clone();
        let epoch = branch.epoch;
        let record = CheckpointRecord {
            format: FORMAT.to_string(),
            checkpoint_id: CheckpointId::fresh(),
            workspace_id: self.workspace_id.clone(),
            owner_id: self.owner_id.clone(),
            branch_id: self.branch_id.clone(),
            lineage: workspace.lineage.clone(),
            immutable_root: head.clone(),
            epoch,
            parent_head: head.clone(),
            active_writers: 0,
            import_consistency: workspace.import_consistency,
            external_effects_not_reverted: Vec::new(),
        };
        write_checkpoint_file(&self.store.root, &record)?;
        workspace
            .checkpoints
            .insert(record.checkpoint_id.clone(), record.clone());
        workspace.journal.push(JournalEntry {
            kind: JournalKind::Checkpoint,
            branch_id: self.branch_id.clone(),
            head,
            epoch,
        });
        Ok(record)
    }

    pub fn restore(
        &self,
        request: super::types::RestoreRequest,
    ) -> Result<RestoredBranch, EffectError> {
        request.deadline.check()?;
        request.cancellation.poll_quiet()?;
        let mut state = self.store.state.lock();
        let workspace = self.workspace_mut(&mut state)?;
        if workspace.revoked {
            return Err(revoked());
        }
        let current = workspace
            .branches
            .get(&self.branch_id)
            .ok_or_else(|| not_found("branch"))?;
        if current.epoch != self.epoch {
            return Err(stale());
        }
        if !current.writers.is_empty() {
            return Err(EffectError::new(
                EffectErrorKind::Busy,
                "a writable view is still open",
            ));
        }
        if request.expected_epoch != current.epoch {
            return Err(stale());
        }
        if request.expected_head != current.head {
            return Err(EffectError::new(
                EffectErrorKind::Conflict,
                "expected head does not match",
            ));
        }
        let bumped = current.epoch.next();
        let record = workspace
            .checkpoints
            .get(&request.checkpoint_id)
            .cloned()
            .ok_or_else(|| not_found("checkpoint"))?;
        let previous_branch = self.branch_id.clone();
        let restored_head = record.immutable_root.clone();
        workspace
            .branches
            .get_mut(&self.branch_id)
            .expect("branch exists")
            .epoch = bumped;
        let new_branch = BranchId::fresh();
        workspace.branches.insert(
            new_branch.clone(),
            BranchRecord {
                epoch: bumped,
                head: restored_head.clone(),
                writers: Default::default(),
            },
        );
        workspace.lineage.push(new_branch.clone());
        workspace.journal.push(JournalEntry {
            kind: JournalKind::Restored,
            branch_id: new_branch.clone(),
            head: restored_head.clone(),
            epoch: bumped,
        });
        let handle = WorkspaceHandle {
            store: std::sync::Arc::clone(&self.store),
            workspace_id: self.workspace_id.clone(),
            owner_id: self.owner_id.clone(),
            branch_id: new_branch,
            epoch: bumped,
            secret: self.secret.clone(),
        };
        Ok(RestoredBranch {
            handle,
            previous_branch,
            head: restored_head,
            epoch: bumped,
            external_effects_not_reverted: Vec::new(),
        })
    }
}

impl EffectStore {
    pub fn restore_from_public_ids(
        &self,
        _checkpoint: &PublicCheckpointRef,
    ) -> Result<RestoredBranch, EffectError> {
        Err(EffectError::new(
            EffectErrorKind::AuthorityRequired,
            "public identifiers cannot restore a branch",
        ))
    }
}

pub fn parse_checkpoint_yaml(text: &str) -> Result<CheckpointRecord, EffectError> {
    if text.len() > MAX_YAML_BYTES {
        return Err(schema("checkpoint yaml exceeds 65536 bytes"));
    }
    reject_yaml_constructs(text)?;
    let documents = YamlLoader::load_from_str(text).map_err(|error| schema(error.to_string()))?;
    if documents.len() != 1 {
        return Err(schema("checkpoint yaml must contain one document"));
    }
    let document: CheckpointDocument =
        serde_yaml::from_str(text).map_err(|error| schema(error.to_string()))?;
    document.into_record()
}

/// Production pre-conversion scanner used by [`parse_checkpoint_yaml`].
///
/// Test seam only: it does not restore a branch or accept a checkpoint.
#[doc(hidden)]
pub fn pre_conversion_yaml_error(text: &str) -> Result<(), EffectError> {
    reject_yaml_constructs(text)
}

impl CheckpointDocument {
    fn into_record(self) -> Result<CheckpointRecord, EffectError> {
        if self.format != FORMAT {
            return Err(schema("format is not rustscript.checkpoint/v1"));
        }
        if self.active_writers != 0 {
            return Err(schema("active_writers must be 0"));
        }
        if self.lineage.is_empty() || self.lineage.len() > MAX_LINEAGE {
            return Err(schema("lineage length is outside 1..=64"));
        }
        for scope in [&self.plugin_state, &self.graph, &self.history] {
            if scope.availability != NOT_IN_SCOPE {
                return Err(schema("plugin, graph, and history cannot be snapshotted"));
            }
        }
        if !self.external_effects_not_reverted.is_empty() {
            return Err(schema("this version records no remote effect"));
        }
        Ok(CheckpointRecord {
            format: self.format,
            checkpoint_id: CheckpointId::parse(&self.checkpoint_id)?,
            workspace_id: WorkspaceId::parse(&self.workspace_id)?,
            owner_id: OwnerId::parse(&self.owner_id)?,
            branch_id: BranchId::parse(&self.branch_id)?,
            lineage: self
                .lineage
                .iter()
                .map(|branch| BranchId::parse(branch))
                .collect::<Result<Vec<_>, _>>()?,
            immutable_root: TreeId::parse(&self.immutable_root)?,
            epoch: BranchEpoch::from_raw(self.epoch)?,
            parent_head: TreeId::parse(&self.parent_head)?,
            active_writers: 0,
            import_consistency: ImportConsistency::parse(&self.import_consistency)?,
            external_effects_not_reverted: self.external_effects_not_reverted,
        })
    }
}

fn write_checkpoint_file(
    root: &std::path::Path,
    record: &CheckpointRecord,
) -> Result<(), EffectError> {
    let final_path = root
        .join("checkpoints")
        .join(format!("{}.yaml", record.checkpoint_id));
    let temporary = PathBuf::from(format!("{}.tmp", final_path.display()));
    let payload = record.to_yaml();
    {
        let mut file = File::create(&temporary).map_err(|error| {
            EffectError::new(
                EffectErrorKind::Io,
                format!("create checkpoint failed: {error}"),
            )
        })?;
        file.write_all(payload.as_bytes()).map_err(|error| {
            EffectError::new(
                EffectErrorKind::Io,
                format!("write checkpoint failed: {error}"),
            )
        })?;
        file.sync_all().map_err(|error| {
            EffectError::new(
                EffectErrorKind::Io,
                format!("sync checkpoint failed: {error}"),
            )
        })?;
    }
    fs::rename(&temporary, &final_path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        EffectError::new(
            EffectErrorKind::Io,
            format!("rename checkpoint failed: {error}"),
        )
    })?;
    super::tree_store::fsync_dir(&root.join("checkpoints"))?;
    Ok(())
}

fn reject_yaml_constructs(text: &str) -> Result<(), EffectError> {
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<YamlFrame> = Vec::new();
    loop {
        let (event, _) = parser
            .next_token()
            .map_err(|error| schema(error.to_string()))?;
        match event {
            Event::StreamEnd => break,
            Event::Alias(_) => return Err(schema("yaml alias is not allowed")),
            Event::Scalar(value, _, anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(schema("yaml anchor or tag is not allowed"));
                }
                if let Some(YamlFrame::Mapping { expect_key, seen }) = stack.last_mut() {
                    if *expect_key {
                        if value == "<<" {
                            return Err(schema("yaml merge is not allowed"));
                        }
                        if !seen.insert(value) {
                            return Err(schema("duplicate yaml key before conversion"));
                        }
                    }
                    *expect_key = !*expect_key;
                }
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag)
                if anchor != 0 || tag.is_some() =>
            {
                return Err(schema("yaml anchor or tag is not allowed"));
            }
            Event::MappingStart(_, _) => stack.push(YamlFrame::mapping()),
            Event::SequenceStart(_, _) => stack.push(YamlFrame::Sequence),
            Event::MappingEnd | Event::SequenceEnd => {
                stack.pop();
                if let Some(YamlFrame::Mapping { expect_key, .. }) = stack.last_mut() {
                    *expect_key = !*expect_key;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

enum YamlFrame {
    Mapping {
        expect_key: bool,
        seen: HashSet<String>,
    },
    Sequence,
}

impl YamlFrame {
    fn mapping() -> Self {
        Self::Mapping {
            expect_key: true,
            seen: HashSet::new(),
        }
    }
}

fn schema(message: impl Into<String>) -> EffectError {
    EffectError::new(EffectErrorKind::SchemaRejected, message)
}

fn not_found(what: &str) -> EffectError {
    EffectError::new(EffectErrorKind::NotFound, format!("{what} was not found"))
}

fn stale() -> EffectError {
    EffectError::new(EffectErrorKind::StaleEpoch, "branch epoch changed")
}

fn revoked() -> EffectError {
    EffectError::new(EffectErrorKind::Revoked, "workspace capability was revoked")
}
