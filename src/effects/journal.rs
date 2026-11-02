//! Named managed-effect protocol over the formal RSS storage worker.
use crate::gateway::store::{GatewayPersistence, StorageError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedMaintenanceFailure {
    Rejected {
        code: String,
    },
    SubmittedUnknown {
        request_id: String,
        receipt_lookup_id: String,
    },
}
impl std::fmt::Display for ManagedMaintenanceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected { code } => code,
            Self::SubmittedUnknown { .. } => "managed_submitted_unknown",
        })
    }
}
impl std::error::Error for ManagedMaintenanceFailure {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedSavedCheckpointReceipt {
    pub(crate) original_request_proof: String,
    pub(crate) receipt: ManagedCheckpointReceipt,
}

pub const MANAGED_FORMAT: &str = "agent.managed-effect/v1";
pub const WORKSPACE_FORMAT: &str = "agent.managed-workspace/v1";
pub const METADATA_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSourceCas {
    pub store_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub epoch: u64,
    pub head_object_id: String,
    pub head_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCheckpointMode {
    AtClosedBatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckpointCreateRequest {
    pub source_run_id: String,
    pub workspace_id: String,
    pub source_branch_id: String,
    pub expected_epoch: u64,
    pub request_id: String,
    pub mode: ManagedCheckpointMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedClosedOutputRef {
    pub run_id: String,
    pub call_id: String,
    pub parent_message_id: String,
    pub output_message_id: String,
    pub receipt_id: String,
    pub result: ManagedObjectRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFrozenHistoryRef {
    pub history_root_id: String,
    pub source_session_id: String,
    pub session_generation: u64,
    pub last_message_id: String,
    pub last_ordinal: u64,
    pub last_closed_batch_id: String,
    pub message_count: usize,
    pub byte_count: usize,
    pub closed_output_refs: Vec<ManagedClosedOutputRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckpointGraphRef {
    pub graph_id: String,
    pub harness_selection: crate::plugins::HarnessSelection,
    pub checkpoint_graph_ref_id: String,
    pub captured_activation_generation: u64,
    pub package_id: String,
    pub artifact_id: String,
    pub export: String,
    pub registry_identity: String,
    pub effect_contract_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckpointPublicConfig {
    pub model: String,
    pub provider: Option<String>,
    pub system_instructions: Option<String>,
    pub registry_identity: String,
    pub tool_schemas_ref: String,
    pub policy_revision: String,
    pub publication_policy: ManagedCheckpointPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCheckpointPublication {
    ManagedOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPublicConfigRef {
    pub config_ref_id: String,
    pub config: ManagedCheckpointPublicConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPluginStateRootRef {
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub scope: String,
    pub schema: String,
    pub revision: u64,
    pub immutable_root_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedCheckpointStateCoverage {
    Stateful {
        graph_id: String,
        package_id: String,
        artifact_id: String,
        manifest_state_present: bool,
        invocation_excluded_from_checkpoint: bool,
        roots: Vec<ManagedPluginStateRootRef>,
    },
    StatelessBuiltinWithPurePolicy {
        graph_id: String,
        package_id: String,
        artifact_id: String,
        policy: crate::plugins::PurePolicySelection,
        manifest_state_absent: bool,
        state_effects_absent: bool,
        policy_host_imports_absent: bool,
        roots: Vec<ManagedPluginStateRootRef>,
    },
    StatelessBuiltin {
        graph_id: String,
        package_id: String,
        artifact_id: String,
        manifest_state_absent: bool,
        state_effects_absent: bool,
        roots: Vec<ManagedPluginStateRootRef>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedExternalHighWater {
    pub run_id: String,
    pub event_seq: u64,
    pub provider_request_count: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedExternalNotice {
    ProviderUsageNotReverted,
    DeliveredContentNotReverted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckpointArtifactRef {
    pub artifact_id: String,
    pub object: ManagedObjectRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedExternalBoundary {
    pub high_water: Vec<ManagedExternalHighWater>,
    pub not_reverted: Vec<ManagedExternalNotice>,
    pub artifact_refs: Vec<ManagedCheckpointArtifactRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckpointRef {
    pub checkpoint_id: String,
    pub workspace_id: String,
    pub parent_run_id: String,
    pub source_branch_id: String,
    pub source_epoch: u64,
    pub frozen_root: ManagedObjectRef,
    pub history: ManagedFrozenHistoryRef,
    pub graph: ManagedCheckpointGraphRef,
    pub public_config: ManagedPublicConfigRef,
    pub plugin_state: ManagedCheckpointStateCoverage,
    pub external_boundary: ManagedExternalBoundary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckpointReceipt {
    pub request_id: String,
    pub checkpoint: ManagedCheckpointRef,
    pub committed_at_ms: u64,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedBranchCreateRequest {
    pub workspace_id: String,
    pub source_branch_id: String,
    pub checkpoint_id: Option<String>,
    pub expected_source: Option<ManagedSourceCas>,
    pub request_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedBranchReceipt {
    pub request_id: String,
    pub checkpoint_id: Option<String>,
    pub source: ManagedSourceCas,
    pub branch: ManagedSourceCas,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedSavedBranchReceipt {
    pub proof: String,
    pub receipt: ManagedBranchReceipt,
    pub origin: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPublishRequest {
    pub workspace_id: String,
    pub branch_id: String,
    pub expected_head: ManagedWorkspaceHead,
    pub request_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPublishReceipt {
    pub status: String,
    pub workspace_id: String,
    pub profile: String,
    pub branch_id: String,
    pub epoch: u64,
    pub head_object_id: String,
    pub head_version: u64,
    pub previous_published_head: Option<String>,
    pub request_id: String,
    pub published_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkspacePublication {
    pub workspace_id: String,
    pub profile: String,
    pub branch_id: String,
    pub epoch: u64,
    pub head_object_id: String,
    pub head_version: u64,
    pub previous_published_head: Option<String>,
    pub request_id: String,
    pub published_at_ms: u64,
    pub revision: u64,
    pub store_id: String,
    pub schema_version: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedSavedPublishReceipt {
    pub proof: String,
    pub receipt: ManagedPublishReceipt,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedPublishEligibility {
    pub code: String,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreRunInput {
    pub text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRestoreGraphSelection {
    CheckpointExact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreAndAdmitRequest {
    pub workspace_id: String,
    pub source_branch_id: String,
    pub checkpoint_id: String,
    pub expected_source: ManagedSourceCas,
    pub request_id: String,
    pub input: ManagedRestoreRunInput,
    pub cancel_active_source: bool,
    pub graph_selection: ManagedRestoreGraphSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRestoreDisposition {
    RestoredAndAdmitted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreAndAdmitResult {
    pub disposition: ManagedRestoreDisposition,
    pub receipt_id: String,
    pub checkpoint_id: String,
    pub source_before: ManagedSourceCas,
    pub source_after: ManagedSourceCas,
    pub new_branch: ManagedSourceCas,
    pub new_session_id: String,
    pub new_run_id: String,
    pub new_run_deadline_at_ms: u64,
    pub graph: ManagedCheckpointGraphRef,
    pub publication: ManagedCheckpointPublication,
    pub external_effects_not_reverted: Vec<ManagedExternalNotice>,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOwnerScope {
    pub profile: String,
    pub session_id: String,
    pub run_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device_decimal: String,
    pub inode_decimal: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkspaceIdentity {
    pub store_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub source_identity: DirectoryIdentity,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCodeIdentity {
    pub graph_id: String,
    pub activation_generation: u64,
    pub graph_ref_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub export: String,
    pub registry_identity: String,
    pub effect_contract_version: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedObjectKind {
    Tree,
    CanonicalResult,
    IntentDetails,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedObjectRef {
    pub store_id: String,
    pub object_id: String,
    pub object_kind: ManagedObjectKind,
    pub byte_count: String,
    pub entry_count: String,
    pub object_format: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedArgumentIdentity {
    Inline { canonical_arguments: String },
    Object { details: ManagedObjectRef },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedApprovalBasis {
    ReadWithoutAttestation,
    GuardianAttested,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCallIdentity {
    pub owner: ManagedOwnerScope,
    pub call_id: String,
    pub tool_name: String,
    pub argument_identity: ManagedArgumentIdentity,
    pub code: ManagedCodeIdentity,
    pub workspace: ManagedWorkspaceIdentity,
    pub epoch: u64,
    pub expected_head: String,
    pub expected_head_version: u64,
    pub original_deadline_ms: u64,
    pub authorization_generation: u64,
    pub approved_risk: String,
    pub approval_basis: ManagedApprovalBasis,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationClass {
    ReadOnly,
    TreeWrite,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedWriterState {
    Settled,
    NoProcess,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedExternalEffects {
    NoneClaimed,
    OutsideTreeNotReverted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPreparedStatePublication {
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub schema_version: u32,
    pub expected_revision: u64,
    pub expected_object_id: String,
    pub object_id: String,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPreparedRecord {
    pub format: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub effect_id: String,
    pub identity: ManagedCallIdentity,
    pub parent_root: ManagedObjectRef,
    pub candidate_root: Option<ManagedObjectRef>,
    pub canonical_result: ManagedObjectRef,
    pub conflict_result: Option<ManagedObjectRef>,
    pub writer_state: ManagedWriterState,
    pub operation_class: ManagedOperationClass,
    pub prepared_at_ms: u64,
    pub observation_ok: bool,
    pub external_effects: ManagedExternalEffects,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_state: Option<ManagedPreparedStatePublication>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPublicationStatus {
    ReadOnly,
    Committed,
    Staged,
    Conflict,
    NotPublished,
    Indeterminate,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPublicationRef {
    pub format: String,
    pub effect_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub epoch: u64,
    pub base_head: String,
    pub base_head_version: u64,
    pub candidate_head: Option<String>,
    pub observed_head: String,
    pub observed_head_version: u64,
    pub status: ManagedPublicationStatus,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEventRef {
    pub event_id: String,
    pub seq: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedMessageRef {
    pub id: String,
    pub ordinal: i64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCommitOutcome {
    pub disposition: ManagedPublicationStatus,
    pub publication: ManagedPublicationRef,
    pub canonical_result_ref: ManagedObjectRef,
    pub output_event: ManagedEventRef,
    pub terminal_event: ManagedEventRef,
    pub message: ManagedMessageRef,
    pub replayed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkspaceRecord {
    pub format: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub identity: ManagedWorkspaceIdentity,
    pub profile: String,
    pub seed_root: ManagedObjectRef,
    pub max_entries: u64,
    pub max_bytes: u64,
    pub max_depth: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkspaceHead {
    pub workspace_id: String,
    pub branch_id: String,
    pub epoch: u64,
    pub head_object_id: String,
    pub head_version: u64,
    pub store_id: String,
    pub schema_version: u32,
    pub process_lineage_tainted: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectGetRequest {
    pub owner: ManagedOwnerScope,
    pub call_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRunEffectListRequest {
    pub run_id: String,
    pub after_effect_id: Option<String>,
    pub limit: usize,
}

/// Closed public failures. Private Native/storage diagnostics never cross HTTP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedRunEffectError {
    InvalidRequest,
    Unavailable,
    StorageUnavailable,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedRunQueryBinding {
    pub owner: ManagedOwnerScope,
    pub workspace: ManagedWorkspaceIdentity,
    pub epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectListRequest {
    pub workspace_id: String,
    pub after_effect_id: Option<String>,
    pub limit: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectSummary {
    pub effect_id: String,
    pub run_id: String,
    pub call_id: String,
    pub state: ManagedPublicationStatus,
    pub workspace_id: String,
    pub branch_id: String,
    pub epoch: u64,
    pub prepared_at_ms: Option<u64>,
    pub decided_at_ms: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectPage {
    pub entries: Vec<ManagedEffectSummary>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResultReadRequest {
    pub effect_id: String,
    pub offset: u64,
    pub limit: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResultChunk {
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
    pub total_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedObjectReferenceKind {
    RegisteredObject,
    Seed,
    BranchHead,
    History,
    CallBase,
    PreparedCandidate,
    PreparedResult,
    PreparedConflict,
    SelectedResult,
    IntentDetails,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedObjectReferencesRequest {
    pub store_id: String,
    pub object_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedObjectReference {
    pub store_id: String,
    pub object_id: String,
    pub reference_kind: ManagedObjectReferenceKind,
    pub reference_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalToolResultJson {
    json: String,
}
impl CanonicalToolResultJson {
    pub fn as_str(&self) -> &str {
        &self.json
    }
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        crate::capabilities::lifecycle::validate_canonical_result(value)
            .map_err(|e| e.code().to_string())?;
        if value.as_object().is_none_or(|fields| {
            fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "ok" | "content" | "data" | "error" | "truncated" | "artifacts"
                )
            })
        }) {
            return Err("guest result fields denied".into());
        }
        // RSS map carriers omit null fields. Canonicalize once through the
        // existing observation decoder before sealing bytes, so the live result,
        // immutable receipt and typed durable facade have the same envelope.
        let result =
            crate::service::canonical_tool_result(value).map_err(|e| e.code().to_string())?;
        let canonical = serde_json::to_value(result).map_err(|e| e.to_string())?;
        Ok(Self {
            json: serde_json::to_string(&canonical).map_err(|e| e.to_string())?,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRecoveryObservation {
    pub code: String,
    pub publication: ManagedPublicationRef,
    pub canonical_failure_json: CanonicalToolResultJson,
    pub output_event: ManagedEventRef,
    pub terminal_event: ManagedEventRef,
    pub message: ManagedMessageRef,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectRecord {
    pub format: String,
    pub effect_id: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub identity: ManagedCallIdentity,
    pub state: ManagedPublicationStatus,
    pub prepared: Option<ManagedPreparedRecord>,
    pub outcome: Option<ManagedCommitOutcome>,
    pub recovery: Option<ManagedRecoveryObservation>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedCallReplay {
    Final {
        outcome: Box<ManagedCommitOutcome>,
        canonical_result: CanonicalToolResultJson,
    },
    Staged {
        record: Box<ManagedEffectRecord>,
    },
    Indeterminate {
        record: Box<ManagedEffectRecord>,
    },
    Unavailable {
        code: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedFrozenMessage {
    pub id: String,
    pub ordinal: u64,
    pub role: String,
    pub content_json: String,
    pub metadata_json: String,
    pub run_id: Option<String>,
    pub name: Option<String>,
    pub tool_call_id: Option<String>,
    pub parent_message_id: Option<String>,
    pub finish_reason: Option<String>,
    pub token_estimate: Option<i64>,
    pub compacted: bool,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedSourceRunRef {
    pub run_id: String,
    pub session_id: String,
    pub status: String,
    pub original_deadline_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedFrozenCompaction {
    pub id: String,
    pub generation: u64,
    pub source_start_ordinal: u64,
    pub source_end_ordinal: u64,
    pub retained_tail_ordinal: u64,
    pub summary_json: String,
    pub token_estimate: i64,
    pub model: String,
    pub created_at_ms: u64,
    pub completed_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedFrozenProviderOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedFrozenExecutionConfig {
    pub provider_profile: String,
    pub provider_options: ManagedFrozenProviderOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedCheckpointContext {
    pub workspace: ManagedWorkspaceRecord,
    pub head: ManagedWorkspaceHead,
    pub session_id: String,
    pub session_generation: u64,
    pub last_ordinal: u64,
    pub messages: Vec<ManagedFrozenMessage>,
    pub effects: Vec<ManagedEffectRecord>,
    pub external: Vec<ManagedExternalHighWater>,
    pub unsettled_runs: usize,
    pub source_runs: Vec<ManagedSourceRunRef>,
    pub pending_compactions: usize,
    pub compaction: Option<ManagedFrozenCompaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedCheckpointCommitInput {
    pub request: ManagedCheckpointCreateRequest,
    pub original_request_proof: String,
    pub captured_source: ManagedSourceCas,
    pub receipt: ManagedCheckpointReceipt,
    pub messages: Vec<ManagedFrozenMessage>,
    pub compaction: Option<ManagedFrozenCompaction>,
    pub execution_config: ManagedFrozenExecutionConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedCheckpointLookup {
    pub checkpoint: ManagedCheckpointRef,
    pub messages: Vec<ManagedFrozenMessage>,
    pub compaction: Option<ManagedFrozenCompaction>,
    pub execution_config: ManagedFrozenExecutionConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedAdmissionPin {
    pub harness_selection: crate::plugins::HarnessSelection,
    pub graph_id: String,
    pub ref_id: String,
    pub generation: u64,
    pub run_id: String,
    pub session_id: String,
    pub registry_identity: String,
    pub workspace: String,
    pub profile: String,
    pub pinned: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedRollbackFacts {
    pub source: ManagedSourceCas,
    pub current_branch_id: String,
    pub target_rows: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedBranchPublication {
    pub graph: ManagedCheckpointGraphRef,
    pub source: ManagedSourceCas,
    pub current: ManagedSourceCas,
    pub history_count: usize,
    pub admission_pin: ManagedAdmissionPin,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedRestoreExecutionEnvelope {
    pub admission_pin: ManagedAdmissionPin,
    pub request: ManagedRestoreAndAdmitRequest,
    pub original_request_proof: String,
    pub result: ManagedRestoreAndAdmitResult,
    pub history_root_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedSavedRestoreReceipt {
    checkpoint_graph: ManagedCheckpointGraphRef,
    original_request_proof: String,
    envelope: ManagedRestoreExecutionEnvelope,
}

#[derive(Clone)]
pub(crate) struct ManagedEffectRepository {
    persistence: Arc<GatewayPersistence>,
}
impl ManagedEffectRepository {
    pub(crate) fn new(persistence: Arc<GatewayPersistence>) -> Self {
        Self { persistence }
    }
    pub(crate) fn command_with_cancellation(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, String> {
        for field in ["record_json", "prepared_json", "workspace_json"] {
            if let Some(text) = payload
                .get(field)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
            {
                let validation = managed_document(text);
                #[cfg(feature = "workspace-io-fault")]
                let validation = validation.inspect_err(|error| {
                    eprintln!("managed document validation rejected {field}: {error}");
                });
                validation?;
            }
        }
        self.persistence
            .managed_effect_command_with_cancellation(op, payload, cancellation)
            .map_err(|e| match e.code.as_str() {
                "plugin_graph_revoked" | "plugin_graph_pin_required" => e.code,
                _ => e.to_string(),
            })
    }
    pub(crate) fn command_with_cancellation_and_owner(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, String> {
        for field in ["record_json", "prepared_json", "workspace_json"] {
            if let Some(text) = payload
                .get(field)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
            {
                let validation = managed_document(text);
                #[cfg(feature = "workspace-io-fault")]
                let validation = validation.inspect_err(|error| {
                    eprintln!("managed document validation rejected {field}: {error}");
                });
                validation?;
            }
        }
        self.persistence
            .managed_effect_command_with_cancellation_and_owner(
                op,
                payload,
                cancellation,
                state_owner,
            )
            .map_err(|e| match e.code.as_str() {
                "plugin_graph_revoked" | "plugin_graph_pin_required" => e.code,
                _ => e.to_string(),
            })
    }
    /// Settle sidecar for commit requests: re-reserves the already-durable
    /// prepared state object for the duration of one commit request. Never
    /// fails the caller: if the registry is full the commit still proceeds,
    /// protected by the atomic prepared-to-root/binding handoff executed by
    /// the same single worker.
    pub(crate) fn try_reserve_state_owner(
        &self,
        object_id: &str,
    ) -> Option<crate::plugins::PluginStateCandidateLease> {
        self.persistence
            .plugin_state_candidates
            .reserve(object_id)
            .ok()
    }
    pub(crate) fn checkpoint_receipt(
        &self,
        request: &ManagedCheckpointCreateRequest,
        cancellation: &crate::RunCancellation,
        claim: Option<&Arc<crate::gateway::store::ManagedMaintenanceClaim>>,
    ) -> Result<Option<ManagedCheckpointReceipt>, String> {
        let proof =
            serde_json::to_string(request).map_err(|_| "managed_metadata_budget_exceeded")?;
        let payload = json!({"workspace_id":request.workspace_id,"receipt_id":request.request_id,"cut":"checkpoint"});
        let result = if let Some(claim) = claim {
            self.persistence.maintenance_read(
                claim,
                &claim.identity,
                &proof,
                "effect.maintenance_receipt",
                &payload,
                cancellation,
            )?
        } else {
            self.command_with_cancellation("effect.maintenance_receipt", &payload, cancellation)?
        };
        let Some(saved): Option<ManagedSavedCheckpointReceipt> = decode_record(&result)? else {
            return Ok(None);
        };
        let original: ManagedCheckpointCreateRequest =
            serde_json::from_str(&saved.original_request_proof)
                .map_err(|_| "managed_restore_reconciliation_required")?;
        if original != *request {
            return Err("managed_request_conflict".into());
        }
        if saved.receipt.request_id != request.request_id
            || saved.receipt.checkpoint.workspace_id != request.workspace_id
            || saved.receipt.checkpoint.source_branch_id != request.source_branch_id
            || saved.receipt.checkpoint.parent_run_id != request.source_run_id
            || saved.receipt.checkpoint.source_epoch != request.expected_epoch
        {
            return Err("managed_restore_reconciliation_required".into());
        }
        Ok(Some(saved.receipt))
    }
    pub(crate) fn maintenance_claim(
        &self,
        identity: ManagedWorkspaceIdentity,
        proof: String,
        request_id: String,
        action: &'static str,
    ) -> Result<Arc<crate::gateway::store::ManagedMaintenanceClaim>, String> {
        self.persistence
            .maintenance_claim(identity, proof, request_id, action)
    }
    pub(crate) fn checkpoint_submit(
        &self,
        input: &ManagedCheckpointCommitInput,
        cancellation: &crate::RunCancellation,
        claim: &Arc<crate::gateway::store::ManagedMaintenanceClaim>,
    ) -> Result<ManagedCheckpointReceipt, String> {
        let payload = json!({"maintenance_json":serde_json::to_string(input).map_err(|_| "managed_metadata_budget_exceeded")?});
        let result = self
            .persistence
            .maintenance_submit(claim, &payload, cancellation)
            .map_err(|error| error.code)?;
        let receipt: ManagedCheckpointReceipt = decode_record(&result)
            .map_err(|_| "managed_submitted_unknown")?
            .ok_or("managed_submitted_unknown")?;
        if receipt != input.receipt {
            return Err("managed_submitted_unknown".into());
        }
        Ok(receipt)
    }
    pub(crate) fn checkpoint_context(
        &self,
        request: &ManagedCheckpointCreateRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedCheckpointContext, String> {
        let result = self.command_with_cancellation(
            "effect.checkpoint_context",
            &json!({"run_id": request.source_run_id, "workspace_id": request.workspace_id,
                "branch_id": request.source_branch_id, "profile": crate::config::ADMISSION_SESSION_PROFILE}),
            cancellation,
        )?;
        decode_record(&result)?.ok_or_else(|| "managed_authority_required".into())
    }
    pub(crate) fn lookup_restore_receipt(
        &self,
        request: &ManagedRestoreAndAdmitRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedRestoreAndAdmitResult>, String> {
        self.lookup_restore_receipt_claim(request, cancellation, None)
    }
    pub(crate) fn lookup_restore_receipt_claim(
        &self,
        request: &ManagedRestoreAndAdmitRequest,
        cancellation: &crate::RunCancellation,
        claim: Option<&Arc<crate::gateway::store::ManagedMaintenanceClaim>>,
    ) -> Result<Option<ManagedRestoreAndAdmitResult>, String> {
        let proof =
            serde_json::to_string(request).map_err(|_| "managed_metadata_budget_exceeded")?;
        let payload = json!({"workspace_id":request.workspace_id,"receipt_id":request.request_id,"cut":"restore","record_json":proof});
        let result = if let Some(claim) = claim {
            self.persistence.maintenance_read(
                claim,
                &claim.identity,
                &proof,
                "effect.maintenance_receipt",
                &payload,
                cancellation,
            )?
        } else {
            self.command_with_cancellation("effect.maintenance_receipt", &payload, cancellation)?
        };
        let Some(saved): Option<ManagedSavedRestoreReceipt> = decode_record(&result)? else {
            return Ok(None);
        };
        let original = serde_json::to_string(&saved.envelope.request)
            .map_err(|_| "managed_restore_reconciliation_required")?;
        if saved.envelope.admission_pin.harness_selection
            != saved.envelope.result.graph.harness_selection
            || saved.envelope.result.graph != saved.checkpoint_graph
            || saved.envelope.admission_pin.graph_id != saved.envelope.result.graph.graph_id
            || original != saved.original_request_proof
            || saved.envelope.result.source_before != saved.envelope.request.expected_source
            || saved.envelope.result.receipt_id != saved.envelope.request.request_id
            || saved.envelope.result.checkpoint_id != saved.envelope.request.checkpoint_id
        {
            return Err("managed_restore_reconciliation_required".into());
        }
        if proof != original {
            return Err("managed_request_conflict".into());
        }
        Ok(Some(saved.envelope.result))
    }
    pub(crate) fn checkpoint_rollback_confirmed(
        &self,
        claim: &Arc<crate::gateway::store::ManagedMaintenanceClaim>,
        input: &ManagedCheckpointCommitInput,
        cancellation: &crate::RunCancellation,
    ) -> Result<bool, String> {
        if !claim.worker_failed() {
            return Ok(false);
        }
        let payload = json!({"workspace_id":claim.identity.workspace_id,"receipt_id":claim.request_id,"cut":"checkpoint_rollback","record_json":serde_json::to_string(input).map_err(|_| "managed_metadata_budget_exceeded")?});
        let value = self.persistence.maintenance_read(
            claim,
            &claim.identity,
            &claim.proof,
            "effect.branch_publication_history",
            &payload,
            cancellation,
        )?;
        let facts: ManagedRollbackFacts =
            decode_record(&value)?.ok_or("managed_restore_reconciliation_required")?;
        Ok(facts.source == input.captured_source
            && facts.current_branch_id == input.request.source_branch_id
            && facts.target_rows == 0)
    }
    pub(crate) fn restore_rollback_confirmed(
        &self,
        claim: &Arc<crate::gateway::store::ManagedMaintenanceClaim>,
        envelope: &ManagedRestoreExecutionEnvelope,
        cancellation: &crate::RunCancellation,
    ) -> Result<bool, String> {
        if !claim.worker_failed() {
            return Ok(false);
        }
        let payload = json!({"workspace_id":claim.identity.workspace_id,"receipt_id":claim.request_id,"cut":"rollback","record_json":serde_json::to_string(envelope).map_err(|_| "managed_metadata_budget_exceeded")?});
        let value = self.persistence.maintenance_read(
            claim,
            &claim.identity,
            &claim.proof,
            "effect.branch_publication_history",
            &payload,
            cancellation,
        )?;
        let facts: ManagedRollbackFacts =
            decode_record(&value)?.ok_or("managed_restore_reconciliation_required")?;
        Ok(facts.source == envelope.result.source_before
            && facts.current_branch_id == envelope.request.source_branch_id
            && facts.target_rows == 0)
    }
    pub(crate) fn branch_publication_history(
        &self,
        claim: &Arc<crate::gateway::store::ManagedMaintenanceClaim>,
        envelope: &ManagedRestoreExecutionEnvelope,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedBranchPublication, String> {
        let payload =
            json!({"workspace_id":claim.identity.workspace_id,"receipt_id":claim.request_id});
        let value = self.persistence.maintenance_read(
            claim,
            &claim.identity,
            &claim.proof,
            "effect.branch_publication_history",
            &payload,
            cancellation,
        )?;
        let page: ManagedBranchPublication =
            decode_record(&value)?.ok_or("managed_restore_reconciliation_required")?;
        if page.source != envelope.result.source_after
            || page.current != envelope.result.new_branch
            || page.history_count != 2
            || page.admission_pin != envelope.admission_pin
            || page.graph != envelope.result.graph
        {
            return Err("managed_restore_reconciliation_required".into());
        }
        Ok(page)
    }
    #[cfg(test)]
    pub(crate) fn restore_receipt(
        &self,
        request: &ManagedRestoreAndAdmitRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedRestoreAndAdmitResult, String> {
        self.lookup_restore_receipt(request, cancellation)?
            .ok_or_else(|| "managed_restore_reconciliation_required".into())
    }
    pub(crate) fn checkpoint_get(
        &self,
        workspace_id: &str,
        checkpoint_id: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedCheckpointLookup, String> {
        let result = self.command_with_cancellation(
            "effect.checkpoint_get",
            &json!({"workspace_id":workspace_id,"commit_id":checkpoint_id}),
            cancellation,
        )?;
        decode_record(&result)?.ok_or_else(|| "managed_authority_required".into())
    }
    pub(crate) fn branch_receipt(
        &self,
        workspace_id: &str,
        request_id: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedSavedBranchReceipt>, String> {
        let result = self.command_with_cancellation(
            "effect.branch_receipt",
            &json!({"workspace_id": workspace_id, "receipt_id": request_id}),
            cancellation,
        )?;
        decode_record(&result)
    }
    pub(crate) fn branch_origin(
        &self,
        workspace_id: &str,
        branch_id: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedSavedBranchReceipt, String> {
        let result = self.command_with_cancellation(
            "effect.branch_origin",
            &json!({"workspace_id": workspace_id, "branch_id": branch_id}),
            cancellation,
        )?;
        let cell = result
            .get("rows")
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
            .and_then(Value::as_array)
            .and_then(|row| row.first())
            .ok_or("managed_storage_unavailable")?;
        let value = if let Some(text) = cell.as_str() {
            serde_json::from_str::<Value>(text)
                .map_err(|_| "managed_storage_unavailable".to_string())?
        } else {
            cell.clone()
        };
        if value.get("foreign") == Some(&Value::Bool(true)) {
            return Err("managed_authority_required".into());
        }
        if value.get("missing") == Some(&Value::Bool(true)) {
            return Err("managed_branch_missing".into());
        }
        serde_json::from_value(value).map_err(|_| "managed_storage_unavailable".to_string())
    }
    pub(crate) fn publish_receipt(
        &self,
        workspace_id: &str,
        request_id: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedSavedPublishReceipt>, String> {
        let payload = maintenance_payload(&json!({
            "workspace_id": workspace_id,
            "request_id": request_id,
        }))?;
        let result = self
            .command_with_cancellation("effect.publish_receipt", &payload, cancellation)
            .map_err(|error| closed_read(&error))?;
        decode_record(&result).map_err(|_| "managed_storage_unavailable".to_string())
    }
    pub(crate) fn publish_eligibility(
        &self,
        document: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedPublishEligibility, String> {
        let payload = maintenance_payload(document)?;
        let result = self
            .command_with_cancellation("effect.publish_eligibility", &payload, cancellation)
            .map_err(|error| closed_read(&error))?;
        decode_record(&result)?.ok_or_else(|| "managed_storage_unavailable".to_string())
    }
    pub(crate) fn publication(
        &self,
        workspace_id: &str,
        profile: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedWorkspacePublication>, String> {
        let payload = maintenance_payload(&json!({
            "workspace_id": workspace_id,
            "profile": profile,
        }))?;
        let result = self
            .command_with_cancellation("effect.publication_get", &payload, cancellation)
            .map_err(|error| closed_read(&error))?;
        decode_record(&result).map_err(|_| "managed_storage_unavailable".to_string())
    }
    pub(crate) fn publish_submit(
        &self,
        document: &Value,
        cancellation: &crate::RunCancellation,
        claim: &Arc<crate::gateway::store::ManagedMaintenanceClaim>,
    ) -> Result<ManagedPublishReceipt, String> {
        let payload = maintenance_payload(document)?;
        match self.persistence.publish_command(
            "effect.publish_submit",
            &payload,
            cancellation,
            Some(claim),
        ) {
            Ok(result) => decode_record(&result)
                .map_err(|_| "managed_submitted_unknown".to_string())?
                .ok_or_else(|| "managed_submitted_unknown".to_string()),
            Err(error) if error.code == "managed_transaction_rolled_back" => {
                Err("managed_transaction_rolled_back".into())
            }
            Err(_) if claim.submitted() => Err("managed_submitted_unknown".into()),
            Err(_) if cancellation.deadline_passed() || cancellation.has_deadline_overflow() => {
                Err("managed_deadline_elapsed".into())
            }
            Err(_) if cancellation.requested().is_some() => Err("managed_checkpoint_busy".into()),
            Err(_) => Err("managed_storage_unavailable".into()),
        }
    }
    pub(crate) fn branch_submit(
        &self,
        document: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedBranchReceipt, String> {
        let payload = json!({
            "maintenance_json": serde_json::to_string(document)
                .map_err(|_| "managed_metadata_budget_exceeded")?
        });
        let result =
            self.command_with_cancellation("effect.branch_create", &payload, cancellation)?;
        decode_record(&result)?.ok_or_else(|| "managed_source_conflict".into())
    }
    pub(crate) fn workspace(
        &self,
        store_id: &str,
        profile: &str,
        source: &DirectoryIdentity,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedWorkspaceRecord>, String> {
        let result = self.command_with_cancellation("effect.workspace_get", &json!({"store_id":store_id,"profile":profile,"source_device":source.device_decimal,"source_inode":source.inode_decimal}), cancellation)?;
        decode_record(&result)
    }
    pub(crate) fn current_head(
        &self,
        workspace: &ManagedWorkspaceIdentity,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedWorkspaceHead, String> {
        let result = self.command_with_cancellation(
            "effect.head",
            &json!({"workspace_id":workspace.workspace_id,"branch_id":""}),
            cancellation,
        )?;
        decode_record(&result)?.ok_or_else(|| "managed workspace head missing".into())
    }
    pub(crate) fn head(
        &self,
        workspace: &ManagedWorkspaceIdentity,
        cancellation: &crate::RunCancellation,
    ) -> Result<ManagedWorkspaceHead, String> {
        let result = self.command_with_cancellation(
            "effect.head",
            &json!({"workspace_id":workspace.workspace_id,"branch_id":workspace.branch_id}),
            cancellation,
        )?;
        decode_record(&result)?.ok_or_else(|| "managed workspace head missing".into())
    }
    pub(crate) fn get(
        &self,
        request: &ManagedEffectGetRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedEffectRecord>, String> {
        self.persistence
            .managed_effect_get_with_cancellation(request, cancellation)
            .map_err(|e| e.to_string())
    }
    #[cfg(feature = "workspace-io-fault")]
    pub(crate) fn inject_reference_transport_failure(&self) {
        self.persistence.inject_persist_failure();
    }
    pub(crate) fn object_references(
        &self,
        request: &ManagedObjectReferencesRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Vec<ManagedObjectReference>, String> {
        self.persistence
            .managed_object_references_with_cancellation(request, cancellation)
            .map_err(|e| e.to_string())
    }
    pub(crate) fn object_metadata(
        &self,
        request: &ManagedObjectReferencesRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<ManagedObjectRef>, String> {
        self.persistence
            .managed_object_metadata_with_cancellation(request, cancellation)
            .map_err(|e| e.to_string())
    }
}
pub(crate) fn decode_effect_summaries(
    value: &Value,
    limit: usize,
) -> Result<Vec<ManagedEffectSummary>, String> {
    const COLUMNS: [&str; 9] = [
        "effect_id",
        "run_id",
        "call_id",
        "state",
        "workspace_id",
        "branch_id",
        "epoch",
        "prepared_at_ms",
        "decided_at_ms",
    ];
    if value.get("columns") != Some(&json!(COLUMNS))
        || value.get("truncated") != Some(&json!(false))
    {
        return Err("managed summary layout/truncation invalid".into());
    }
    let rows = value
        .get("rows")
        .and_then(Value::as_array)
        .ok_or("managed summary rows missing")?;
    if limit == 0 || limit > 128 || rows.len() > limit {
        return Err("managed summary page exceeds bound".into());
    }
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let cells = row
            .as_array()
            .ok_or("managed summary row must be an array")?;
        if cells.len() != COLUMNS.len()
            || serde_json::to_vec(row)
                .map_err(|_| "managed summary serialization failed")?
                .len()
                > 4096
        {
            return Err("managed summary cell/byte bound invalid".into());
        }
        let record: serde_json::Map<String, Value> = COLUMNS
            .iter()
            .zip(cells)
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect();
        let summary: ManagedEffectSummary = serde_json::from_value(Value::Object(record))
            .map_err(|_| "managed summary cell types invalid")?;
        super::broker::validate_id("effect", &summary.effect_id)?;
        super::broker::validate_id("ws", &summary.workspace_id)?;
        super::broker::validate_id("br", &summary.branch_id)?;
        if summary.epoch == 0 {
            return Err("managed summary epoch invalid".into());
        }
        entries.push(summary);
    }
    Ok(entries)
}

fn maintenance_payload(document: &Value) -> Result<Value, String> {
    let text = serde_json::to_string(document).map_err(|_| "managed_metadata_budget_exceeded")?;
    if text.len() > METADATA_BYTES {
        return Err("managed_metadata_budget_exceeded".into());
    }
    Ok(json!({"maintenance_json": text}))
}

fn closed_read(error: &str) -> String {
    match error {
        "managed_deadline_elapsed" | "deadline_elapsed" => "managed_deadline_elapsed".into(),
        "managed_checkpoint_busy" | "cancelled" => "managed_checkpoint_busy".into(),
        "managed_metadata_budget_exceeded" => "managed_metadata_budget_exceeded".into(),
        other if other.contains("deadline") => "managed_deadline_elapsed".into(),
        other if other.contains("cancel") => "managed_checkpoint_busy".into(),
        _ => "managed_storage_unavailable".into(),
    }
}

pub(crate) fn decode_record<T: for<'de> Deserialize<'de>>(
    value: &Value,
) -> Result<Option<T>, String> {
    let columns = value
        .get("columns")
        .and_then(Value::as_array)
        .ok_or("managed query columns missing")?;
    if columns != &[json!("record_json")] || value.get("truncated") != Some(&json!(false)) {
        return Err("managed query layout/truncation invalid".into());
    }
    let rows = value
        .get("rows")
        .and_then(Value::as_array)
        .ok_or("managed rows missing")?;
    if rows.len() > 1 {
        return Err("managed exact query returned multiple rows".into());
    }
    rows.first()
        .map(|row| {
            let cells = row.as_array().ok_or("managed row is not an array")?;
            if cells.len() != 1 {
                return Err("managed cell count invalid".into());
            }
            let text = cells[0].as_str().ok_or("managed record must be text")?;
            if text.len() > METADATA_BYTES {
                return Err("managed record exceeds bound".into());
            }
            let value = managed_document(text)?;
            validate_maintenance_value::<T>(&value)?;
            serde_json::from_value(value).map_err(|_| "managed named record decoding failed".into())
        })
        .transpose()
}

pub(crate) fn storage_error(message: impl Into<String>) -> StorageError {
    StorageError {
        code: "managed_effect_invalid".into(),
        message: message.into(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRecoveryContext {
    next_seq: u64,
    ordinal: i64,
    parent: String,
}

pub(crate) fn validate_maintenance_value<T>(value: &Value) -> Result<(), String> {
    let ty = std::any::type_name::<T>();
    let definition = ty.rsplit("::").next().unwrap_or("");
    let schema = match definition {
        "ManagedCheckpointCreateRequest"
        | "ManagedCheckpointReceipt"
        | "ManagedCheckpointRef"
        | "ManagedCheckpointCommitInput"
        | "ManagedCheckpointLookup"
        | "ManagedCheckpointContext"
        | "ManagedSavedCheckpointReceipt"
        | "ManagedPublishRequest"
        | "ManagedPublishReceipt"
        | "ManagedWorkspacePublication" => "managed-checkpoint.schema.yaml",
        "ManagedRestoreAndAdmitRequest"
        | "ManagedRestoreAndAdmitResult"
        | "ManagedRestoreExecutionEnvelope"
        | "ManagedSavedRestoreReceipt"
        | "ManagedMaintenanceFailure"
        | "ManagedBranchPublication"
        | "ManagedRollbackFacts" => "managed-restore.schema.yaml",
        _ => return Ok(()),
    };
    crate::plugins::validate_managed_maintenance(schema, definition, value)
        .map_err(|_| "managed maintenance schema rejected".into())
}

fn parse_maintenance<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, String> {
    let value = managed_document(text)?;
    validate_maintenance_value::<T>(&value)?;
    serde_json::from_value(value).map_err(|_| "managed named maintenance decoding failed".into())
}

pub fn parse_managed_checkpoint_request_yaml(
    text: &str,
) -> Result<ManagedCheckpointCreateRequest, String> {
    parse_maintenance(text)
}
pub fn parse_managed_checkpoint_yaml(text: &str) -> Result<ManagedCheckpointReceipt, String> {
    parse_maintenance(text)
}
pub fn parse_managed_restore_request_yaml(
    text: &str,
) -> Result<ManagedRestoreAndAdmitRequest, String> {
    parse_maintenance(text)
}
pub fn parse_managed_restore_yaml(text: &str) -> Result<ManagedRestoreAndAdmitResult, String> {
    parse_maintenance(text)
}

pub fn parse_managed_effect_yaml(text: &str) -> Result<ManagedEffectRecord, String> {
    let value = managed_document(text)?;
    crate::plugins::validate_managed_effect(&value)
        .map_err(|_| "managed effect schema rejected")?;
    serde_json::from_value(value).map_err(|_| "managed named effect decoding failed".into())
}

pub fn parse_managed_workspace_yaml(text: &str) -> Result<ManagedWorkspaceRecord, String> {
    let value = managed_document(text)?;
    crate::plugins::validate_managed_workspace(&value)
        .map_err(|_| "managed workspace schema rejected")?;
    serde_json::from_value(value).map_err(|_| "managed named workspace decoding failed".into())
}

fn managed_document(text: &str) -> Result<Value, String> {
    if text.len() > METADATA_BYTES {
        return Err("managed metadata exceeds 1 MiB".into());
    }
    let value = crate::plugins::strict_managed_yaml_to_json(text)
        .map_err(|_| "managed raw document rejected")?;
    match value.get("format").and_then(Value::as_str) {
        Some(MANAGED_FORMAT) => {
            crate::plugins::validate_managed_effect(&value).map_err(|e| e.to_string())?
        }
        Some(WORKSPACE_FORMAT) => {
            crate::plugins::validate_managed_workspace(&value).map_err(|e| e.to_string())?
        }
        Some(_) => return Err("managed format unsupported".into()),
        None if value.get("identity").is_some() => return Err("managed format missing".into()),
        None => {}
    }
    Ok(value)
}

/// Startup uses only the formal SDK. No filesystem result object is fabricated.
pub(crate) fn recover_managed_effects(persistence: &GatewayPersistence) -> Result<(), String> {
    use crate::domain::{durable_message_id, durable_tool_event_id};
    for _ in 0..1024 {
        let page = persistence
            .managed_effect_command("effect.pending", &json!({}))
            .map_err(|e| e.to_string())?;
        if page.get("columns") != Some(&json!(["record_json"]))
            || page.get("truncated") != Some(&json!(false))
        {
            return Err("managed recovery page layout/truncation invalid".into());
        }
        let rows = page
            .get("rows")
            .and_then(Value::as_array)
            .ok_or("managed recovery rows missing")?;
        if rows.len() > 128 {
            return Err("managed recovery page exceeds bound".into());
        }
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let cells = row
                .as_array()
                .ok_or("managed recovery cell layout invalid")?;
            if cells.len() != 1 {
                return Err("managed recovery column count invalid".into());
            }
            let record: ManagedEffectRecord = serde_json::from_str(
                cells[0]
                    .as_str()
                    .ok_or("managed recovery record must be text")?,
            )
            .map_err(|e| e.to_string())?;
            let owner = &record.identity.owner;
            let call = &record.identity.call_id;
            let value = persistence
                .managed_effect_command(
                    "effect.recovery_context",
                    &json!({"run_id":owner.run_id,"call_id":call}),
                )
                .map_err(|e| e.to_string())?;
            let context: ManagedRecoveryContext =
                decode_record(&value)?.ok_or("managed recovery context missing")?;
            if context.parent.is_empty() {
                return Err("managed recovery parent missing".into());
            }
            let staged = record.prepared.is_some();
            let code = if staged {
                "effect_staged"
            } else {
                "effect_indeterminate"
            };
            let publication = ManagedPublicationRef {
                format: MANAGED_FORMAT.into(),
                effect_id: record.effect_id.clone(),
                workspace_id: record.identity.workspace.workspace_id.clone(),
                branch_id: record.identity.workspace.branch_id.clone(),
                epoch: record.identity.epoch,
                base_head: record.identity.expected_head.clone(),
                base_head_version: record.identity.expected_head_version,
                candidate_head: record.prepared.as_ref().and_then(|prepared| {
                    prepared
                        .candidate_root
                        .as_ref()
                        .map(|object| object.object_id.clone())
                }),
                observed_head: record.identity.expected_head.clone(),
                observed_head_version: record.identity.expected_head_version,
                status: if staged {
                    ManagedPublicationStatus::Staged
                } else {
                    ManagedPublicationStatus::Indeterminate
                },
            };
            let failure = crate::tool_result::ToolResult::failure(
                code,
                "managed effect interrupted; old execution will not resume",
            );
            let canonical = CanonicalToolResultJson::from_value(
                &serde_json::to_value(&failure).map_err(|e| e.to_string())?,
            )?;
            if canonical.as_str().len() > 4096 {
                return Err("managed recovery failure exceeds bound".into());
            }
            let content = crate::service::tool_result_content_json(call, &failure);
            let output = ManagedEventRef {
                event_id: durable_tool_event_id(&owner.run_id, call, "tool.output"),
                seq: context.next_seq,
            };
            let terminal = ManagedEventRef {
                event_id: durable_tool_event_id(&owner.run_id, call, "tool.failed"),
                seq: context.next_seq + 1,
            };
            let message = ManagedMessageRef {
                id: durable_message_id(&owner.run_id, "result", call),
                ordinal: context.ordinal,
            };
            let recovery = ManagedRecoveryObservation {
                code: code.into(),
                publication: publication.clone(),
                canonical_failure_json: canonical,
                output_event: output.clone(),
                terminal_event: terminal.clone(),
                message: message.clone(),
            };
            let data = json!({"tool_call_id":call,"ok":false,"truncated":false,"error_code":code,"managed_publication":publication});
            let created_at_ms = crate::domain::timestamp();
            let projections = json!({"normal":{"recovery":recovery,
                "output":{"event_id":output.event_id,"event_type":"tool.output","seq":output.seq,"payload_json":data.to_string(),"created_at_ms":created_at_ms},
                "terminal":{"event_id":terminal.event_id,"event_type":"tool.failed","seq":terminal.seq,"payload_json":data.to_string(),"created_at_ms":created_at_ms},
                "message":{"id":message.id,"ordinal":message.ordinal,"content_json":content.to_string(),"parent_message_id":context.parent}}});
            persistence.managed_effect_command("effect.recover_one",&json!({"effect_id":record.effect_id,"run_id":owner.run_id,"call_id":call,"commit_id":format!("recovery:{}",record.effect_id),"projections_json":projections.to_string()})).map_err(|e|e.to_string())?;
        }
    }
    Err("managed recovery work bound reached; startup unavailable with pending records".into())
}

#[cfg(test)]
#[path = "managed_checkpoint_schema_tests.rs"]
mod managed_checkpoint_schema_tests;

#[cfg(test)]
mod document_gate {
    use super::*;
    use crate::gateway::store::GatewayPersistence;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    #[test]
    fn managed_named_decoder_rejects_false_restore_cancellation_by_current_schema() {
        let mut document = json!({"workspace_id":format!("ws-{}","0".repeat(32)),"source_branch_id":format!("br-{}","0".repeat(32)),"checkpoint_id":"00000000-0000-4000-8000-000000000001","expected_source":{"store_id":format!("store-{}","0".repeat(32)),"workspace_id":format!("ws-{}","0".repeat(32)),"branch_id":format!("br-{}","0".repeat(32)),"epoch":1,"head_object_id":format!("tree-{}","0".repeat(32)),"head_version":1},"request_id":"00000000-0000-4000-8000-000000000002","input":{"text":"resume"},"cancel_active_source":true,"graph_selection":"checkpoint_exact"});
        let positive =
            json!({"columns":["record_json"],"rows":[[document.to_string()]],"truncated":false});
        assert!(
            decode_record::<ManagedRestoreAndAdmitRequest>(&positive)
                .unwrap()
                .is_some()
        );
        document["cancel_active_source"] = json!(false);
        let wire =
            json!({"columns":["record_json"],"rows":[[document.to_string()]],"truncated":false});
        assert!(
            decode_record::<ManagedRestoreAndAdmitRequest>(&wire).is_err(),
            "formal typed decoder must enforce the current managed schema, including boolean rules"
        );
    }

    fn open_repository() -> (Arc<GatewayPersistence>, ManagedEffectRepository) {
        let root =
            std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(
                format!("journal-document-gate-{}", uuid::Uuid::new_v4().simple()),
            );
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let persistence = GatewayPersistence::open(
            &crate::AgentGatewayConfig::default(),
            &root.join("state.sqlite"),
        )
        .unwrap();
        persistence.load().unwrap();
        let persistence = Arc::new(persistence);
        let repository = ManagedEffectRepository::new(Arc::clone(&persistence));
        (persistence, repository)
    }

    #[test]
    fn invalid_document_is_rejected_before_storage_with_the_parser_error_and_a_valid_document_reaches_the_worker()
     {
        let (persistence, repository) = open_repository();
        let cancellation = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
        let deadline = cancellation.deadline_instant();
        assert!(deadline.is_some());
        assert!(cancellation.requested().is_none());
        let invalid = "format: agent.managed-effect/v2\n";
        let expected = parse_managed_effect_yaml(invalid).unwrap_err();
        assert_eq!(expected, "managed format unsupported");
        let before = persistence.executed_storage_commands();
        for field in ["record_json", "prepared_json", "workspace_json"] {
            let mut payload = json!({});
            payload[field] = json!(invalid);
            let actual = repository
                .command_with_cancellation("effect.workspace_get", &payload, &cancellation)
                .unwrap_err();
            assert_eq!(actual, expected, "{field}");
            assert_eq!(
                persistence.executed_storage_commands(),
                before,
                "{field} must not enter the SDK worker"
            );
        }
        assert!(cancellation.requested().is_none());
        assert_eq!(cancellation.deadline_instant(), deadline);
        let valid = "note: kept\n";
        assert!(managed_document(valid).is_ok());
        let reached = repository.command_with_cancellation(
            "effect.workspace_get",
            &json!({"record_json": valid}),
            &cancellation,
        );
        assert!(
            persistence.executed_storage_commands() > before,
            "a document accepted by managed validation must reach the SDK worker; result={reached:?}"
        );
        if let Err(error) = reached {
            assert_ne!(error, expected);
        }
        assert!(cancellation.requested().is_none());
        assert_eq!(cancellation.deadline_instant(), deadline);
        persistence.shutdown();
    }
}
