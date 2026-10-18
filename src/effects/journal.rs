//! Named managed-effect protocol over the formal RSS storage worker.
use crate::gateway::store::{GatewayPersistence, StorageError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

pub const MANAGED_FORMAT: &str = "agent.managed-effect/v1";
pub const WORKSPACE_FORMAT: &str = "agent.managed-workspace/v1";
pub const METADATA_BYTES: usize = 1024 * 1024;

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
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectGetRequest {
    pub owner: ManagedOwnerScope,
    pub call_id: String,
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

#[derive(Clone)]
pub(crate) struct ManagedEffectRepository {
    persistence: Arc<GatewayPersistence>,
}
impl ManagedEffectRepository {
    pub(crate) fn new(persistence: Arc<GatewayPersistence>) -> Self {
        Self { persistence }
    }
    pub(crate) fn command(&self, op: &str, payload: &Value) -> Result<Value, String> {
        self.command_inner(op, payload, None)
    }
    pub(crate) fn command_with_cancellation(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, String> {
        self.command_inner(op, payload, Some(cancellation))
    }
    fn command_inner(
        &self,
        op: &str,
        payload: &Value,
        cancellation: Option<&crate::RunCancellation>,
    ) -> Result<Value, String> {
        for field in ["record_json", "prepared_json", "workspace_json"] {
            if let Some(text) = payload
                .get(field)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
            {
                managed_document(text).map_err(|error| {
                    #[cfg(feature = "workspace-io-fault")]
                    eprintln!("managed document validation rejected {field}: {error}");
                    error
                })?;
            }
        }
        if let Some(cancellation) = cancellation {
            self.persistence
                .managed_effect_command_with_cancellation(op, payload, cancellation)
        } else {
            self.persistence.managed_effect_command(op, payload)
        }
        .map_err(|e| e.to_string())
    }
    pub(crate) fn workspace(
        &self,
        store_id: &str,
        profile: &str,
        source: &DirectoryIdentity,
    ) -> Result<Option<ManagedWorkspaceRecord>, String> {
        let result = self.command("effect.workspace_get", &json!({"store_id":store_id,"profile":profile,"source_device":source.device_decimal,"source_inode":source.inode_decimal}))?;
        decode_record(&result)
    }
    pub(crate) fn head(
        &self,
        workspace: &ManagedWorkspaceIdentity,
    ) -> Result<ManagedWorkspaceHead, String> {
        let result = self.command(
            "effect.head",
            &json!({"workspace_id":workspace.workspace_id,"branch_id":workspace.branch_id}),
        )?;
        decode_record(&result)?.ok_or_else(|| "managed workspace head missing".into())
    }
    pub(crate) fn get(
        &self,
        request: &ManagedEffectGetRequest,
    ) -> Result<Option<ManagedEffectRecord>, String> {
        decode_record(&self.command("effect.get", &json!(request))?)
    }
    #[cfg(feature = "workspace-io-fault")]
    pub(crate) fn inject_reference_transport_failure(&self) {
        self.persistence.inject_persist_failure();
    }
    pub(crate) fn object_references(
        &self,
        request: &ManagedObjectReferencesRequest,
    ) -> Result<Vec<ManagedObjectReference>, String> {
        self.persistence
            .managed_object_references(request)
            .map_err(|e| e.to_string())
    }
    pub(crate) fn object_metadata(
        &self,
        request: &ManagedObjectReferencesRequest,
    ) -> Result<Option<ManagedObjectRef>, String> {
        self.persistence
            .managed_object_metadata(request)
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
            let projections = json!({"normal":{"recovery":recovery,
                "output":{"event_id":output.event_id,"event_type":"tool.output","seq":output.seq,"payload_json":data.to_string()},
                "terminal":{"event_id":terminal.event_id,"event_type":"tool.failed","seq":terminal.seq,"payload_json":data.to_string()},
                "message":{"id":message.id,"ordinal":message.ordinal,"content_json":content.to_string(),"parent_message_id":context.parent}}});
            persistence.managed_effect_command("effect.recover_one",&json!({"effect_id":record.effect_id,"run_id":owner.run_id,"call_id":call,"commit_id":format!("recovery:{}",record.effect_id),"projections_json":projections.to_string()})).map_err(|e|e.to_string())?;
        }
    }
    Err("managed recovery work bound reached; startup unavailable with pending records".into())
}
