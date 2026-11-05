//! Durable plugin-control metadata on the production RSS SQLite path.
//!
//! A loaded lock is validated metadata only. It does not rebuild a callable
//! program, grant host-catalog authority, pin a live run, or hot-swap tools.
//! Guest approval operations are not plugin-control operations.

use serde::Serialize;
use serde_json::{Value, json};

use super::resolve::{GraphLock, PermissionDiff, compare_graph_permissions};
use super::schema::validate_lock;
use crate::GatewayPersistence;

const MAX_LOCK_BYTES: usize = 256 * 1024;
const MAX_ID_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginControlError {
    pub code: &'static str,
    pub message: &'static str,
}

impl PluginControlError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    fn unavailable() -> Self {
        Self::new(
            "plugin_control_unavailable",
            "plugin control store is not available",
        )
    }

    fn invalid() -> Self {
        Self::new("plugin_lock_invalid", "plugin lock metadata is invalid")
    }

    fn conflict() -> Self {
        Self::new("plugin_lock_conflict", "plugin lock identity is immutable")
    }

    fn missing_graph() -> Self {
        Self::new("plugin_graph_missing", "plugin graph lock is not stored")
    }

    fn missing_ref() -> Self {
        Self::new(
            "plugin_package_ref_missing",
            "plugin package reference does not match the stored lock",
        )
    }

    fn activation_conflict() -> Self {
        Self::new(
            "plugin_activation_conflict",
            "plugin activation generation does not match",
        )
    }

    fn fixture_aborted() -> Self {
        Self::new(
            "plugin_control_fixture_aborted",
            "plugin control fixture aborted",
        )
    }

    fn fixture_timeout() -> Self {
        Self::new(
            "plugin_control_fixture_timeout",
            "plugin control fixture timed out",
        )
    }

    fn fixture_closed() -> Self {
        Self::new(
            "plugin_control_fixture_closed",
            "plugin control fixture rendezvous is closed",
        )
    }

    fn invalid_ref() -> Self {
        Self::new("plugin_ref_invalid", "plugin graph reference is invalid")
    }
}

impl std::fmt::Display for PluginControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for PluginControlError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PackageArtifactRef {
    pub package_id: String,
    pub version: String,
    pub kind: String,
    pub artifact_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLockMetadata {
    pub lock: GraphLock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreLockReceipt {
    pub graph_id: String,
    pub idempotent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationPointer {
    pub graph_id: String,
    pub generation: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationHistoryEntry {
    pub graph_id: String,
    pub generation: u64,
    pub previous_graph_id: String,
    pub activated_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphRetention {
    pub graph_id: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub ref_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphRevocation {
    pub graph_id: String,
    pub revoked_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphPinRequirement {
    pub run_id: String,
    pub graph_id: String,
    pub ref_id: String,
}

pub struct PluginControlStore<'a> {
    persistence: &'a GatewayPersistence,
}

impl<'a> PluginControlStore<'a> {
    pub fn new(persistence: &'a GatewayPersistence) -> Self {
        Self { persistence }
    }

    pub fn store_lock(&self, lock: &GraphLock) -> Result<StoreLockReceipt, PluginControlError> {
        let document = validated_document(lock)?;
        let encoded =
            serde_json::to_string(&document).map_err(|_| PluginControlError::invalid())?;
        if encoded.len() > MAX_LOCK_BYTES {
            return Err(PluginControlError::invalid());
        }
        match self.load_lock(&lock.graph_id) {
            Ok(existing) if existing.lock == *lock => {
                return Ok(StoreLockReceipt {
                    graph_id: lock.graph_id.clone(),
                    idempotent: true,
                });
            }
            Ok(_) => return Err(PluginControlError::conflict()),
            Err(err) if err.code == "plugin_graph_missing" => {}
            Err(err) => return Err(err),
        }
        let refs = refs_of(lock);
        self.command(
            "plugin.lock_put",
            &json!({
                "graph_id": lock.graph_id,
                "lock_json": encoded,
                "packages_json": serde_json::to_string(&refs).map_err(|_| PluginControlError::invalid())?,
                "package_count": refs.len(),
                "now_ms": now_ms(),
                "failpoint": self.failpoint(),
            }),
        )?;
        Ok(StoreLockReceipt {
            graph_id: lock.graph_id.clone(),
            idempotent: false,
        })
    }

    pub fn load_lock(&self, graph_id: &str) -> Result<ValidatedLockMetadata, PluginControlError> {
        let data = self.command("plugin.lock_get", &json!({ "graph_id": graph_id }))?;
        let rows = storage_rows(&data)?;
        let Some(row) = rows.first() else {
            return Err(PluginControlError::missing_graph());
        };
        let encoded = text_at(row, 0)?;
        let lock = parse_lock(&encoded)?;
        if lock.graph_id != graph_id {
            return Err(PluginControlError::invalid());
        }
        let stored_refs = self.package_refs(graph_id)?;
        if stored_refs != refs_of(&lock) {
            return Err(PluginControlError::missing_ref());
        }
        Ok(ValidatedLockMetadata { lock })
    }

    /// Reads two stored, validated locks. The result is not an activation permit.
    pub fn permission_diff(
        &self,
        previous_graph_id: &str,
        candidate_graph_id: &str,
    ) -> Result<PermissionDiff, PluginControlError> {
        let previous = self.load_lock(previous_graph_id)?;
        let candidate = self.load_lock(candidate_graph_id)?;
        compare_graph_permissions(&previous.lock, &candidate.lock).map_err(|_| {
            PluginControlError::new(
                "plugin_diff_budget_exceeded",
                "plugin permission diff exceeds comparison budget",
            )
        })
    }

    pub fn list_locks(&self) -> Result<Vec<String>, PluginControlError> {
        let data = self.command("plugin.lock_list", &json!({}))?;
        storage_rows(&data)?
            .iter()
            .map(|row| text_at(row, 0))
            .collect()
    }

    /// Reads the live retention slot for one graph through the production command.
    pub fn retained(&self, graph_id: &str) -> Result<Vec<GraphRetention>, PluginControlError> {
        let data = self.command("plugin.retention_get", &json!({ "graph_id": graph_id }))?;
        storage_rows(&data)?
            .iter()
            .map(|row| {
                Ok(GraphRetention {
                    graph_id: text_at(row, 0)?,
                    owner_kind: text_at(row, 1)?,
                    owner_id: text_at(row, 2)?,
                    ref_id: text_at(row, 3)?,
                })
            })
            .collect()
    }

    pub fn package_refs(
        &self,
        graph_id: &str,
    ) -> Result<Vec<PackageArtifactRef>, PluginControlError> {
        let data = self.command("plugin.ref_list", &json!({ "graph_id": graph_id }))?;
        storage_rows(&data)?
            .iter()
            .map(|row| {
                Ok(PackageArtifactRef {
                    package_id: text_at(row, 0)?,
                    version: text_at(row, 1)?,
                    kind: text_at(row, 2)?,
                    artifact_id: text_at(row, 3)?,
                })
            })
            .collect()
    }

    pub fn activate(
        &self,
        graph_id: &str,
        expected_generation: u64,
        refs: &[PackageArtifactRef],
    ) -> Result<ActivationPointer, PluginControlError> {
        let attempt = self.persistence.begin_plugin_activate_receipt_attempt();
        let loaded = match self.load_lock(graph_id) {
            Ok(loaded) => loaded,
            Err(err) => {
                self.persistence.abort_plugin_control_precommit_gate();
                return Err(err);
            }
        };
        if !same_refs(&refs_of(&loaded.lock), refs) {
            self.persistence.abort_plugin_control_precommit_gate();
            return Err(PluginControlError::missing_ref());
        }
        let current = match self.activation() {
            Ok(current) => current,
            Err(err) => {
                self.persistence.abort_plugin_control_precommit_gate();
                return Err(err);
            }
        };
        if current.generation != expected_generation {
            self.persistence.abort_plugin_control_precommit_gate();
            return Err(PluginControlError::activation_conflict());
        }
        self.persistence
            .enter_plugin_control_precommit_gate()
            .map_err(map_storage)?;
        let next = expected_generation.saturating_add(1);
        let now = now_ms();
        let data = self.command(
            "plugin.activate",
            &json!({
                "graph_id": graph_id,
                "expected_generation": expected_generation,
                "packages_json": serde_json::to_string(refs).map_err(|_| PluginControlError::invalid())?,
                "package_count": refs.len(),
                "now_ms": now,
                "failpoint": self.failpoint(),
            }),
        )?;
        attempt.run();
        let pointer = activation_receipt(&data)?;
        if pointer.graph_id != graph_id
            || pointer.generation != next
            || pointer.updated_at_ms != now
        {
            return Err(PluginControlError::unavailable());
        }
        Ok(pointer)
    }

    pub fn activation(&self) -> Result<ActivationPointer, PluginControlError> {
        let data = self.command("plugin.activation_get", &json!({}))?;
        let rows = storage_rows(&data)?;
        let Some(row) = rows.first() else {
            return Ok(ActivationPointer {
                graph_id: String::new(),
                generation: 0,
                updated_at_ms: 0,
            });
        };
        Ok(ActivationPointer {
            graph_id: text_at(row, 0)?,
            generation: int_at(row, 1)?,
            updated_at_ms: int_at(row, 2)?,
        })
    }

    pub fn activation_history(&self) -> Result<Vec<ActivationHistoryEntry>, PluginControlError> {
        let data = self.command("plugin.activation_history", &json!({}))?;
        storage_rows(&data)?
            .iter()
            .map(|row| {
                Ok(ActivationHistoryEntry {
                    graph_id: text_at(row, 0)?,
                    generation: int_at(row, 1)?,
                    previous_graph_id: text_at(row, 2)?,
                    activated_at_ms: int_at(row, 3)?,
                })
            })
            .collect()
    }

    pub fn retain(&self, retention: &GraphRetention) -> Result<bool, PluginControlError> {
        if let Err(err) = validate_retention(retention) {
            self.persistence.abort_plugin_control_precommit_gate();
            return Err(err);
        }
        if let Err(err) = self.load_lock(&retention.graph_id) {
            self.persistence.abort_plugin_control_precommit_gate();
            return Err(err);
        }
        self.persistence
            .enter_plugin_retain_precommit_pause()
            .map_err(map_storage)?;
        self.persistence
            .enter_plugin_control_precommit_gate()
            .map_err(map_storage)?;
        let data = self.command(
            "plugin.retain",
            &retention_payload(retention, self.failpoint()),
        )?;
        data.get("idempotent")
            .and_then(Value::as_bool)
            .ok_or_else(PluginControlError::unavailable)
    }

    pub fn release(&self, retention: &GraphRetention) -> Result<(), PluginControlError> {
        validate_retention(retention)?;
        self.command(
            "plugin.release",
            &retention_payload(retention, self.failpoint()),
        )?;
        Ok(())
    }

    /// Revoke one supported graph; shared package identity does not widen the
    /// revocation to any other graph. Embedding-owned graphs use the original
    /// path; phase-A tool plus pure-leaf graphs revoke through the same
    /// verified narrow topology. Revocation tombstones the graph id only and
    /// never grants execution: the leaf manifest and sources are re-verified
    /// at prepare time before anything runs.
    pub fn revoke_graph(
        &self,
        packages: &super::PackageStore,
        graph_id: &str,
    ) -> Result<GraphRevocation, PluginControlError> {
        let loaded = self.load_lock(graph_id)?;
        let tool_id = match &loaded.lock.harness_selection {
            super::HarnessSelection::ToolOnly { tool_package }
            | super::HarnessSelection::ContextPrompt { tool_package, .. } => tool_package,
            super::HarnessSelection::Unselected => return Err(PluginControlError::invalid()),
        };
        let package = loaded
            .lock
            .packages
            .iter()
            .find(|p| &p.id == tool_id)
            .ok_or_else(PluginControlError::invalid)?;
        let installed = packages
            .read_installed(&package.artifact_id)
            .map_err(|_| PluginControlError::invalid())?;
        if installed.manifest.id != package.id
            || super::SupportedManagedTopology::validate(&loaded.lock, &installed).is_none()
        {
            return Err(PluginControlError::invalid());
        }
        if installed.trust == super::PackageTrust::EmbeddingOwnedBuiltin {
            if package.id != crate::runtime::native_tools::EMBEDDING_PACKAGE_ID {
                return Err(PluginControlError::invalid());
            }
        } else if installed.trust != super::PackageTrust::AcceptedPublisher
            || (super::prepare::tool_library_topology(&loaded.lock, &installed).is_none()
                && super::prepare::tool_delegation_topology(&loaded.lock, &installed).is_none())
        {
            return Err(PluginControlError::invalid());
        }
        let data = self.command(
            "plugin.graph_revoke",
            &json!({"graph_id":graph_id,"now_ms":now_ms(),"failpoint":self.failpoint()}),
        )?;
        let rows = storage_rows(&data)?;
        let row = rows.first().ok_or_else(PluginControlError::unavailable)?;
        let fact = GraphRevocation {
            graph_id: text_at(row, 0)?,
            revoked_at_ms: int_at(row, 1)?,
        };
        if fact.graph_id != graph_id {
            return Err(PluginControlError::unavailable());
        }
        Ok(fact)
    }

    pub fn graph_revocation(
        &self,
        graph_id: &str,
    ) -> Result<Option<GraphRevocation>, PluginControlError> {
        let data = self.command("plugin.graph_revocation_get", &json!({"graph_id":graph_id}))?;
        storage_rows(&data)?
            .first()
            .map(|row| {
                Ok(GraphRevocation {
                    graph_id: text_at(row, 0)?,
                    revoked_at_ms: int_at(row, 1)?,
                })
            })
            .transpose()
    }

    /// Execution-guard typed read of the exact sealed graph revocation. The
    /// query runs under the original run cancellation with the existing
    /// remaining-deadline bound; any query failure is fail-closed by the
    /// caller, and a row for a different graph never authorizes this one.
    pub(crate) fn graph_revocation_for_execution(
        &self,
        graph_id: &str,
        cancel: &crate::RunCancellation,
    ) -> Result<Option<GraphRevocation>, PluginControlError> {
        let data = self
            .persistence
            .plugin_control_command_for_execution(
                "plugin.graph_revocation_get",
                &json!({"graph_id":graph_id}),
                cancel,
            )
            .map_err(map_storage)?;
        storage_rows(&data)?
            .first()
            .map(|row| {
                let fact = GraphRevocation {
                    graph_id: text_at(row, 0)?,
                    revoked_at_ms: int_at(row, 1)?,
                };
                if fact.graph_id != graph_id {
                    return Err(PluginControlError::unavailable());
                }
                Ok(fact)
            })
            .transpose()
    }

    pub fn pin_requirement_for_run(
        &self,
        run_id: &str,
    ) -> Result<Option<GraphPinRequirement>, PluginControlError> {
        let data = self.command("plugin.pin_requirement_get", &json!({"owner_id":run_id}))?;
        storage_rows(&data)?
            .first()
            .map(|row| {
                if text_at(row, 3)? != "required" {
                    return Err(PluginControlError::unavailable());
                }
                Ok(GraphPinRequirement {
                    run_id: text_at(row, 0)?,
                    graph_id: text_at(row, 1)?,
                    ref_id: text_at(row, 2)?,
                })
            })
            .transpose()
    }

    pub(crate) fn harness_binding_matches(
        &self,
        owner: &crate::effects::ManagedOwnerScope,
        code: &crate::effects::ManagedCodeIdentity,
        branch: &crate::effects::ManagedWorkspaceIdentity,
        epoch: u64,
        deadline: u64,
    ) -> Result<bool, PluginControlError> {
        let data=self.command("plugin.harness_binding_matches",&json!({"owner_id":owner.run_id,"profile":owner.profile,"session_id":owner.session_id,"workspace_id":branch.workspace_id,"branch_id":branch.branch_id,"epoch":epoch,"deadline_ms":deadline,"graph_id":code.graph_id,"ref_id":code.graph_ref_id}))?;
        Ok(!storage_rows(&data)?.is_empty())
    }

    pub fn pin_for_run(&self, owner_id: &str) -> Result<Value, PluginControlError> {
        self.command("plugin.pin_for_owner", &json!({ "owner_id": owner_id }))
    }

    pub fn collect_unreferenced(&self) -> Result<Vec<String>, PluginControlError> {
        let data = self.command("plugin.collect", &json!({ "failpoint": self.failpoint() }))?;
        let mut collected = Vec::new();
        for row in storage_rows(&data)? {
            let graph_id = text_at(&row, 0)?;
            match self.load_lock(&graph_id) {
                Err(err) if err.code == "plugin_graph_missing" => collected.push(graph_id),
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        }
        Ok(collected)
    }

    fn command(&self, op: &str, payload: &Value) -> Result<Value, PluginControlError> {
        self.persistence
            .plugin_control_command(op, payload)
            .map_err(map_storage)
    }

    fn command_for_proof(
        &self,
        op: &str,
        payload: &Value,
        budget_until: Option<std::time::Instant>,
    ) -> Result<Value, PluginControlError> {
        self.persistence
            .plugin_control_command_for_proof(op, payload, budget_until)
            .map_err(map_storage)
    }

    pub(crate) fn pin_for_run_for_proof(
        &self,
        owner_id: &str,
        budget_until: Option<std::time::Instant>,
    ) -> Result<Value, PluginControlError> {
        self.command_for_proof(
            "plugin.pin_for_owner",
            &json!({ "owner_id": owner_id }),
            budget_until,
        )
    }

    pub(crate) fn pin_requirement_for_run_for_proof(
        &self,
        run_id: &str,
        budget_until: Option<std::time::Instant>,
    ) -> Result<Option<GraphPinRequirement>, PluginControlError> {
        let data = self.command_for_proof(
            "plugin.pin_requirement_get",
            &json!({"owner_id": run_id}),
            budget_until,
        )?;
        storage_rows(&data)?
            .first()
            .map(|row| {
                if text_at(row, 3)? != "required" {
                    return Err(PluginControlError::unavailable());
                }
                Ok(GraphPinRequirement {
                    run_id: text_at(row, 0)?,
                    graph_id: text_at(row, 1)?,
                    ref_id: text_at(row, 2)?,
                })
            })
            .transpose()
    }

    pub(crate) fn harness_binding_matches_for_proof(
        &self,
        owner: &crate::effects::ManagedOwnerScope,
        code: &crate::effects::ManagedCodeIdentity,
        branch: &crate::effects::ManagedWorkspaceIdentity,
        epoch: u64,
        deadline: u64,
        budget_until: Option<std::time::Instant>,
    ) -> Result<bool, PluginControlError> {
        let data = self.command_for_proof(
            "plugin.harness_binding_matches",
            &json!({"owner_id":owner.run_id,"profile":owner.profile,"session_id":owner.session_id,"workspace_id":branch.workspace_id,"branch_id":branch.branch_id,"epoch":epoch,"deadline_ms":deadline,"graph_id":code.graph_id,"ref_id":code.graph_ref_id}),
            budget_until,
        )?;
        Ok(!storage_rows(&data)?.is_empty())
    }

    fn failpoint(&self) -> &'static str {
        if self.persistence.take_plugin_control_failpoint() {
            "after_partial_write"
        } else {
            ""
        }
    }
}

fn activation_receipt(data: &Value) -> Result<ActivationPointer, PluginControlError> {
    Ok(ActivationPointer {
        graph_id: data
            .get("graph_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(PluginControlError::unavailable)?,
        generation: json_u64(data.get("generation"))?,
        updated_at_ms: json_u64(data.get("updated_at_ms"))?,
    })
}

fn json_u64(value: Option<&Value>) -> Result<u64, PluginControlError> {
    value
        .and_then(Value::as_u64)
        .or_else(|| {
            value
                .and_then(Value::as_i64)
                .and_then(|item| u64::try_from(item).ok())
        })
        .ok_or_else(PluginControlError::unavailable)
}

fn retention_payload(retention: &GraphRetention, failpoint: &str) -> Value {
    json!({
        "graph_id": retention.graph_id,
        "owner_kind": retention.owner_kind,
        "owner_id": retention.owner_id,
        "ref_id": retention.ref_id,
        "now_ms": now_ms(),
        "failpoint": failpoint,
    })
}

fn validated_document(lock: &GraphLock) -> Result<Value, PluginControlError> {
    let document = lock.schema_value();
    validate_lock(&document).map_err(|_| PluginControlError::invalid())?;
    let parsed =
        GraphLock::from_schema_value(document).map_err(|_| PluginControlError::invalid())?;
    if parsed != *lock {
        return Err(PluginControlError::invalid());
    }
    parsed
        .validate_persisted()
        .map_err(|_| PluginControlError::invalid())?;
    Ok(lock.schema_value())
}

fn parse_lock(encoded: &str) -> Result<GraphLock, PluginControlError> {
    if encoded.len() > MAX_LOCK_BYTES {
        return Err(PluginControlError::invalid());
    }
    let document = serde_json::from_str(encoded).map_err(|_| PluginControlError::invalid())?;
    validate_lock(&document).map_err(|_| PluginControlError::invalid())?;
    let lock = GraphLock::from_schema_value(document).map_err(|_| PluginControlError::invalid())?;
    lock.validate_persisted()
        .map_err(|_| PluginControlError::invalid())?;
    Ok(lock)
}

fn refs_of(lock: &GraphLock) -> Vec<PackageArtifactRef> {
    lock.packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect()
}

fn validate_retention(retention: &GraphRetention) -> Result<(), PluginControlError> {
    if retention.owner_kind != "run" && retention.owner_kind != "checkpoint" {
        return Err(PluginControlError::invalid_ref());
    }
    if !plain_id(&retention.graph_id)
        || !plain_id(&retention.owner_id)
        || !plain_id(&retention.ref_id)
    {
        return Err(PluginControlError::invalid_ref());
    }
    Ok(())
}

fn plain_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains("..")
        && value.chars().all(|item| !item.is_control())
}

fn storage_rows(data: &Value) -> Result<Vec<Vec<Value>>, PluginControlError> {
    crate::sqlite_storage_rows::sqlite_storage_rows(data)
        .map_err(|_| PluginControlError::unavailable())
}

fn text_at(row: &[Value], index: usize) -> Result<String, PluginControlError> {
    row.get(index)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(PluginControlError::unavailable)
}

fn int_at(row: &[Value], index: usize) -> Result<u64, PluginControlError> {
    row.get(index)
        .and_then(Value::as_u64)
        .or_else(|| {
            row.get(index)
                .and_then(Value::as_i64)
                .and_then(|value| u64::try_from(value).ok())
        })
        .ok_or_else(PluginControlError::unavailable)
}

fn map_storage(err: crate::gateway::store::StorageError) -> PluginControlError {
    match err.code.as_str() {
        "plugin_lock_conflict" => PluginControlError::conflict(),
        "plugin_lock_invalid" => PluginControlError::invalid(),
        "plugin_graph_missing" => PluginControlError::missing_graph(),
        "plugin_package_ref_missing" => PluginControlError::missing_ref(),
        "plugin_activation_conflict" => PluginControlError::activation_conflict(),
        "plugin_graph_revoked" => {
            PluginControlError::new("plugin_graph_revoked", "plugin graph is revoked")
        }
        "plugin_graph_pin_required" => {
            PluginControlError::new("plugin_graph_pin_required", "tool graph pin is required")
        }
        "plugin_ref_invalid" => PluginControlError::invalid_ref(),
        crate::gateway::store::PLUGIN_CONTROL_FIXTURE_ABORTED => {
            PluginControlError::fixture_aborted()
        }
        crate::gateway::store::PLUGIN_CONTROL_FIXTURE_TIMEOUT => {
            PluginControlError::fixture_timeout()
        }
        crate::gateway::store::PLUGIN_CONTROL_FIXTURE_CLOSED => {
            PluginControlError::fixture_closed()
        }
        _ => PluginControlError::unavailable(),
    }
}

fn same_refs(left: &[PackageArtifactRef], right: &[PackageArtifactRef]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_by(|left, right| left.package_id.cmp(&right.package_id));
    right.sort_by(|left, right| left.package_id.cmp(&right.package_id));
    left == right
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod t14_lock_budget_tests {
    use super::*;

    #[test]
    fn t14_lock_decode_exact_256k_and_one_over() {
        let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("t195-lock-budget-{}", uuid::Uuid::new_v4()));
        let store = crate::plugins::PackageStore::open(root).unwrap();
        store.bind_policy(&crate::plugins::InstallAuthorization {
            admin: false,
            accepted_publishers: vec![],
            unsigned_dev_space: None,
        });
        store.install_embedding_owned().unwrap();
        let lock = store
            .resolve(&crate::plugins::ResolveRequest {
                roots: vec![crate::plugins::PackageRequirement {
                    id: crate::runtime::native_tools::EMBEDDING_PACKAGE_ID.into(),
                    version: "1.0.0".into(),
                }],
                host_runtime: crate::plugins::HOST_RUNTIME.into(),
                harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: crate::runtime::native_tools::EMBEDDING_PACKAGE_ID.into(),
                },
            })
            .unwrap();
        let mut encoded = serde_json::to_string(&lock.schema_value()).unwrap();
        assert!(encoded.len() < MAX_LOCK_BYTES);
        // The closed canonical producer does not emit padding. This is the
        // real private decoder bound, using valid JSON whitespace and the
        // unchanged valid lock, not an invented end-to-end policy graph.
        encoded.push_str(&" ".repeat(MAX_LOCK_BYTES - encoded.len()));
        assert_eq!(encoded.len(), 262144);
        assert_eq!(parse_lock(&encoded).unwrap(), lock);
        encoded.push(' ');
        assert_eq!(encoded.len(), 262145);
        assert_eq!(
            parse_lock(&encoded).unwrap_err().code,
            "plugin_lock_invalid"
        );
    }
}
