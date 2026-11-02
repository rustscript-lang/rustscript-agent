//! Host-bound plugin graph control on the existing Native store.
//! Signatures, graph ids, and request JSON do not grant authority.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{AdmitError, AgentService};
use crate::GatewayPersistence;
use crate::plugins::{
    HOST_RUNTIME, HarnessSelection, HarnessSelectionRequest, InstallAuthorization,
    PackageArtifactRef, PackageRequirement, PackageTrust, PluginControlStore, PluginErrorKind,
    PluginStateObject, ResolveRequest,
};
use crate::runtime::rss_runner::RunCancellation;

pub(crate) struct PluginControlBinding {
    authorization: InstallAuthorization,
    source_root: PathBuf,
    deployment_space: String,
}

/// Prepared (never published) session schema migration for one admission.
/// The lease keeps another same-session admission or maintenance action out
/// until the durable admission transaction succeeds or fails.
pub(crate) struct PreparedStateMigration {
    session_id: String,
    run_id: String,
    workspace_id: String,
    branch_id: String,
    plugin_id: String,
    package_id: String,
    artifact_id: String,
    graph_id: String,
    generation: u64,
    ref_id: String,
    epoch: u64,
    old_schema: u32,
    expected_revision: u64,
    expected_object_id: String,
    object: Option<PluginStateObject>,
    state_store: crate::plugins::PluginStateStore,
    _candidate: Option<crate::plugins::PluginStateCandidateLease>,
    _lease: Option<super::SessionMaintenanceLease>,
}

impl Drop for PreparedStateMigration {
    fn drop(&mut self) {
        // Settle order is explicit: release the session lease, drop the
        // candidate protection, then run the existing bounded typed collector
        // for the now-abandoned object. This drop runs only after the
        // admission's commit-gate guard has been released: the guard is
        // declared in a later inner scope, and every return/continue path
        // leaves that scope before this loop-body local is dropped. The
        // collection therefore never blocks while the global gate is held.
        let _ = self._lease.take();
        let _ = self._candidate.take();
        if self.object.is_some() {
            let _ = self.state_store.collect_orphans();
        }
    }
}

impl PreparedStateMigration {
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }
    /// Clone of the unsettled migration candidate owner for the admission
    /// request sidecar. The migration holder keeps its own reference; the
    /// request sidecar keeps the id protected until the worker settles the
    /// admission even after this holder is released by a caller timeout.
    pub(crate) fn owner(&self) -> Option<crate::plugins::PluginStateCandidateLease> {
        self._candidate.clone()
    }
    pub(crate) fn has_root_cas(&self) -> bool {
        self.object.is_some()
    }

    pub(crate) fn object_id(&self) -> Option<&str> {
        self.object.as_ref().map(|object| object.object_id.as_str())
    }

    pub(crate) fn wire_json(&self) -> Result<Value, &'static str> {
        let object = self
            .object
            .as_ref()
            .ok_or("plugin_state_migration_missing")?;
        let epoch = i64::try_from(self.epoch).map_err(|_| "plugin_state_invalid")?;
        let generation = i64::try_from(self.generation).map_err(|_| "plugin_state_invalid")?;
        Ok(json!({
            "run_id": self.run_id,
            "session_id": self.session_id,
            "owner_kind": "session",
            "workspace_id": self.workspace_id,
            "branch_id": self.branch_id,
            "plugin_id": self.plugin_id,
            "package_id": self.package_id,
            "artifact_id": self.artifact_id,
            "graph_id": self.graph_id,
            "generation": generation,
            "ref_id": self.ref_id,
            "epoch": epoch,
            "old_schema_version": self.old_schema,
            "schema_version": object.schema,
            "expected_revision": self.expected_revision,
            "expected_object_id": self.expected_object_id,
            "object_id": object.object_id,
            "now_ms": now_ms(),
        }))
    }
}

/// Same-schema session state admission guard. The exact live root identity is
/// captured from the actual root read during preparation and re-verified inside
/// the durable admission transaction, so a real schema switch that lands
/// between preparation and commit fails the admission closed instead of
/// admitting a run against a root whose schema no longer matches the pinned
/// graph. The expected identity is the live root's package/artifact/revision/
/// object, never the new pin's artifact: a compatible new artifact revision of
/// the same package and schema must keep reusing the existing root and data.
/// Guarded admissions never take the maintenance lease or wait for other runs.
pub(crate) struct PluginStateGuard {
    session_id: String,
    workspace_id: String,
    branch_id: String,
    plugin_id: String,
    package_id: String,
    artifact_id: String,
    revision: u64,
    object_id: String,
    schema: u32,
}

impl PluginStateGuard {
    fn from_live_root(
        session_id: &str,
        workspace_id: &str,
        branch_id: &str,
        root: &crate::plugins::PluginStateRoot,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            workspace_id: workspace_id.to_string(),
            branch_id: branch_id.to_string(),
            plugin_id: root.plugin_id.clone(),
            package_id: root.package_id.clone(),
            artifact_id: root.artifact_id.clone(),
            revision: root.revision,
            object_id: root.object_id.clone(),
            schema: root.schema,
        }
    }

    pub(crate) fn wire_json(&self) -> Result<Value, &'static str> {
        let revision = i64::try_from(self.revision).map_err(|_| "plugin_state_invalid")?;
        Ok(json!({
            "session_id": self.session_id,
            "workspace_id": self.workspace_id,
            "branch_id": self.branch_id,
            "plugin_id": self.plugin_id,
            "package_id": self.package_id,
            "artifact_id": self.artifact_id,
            "revision": revision,
            "object_id": self.object_id,
            "schema_version": self.schema,
        }))
    }
}

/// What one admission must do with the session state root: verify it is still
/// the same schema (no maintenance lease), or perform a real migration under
/// the maintained lease.
pub(crate) enum PreparedStateAdmission {
    Guard(PluginStateGuard),
    Migration(Box<PreparedStateMigration>),
}

impl PreparedStateAdmission {
    pub(crate) fn migration(&self) -> Option<&PreparedStateMigration> {
        match self {
            Self::Guard(_) => None,
            Self::Migration(migration) => Some(migration.as_ref()),
        }
    }

    pub(crate) fn guard_json(&self) -> Option<Result<Value, &'static str>> {
        match self {
            Self::Guard(guard) => Some(guard.wire_json()),
            Self::Migration(_) => None,
        }
    }

    pub(crate) fn candidate_object_id(&self) -> Option<&str> {
        self.migration().and_then(PreparedStateMigration::object_id)
    }

    pub(crate) fn candidate_owner(&self) -> Option<crate::plugins::PluginStateCandidateLease> {
        self.migration().and_then(PreparedStateMigration::owner)
    }
}

/// Admission identity selected for the exact authorized session branch.
pub(crate) struct StateMigrationIdentity<'a> {
    pub session_id: &'a str,
    pub run_id: &'a str,
    pub graph_id: &'a str,
    pub generation: u64,
    pub ref_id: &'a str,
    pub epoch: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallBody {
    package: String,
    deployment_space: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveBody {
    roots: Vec<RootBody>,
    tool_package: String,
    deployment_space: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootBody {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBody {
    graph_id: String,
    deployment_space: String,
    expected_generation: u64,
}

impl AgentService {
    pub fn bind_plugin_control(
        &self,
        authorization: InstallAuthorization,
        source_root: PathBuf,
        deployment_space: String,
    ) -> Result<(), String> {
        if !authorization.admin {
            return Err("plugin control requires a host admin policy".into());
        }
        if !deployment_space_ok(&deployment_space) {
            return Err("plugin deployment space is invalid".into());
        }
        if !source_root.is_absolute() {
            return Err("plugin source root must be absolute".into());
        }
        let meta = std::fs::symlink_metadata(&source_root)
            .map_err(|_| "plugin source root is unavailable".to_string())?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("plugin source root is unavailable".into());
        }
        if self.inner.persistence.is_none() {
            return Err("plugin control requires the native package store".into());
        }
        let mut slot = lock_mut(&self.inner.plugin_control);
        *slot = Some(PluginControlBinding {
            authorization: authorization.clone(),
            source_root,
            deployment_space,
        });
        let Some(store) = self.tool_store() else {
            *slot = None;
            return Err("plugin control requires the native package store".into());
        };
        // Same trusted authorization the host just published. Request JSON,
        // signatures, and graph ids are not consulted. The control lock is
        // still held, so a concurrent route cannot observe the binding before
        // read/verify uses this policy. A missing store rolls the binding back
        // and leaves the previous policy untouched.
        store.bind_policy(&authorization);
        Ok(())
    }

    pub(super) fn published_install_authorization(&self) -> Option<InstallAuthorization> {
        lock_ref(&self.inner.plugin_control)
            .as_ref()
            .map(|binding| binding.authorization.clone())
    }

    /// Copies the published host authorization onto the live package store.
    /// Returns whether a binding was applied. `bind_policy` drops verified
    /// caches, so a true result means the caller must re-prepare code it still
    /// needs. No binding leaves the store policy unchanged.
    pub(super) fn sync_published_package_policy(&self) -> bool {
        let Some(authorization) = self.published_install_authorization() else {
            return false;
        };
        let Some(store) = self.tool_store() else {
            return false;
        };
        store.bind_policy(&authorization);
        true
    }

    pub(crate) fn plugin_control_configured(&self) -> bool {
        lock_ref(&self.inner.plugin_control).is_some()
    }

    pub(crate) fn install_controlled_plugin(&self, body: &Value) -> Result<Value, &'static str> {
        let binding = self.host_binding()?;
        let request: InstallBody = parse_body(body)?;
        self.require_space(&binding, &request.deployment_space)?;
        let package = controlled_package(&binding.source_root, &request.package)?;
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        let revision = store
            .install(&package, &binding.authorization)
            .map_err(map_plugin)?;
        let installed = store
            .read_installed(&revision.artifact_id)
            .map_err(|_| "plugin_artifact_unavailable")?;
        Ok(json!({
            "artifact_id": revision.artifact_id,
            "package_id": installed.manifest.id,
            "version": installed.manifest.version,
            "trust": trust_label(revision.trust),
        }))
    }

    pub(crate) fn resolve_controlled_graph(&self, body: &Value) -> Result<Value, &'static str> {
        let binding = self.host_binding()?;
        let request: ResolveBody = parse_body(body)?;
        self.require_space(&binding, &request.deployment_space)?;
        if request.roots.is_empty() || request.tool_package.is_empty() {
            return Err("plugin_id_invalid");
        }
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        let persistence = self
            .inner
            .persistence
            .as_ref()
            .ok_or("plugin_control_unconfigured")?;
        let control = PluginControlStore::new(persistence);
        let before = control.activation().map_err(map_control)?;
        let lock = store
            .resolve(&ResolveRequest {
                roots: request
                    .roots
                    .iter()
                    .map(|root| PackageRequirement {
                        id: root.id.clone(),
                        version: root.version.clone(),
                    })
                    .collect(),
                host_runtime: HOST_RUNTIME.into(),
                harness_selection: HarnessSelectionRequest::ToolOnly {
                    tool_package: request.tool_package,
                },
            })
            .map_err(map_plugin)?;
        let receipt = control.store_lock(&lock).map_err(map_control)?;
        let loaded = control.load_lock(&receipt.graph_id).map_err(map_control)?;
        let after = control.activation().map_err(map_control)?;
        if after != before {
            return Err("plugin_activation_conflict");
        }
        let diff = if before.graph_id.is_empty() {
            None
        } else {
            Some(
                control
                    .permission_diff(&before.graph_id, &loaded.lock.graph_id)
                    .map_err(map_control)?,
            )
        };
        Ok(json!({
            "graph_id": loaded.lock.graph_id,
            "activated": false,
            "generation": after.generation,
            "permission_diff": diff.map(|diff| json!({
                "requires_reapproval": diff.requires_reapproval,
                "change_count": diff.changes.len(),
                "edges_changed": diff.metadata.edges_changed,
                "entries_changed": diff.metadata.entries_changed,
                "host_contract_changed": diff.metadata.host_contract_changed,
            })),
        }))
    }

    pub(crate) fn prepare_controlled_graph(&self, graph_id: &str) -> Result<Value, &'static str> {
        let _binding = self.host_binding()?;
        let lock = self.executable_lock(graph_id)?;
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        self.forget_prepared(graph_id);
        let prepared = store.prepare(&lock).map_err(|_| "plugin_prepare_failed")?;
        let tool_package = tool_package(&lock)?;
        if prepared.program(tool_package).is_none() {
            return Err("plugin_prepare_failed");
        }
        lock_mut(&self.inner.prepared_plugin_graphs).insert(graph_id.to_string(), lock.clone());
        Ok(json!({
            "graph_id": lock.graph_id,
            "executable": true,
            "status": "prepared",
        }))
    }

    pub(crate) fn plugin_graph_view(&self, graph_id: &str) -> Result<Value, &'static str> {
        let _binding = self.host_binding()?;
        validate_public_id(graph_id)?;
        let persistence = self
            .inner
            .persistence
            .as_ref()
            .ok_or("plugin_control_unconfigured")?;
        let loaded = PluginControlStore::new(persistence)
            .load_lock(graph_id)
            .map_err(map_control)?;
        if loaded.lock.graph_id != graph_id {
            return Err("plugin_graph_missing");
        }
        Ok(public_graph(&loaded.lock))
    }

    pub(crate) fn activate_controlled_graph(&self, body: &Value) -> Result<Value, &'static str> {
        let binding = self.host_binding()?;
        let request: ActivateBody = parse_body(body)?;
        self.require_space(&binding, &request.deployment_space)?;
        validate_public_id(&request.graph_id)?;
        let lock = self.prepared_lock(&request.graph_id)?;
        self.ensure_current(&lock)?;
        let persistence = self
            .inner
            .persistence
            .as_ref()
            .ok_or("plugin_control_unconfigured")?;
        let control = PluginControlStore::new(persistence);
        let receipt = control
            .activate(
                &lock.graph_id,
                request.expected_generation,
                &artifact_refs(&lock),
            )
            .map_err(map_control)?;
        Ok(activation_body(&binding.deployment_space, &receipt))
    }

    pub(crate) fn rollback_controlled_activation(
        &self,
        activation_id: &str,
    ) -> Result<Value, &'static str> {
        let binding = self.host_binding()?;
        if activation_id.len() > 128 || activation_id.contains('/') || activation_id.contains('\\')
        {
            return Err("plugin_id_invalid");
        }
        let generation = parse_activation_id(&binding.deployment_space, activation_id)?;
        let persistence = self
            .inner
            .persistence
            .as_ref()
            .ok_or("plugin_control_unconfigured")?;
        let control = PluginControlStore::new(persistence);
        let history = control.activation_history().map_err(map_control)?;
        let entry = history
            .iter()
            .find(|entry| entry.generation == generation)
            .ok_or("plugin_activation_missing")?;
        let lock = self.prepared_lock(&entry.graph_id)?;
        self.ensure_current(&lock)?;
        self.require_rollback_state_compatible(&lock, persistence)?;
        let current = control.activation().map_err(map_control)?;
        let receipt = control
            .activate(&lock.graph_id, current.generation, &artifact_refs(&lock))
            .map_err(map_control)?;
        if receipt.generation <= current.generation {
            return Err("plugin_activation_conflict");
        }
        Ok(activation_body(&binding.deployment_space, &receipt))
    }

    pub(crate) fn captured_run_projection(&self, run_id: &str) -> Value {
        let mut graph_id = Value::Null;
        let mut generation = Value::Null;
        let mut branch = Value::Null;
        let mut epoch = Value::Null;
        let mut head_object_id = Value::Null;
        let mut head_version = Value::Null;
        let mut publication = json!("unsupported");
        if let Some(persistence) = &self.inner.persistence {
            if let Ok(pin) = PluginControlStore::new(persistence).pin_for_run(run_id)
                && pin.get("pinned") == Some(&Value::Bool(true))
            {
                if let Some(id) = pin.get("graph_id").and_then(Value::as_str)
                    && !id.is_empty()
                {
                    graph_id = json!(id);
                }
                if let Some(value) = pin.get("generation").and_then(Value::as_u64) {
                    generation = json!(value);
                }
            }
            if self.inner.config.managed_workspace.is_some() {
                publication = Value::Null;
                let cancel = RunCancellation::with_deadline(
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                );
                if let Ok(Some(saved)) = persistence.managed_run_query_binding(run_id, &cancel) {
                    if !saved.workspace.branch_id.is_empty() {
                        branch = json!(saved.workspace.branch_id);
                    }
                    epoch = json!(saved.epoch);
                    if let Ok(head) = persistence
                        .managed_workspace_head_with_cancellation(&saved.workspace, &cancel)
                        && head.branch_id == saved.workspace.branch_id
                        && head.workspace_id == saved.workspace.workspace_id
                        && head.store_id == saved.workspace.store_id
                    {
                        head_object_id = json!(head.head_object_id);
                        head_version = json!(head.head_version);
                    }
                }
            }
        }
        json!({
            "graph_id": graph_id,
            "activation_generation": generation,
            "workspace_branch": branch,
            "epoch": epoch,
            "head_object_id": head_object_id,
            "head_version": head_version,
            "publication": publication,
        })
    }

    fn host_binding(&self) -> Result<PluginControlBinding, &'static str> {
        lock_ref(&self.inner.plugin_control)
            .clone()
            .ok_or("plugin_control_unconfigured")
    }

    fn require_space(
        &self,
        binding: &PluginControlBinding,
        requested: &str,
    ) -> Result<(), &'static str> {
        if requested == binding.deployment_space {
            Ok(())
        } else {
            Err("plugin_space_mismatch")
        }
    }

    fn executable_lock(&self, graph_id: &str) -> Result<crate::plugins::GraphLock, &'static str> {
        validate_public_id(graph_id)?;
        let persistence = self
            .inner
            .persistence
            .as_ref()
            .ok_or("plugin_control_unconfigured")?;
        let control = PluginControlStore::new(persistence);
        if control
            .graph_revocation(graph_id)
            .map_err(map_control)?
            .is_some()
        {
            return Err("plugin_graph_revoked");
        }
        let loaded = control.load_lock(graph_id).map_err(map_control)?;
        if loaded.lock.graph_id != graph_id {
            return Err("plugin_graph_missing");
        }
        self.validate_stateful(&loaded.lock)?;
        self.require_artifacts(&loaded.lock)?;
        Ok(loaded.lock)
    }

    fn prepared_lock(&self, graph_id: &str) -> Result<crate::plugins::GraphLock, &'static str> {
        let lock = self.executable_lock(graph_id)?;
        let prepared = lock_ref(&self.inner.prepared_plugin_graphs)
            .get(graph_id)
            .cloned();
        match prepared {
            Some(saved) if saved == lock => Ok(lock),
            _ => Err("plugin_graph_not_prepared"),
        }
    }

    fn ensure_current(&self, lock: &crate::plugins::GraphLock) -> Result<(), &'static str> {
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        self.validate_stateful(lock)?;
        self.require_artifacts(lock)?;
        let prepared = store.prepare(lock).map_err(|_| "plugin_prepare_failed")?;
        if prepared.program(tool_package(lock)?).is_none() {
            return Err("plugin_prepare_failed");
        }
        Ok(())
    }

    pub fn switch_plugin_state_schema(
        &self,
        session_id: &str,
        graph_id: &str,
        cancellation: &RunCancellation,
    ) -> Result<Option<u64>, &'static str> {
        validate_public_id(session_id)?;
        let lock = self.prepared_lock(graph_id)?;
        let package_id = tool_package(&lock)?.to_string();
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        let installed = store
            .read_installed(
                &lock
                    .packages
                    .iter()
                    .find(|package| package.id == package_id)
                    .ok_or("plugin_artifact_unavailable")?
                    .artifact_id,
            )
            .map_err(|_| "plugin_artifact_unavailable")?;
        let Some(state) = installed.manifest.state.as_ref() else {
            return Ok(None);
        };
        if state.scope != "session" {
            return Ok(None);
        }
        let target_schema = u32::try_from(state.schema).map_err(|_| "plugin_state_invalid")?;
        // Same linearization rule as admission migration: publish the lease in
        // the short commit_gate section, then do every read/write outside it.
        let _lease = {
            let _gate = self.inner.commit_gate.lock();
            cancellation.ensure_open().map_err(|_| "cancelled")?;
            super::SessionMaintenanceLease::acquire(
                Arc::clone(&self.inner.session_maintenance),
                session_id,
            )
            .ok_or("session_busy")?
        };
        let persistence = self
            .inner
            .persistence
            .as_ref()
            .ok_or("plugin_control_unconfigured")?;
        let state_store = crate::plugins::PluginStateStore::open(Arc::clone(persistence));
        loop {
            cancellation.ensure_open().map_err(|_| "cancelled")?;
            if state_store
                .session_nonterminal_runs(session_id)
                .map_err(|_| "plugin_state_unavailable")?
                == 0
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let Some(key) = state_store
            .session_root_key(session_id, &package_id)
            .map_err(|_| "plugin_state_unavailable")?
        else {
            return Ok(None);
        };
        let root = state_store
            .root(&key)
            .map_err(|_| "plugin_state_unavailable")?
            .ok_or("plugin_state_root_missing")?;
        if root.schema == target_schema {
            return Ok(Some(root.revision));
        }
        if root.schema > target_schema {
            return Err("state_incompatible");
        }
        let prepared = store.prepare(&lock).map_err(|_| "plugin_prepare_failed")?;
        let migration = prepared
            .state_migration(&package_id)
            .ok_or("state_incompatible")?;
        let old = state_store
            .object_payload(&root.object_id)
            .map_err(|_| "plugin_state_object_missing")?;
        let payload = migration
            .evaluate(root.schema, &old, cancellation)
            .map_err(|_| "plugin_state_migration_failed")?;
        cancellation.ensure_open().map_err(|_| "cancelled")?;
        let (object, owner) = state_store
            .put_object_reserved(&package_id, &installed.artifact_id, target_schema, &payload)
            .map_err(|_| "plugin_state_unavailable")?;
        cancellation.ensure_open().map_err(|_| "cancelled")?;
        let switched = state_store
            .migrate_root_with_owner(&key, root.revision, &object, Some(owner))
            .map_err(|error| error.code)?;
        Ok(Some(switched.revision))
    }

    /// Prepares the pure migration for the exact authorized session root of the
    /// run being admitted. The payload and its immutable object are written
    /// outside the global admission gate; the root CAS and run binding are
    /// published by the durable admission transaction itself. The session
    /// maintenance lease is returned with the plan and held until admission
    /// succeeds or fails.
    pub(crate) fn prepare_admitted_pin_state(
        &self,
        identity: &StateMigrationIdentity<'_>,
        pin: &crate::plugins::PreparedProductionPin,
        workspace_id: &str,
        branch_id: &str,
        cancellation: &RunCancellation,
    ) -> Result<Option<PreparedStateAdmission>, AdmitError> {
        let Some(state) = pin.state() else {
            return Ok(None);
        };
        if state.scope != "session" {
            return Ok(None);
        }
        let target = u32::try_from(state.schema)
            .map_err(|_| AdmitError::Invalid("plugin_state_invalid".into()))?;
        if target == 0 || target > 64 {
            return Err(AdmitError::Invalid("plugin_state_invalid".into()));
        }
        let persistence = self
            .inner
            .persistence
            .clone()
            .ok_or_else(|| AdmitError::Invalid("plugin_state_unavailable".into()))?;
        let state_store = crate::plugins::PluginStateStore::open(Arc::clone(&persistence));
        let Some(key) = state_store
            .session_root_key_for(
                identity.session_id,
                pin.package_id(),
                workspace_id,
                branch_id,
            )
            .map_err(|error| AdmitError::Invalid(error.code.into()))?
        else {
            return Ok(None);
        };
        let Some(live) = state_store
            .root(&key)
            .map_err(|error| AdmitError::Invalid(error.code.into()))?
        else {
            return Ok(None);
        };
        if live.schema > target {
            return Err(AdmitError::Invalid("state_incompatible".into()));
        }
        if live.schema == target {
            return Ok(Some(PreparedStateAdmission::Guard(
                PluginStateGuard::from_live_root(
                    identity.session_id,
                    workspace_id,
                    branch_id,
                    &live,
                ),
            )));
        }
        // Only a real schema switch takes the session maintenance lease and
        // waits for every nonterminal run of the session. Same-schema
        // admissions above never enter this path, so they cannot be blocked
        // by, or block on, an unrelated run or another branch.
        // Publish the maintenance lease inside the short commit_gate critical
        // section, then release the gate before waiting, reading or writing.
        // The admission maintenance check and this lease publication therefore
        // share one linearization point: an admission that already passed its
        // in-gate check must complete its durable commit before this lease is
        // visible, and any later admission observes the lease and is rejected.
        let lease = {
            let _gate = self.inner.commit_gate.lock();
            cancellation
                .ensure_open()
                .map_err(|_| AdmitError::Invalid("cancelled".into()))?;
            super::SessionMaintenanceLease::acquire(
                Arc::clone(&self.inner.session_maintenance),
                identity.session_id,
            )
            .ok_or(AdmitError::SessionMaintenanceBusy(
                crate::service::CompactionError::from_rss(
                    "busy",
                    "session maintenance is in progress",
                ),
            ))?
        };
        loop {
            cancellation
                .ensure_open()
                .map_err(|_| AdmitError::Invalid("cancelled".into()))?;
            if state_store
                .session_nonterminal_runs(identity.session_id)
                .map_err(|error| AdmitError::Invalid(error.code.into()))?
                == 0
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // The lease excludes a concurrent switch, but a switch that completed
        // while this admission was waiting may already have reached the target
        // schema. Decide from this fresh read, never from the pre-lease one.
        let Some(live) = state_store
            .root(&key)
            .map_err(|error| AdmitError::Invalid(error.code.into()))?
        else {
            return Ok(None);
        };
        if live.schema > target {
            return Err(AdmitError::Invalid("state_incompatible".into()));
        }
        if live.schema == target {
            return Ok(Some(PreparedStateAdmission::Guard(
                PluginStateGuard::from_live_root(
                    identity.session_id,
                    workspace_id,
                    branch_id,
                    &live,
                ),
            )));
        }
        let migration = pin
            .migration()
            .ok_or_else(|| AdmitError::Invalid("state_incompatible".into()))?;
        let payload = state_store
            .object_payload(&live.object_id)
            .map_err(|error| AdmitError::Invalid(error.code.into()))?;
        let migrated = migration
            .evaluate(live.schema, &payload, cancellation)
            .map_err(|error| AdmitError::Invalid(error.code.into()))?;
        cancellation
            .ensure_open()
            .map_err(|_| AdmitError::Invalid("cancelled".into()))?;
        let (object, owner) = state_store
            .put_object_reserved(pin.package_id(), pin.artifact_id(), target, &migrated)
            .map_err(|error| AdmitError::Invalid(error.code.into()))?;
        Ok(Some(PreparedStateAdmission::Migration(Box::new(
            PreparedStateMigration {
                session_id: identity.session_id.to_string(),
                run_id: identity.run_id.to_string(),
                workspace_id: workspace_id.to_string(),
                branch_id: branch_id.to_string(),
                plugin_id: key.plugin_id,
                package_id: pin.package_id().to_string(),
                artifact_id: pin.artifact_id().to_string(),
                graph_id: identity.graph_id.to_string(),
                generation: identity.generation,
                ref_id: identity.ref_id.to_string(),
                epoch: identity.epoch,
                old_schema: live.schema,
                expected_revision: live.revision,
                expected_object_id: live.object_id,
                object: Some(object),
                state_store: state_store.clone(),
                _candidate: Some(owner),
                _lease: Some(lease),
            },
        ))))
    }

    fn require_rollback_state_compatible(
        &self,
        lock: &crate::plugins::GraphLock,
        _persistence: &GatewayPersistence,
    ) -> Result<(), &'static str> {
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        let state_store = crate::plugins::PluginStateStore::open(Arc::clone(
            &self
                .inner
                .persistence
                .clone()
                .ok_or("plugin_control_unconfigured")?,
        ));
        for package in &lock.packages {
            let installed = store
                .read_installed(&package.artifact_id)
                .map_err(|_| "plugin_artifact_unavailable")?;
            let target = installed
                .manifest
                .state
                .as_ref()
                .map(|state| state.schema)
                .unwrap_or(0);
            let live = state_store
                .session_max_schema(&installed.manifest.id)
                .map_err(|_| "plugin_state_unavailable")?;
            if live > target {
                return Err("state_incompatible");
            }
        }
        Ok(())
    }

    fn validate_stateful(&self, lock: &crate::plugins::GraphLock) -> Result<(), &'static str> {
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        for package in &lock.packages {
            let installed = store
                .read_installed(&package.artifact_id)
                .map_err(|_| "plugin_artifact_unavailable")?;
            let Some(state) = installed.manifest.state.as_ref() else {
                continue;
            };
            if state.scope != "run" && state.scope != "session" && state.scope != "invocation" {
                return Err("plugin_state_invalid");
            }
            if state.schema == 0 || state.schema > 64 {
                return Err("plugin_state_invalid");
            }
            if let Some(migration) = state.migration.as_ref() {
                let entry = installed
                    .manifest
                    .effects
                    .entries
                    .get(&migration.entry)
                    .ok_or("plugin_state_migration_undeclared")?;
                if !entry.direct.is_empty() || !entry.delegated.is_empty() {
                    return Err("plugin_state_migration_impure");
                }
                crate::plugins::validate_state_migration_source(&installed, &migration.entry)?;
            }
        }
        Ok(())
    }

    fn require_artifacts(&self, lock: &crate::plugins::GraphLock) -> Result<(), &'static str> {
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        for package in &lock.packages {
            store
                .read_installed(&package.artifact_id)
                .map_err(|_| "plugin_artifact_unavailable")?;
        }
        Ok(())
    }

    fn forget_prepared(&self, graph_id: &str) {
        lock_mut(&self.inner.prepared_plugin_graphs).remove(graph_id);
    }
}

impl Clone for PluginControlBinding {
    fn clone(&self) -> Self {
        Self {
            authorization: InstallAuthorization {
                admin: self.authorization.admin,
                accepted_publishers: self.authorization.accepted_publishers.clone(),
                unsigned_dev_space: self.authorization.unsigned_dev_space.clone(),
            },
            source_root: self.source_root.clone(),
            deployment_space: self.deployment_space.clone(),
        }
    }
}

fn activation_body(space: &str, receipt: &crate::plugins::ActivationPointer) -> Value {
    json!({
        "graph_id": receipt.graph_id,
        "generation": receipt.generation,
        "activation_id": format!("{space}.{}", receipt.generation),
    })
}

fn public_graph(lock: &crate::plugins::GraphLock) -> Value {
    let nodes: Vec<Value> = lock
        .packages
        .iter()
        .map(|package| {
            json!({
                "id": package.id,
                "version": package.version,
                "kind": package.kind,
            })
        })
        .collect();
    let edges: Vec<Value> = lock
        .edges
        .iter()
        .map(|edge| {
            json!({
                "from": edge.from,
                "to": edge.to,
                "relation": edge.relation,
            })
        })
        .collect();
    let permissions: Vec<Value> = lock
        .closure
        .iter()
        .map(|effect| {
            json!({
                "package": effect.package,
                "kinds": effect.effects.iter().map(|item| item.kind.clone()).collect::<Vec<_>>(),
            })
        })
        .collect();
    let contract = match &lock.harness_selection {
        HarnessSelection::ToolOnly { tool_package } => json!({
            "mode": "tool_only",
            "tool_package": tool_package,
        }),
        HarnessSelection::Unselected => json!({"mode": "unselected"}),
        HarnessSelection::ContextPrompt {
            tool_package,
            policy,
        } => json!({
            "mode": "context_prompt",
            "tool_package": tool_package,
            "policy_package": policy.package_id,
        }),
    };
    json!({
        "graph_id": lock.graph_id,
        "nodes": nodes,
        "edges": edges,
        "contract": contract,
        "permissions": permissions,
        "errors": [],
    })
}

fn artifact_refs(lock: &crate::plugins::GraphLock) -> Vec<PackageArtifactRef> {
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

fn tool_package(lock: &crate::plugins::GraphLock) -> Result<&str, &'static str> {
    match &lock.harness_selection {
        HarnessSelection::ToolOnly { tool_package } => Ok(tool_package.as_str()),
        _ => Err("plugin_prepare_failed"),
    }
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: &Value) -> Result<T, &'static str> {
    serde_json::from_value(body.clone()).map_err(|_| "plugin_request_invalid")
}

fn map_plugin(error: crate::plugins::PluginError) -> &'static str {
    match error.kind {
        PluginErrorKind::PathEscape | PluginErrorKind::SymlinkDenied => "plugin_source_rejected",
        PluginErrorKind::PublisherUnauthorized => "plugin_publisher_unauthorized",
        PluginErrorKind::MissingDependency => "plugin_artifact_unavailable",
        PluginErrorKind::BudgetExceeded => "plugin_budget_exceeded",
        _ => "plugin_prepare_failed",
    }
}

fn map_control(error: crate::plugins::PluginControlError) -> &'static str {
    match error.code {
        "plugin_activation_conflict" => "plugin_activation_conflict",
        "plugin_graph_missing" => "plugin_graph_missing",
        "plugin_graph_revoked" => "plugin_graph_revoked",
        _ => "plugin_artifact_unavailable",
    }
}

fn trust_label(trust: PackageTrust) -> &'static str {
    match trust {
        PackageTrust::AcceptedPublisher => "accepted_publisher",
        PackageTrust::DevUnsigned => "dev_unsigned",
        PackageTrust::EmbeddingOwnedBuiltin => "embedding_builtin",
    }
}

fn deployment_space_ok(space: &str) -> bool {
    let mut chars = space.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    space.len() <= 64 && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn validate_public_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() || id.len() > 128 || id.contains('/') || id.contains('\\') || id.contains('\0')
    {
        Err("plugin_id_invalid")
    } else {
        Ok(())
    }
}

fn parse_activation_id(space: &str, label: &str) -> Result<u64, &'static str> {
    let Some(rest) = label.strip_prefix(space) else {
        return Err("plugin_activation_missing");
    };
    let Some(rest) = rest.strip_prefix('.') else {
        return Err("plugin_activation_missing");
    };
    if rest.is_empty() || rest.len() > 20 || (rest.starts_with('0') && rest != "0") {
        return Err("plugin_id_invalid");
    }
    if !rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("plugin_activation_missing");
    }
    rest.parse().map_err(|_| "plugin_id_invalid")
}

fn controlled_package(root: &Path, relative: &str) -> Result<PathBuf, &'static str> {
    if relative.is_empty()
        || relative.len() > 128
        || relative.contains('\0')
        || relative.contains('\\')
        || relative.starts_with('/')
    {
        return Err("plugin_source_rejected");
    }
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() {
        return Err("plugin_source_rejected");
    }
    let mut parts = Vec::new();
    for component in relative_path.components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str().ok_or("plugin_source_rejected")?;
                if text.starts_with('.') {
                    return Err("plugin_source_rejected");
                }
                parts.push(part.to_os_string());
            }
            _ => return Err("plugin_source_rejected"),
        }
    }
    if parts.is_empty() {
        return Err("plugin_source_rejected");
    }
    let root_meta = std::fs::symlink_metadata(root).map_err(|_| "plugin_source_rejected")?;
    if root_meta.file_type().is_symlink() {
        return Err("plugin_source_rejected");
    }
    let mut current = root.to_path_buf();
    for part in parts {
        current.push(part);
        let meta = std::fs::symlink_metadata(&current).map_err(|_| "plugin_source_rejected")?;
        if meta.file_type().is_symlink() {
            return Err("plugin_source_rejected");
        }
    }
    if !current.is_dir() {
        return Err("plugin_source_rejected");
    }
    let root_abs = root.canonicalize().map_err(|_| "plugin_source_rejected")?;
    let current_abs = current
        .canonicalize()
        .map_err(|_| "plugin_source_rejected")?;
    if !current_abs.starts_with(&root_abs) {
        return Err("plugin_source_rejected");
    }
    Ok(current)
}

fn lock_ref<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn lock_mut<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}
