//! Host-bound plugin graph control on the existing Native store.
//! Signatures, graph ids, and request JSON do not grant authority.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use super::AgentService;
use crate::plugins::{
    HOST_RUNTIME, HarnessSelection, HarnessSelectionRequest, InstallAuthorization,
    PackageArtifactRef, PackageRequirement, PackageTrust, PluginControlStore, PluginErrorKind,
    ResolveRequest,
};
use crate::runtime::rss_runner::RunCancellation;

pub(crate) struct PluginControlBinding {
    authorization: InstallAuthorization,
    source_root: PathBuf,
    deployment_space: String,
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
        self.reject_stateful(&loaded.lock)?;
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
        self.reject_stateful(lock)?;
        self.require_artifacts(lock)?;
        let prepared = store.prepare(lock).map_err(|_| "plugin_prepare_failed")?;
        if prepared.program(tool_package(lock)?).is_none() {
            return Err("plugin_prepare_failed");
        }
        Ok(())
    }

    fn reject_stateful(&self, lock: &crate::plugins::GraphLock) -> Result<(), &'static str> {
        let store = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        for package in &lock.packages {
            let installed = store
                .read_installed(&package.artifact_id)
                .map_err(|_| "plugin_artifact_unavailable")?;
            if installed.manifest.state.is_some() {
                return Err("plugin_state_unsupported");
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
