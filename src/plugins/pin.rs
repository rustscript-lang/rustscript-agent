//! Native admission pins one captured tool program inside the original
//! admission transaction.
//!
//! Caller JSON cannot select the graph, mint a ref, or choose the callable.
//! A successful replay returns the original run and ref without reading the
//! current activation or compiling a newer graph.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use uuid::Uuid;

use super::control_store::PluginControlStore;
use super::resolve::{GraphLock, LockedPackage};
use super::store::PackageStore;
use crate::gateway::store::GatewayPersistence;
use crate::runtime::agent_host::{
    NativeExecutionAuthority, PinnedToolCode, PinnedToolProgram, PinnedToolReceipt,
};

const POSTCOMMIT_UNPUBLISHED: &str = "failpoint_after_commit_before_publish";

#[derive(Debug)]
pub struct PinnedToolAdmitError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for PinnedToolAdmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl PinnedToolAdmitError {
    fn plugin(error: super::PluginError) -> Self {
        let code = error
            .chain
            .first()
            .and_then(|item| graph_admit_code(item))
            .unwrap_or("pinned_tool_unavailable");
        Self {
            code,
            message: if code == "pinned_tool_unavailable" {
                error.to_string()
            } else {
                code.into()
            },
        }
    }
    fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        let code = graph_admit_code(&message).unwrap_or("pinned_tool_unavailable");
        Self { code, message }
    }
}

fn graph_admit_code(message: &str) -> Option<&'static str> {
    const CODES: &[&str] = &[
        "plugin_graph_revoked",
        "plugin_graph_pin_required",
        "plugin_artifact_unavailable",
        "harness_policy_selection_invalid",
        "harness_topology_unsupported",
        "pinned_tool_unavailable",
        "deadline_elapsed",
        "cancelled",
    ];
    CODES.iter().copied().find(|code| *code == message)
}

/// Trusted host identity for a new admission. It is not read from caller JSON.
#[derive(Clone)]
pub struct PinnedAdmitContext {
    /// Original Native run root. Required for a policy-bearing graph.
    pub original_cancellation: Option<crate::RunCancellation>,
    pub registry_identity: String,
    pub workspace: PathBuf,
}

impl std::fmt::Debug for PinnedAdmitContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedAdmitContext")
            .field("registry_identity", &self.registry_identity)
            .field("workspace", &self.workspace)
            .finish_non_exhaustive()
    }
}

/// Admission receipt plus the callable program compiled from the pinned capture.
/// Display fields are not the execution identity. `program_handle` clones the
/// binding sealed once from the verified capture and committed receipt.
#[derive(Clone)]
pub struct PinnedToolAdmission {
    binding: Arc<PinnedToolProgram>,
    pub graph_id: String,
    pub generation: u64,
    pub ref_id: String,
    pub run_id: String,
    pub session_id: String,
    pub profile: String,
    pub entry: String,
}

impl PinnedToolAdmission {
    pub fn program_handle(&self) -> PinnedToolProgram {
        (*self.binding).clone()
    }

    pub fn shares_program(&self, other: &Arc<rustscript_vm::Program>) -> bool {
        self.binding.shares_program(other)
    }
}

/// Pins the active tool program, or replays the original pin for the same key.
///
/// Replay does not read the current activation, allocate a ref, or prepare a
/// newer graph. A post-commit publication failure is recovered from the
/// committed receipt; it is not reported as a rollback.
pub fn admit_pinned_tool_run(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    caller: &Value,
    context: &PinnedAdmitContext,
) -> Result<PinnedToolAdmission, PinnedToolAdmitError> {
    let key = text_field(caller, "idempotency_key");
    let scope = text_field(caller, "idempotency_scope");
    let hash = text_field(caller, "request_hash");
    if !key.is_empty() {
        let selector = optional_selector(caller);
        let replayed = persistence
            .admission_replay(&scope, &key, &hash, selector.as_deref())
            .map_err(|error| {
                PinnedToolAdmitError::new(format!("{}: {}", error.code, error.message))
            })?;
        if replayed.get("conflict") == Some(&Value::Bool(true)) {
            return Err(PinnedToolAdmitError::new(
                "idempotency key was used with a different request",
            ));
        }
        if replayed.get("replayed") == Some(&Value::Bool(true)) {
            return recover_pinned(
                persistence,
                store,
                &replayed,
                context.original_cancellation.as_ref(),
            );
        }
    }
    admit_new(persistence, store, caller, context)
}

fn admit_new(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    caller: &Value,
    context: &PinnedAdmitContext,
) -> Result<PinnedToolAdmission, PinnedToolAdmitError> {
    let control = PluginControlStore::new(persistence);
    let active = control
        .activation()
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
    if active.graph_id.is_empty() {
        return Err(PinnedToolAdmitError::new(
            "tool admission requires an active plugin graph",
        ));
    }
    let loaded = control
        .load_lock(&active.graph_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
    let package = select_tool_package(&loaded.lock)?;
    if matches!(
        loaded.lock.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) && context.original_cancellation.is_none()
    {
        return Err(PinnedToolAdmitError::new("deadline_elapsed"));
    }
    let prepared = match &context.original_cancellation {
        Some(cancel) => store.prepare_harness_graph(&loaded.lock, cancel),
        None => store.prepare(&loaded.lock),
    }
    .map_err(PinnedToolAdmitError::plugin)?;
    let captured = capture_tool(&prepared, package)?;
    let ref_id = Uuid::new_v4().to_string();
    let now_ms = caller.get("now_ms").cloned().unwrap_or(json!(0));
    let mut payload = caller.clone();
    let Some(object) = payload.as_object_mut() else {
        return Err(PinnedToolAdmitError::new(
            "admission payload must be an object",
        ));
    };
    for key in [
        "graph_id",
        "tool_graph_id",
        "tool_graph_generation",
        "tool_ref_id",
        "tool_pin_now_ms",
        "tool_registry_identity",
        "tool_workspace",
    ] {
        object.remove(key);
    }
    object.insert("tool_graph_id".to_string(), json!(active.graph_id));
    object.insert(
        "tool_graph_generation".to_string(),
        json!(active.generation),
    );
    object.insert("tool_ref_id".to_string(), json!(ref_id));
    object.insert("tool_pin_now_ms".to_string(), now_ms);
    object.insert(
        "tool_registry_identity".to_string(),
        json!(context.registry_identity),
    );
    object.insert(
        "tool_workspace".to_string(),
        json!(path_text(&context.workspace)),
    );
    if matches!(
        loaded.lock.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) {
        let encoded = payload["input_json"]
            .as_str()
            .ok_or_else(|| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
        let mut outer: Value = serde_json::from_str(encoded)
            .map_err(|_| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
        if !outer["run_context"].is_object() {
            return Err(PinnedToolAdmitError::new(
                "harness_policy_selection_invalid",
            ));
        }
        outer["run_graph_selection"] = json!({"graph_id":active.graph_id,"ref_id":ref_id,"harness_selection":loaded.lock.harness_selection});
        let encoded = serde_json::to_string(&outer)
            .map_err(|_| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
        if encoded.len() > crate::config::MAX_RUN_CONTEXT_STORAGE_BYTES {
            return Err(PinnedToolAdmitError::new(
                "harness_policy_input_budget_exceeded",
            ));
        }
        payload["input_json"] = json!(encoded);
    }
    if let Some(cancel) = &context.original_cancellation {
        cancel.ensure_open().map_err(PinnedToolAdmitError::new)?;
    }
    match persistence.admission_create(&payload) {
        Ok(data) => {
            if data.get("replayed") == Some(&Value::Bool(true)) {
                return recover_pinned(
                    persistence,
                    store,
                    &data,
                    context.original_cancellation.as_ref(),
                );
            }
            let pin = data
                .get("pin")
                .ok_or_else(|| PinnedToolAdmitError::new("admission did not return a tool pin"))?;
            validate_pin_selection(pin, &loaded.lock)?;
            let pinned_graph = text_field(pin, "graph_id");
            let pinned_ref = text_field(pin, "ref_id");
            let pinned_generation = number_field(pin, "generation");
            if pinned_graph != active.graph_id
                || pinned_ref != ref_id
                || pinned_generation != active.generation
            {
                return Err(PinnedToolAdmitError::new(
                    "admission pin receipt does not match the active graph",
                ));
            }
            let run_id = first_present(&[text_field(pin, "run_id"), text_field(caller, "run_id")]);
            let session_id = first_present(&[
                text_field(pin, "session_id"),
                text_field(caller, "session_id"),
            ]);
            let profile =
                first_present(&[text_field(pin, "profile"), text_field(caller, "profile")]);
            if run_id.is_empty() || session_id.is_empty() || profile.is_empty() {
                return Err(PinnedToolAdmitError::new(
                    "admission receipt is missing the committed run identity",
                ));
            }
            if let Some(cancel) = &context.original_cancellation {
                cancel.ensure_open().map_err(PinnedToolAdmitError::new)?;
            }
            Ok(binding_from_capture(
                captured,
                PinnedToolReceipt {
                    graph_id: active.graph_id,
                    generation: active.generation,
                    ref_id,
                    run_id,
                    session_id,
                    profile,
                    registry_identity: context.registry_identity.clone(),
                    workspace: context.workspace.clone(),
                },
                persistence,
            ))
        }
        Err(error) if error.code == POSTCOMMIT_UNPUBLISHED => recover_unpublished(
            persistence,
            store,
            &text_field(caller, "idempotency_scope"),
            &text_field(caller, "idempotency_key"),
            &text_field(caller, "request_hash"),
            optional_selector(caller).as_deref(),
            context.original_cancellation.as_ref(),
        ),
        Err(error) => Err(PinnedToolAdmitError::new(format!(
            "{}: {}",
            error.code, error.message
        ))),
    }
}

fn recover_unpublished(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    scope: &str,
    key: &str,
    hash: &str,
    selector: Option<&str>,
    cancel: Option<&crate::RunCancellation>,
) -> Result<PinnedToolAdmission, PinnedToolAdmitError> {
    if key.is_empty() {
        return Err(PinnedToolAdmitError::new(
            "admission committed but live publication failed and no idempotency key can recover it",
        ));
    }
    let replayed = persistence
        .admission_replay(scope, key, hash, selector)
        .map_err(|error| PinnedToolAdmitError::new(format!("{}: {}", error.code, error.message)))?;
    if replayed.get("replayed") != Some(&Value::Bool(true)) {
        return Err(PinnedToolAdmitError::new(
            "admission committed but live publication failed and exact recovery did not return the original run",
        ));
    }
    recover_pinned(persistence, store, &replayed, cancel)
}

fn recover_pinned(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    data: &Value,
    cancel: Option<&crate::RunCancellation>,
) -> Result<PinnedToolAdmission, PinnedToolAdmitError> {
    let pin = data
        .get("pin")
        .ok_or_else(|| PinnedToolAdmitError::new("replay did not return the original tool pin"))?;
    if pin.get("pinned") != Some(&Value::Bool(true)) {
        return Err(PinnedToolAdmitError::new(
            "replayed admission has no durable tool pin",
        ));
    }
    let graph_id = required_text(pin, "graph_id")?;
    let ref_id = required_text(pin, "ref_id")?;
    let run_id = required_text(pin, "run_id")?;
    let session_id = required_text(pin, "session_id")?;
    let profile = required_text(pin, "profile")?;
    let registry_identity = required_text(pin, "registry_identity")?;
    let workspace = pinned_workspace(pin)?;
    let generation = number_field(pin, "generation");
    let control = PluginControlStore::new(persistence);
    let loaded = control
        .load_lock(&graph_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
    validate_pin_selection(pin, &loaded.lock)?;
    if matches!(
        loaded.lock.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) {
        let cancel = cancel.ok_or_else(|| PinnedToolAdmitError::new("deadline_elapsed"))?;
        let binding = restore_owned_pin_with_cancellation(persistence, store, &run_id, cancel)?;
        let entry = binding.declared_export().to_string();
        return Ok(PinnedToolAdmission {
            binding: Arc::new(binding),
            graph_id,
            generation,
            ref_id,
            run_id,
            session_id,
            profile,
            entry,
        });
    }
    let package = select_tool_package(&loaded.lock)?;
    if !control
        .package_refs(&graph_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?
        .iter()
        .any(|item| item.package_id == package.id && item.artifact_id == package.artifact_id)
    {
        return Err(PinnedToolAdmitError::new(
            "pinned package artifact is no longer the captured ref",
        ));
    }
    // A recovered executable binding re-checks the exact current graph
    // revocation before it can run; the reader stays attached to the pin.
    let revoked = match cancel {
        Some(cancel) => control
            .graph_revocation_for_execution(&graph_id, cancel)
            .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?,
        None => control
            .graph_revocation(&graph_id)
            .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
            .filter(|fact| fact.graph_id == graph_id),
    };
    if revoked.is_some() {
        return Err(PinnedToolAdmitError::new("plugin_graph_revoked"));
    }
    let prepared = store
        .prepare(&loaded.lock)
        .map_err(PinnedToolAdmitError::plugin)?;
    let captured = capture_tool(&prepared, package)?;
    Ok(binding_from_capture(
        captured,
        PinnedToolReceipt {
            graph_id,
            generation,
            ref_id,
            run_id,
            session_id,
            profile,
            registry_identity,
            workspace,
        },
        persistence,
    ))
}

/// Immutable capture of the one stateless callee: its program, entry,
/// registry, catalog and the single plugin edge.
struct CapturedChild {
    callee_package: String,
    callee_artifact: String,
    callee_export: String,
    callee_entry: String,
    callee_tool: String,
    callee_catalog: Arc<crate::effects::authority::ManagedToolPolicyCatalog>,
    callee_program: Arc<rustscript_vm::Program>,
    callee_registry: Result<Arc<rustscript_vm::HostFunctionRegistry>, String>,
    callee_state: Option<crate::plugins::StateDeclaration>,
    callee_contract: Option<crate::effects::broker::ManagedEntryContract>,
    edge_alias: String,
    from_entry: String,
    to_entry: String,
    effect: crate::effects::broker::ManagedEffectRequirement,
}

struct CapturedTool {
    harness_selection: super::resolve::HarnessSelection,
    managed_policy_catalog: Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>>,
    child: Option<CapturedChild>,
    managed_contract: Option<crate::effects::broker::ManagedEntryContract>,
    state: Option<crate::plugins::StateDeclaration>,
    program: Arc<rustscript_vm::Program>,
    invoke_entry: String,
    export: String,
    package_id: String,
    artifact_id: String,
    registry: Result<Arc<rustscript_vm::HostFunctionRegistry>, String>,
}

fn capture_tool(
    prepared: &super::prepare::PreparedGraph,
    package: &LockedPackage,
) -> Result<CapturedTool, PinnedToolAdmitError> {
    if matches!(
        prepared.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) && prepared
        .managed_contract(&package.id)
        .is_none_or(|contract| contract.topology.is_none())
    {
        return Err(PinnedToolAdmitError::new("harness_topology_unsupported"));
    }
    let program = prepared.program(&package.id).ok_or_else(|| {
        PinnedToolAdmitError::new(format!("prepared graph dropped program {}", package.id))
    })?;
    let invoke_entry = prepared
        .entry_callable(&package.id)
        .filter(|entry| !entry.is_empty())
        .ok_or_else(|| PinnedToolAdmitError::new("captured tool has no callable entry"))?
        .to_string();
    let export = prepared
        .export_name(&package.id)
        .filter(|export| !export.is_empty())
        .ok_or_else(|| PinnedToolAdmitError::new("captured manifest has no export"))?
        .to_string();
    Ok(CapturedTool {
        child: prepared
            .delegation(&package.id)
            .map(|linked| CapturedChild {
                callee_package: linked.callee_package,
                callee_artifact: linked.callee_artifact,
                callee_export: linked.callee_export,
                callee_entry: linked.callee_entry,
                callee_tool: linked.callee_tool,
                callee_catalog: linked.callee_catalog,
                callee_program: linked.callee_program,
                callee_registry: linked.callee_registry,
                callee_state: linked.callee_state,
                callee_contract: linked.callee_contract,
                edge_alias: linked.edge_alias,
                from_entry: linked.from_entry,
                to_entry: linked.to_entry,
                effect: linked.effect,
            }),
        harness_selection: prepared.harness_selection.clone(),
        managed_contract: prepared.managed_contract(&package.id),
        managed_policy_catalog: prepared.managed_policy_catalog(&package.id),
        state: prepared.state_declaration(&package.id),
        registry: prepared
            .registry(&package.id)
            .ok_or_else(|| PinnedToolAdmitError::new("prepared graph dropped tool registry"))?,
        program,
        invoke_entry,
        export,
        package_id: package.id.clone(),
        artifact_id: package.artifact_id.clone(),
    })
}

fn binding_from_capture(
    captured: CapturedTool,
    receipt: PinnedToolReceipt,
    persistence: &Arc<GatewayPersistence>,
) -> PinnedToolAdmission {
    let child = captured.child.as_ref().map(|linked| {
        Arc::new(crate::runtime::agent_host::PinnedPluginChildTemplate {
            caller_package: captured.package_id.clone(),
            caller_catalog: captured
                .managed_policy_catalog
                .clone()
                .expect("caller catalog captured with the delegation topology"),
            callee_package: linked.callee_package.clone(),
            callee_artifact: linked.callee_artifact.clone(),
            callee_export: linked.callee_export.clone(),
            callee_tool: linked.callee_tool.clone(),
            callee_code: crate::effects::ManagedCodeIdentity {
                graph_id: receipt.graph_id.clone(),
                activation_generation: receipt.generation,
                graph_ref_id: receipt.ref_id.clone(),
                package_id: linked.callee_package.clone(),
                artifact_id: linked.callee_artifact.clone(),
                export: linked.callee_export.clone(),
                registry_identity: linked
                    .callee_catalog
                    .descriptor_registry_identity()
                    .to_string(),
                effect_contract_version: 1,
            },
            callee_catalog: Arc::clone(&linked.callee_catalog),
            callee_program: Arc::clone(&linked.callee_program),
            callee_entry: linked.callee_entry.clone(),
            callee_registry: linked.callee_registry.clone(),
            callee_state: linked.callee_state.clone(),
            callee_contract: linked.callee_contract.clone(),
            edge_alias: linked.edge_alias.clone(),
            from_entry: linked.from_entry.clone(),
            to_entry: linked.to_entry.clone(),
            effect: linked.effect.clone(),
            run_id: receipt.run_id.clone(),
            session_id: receipt.session_id.clone(),
            profile: receipt.profile.clone(),
            workspace: receipt.workspace.clone(),
        })
    });
    let binding = PinnedToolProgram::seal(
        PinnedToolCode {
            child,
            harness_selection: captured.harness_selection,
            managed_contract: captured.managed_contract,
            managed_policy_catalog: captured.managed_policy_catalog,
            state: captured.state,
            program: captured.program,
            entry: captured.invoke_entry,
            package_id: captured.package_id.clone(),
            artifact_id: captured.artifact_id,
            export: captured.export.clone(),
            registry: captured.registry,
            expects_dispatch_input: captured.package_id
                == crate::runtime::native_tools::EMBEDDING_PACKAGE_ID,
        },
        receipt.clone(),
        NativeExecutionAuthority::Persistent {
            persistence: Arc::clone(persistence),
        },
    );
    PinnedToolAdmission {
        binding: Arc::new(binding),
        graph_id: receipt.graph_id,
        generation: receipt.generation,
        ref_id: receipt.ref_id,
        run_id: receipt.run_id,
        session_id: receipt.session_id,
        profile: receipt.profile,
        entry: captured.export,
    }
}

/// Active graph prepared outside the admission gate. The ref is this attempt's
/// receipt identity, not a caller-selected graph.
pub(crate) struct PreparedProductionPin {
    pub(crate) graph_id: String,
    pub(crate) generation: u64,
    pub(crate) ref_id: String,
    pub(crate) checkpoint_id: Option<String>,
    pub(crate) checkpoint_state_roots: Vec<crate::effects::journal::ManagedPluginStateRootRef>,
    captured: CapturedTool,
    migration: Option<Arc<crate::plugins::PluginStateMigrationProgram>>,
}

impl PreparedProductionPin {
    pub(crate) fn harness_selection(&self) -> &super::resolve::HarnessSelection {
        &self.captured.harness_selection
    }
    pub(crate) fn state(&self) -> Option<&crate::plugins::StateDeclaration> {
        self.captured.state.as_ref()
    }
    pub(crate) fn migration(&self) -> Option<Arc<crate::plugins::PluginStateMigrationProgram>> {
        self.migration.clone()
    }
    /// A checkpoint pin restores exact captured roots; it never prepares a
    /// schema migration against the live branch.
    pub(crate) fn has_checkpoint_state(&self) -> bool {
        !self.checkpoint_state_roots.is_empty()
    }
    pub(crate) fn package_id(&self) -> &str {
        &self.captured.package_id
    }
    pub(crate) fn artifact_id(&self) -> &str {
        &self.captured.artifact_id
    }
    pub(crate) fn managed_policy_catalog(
        &self,
    ) -> Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>> {
        self.captured.managed_policy_catalog.clone()
    }
    pub(crate) fn managed_contract(&self) -> Option<crate::effects::broker::ManagedEntryContract> {
        self.captured.managed_contract.clone()
    }
    pub(crate) fn managed_code(&self, registry: &str) -> crate::effects::ManagedCodeIdentity {
        crate::effects::ManagedCodeIdentity {
            graph_id: self.graph_id.clone(),
            activation_generation: self.generation,
            graph_ref_id: self.ref_id.clone(),
            package_id: self.captured.package_id.clone(),
            artifact_id: self.captured.artifact_id.clone(),
            export: self.captured.export.clone(),
            registry_identity: registry.into(),
            effect_contract_version: 1,
        }
    }
}

pub(crate) fn prepare_checkpoint_pin(
    persistence: &GatewayPersistence,
    store: &PackageStore,
    checkpoint: &crate::effects::ManagedCheckpointRef,
    cancellation: &crate::RunCancellation,
) -> Result<PreparedProductionPin, PinnedToolAdmitError> {
    cancellation
        .ensure_open()
        .map_err(PinnedToolAdmitError::new)?;
    let graph = &checkpoint.graph;
    let control = PluginControlStore::new(persistence);
    if control
        .graph_revocation(&graph.graph_id)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
        .is_some()
    {
        return Err(PinnedToolAdmitError::new("plugin_graph_revoked"));
    }
    if !control
        .retained(&graph.graph_id)
        .map_err(|_| PinnedToolAdmitError::new("checkpoint graph unavailable"))?
        .iter()
        .any(|reference| {
            reference.owner_kind == "checkpoint"
                && reference.owner_id == checkpoint.checkpoint_id
                && reference.ref_id == graph.checkpoint_graph_ref_id
        })
    {
        return Err(PinnedToolAdmitError {
            code: "plugin_graph_pin_required",
            message: "tool graph pin is required".into(),
        });
    }
    let loaded = control
        .load_lock(&graph.graph_id)
        .map_err(|_| PinnedToolAdmitError::new("checkpoint graph unavailable"))?;
    let package = select_tool_package(&loaded.lock)?;
    // S2: the harness caller stays stateless and the single locked callee owns
    // the run-scoped state the checkpoint covers. Every caller-owned state path
    // keeps naming the harness tool.
    let callee = locked_link_callee(&loaded.lock, package);
    let state_owner = callee.map_or(
        (package.id.as_str(), package.artifact_id.as_str()),
        |callee| (callee.id.as_str(), callee.artifact_id.as_str()),
    );
    if loaded.lock.harness_selection != graph.harness_selection {
        // The retained graph owns the library identity. Do not reclassify a
        // primary-tool or selection-mode mismatch as a policy failure.
        if matches!(
            (&loaded.lock.harness_selection, &graph.harness_selection),
            (
                super::HarnessSelection::ContextPrompt { tool_package: expected, policy },
                super::HarnessSelection::ContextPrompt { tool_package: actual, policy: supplied },
            ) if expected == actual
                && policy.package_id == supplied.package_id
                && policy.artifact_id == supplied.artifact_id
                && policy.entry_path == supplied.entry_path
                && policy.prompt_export == supplied.prompt_export
                && policy.context_export == supplied.context_export
                && policy.guardian_export != supplied.guardian_export
        ) {
            return Err(PinnedToolAdmitError::new(
                "harness_policy_selection_invalid",
            ));
        }
        return Err(PinnedToolAdmitError::new(
            "checkpoint harness selection mismatch",
        ));
    }
    use crate::effects::journal::ManagedCheckpointStateCoverage as Coverage;
    let covered = match (&loaded.lock.harness_selection, &checkpoint.plugin_state) {
        (
            _,
            Coverage::Stateful {
                graph_id,
                package_id,
                artifact_id,
                manifest_state_present,
                invocation_excluded_from_checkpoint,
                roots,
            },
        ) => {
            graph_id == &graph.graph_id
                && package_id.as_str() == state_owner.0
                && artifact_id.as_str() == state_owner.1
                && *manifest_state_present
                && if *invocation_excluded_from_checkpoint {
                    roots.is_empty()
                } else {
                    !roots.is_empty()
                }
                && roots.iter().all(|root| {
                    root.package_id.as_str() == state_owner.0
                        && root.artifact_id.as_str() == state_owner.1
                        && root.plugin_id.as_str() == state_owner.0
                        && root.owner_kind == root.scope
                        && matches!(root.owner_kind.as_str(), "run" | "session")
                        && root
                            .schema
                            .parse::<u32>()
                            .is_ok_and(|schema| (1..=64).contains(&schema))
                        && root.revision >= 1
                        && !root.immutable_root_id.is_empty()
                })
        }
        (
            super::HarnessSelection::ToolOnly { .. },
            Coverage::StatelessBuiltin {
                graph_id,
                package_id,
                artifact_id,
                manifest_state_absent,
                state_effects_absent,
                roots,
            },
        ) => {
            graph_id == &graph.graph_id
                && package_id == &package.id
                && artifact_id == &package.artifact_id
                && *manifest_state_absent
                && *state_effects_absent
                && roots.is_empty()
                && checkpoint.public_config.config.policy_revision == "stateless_builtin"
        }
        (
            super::HarnessSelection::ContextPrompt { policy, .. },
            Coverage::StatelessBuiltinWithPurePolicy {
                graph_id,
                package_id,
                artifact_id,
                policy: proof,
                manifest_state_absent,
                state_effects_absent,
                policy_host_imports_absent,
                roots,
            },
        ) => {
            graph_id == &graph.graph_id
                && package_id == &package.id
                && artifact_id == &package.artifact_id
                && proof == policy
                && *manifest_state_absent
                && *state_effects_absent
                && *policy_host_imports_absent
                && roots.is_empty()
                && checkpoint.public_config.config.policy_revision
                    == "stateless_builtin_with_pure_policy"
        }
        _ => false,
    };
    if !covered {
        return Err(PinnedToolAdmitError::new(
            "harness_policy_selection_invalid",
        ));
    }
    if package.id != graph.package_id || package.artifact_id != graph.artifact_id {
        return Err(PinnedToolAdmitError::new("checkpoint package mismatch"));
    }
    // A compiled capture does not replace the checkpoint package's required
    // installed artifact on a fresh restore admission.
    let installed =
        store
            .read_installed(&package.artifact_id)
            .map_err(|_| PinnedToolAdmitError {
                code: "plugin_artifact_unavailable",
                message: "plugin artifact is unavailable".into(),
            })?;
    if let Coverage::Stateful { roots, .. } = &checkpoint.plugin_state {
        // The state declaration belongs to the covered owner: the harness tool
        // for caller-owned state, the locked callee for S2.
        let state_owner_installed = if state_owner.1 == package.artifact_id {
            None
        } else {
            Some(
                store
                    .read_installed(state_owner.1)
                    .map_err(|_| PinnedToolAdmitError {
                        code: "plugin_artifact_unavailable",
                        message: "plugin artifact is unavailable".into(),
                    })?,
            )
        };
        let owner = state_owner_installed.as_ref().unwrap_or(&installed);
        let state = owner
            .manifest
            .state
            .as_ref()
            .ok_or_else(|| PinnedToolAdmitError::new("plugin_state_root_mismatch"))?;
        let schema = state.schema.to_string();
        if roots.iter().any(|root| root.schema != schema) {
            return Err(PinnedToolAdmitError::new("plugin_state_root_mismatch"));
        }
    }
    let prepared = store
        .prepare_harness_graph(&loaded.lock, cancellation)
        .map_err(PinnedToolAdmitError::plugin)?;
    let captured = capture_tool(&prepared, package)?;
    if captured.export != graph.export {
        return Err(PinnedToolAdmitError::new("checkpoint export mismatch"));
    }
    let checkpoint_state_roots = match &checkpoint.plugin_state {
        Coverage::Stateful { roots, .. } => roots.clone(),
        _ => Vec::new(),
    };
    let checkpoint_id = if checkpoint_state_roots.is_empty() {
        None
    } else {
        Some(checkpoint.checkpoint_id.clone())
    };
    Ok(PreparedProductionPin {
        graph_id: graph.graph_id.clone(),
        generation: graph.captured_activation_generation,
        ref_id: Uuid::new_v4().to_string(),
        checkpoint_id,
        checkpoint_state_roots,
        captured,
        migration: None,
    })
}

pub(crate) fn prepare_production_pin(
    persistence: &GatewayPersistence,
    store: &PackageStore,
    active: &super::control_store::ActivationPointer,
    cancellation: &crate::RunCancellation,
) -> Result<PreparedProductionPin, PinnedToolAdmitError> {
    let control = PluginControlStore::new(persistence);
    cancellation
        .ensure_open()
        .map_err(PinnedToolAdmitError::new)?;
    if control
        .graph_revocation(&active.graph_id)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
        .is_some()
    {
        return Err(PinnedToolAdmitError::new("plugin_graph_revoked"));
    }
    if active.graph_id.is_empty() {
        return Err(PinnedToolAdmitError::new(
            "tool admission requires an active plugin graph",
        ));
    }
    let lock = control
        .load_lock(&active.graph_id)
        .map_err(|e| PinnedToolAdmitError::new(e.message))?
        .lock;
    let package = select_tool_package(&lock)?;
    let prepared = store
        .prepare_harness_graph(&lock, cancellation)
        .map_err(PinnedToolAdmitError::plugin)?;
    let captured = capture_tool(&prepared, package)?;
    let migration = prepared.state_migration(&package.id);
    Ok(PreparedProductionPin {
        graph_id: active.graph_id.clone(),
        generation: active.generation,
        ref_id: Uuid::new_v4().to_string(),
        checkpoint_id: None,
        checkpoint_state_roots: Vec::new(),
        captured,
        migration,
    })
}

pub(crate) fn seal_production_receipt(
    prepared: PreparedProductionPin,
    receipt: &Value,
    registry_identity: String,
    workspace: PathBuf,
    state_store: Option<crate::plugins::PluginStateStore>,
    persistence: &Arc<GatewayPersistence>,
) -> Result<crate::runtime::agent_host::PinnedToolProgram, PinnedToolAdmitError> {
    let pin = receipt
        .get("pin")
        .ok_or_else(|| PinnedToolAdmitError::new("admission did not return a tool pin"))?;
    let pinned_graph = required_text(pin, "graph_id")?;
    let pinned_ref = required_text(pin, "ref_id")?;
    let pinned_generation = number_field(pin, "generation");
    let selection: super::resolve::HarnessSelection = serde_json::from_value(
        pin.get("harness_selection")
            .cloned()
            .ok_or_else(|| PinnedToolAdmitError::new("harness selection missing"))?,
    )
    .map_err(|_| PinnedToolAdmitError::new("harness selection invalid"))?;
    if selection != *prepared.harness_selection() {
        return Err(PinnedToolAdmitError::new("harness selection mismatch"));
    }
    if pinned_graph != prepared.graph_id
        || pinned_ref != prepared.ref_id
        || pinned_generation != prepared.generation
    {
        return Err(PinnedToolAdmitError::new(
            "admission pin receipt does not match the prepared graph",
        ));
    }
    let run_id = required_text(pin, "run_id")?;
    let session_id = required_text(pin, "session_id")?;
    let profile = required_text(pin, "profile")?;
    if required_text(pin, "registry_identity")? != registry_identity
        || pinned_workspace(pin)? != workspace
    {
        return Err(PinnedToolAdmitError::new(
            "admission pin Native context does not match its own receipt",
        ));
    }
    let checkpoint_state_roots = prepared.checkpoint_state_roots.clone();
    let checkpoint_id = prepared.checkpoint_id.clone();
    let mut pin = binding_from_capture(
        prepared.captured,
        PinnedToolReceipt {
            graph_id: prepared.graph_id,
            generation: prepared.generation,
            ref_id: prepared.ref_id,
            run_id,
            session_id,
            profile,
            registry_identity,
            workspace,
        },
        persistence,
    )
    .program_handle();
    if let Some(state) = pin.state.clone() {
        let store =
            state_store.ok_or_else(|| PinnedToolAdmitError::new("plugin_state_binding_missing"))?;
        let scope = crate::plugins::PluginStateScope::parse(&state.scope)
            .ok_or_else(|| PinnedToolAdmitError::new("plugin_state_invalid"))?;
        let schema = u32::try_from(state.schema)
            .map_err(|_| PinnedToolAdmitError::new("plugin_state_invalid"))?;
        if scope == crate::plugins::PluginStateScope::Invocation {
            pin.state_store = Some(store);
            return Ok(pin);
        }
        let (workspace_id, branch_id, epoch) = state_workspace_identity(&pin, &store);
        let binding = if checkpoint_state_roots.is_empty() {
            store.bind_run(&crate::plugins::PluginStateBindRequest {
                run_id: pin.run_id.clone(),
                session_id: pin.session_id.clone(),
                workspace_id,
                branch_id,
                plugin_id: pin.package_id.clone(),
                package_id: pin.package_id.clone(),
                artifact_id: pin.artifact_id.clone(),
                scope,
                graph_id: pin.graph_id.clone(),
                epoch,
                schema,
                checkpoint_id: String::new(),
            })
        } else {
            let roots = checkpoint_state_roots
                .iter()
                .map(|root| {
                    Ok(crate::plugins::PluginStateRootRef {
                        owner_kind: root.owner_kind.clone(),
                        owner_id: root.owner_id.clone(),
                        workspace_id: root.workspace_id.clone(),
                        branch_id: root.branch_id.clone(),
                        plugin_id: root.plugin_id.clone(),
                        package_id: root.package_id.clone(),
                        artifact_id: root.artifact_id.clone(),
                        schema: root
                            .schema
                            .parse::<u32>()
                            .map_err(|_| PinnedToolAdmitError::new("plugin_state_root_mismatch"))?,
                        revision: root.revision,
                        object_id: root.immutable_root_id.clone(),
                    })
                })
                .collect::<Result<Vec<_>, PinnedToolAdmitError>>()?;
            store.restore_binding(&crate::plugins::PluginStateRestoreRequest {
                scope,
                run_id: pin.run_id.clone(),
                session_id: pin.session_id.clone(),
                workspace_id,
                branch_id,
                plugin_id: pin.package_id.clone(),
                package_id: pin.package_id.clone(),
                artifact_id: pin.artifact_id.clone(),
                graph_id: pin.graph_id.clone(),
                epoch,
                checkpoint_id: checkpoint_id.clone().unwrap_or_default(),
                roots,
            })
        }
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
        pin.state_binding = Some(binding.binding);
        pin.state_store = Some(store);
    } else if let Some(template) = pin.child.clone()
        && let Some(callee_state) = template.callee_state.clone()
        && callee_state.scope == "run"
        && callee_state.schema == 1
        && callee_state.migration.is_none()
    {
        // S2: the caller is stateless, so the only run binding is the
        // callee's. Retain the store and bind the callee root with the same
        // run identity the caller path uses; the child constructor reads the
        // live binding from this store. A checkpoint pin restores the captured
        // callee root instead of creating a fresh one.
        let store =
            state_store.ok_or_else(|| PinnedToolAdmitError::new("plugin_state_binding_missing"))?;
        let (workspace_id, branch_id, epoch) = state_workspace_identity(&pin, &store);
        if checkpoint_state_roots.is_empty() {
            let schema = u32::try_from(callee_state.schema)
                .map_err(|_| PinnedToolAdmitError::new("plugin_state_invalid"))?;
            store
                .bind_run(&crate::plugins::PluginStateBindRequest {
                    run_id: pin.run_id.clone(),
                    session_id: pin.session_id.clone(),
                    workspace_id,
                    branch_id,
                    plugin_id: template.callee_package.clone(),
                    package_id: template.callee_package.clone(),
                    artifact_id: template.callee_artifact.clone(),
                    scope: crate::plugins::PluginStateScope::Run,
                    graph_id: pin.graph_id.clone(),
                    epoch,
                    schema,
                    checkpoint_id: String::new(),
                })
                .map_err(|error| PinnedToolAdmitError::new(error.message))?;
        } else {
            let roots = checkpoint_state_roots
                .iter()
                .map(|root| {
                    Ok(crate::plugins::PluginStateRootRef {
                        owner_kind: root.owner_kind.clone(),
                        owner_id: root.owner_id.clone(),
                        workspace_id: root.workspace_id.clone(),
                        branch_id: root.branch_id.clone(),
                        plugin_id: root.plugin_id.clone(),
                        package_id: root.package_id.clone(),
                        artifact_id: root.artifact_id.clone(),
                        schema: root
                            .schema
                            .parse::<u32>()
                            .map_err(|_| PinnedToolAdmitError::new("plugin_state_root_mismatch"))?,
                        revision: root.revision,
                        object_id: root.immutable_root_id.clone(),
                    })
                })
                .collect::<Result<Vec<_>, PinnedToolAdmitError>>()?;
            store
                .restore_binding(&crate::plugins::PluginStateRestoreRequest {
                    scope: crate::plugins::PluginStateScope::Run,
                    run_id: pin.run_id.clone(),
                    session_id: pin.session_id.clone(),
                    workspace_id,
                    branch_id,
                    plugin_id: template.callee_package.clone(),
                    package_id: template.callee_package.clone(),
                    artifact_id: template.callee_artifact.clone(),
                    graph_id: pin.graph_id.clone(),
                    epoch,
                    checkpoint_id: checkpoint_id.clone().unwrap_or_default(),
                    roots,
                })
                .map_err(|error| PinnedToolAdmitError::new(error.message))?;
        }
        pin.state_store = Some(store);
    }
    Ok(pin)
}

fn state_workspace_identity(
    pin: &crate::runtime::agent_host::PinnedToolProgram,
    store: &crate::plugins::PluginStateStore,
) -> (String, String, u64) {
    store.managed_run_identity(&pin.run_id).unwrap_or_else(|| {
        (
            pin.workspace.to_string_lossy().to_string(),
            "default".to_string(),
            0,
        )
    })
}

pub fn restore_owned_pin(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    owner_id: &str,
) -> Result<crate::runtime::agent_host::PinnedToolProgram, PinnedToolAdmitError> {
    restore_owned_pin_inner(persistence, store, owner_id, None)
}
/// Read-only receipt validation. This produces no runnable code and does not
/// re-check execution availability or revocation; execution uses the clock-bound
/// restore path before a provider/tool can run.
pub(crate) fn validate_owned_harness_fact(
    persistence: &GatewayPersistence,
    owner: &str,
) -> Result<bool, PinnedToolAdmitError> {
    let control = PluginControlStore::new(persistence);
    let pin = control
        .pin_for_run(owner)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
    if pin["harness_selection"]["mode"] != "context_prompt" {
        return Ok(false);
    }
    let required = control
        .pin_requirement_for_run(owner)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
        .ok_or_else(|| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
    if pin["pinned"] != true
        || pin["run_id"] != owner
        || pin["graph_id"] != required.graph_id
        || pin["ref_id"] != required.ref_id
    {
        return Err(PinnedToolAdmitError::new("plugin_graph_pin_required"));
    }
    let lock = control
        .load_lock(&required.graph_id)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
        .lock;
    validate_pin_selection(&pin, &lock)?;
    let run = persistence
        .run_get(owner)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
    let outer: Value = serde_json::from_str(
        run["rows"][0][4]
            .as_str()
            .ok_or_else(|| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?,
    )
    .map_err(|_| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
    if outer["run_graph_selection"]
        != json!({"graph_id":required.graph_id,"ref_id":required.ref_id,"harness_selection":lock.harness_selection})
    {
        return Err(PinnedToolAdmitError::new(
            "harness_policy_selection_invalid",
        ));
    }
    Ok(true)
}

/// Read-only admission receipt validation for history replay. This proves the
/// exact captured identity/owner binding without constructing executable code,
/// without checking revocation, and without refreshing execution authority.
/// Revoked history stays replayable here; execution restore still refuses.
pub(crate) fn validate_owned_admission_receipt(
    persistence: &GatewayPersistence,
    owner_id: &str,
) -> Result<(), PinnedToolAdmitError> {
    let control = PluginControlStore::new(persistence);
    let pin = control
        .pin_for_run(owner_id)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
    if pin["pinned"] != true || pin["run_id"] != owner_id {
        return Err(PinnedToolAdmitError::new(
            "retained tool pin does not match the original run",
        ));
    }
    let graph_id = required_text(&pin, "graph_id")?;
    let ref_id = required_text(&pin, "ref_id")?;
    if graph_id.is_empty() || ref_id.is_empty() {
        return Err(PinnedToolAdmitError::new(
            "retained tool pin does not match the original run",
        ));
    }
    let required = control
        .pin_requirement_for_run(owner_id)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
        .ok_or_else(|| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
    if required.graph_id != graph_id || required.ref_id != ref_id {
        return Err(PinnedToolAdmitError::new("plugin_graph_pin_required"));
    }
    let loaded = control
        .load_lock(&graph_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
    validate_pin_selection(&pin, &loaded.lock)?;
    let run = persistence
        .run_get(owner_id)
        .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
    if matches!(
        loaded.lock.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) {
        let outer: Value = serde_json::from_str(
            run["rows"][0][4]
                .as_str()
                .ok_or_else(|| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?,
        )
        .map_err(|_| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
        if outer["run_graph_selection"]
            != json!({"graph_id":required.graph_id,"ref_id":required.ref_id,"harness_selection":loaded.lock.harness_selection})
        {
            return Err(PinnedToolAdmitError::new(
                "harness_policy_selection_invalid",
            ));
        }
    }
    Ok(())
}

pub(crate) fn restore_owned_pin_with_cancellation(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    owner_id: &str,
    cancel: &crate::RunCancellation,
) -> Result<PinnedToolProgram, PinnedToolAdmitError> {
    restore_owned_pin_inner(persistence, store, owner_id, Some(cancel))
}
fn restore_owned_pin_inner(
    persistence: &Arc<GatewayPersistence>,
    store: &PackageStore,
    owner_id: &str,
    cancel: Option<&crate::RunCancellation>,
) -> Result<PinnedToolProgram, PinnedToolAdmitError> {
    if let Some(cancel) = cancel {
        cancel.ensure_open().map_err(|code| PinnedToolAdmitError {
            code,
            message: code.into(),
        })?;
    }
    let control = PluginControlStore::new(persistence);
    let pin = control
        .pin_for_run(owner_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
    if pin.get("pinned") != Some(&Value::Bool(true)) {
        return Err(PinnedToolAdmitError::new(
            "durable run has no retained tool pin",
        ));
    }
    let graph_id = required_text(&pin, "graph_id")?;
    let ref_id = required_text(&pin, "ref_id")?;
    let run_id = required_text(&pin, "run_id")?;
    let session_id = required_text(&pin, "session_id")?;
    let profile = required_text(&pin, "profile")?;
    let registry_identity = required_text(&pin, "registry_identity")?;
    let workspace = pinned_workspace(&pin)?;
    let generation = number_field(&pin, "generation");
    if run_id != owner_id || graph_id.is_empty() || ref_id.is_empty() {
        return Err(PinnedToolAdmitError::new(
            "retained tool pin does not match the original run",
        ));
    }
    let loaded = control
        .load_lock(&graph_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?;
    validate_pin_selection(&pin, &loaded.lock)?;
    if matches!(
        loaded.lock.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) {
        let required = control
            .pin_requirement_for_run(owner_id)
            .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
            .ok_or_else(|| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
        if required.graph_id != graph_id || required.ref_id != ref_id {
            return Err(PinnedToolAdmitError::new("plugin_graph_pin_required"));
        }
        if control
            .graph_revocation(&graph_id)
            .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
            .is_some()
        {
            return Err(PinnedToolAdmitError::new("plugin_graph_revoked"));
        }
        for package in &loaded.lock.packages {
            store
                .read_installed(&package.artifact_id)
                .map_err(|_| PinnedToolAdmitError::new("plugin_artifact_unavailable"))?;
        }
        let run = persistence
            .run_get(owner_id)
            .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?;
        let encoded = run["rows"][0][4]
            .as_str()
            .ok_or_else(|| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
        let outer: Value = serde_json::from_str(encoded)
            .map_err(|_| PinnedToolAdmitError::new("harness_policy_selection_invalid"))?;
        if outer["run_graph_selection"]
            != json!({"graph_id":graph_id,"ref_id":ref_id,"harness_selection":loaded.lock.harness_selection})
        {
            return Err(PinnedToolAdmitError::new(
                "harness_policy_selection_invalid",
            ));
        }
    }
    let package = select_tool_package(&loaded.lock)?;
    if !control
        .package_refs(&graph_id)
        .map_err(|error| PinnedToolAdmitError::new(error.message))?
        .iter()
        .any(|item| item.package_id == package.id && item.artifact_id == package.artifact_id)
    {
        return Err(PinnedToolAdmitError::new(
            "pinned package artifact is no longer the captured ref",
        ));
    }
    // Supported executable ToolOnly restores re-check the exact current
    // graph revocation before producing a runnable binding. The ContextPrompt
    // branch above already enforces its own requirement plus revocation.
    if !matches!(
        loaded.lock.harness_selection,
        super::HarnessSelection::ContextPrompt { .. }
    ) {
        let revoked = match cancel {
            Some(cancel) => control
                .graph_revocation_for_execution(&graph_id, cancel)
                .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?,
            None => control
                .graph_revocation(&graph_id)
                .map_err(|_| PinnedToolAdmitError::new("plugin_graph_pin_required"))?
                .filter(|fact| fact.graph_id == graph_id),
        };
        if revoked.is_some() {
            return Err(PinnedToolAdmitError::new("plugin_graph_revoked"));
        }
    }
    let prepared = match cancel {
        Some(cancel) => store.prepare_harness_graph(&loaded.lock, cancel),
        None => store.prepare(&loaded.lock),
    }
    .map_err(PinnedToolAdmitError::plugin)?;
    let captured = capture_tool(&prepared, package)?;
    Ok(binding_from_capture(
        captured,
        PinnedToolReceipt {
            graph_id,
            generation,
            ref_id,
            run_id,
            session_id,
            profile,
            registry_identity,
            workspace,
        },
        persistence,
    )
    .program_handle())
}

fn validate_pin_selection(pin: &Value, lock: &GraphLock) -> Result<(), PinnedToolAdmitError> {
    let selection: super::resolve::HarnessSelection = serde_json::from_value(
        pin.get("harness_selection")
            .cloned()
            .ok_or_else(|| PinnedToolAdmitError::new("harness selection missing"))?,
    )
    .map_err(|_| PinnedToolAdmitError::new("harness selection invalid"))?;
    if selection != lock.harness_selection {
        return Err(PinnedToolAdmitError::new("harness selection mismatch"));
    }
    Ok(())
}

fn select_tool_package(lock: &GraphLock) -> Result<&LockedPackage, PinnedToolAdmitError> {
    use super::resolve::HarnessSelection;
    let tool_package = match &lock.harness_selection {
        HarnessSelection::Unselected => {
            return Err(PinnedToolAdmitError {
                code: "harness_topology_unsupported",
                message: "explicit harness selection required".into(),
            });
        }
        HarnessSelection::ToolOnly { tool_package } => tool_package,
        HarnessSelection::ContextPrompt { tool_package, .. } => tool_package,
    };
    let Some(selected) = lock
        .packages
        .iter()
        .find(|package| package.kind == "tool" && &package.id == tool_package)
    else {
        return Err(PinnedToolAdmitError::new(
            "pinned graph has no tool package",
        ));
    };
    // A second tool package is admissible only as the single captured
    // stateless caller→callee read edge whose caller is this selection.
    let extra = lock
        .packages
        .iter()
        .filter(|package| package.kind == "tool" && package.id != selected.id)
        .count();
    if extra != 0 && !lock_delegation_shape(lock, selected) {
        return Err(PinnedToolAdmitError::new(
            "pinned graph tool entry is ambiguous",
        ));
    }
    Ok(selected)
}

/// Lock-only shape of the one stateless caller→callee read edge. The full
/// manifest/catalog checks run at prepare; this only decides that the selected
/// tool package is that edge's caller rather than an ambiguous extra tool.
fn lock_delegation_shape(lock: &GraphLock, selected: &LockedPackage) -> bool {
    if lock.packages.len() != 2 || lock.edges.len() != 1 {
        return false;
    }
    let edge = &lock.edges[0];
    edge.relation == "plugin"
        && edge.from == selected.id
        && edge.to != selected.id
        && lock
            .packages
            .iter()
            .any(|package| package.id == edge.to && package.kind == "tool")
}

/// The callee of the one lock-only caller→callee edge, when the selected package
/// is that edge's caller. `None` leaves every caller-owned state path unchanged.
fn locked_link_callee<'a>(
    lock: &'a GraphLock,
    caller: &LockedPackage,
) -> Option<&'a LockedPackage> {
    if !lock_delegation_shape(lock, caller) {
        return None;
    }
    lock.packages
        .iter()
        .find(|package| package.id == lock.edges[0].to)
}

fn optional_selector(caller: &Value) -> Option<String> {
    let identity = caller
        .get("workspace_identity_json")
        .and_then(Value::as_str)
        .unwrap_or("");
    if identity.is_empty() {
        return None;
    }
    let Ok(parsed) = serde_json::from_str::<Value>(identity) else {
        return None;
    };
    if parsed.get("request_selector_present") == Some(&Value::Bool(true))
        || parsed.get("request_selector_present") == Some(&json!(1))
    {
        return Some(text_field(&parsed, "request_selector"));
    }
    None
}

fn text_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn pinned_workspace(pin: &Value) -> Result<PathBuf, PinnedToolAdmitError> {
    // Empty represents the original NoAuthority binding. It is not a path grant.
    pin.get("workspace")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| PinnedToolAdmitError::new("replayed pin is missing workspace identity"))
}

fn required_text(value: &Value, key: &str) -> Result<String, PinnedToolAdmitError> {
    let text = text_field(value, key);
    if text.is_empty() {
        return Err(PinnedToolAdmitError::new(format!(
            "replayed pin is missing {key}"
        )));
    }
    Ok(text)
}

fn number_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(|item| {
            item.as_u64()
                .or_else(|| item.as_i64().map(|number| number as u64))
        })
        .unwrap_or(0)
}

fn first_present(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
