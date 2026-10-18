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
use crate::runtime::agent_host::{PinnedToolCode, PinnedToolProgram, PinnedToolReceipt};

const POSTCOMMIT_UNPUBLISHED: &str = "failpoint_after_commit_before_publish";

#[derive(Debug)]
pub struct PinnedToolAdmitError {
    pub message: String,
}

impl std::fmt::Display for PinnedToolAdmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl PinnedToolAdmitError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Trusted host identity for a new admission. It is not read from caller JSON.
#[derive(Clone, Debug)]
pub struct PinnedAdmitContext {
    pub registry_identity: String,
    pub workspace: PathBuf,
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
    persistence: &GatewayPersistence,
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
            return recover_pinned(persistence, store, &replayed);
        }
    }
    admit_new(persistence, store, caller, context)
}

fn admit_new(
    persistence: &GatewayPersistence,
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
    let prepared = store
        .prepare(&loaded.lock)
        .map_err(|error| PinnedToolAdmitError::new(error.to_string()))?;
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
    match persistence.admission_create(&payload) {
        Ok(data) => {
            if data.get("replayed") == Some(&Value::Bool(true)) {
                return recover_pinned(persistence, store, &data);
            }
            let pin = data
                .get("pin")
                .ok_or_else(|| PinnedToolAdmitError::new("admission did not return a tool pin"))?;
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
            ))
        }
        Err(error) if error.code == POSTCOMMIT_UNPUBLISHED => recover_unpublished(
            persistence,
            store,
            &text_field(caller, "idempotency_scope"),
            &text_field(caller, "idempotency_key"),
            &text_field(caller, "request_hash"),
            optional_selector(caller).as_deref(),
        ),
        Err(error) => Err(PinnedToolAdmitError::new(format!(
            "{}: {}",
            error.code, error.message
        ))),
    }
}

fn recover_unpublished(
    persistence: &GatewayPersistence,
    store: &PackageStore,
    scope: &str,
    key: &str,
    hash: &str,
    selector: Option<&str>,
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
    recover_pinned(persistence, store, &replayed)
}

fn recover_pinned(
    persistence: &GatewayPersistence,
    store: &PackageStore,
    data: &Value,
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
    let prepared = store
        .prepare(&loaded.lock)
        .map_err(|error| PinnedToolAdmitError::new(error.to_string()))?;
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
    ))
}

struct CapturedTool {
    managed_contract: Option<crate::effects::broker::ManagedEntryContract>,
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
        managed_contract: prepared.managed_contract(&package.id),
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

fn binding_from_capture(captured: CapturedTool, receipt: PinnedToolReceipt) -> PinnedToolAdmission {
    let binding = PinnedToolProgram::seal(
        PinnedToolCode {
            managed_contract: captured.managed_contract,
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
    captured: CapturedTool,
}

impl PreparedProductionPin {
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

pub(crate) fn prepare_production_pin(
    persistence: &GatewayPersistence,
    store: &PackageStore,
    active: &super::control_store::ActivationPointer,
) -> Result<PreparedProductionPin, PinnedToolAdmitError> {
    let control = PluginControlStore::new(persistence);
    if active.graph_id.is_empty() {
        return Err(PinnedToolAdmitError::new(
            "tool admission requires an active plugin graph",
        ));
    }
    let cached = store
        .prepared
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .filter(|(lock, _)| lock.graph_id == active.graph_id)
        .map(|(lock, _)| lock.clone());
    let lock = match cached {
        Some(lock) => lock,
        None => {
            control
                .load_lock(&active.graph_id)
                .map_err(|error| PinnedToolAdmitError::new(error.message))?
                .lock
        }
    };
    let package = select_tool_package(&lock)?;
    let prepared = store
        .prepare(&lock)
        .map_err(|error| PinnedToolAdmitError::new(error.to_string()))?;
    let captured = capture_tool(&prepared, package)?;
    Ok(PreparedProductionPin {
        graph_id: active.graph_id.clone(),
        generation: active.generation,
        ref_id: Uuid::new_v4().to_string(),
        captured,
    })
}

pub(crate) fn seal_production_receipt(
    prepared: PreparedProductionPin,
    receipt: &Value,
    registry_identity: String,
    workspace: PathBuf,
) -> Result<crate::runtime::agent_host::PinnedToolProgram, PinnedToolAdmitError> {
    let pin = receipt
        .get("pin")
        .ok_or_else(|| PinnedToolAdmitError::new("admission did not return a tool pin"))?;
    let pinned_graph = required_text(pin, "graph_id")?;
    let pinned_ref = required_text(pin, "ref_id")?;
    let pinned_generation = number_field(pin, "generation");
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
    Ok(binding_from_capture(
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
    )
    .program_handle())
}

pub fn restore_owned_pin(
    persistence: &GatewayPersistence,
    store: &PackageStore,
    owner_id: &str,
) -> Result<crate::runtime::agent_host::PinnedToolProgram, PinnedToolAdmitError> {
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
    let prepared = store
        .prepare(&loaded.lock)
        .map_err(|error| PinnedToolAdmitError::new(error.to_string()))?;
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
    )
    .program_handle())
}

fn select_tool_package(lock: &GraphLock) -> Result<&LockedPackage, PinnedToolAdmitError> {
    let mut tools = lock
        .packages
        .iter()
        .filter(|package| package.kind == "tool");
    let Some(selected) = tools.next() else {
        return Err(PinnedToolAdmitError::new(
            "pinned graph has no tool package",
        ));
    };
    if tools.next().is_some() {
        return Err(PinnedToolAdmitError::new(
            "pinned graph tool entry is ambiguous",
        ));
    }
    Ok(selected)
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
