//! Fixture-only host for the RSS auth store entry.
//!
//! `auth::*` functions here are **not** production agent host functions. They
//! exist only on [`auth_store_fixture_catalog`] and are bound by
//! [`AuthFixtureHost`]. Raw secrets stay host-side; RSS receives sanitized
//! metadata and host-owned opaque handles.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustscript_vm::{
    CallOutcome, CallReturn, CompileSourceFileOptions, HostApiBuilder, HostApiCatalog,
    HostFunctionRegistry, HostFunctionSchema, HostParamSchema, HostTypeSchema, Program,
    SourceFlavor, Value, Vm, VmResult, VmStatus, catalog_import_schemas,
    compile_source_at_path_with_flavor_and_options, standard_host_catalog,
};
use serde_json::{Value as JsonValue, json};

use crate::auth::config::CredentialConfig;
use crate::auth::store::{
    ACCESS_HANDLE_CLASS, AuthMetadata, AuthStore, AuthStoreError, OpaqueAccessHandle,
    OpaqueRefreshHandle, OpaqueSecretSlot, REFRESH_HANDLE_CLASS, RefreshSecretAction,
    SaveCredentialRequest, SaveOutcome, SecretSlotKind,
};
use crate::auth::token::CredentialId;
use crate::config_file::{
    AgentPaths, ConfigFileError, OpaquePolicyHandle, PolicyIntent, PolicyOwner,
};
use crate::domain::{json_to_vm_value, vm_value_to_json};
use crate::host_opaque::{OpaqueError, OpaqueRegistry};

const AUTH_LOAD_METADATA: &str = "auth::load_metadata";
const AUTH_SAVE_IF_GENERATION: &str = "auth::save_if_generation";
const AUTH_ACCESS_HANDLE: &str = "auth::access_handle";
const AUTH_REFRESH_HANDLE: &str = "auth::refresh_handle";
const AUTH_DELETE: &str = "auth::delete";
const AUTH_CHECK_HANDLE: &str = "auth::check_handle";
const SECRET_SLOT_CLASS: &str = "OpaqueSecretSlot";
const FIXTURE_RUN_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct FixtureSlotPayload {
    slot: OpaqueSecretSlot,
}

#[derive(Clone)]
struct AuthFixtureState {
    store: AuthStore,
    policies: Arc<PolicyOwner>,
    policy_generation: u64,
    run_id: String,
}

/// Fixture-only host for the real RSS auth entry. It reuses Stage A's
/// `PolicyOwner` and `OpaqueRegistry`; no second forgeable handle scheme is
/// introduced.
pub struct AuthFixtureHost {
    home: PathBuf,
    store: AuthStore,
    opaques: Arc<OpaqueRegistry>,
    policies: Arc<PolicyOwner>,
    policy_handle: OpaquePolicyHandle,
    policy_generation: u64,
    run_id: String,
}

impl AuthFixtureHost {
    pub fn bind(home: impl Into<PathBuf>) -> Result<Self, String> {
        let home = home.into();
        let paths = AgentPaths::from_home(&home).map_err(|error| error.to_string())?;
        let store = AuthStore::open(paths).map_err(|error| error.to_string())?;
        let opaques = OpaqueRegistry::new();
        let policies =
            PolicyOwner::new(Arc::clone(&opaques), Instant::now() + FIXTURE_RUN_DEADLINE);
        let snapshot = policies
            .load_snapshot(&home)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            home,
            store,
            opaques,
            policies,
            policy_handle: snapshot.policy_handle,
            policy_generation: snapshot.policy_generation,
            run_id: format!("auth-fixture-run-{}", std::process::id()),
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn policy_value(&self) -> Value {
        self.policy_handle.to_vm_value()
    }

    pub fn run_json(&self, kind: &str) -> Result<JsonValue, String> {
        Ok(vm_value_to_json(&self.run_value(kind)?))
    }

    pub fn run_value(&self, kind: &str) -> Result<Value, String> {
        self.invoke_context(self.context(kind)?)
    }

    /// Runs RSS with a policy value supplied by another host. This is used
    /// only to prove restart/cross-owner rejection of stale opaque values.
    pub fn run_json_with_policy_value(
        &self,
        kind: &str,
        policy_value: Value,
    ) -> Result<JsonValue, String> {
        let mut context = self.context(kind)?;
        replace_map_value(&mut context, "policy_handle", policy_value);
        Ok(vm_value_to_json(&self.invoke_context(context)?))
    }

    /// Runs RSS with a handle injected from another host/run.
    pub fn run_json_with_injected_handle(
        &self,
        kind: &str,
        handle: Value,
    ) -> Result<JsonValue, String> {
        let mut context = self.context(kind)?;
        replace_map_value(&mut context, "injected_handle", handle);
        Ok(vm_value_to_json(&self.invoke_context(context)?))
    }

    /// Reads a field from a VM map without exposing raw secrets.
    pub fn map_field(value: &Value, key: &str) -> Option<Value> {
        map_get(value, key).cloned()
    }

    fn context(&self, kind: &str) -> Result<Value, String> {
        let current = self.store.load_metadata("primary").ok();
        let current_generation = current.as_ref().map_or(0, |metadata| metadata.generation);
        let expected_generation = match kind {
            "save_adopt" => current_generation.saturating_sub(1),
            "save_future" => current_generation.saturating_add(1),
            _ => current_generation,
        };
        let slot_run_id = if kind == "save_cross_run" {
            "auth-fixture-other-run"
        } else {
            &self.run_id
        };
        let access = self
            .store
            .fixture_secret_slot(
                SecretSlotKind::Access,
                "primary",
                expected_generation,
                self.policy_generation,
                slot_run_id,
                "SYNTHETIC_ACCESS_HOST_ONLY",
            )
            .map_err(|error| error.to_string())?;
        let refresh = self
            .store
            .fixture_secret_slot(
                SecretSlotKind::Refresh,
                "primary",
                expected_generation,
                self.policy_generation,
                slot_run_id,
                "SYNTHETIC_REFRESH_HOST_ONLY",
            )
            .map_err(|error| error.to_string())?;
        let access_value = self.mint_slot(access)?;
        let refresh_value = self.mint_slot(refresh)?;
        let metadata = current.unwrap_or_else(|| AuthMetadata {
            credential_id: "primary".to_string(),
            provider: "synthetic-provider".to_string(),
            kind: "oauth".to_string(),
            source: "synthetic-test".to_string(),
            token_type: "Bearer".to_string(),
            expires_at_ms: 1_900_000_000_000,
            scopes: vec!["scope.synthetic".to_string()],
            account_id: Some("acct.synthetic".to_string()),
            generation: expected_generation,
            status: "active".to_string(),
            last_refresh_at_ms: None,
            has_refresh_token: true,
        });
        Ok(Value::map(vec![
            (Value::string("kind"), Value::string(kind)),
            (Value::string("credential_id"), Value::string("primary")),
            (
                Value::string("expected_generation"),
                Value::Int(i64::try_from(expected_generation).unwrap_or(i64::MAX)),
            ),
            (
                Value::string("policy_generation"),
                Value::Int(i64::try_from(self.policy_generation).unwrap_or(i64::MAX)),
            ),
            (Value::string("run_id"), Value::string(&self.run_id)),
            (
                Value::string("policy_handle"),
                self.policy_handle.to_vm_value(),
            ),
            (Value::string("access_slot"), access_value),
            (Value::string("refresh_slot"), refresh_value),
            (Value::string("provider"), Value::string(&metadata.provider)),
            (
                Value::string("credential_kind"),
                Value::string(&metadata.kind),
            ),
            (Value::string("source"), Value::string(&metadata.source)),
            (
                Value::string("token_type"),
                Value::string(&metadata.token_type),
            ),
            (
                Value::string("expires_at_ms"),
                Value::Int(i64::try_from(metadata.expires_at_ms).unwrap_or(i64::MAX)),
            ),
            (
                Value::string("scopes"),
                json_to_vm_value(&json!(metadata.scopes)),
            ),
            (
                Value::string("account_id"),
                metadata
                    .account_id
                    .as_deref()
                    .map(Value::string)
                    .unwrap_or(Value::Null),
            ),
            (
                Value::string("last_refresh_at_ms"),
                metadata
                    .last_refresh_at_ms
                    .map(|value| Value::Int(i64::try_from(value).unwrap_or(i64::MAX)))
                    .unwrap_or(Value::Null),
            ),
        ]))
    }

    fn mint_slot(&self, slot: OpaqueSecretSlot) -> Result<Value, String> {
        self.opaques
            .mint(SECRET_SLOT_CLASS, FixtureSlotPayload { slot })
            .map(|value| value.to_vm_value())
            .map_err(opaque_error)
    }

    fn invoke_context(&self, context: Value) -> Result<Value, String> {
        let program = fixture_program()?;
        let catalog = auth_store_fixture_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        register_host_functions(&mut registry, catalog.as_ref())
            .map_err(|error| error.to_string())?;
        let mut vm = Vm::try_new_shared(program).map_err(|error| error.to_string())?;
        registry
            .bind_vm_cached(&mut vm)
            .map_err(|error| error.to_string())?;
        vm.host_context().set_module_state(AuthFixtureState {
            store: self.store.clone(),
            policies: Arc::clone(&self.policies),
            policy_generation: self.policy_generation,
            run_id: self.run_id.clone(),
        });
        drive_root_frame(&mut vm)?;
        let callable = vm
            .resolve_exported_callable("run")
            .map_err(|_| "auth store RSS entry `run` is missing".to_string())?;
        vm.invoke_callable(callable, &[context])
            .map_err(|error| error.to_string())
    }
}

impl Drop for AuthFixtureHost {
    fn drop(&mut self) {
        self.policies.clear();
        self.opaques.clear();
    }
}

/// Test-only catalog that exposes the Task 2 auth store bridge.
pub fn auth_store_fixture_catalog() -> Arc<HostApiCatalog> {
    static CATALOG: OnceLock<Arc<HostApiCatalog>> = OnceLock::new();
    Arc::clone(CATALOG.get_or_init(|| {
        let standard = standard_host_catalog();
        let mut builder = HostApiBuilder::new();
        for resource in standard.resources() {
            builder.resource(resource.clone());
        }
        for function in standard.functions() {
            builder.function(function.clone());
        }
        let response = HostTypeSchema::Map(Box::new(HostTypeSchema::Unknown));
        register_catalog_functions(&mut builder, response);
        Arc::new(
            builder
                .build()
                .expect("auth store fixture catalog must build"),
        )
    }))
}

fn register_catalog_functions(builder: &mut HostApiBuilder, response: HostTypeSchema) {
    let request = vec![HostParamSchema::value("request", HostTypeSchema::Unknown)];
    builder.function(HostFunctionSchema::with_return(
        AUTH_LOAD_METADATA,
        request.clone(),
        response.clone(),
    ));
    builder.function(HostFunctionSchema::with_return(
        AUTH_SAVE_IF_GENERATION,
        request.clone(),
        response.clone(),
    ));
    builder.function(HostFunctionSchema::with_return(
        AUTH_ACCESS_HANDLE,
        request.clone(),
        response.clone(),
    ));
    builder.function(HostFunctionSchema::with_return(
        AUTH_REFRESH_HANDLE,
        request.clone(),
        response.clone(),
    ));
    builder.function(HostFunctionSchema::with_return(
        AUTH_DELETE,
        request,
        response.clone(),
    ));
    builder.function(HostFunctionSchema::with_return(
        AUTH_CHECK_HANDLE,
        vec![
            HostParamSchema::value("handle", HostTypeSchema::Unknown),
            HostParamSchema::value("intent", HostTypeSchema::Unknown),
        ],
        response,
    ));
}

fn register_host_functions(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
) -> VmResult<()> {
    register_named(
        registry,
        catalog,
        AUTH_LOAD_METADATA,
        1,
        load_metadata_adapter,
    )?;
    register_named(
        registry,
        catalog,
        AUTH_SAVE_IF_GENERATION,
        1,
        save_if_generation_adapter,
    )?;
    register_named(
        registry,
        catalog,
        AUTH_ACCESS_HANDLE,
        1,
        access_handle_adapter,
    )?;
    register_named(
        registry,
        catalog,
        AUTH_REFRESH_HANDLE,
        1,
        refresh_handle_adapter,
    )?;
    register_named(registry, catalog, AUTH_DELETE, 1, delete_adapter)?;
    register_named(
        registry,
        catalog,
        AUTH_CHECK_HANDLE,
        2,
        check_handle_adapter,
    )?;
    Ok(())
}

fn register_named(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
    name: &'static str,
    arity: u8,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> VmResult<()> {
    for schema in catalog_import_schemas(catalog, name) {
        registry.register_exact_static(name, arity, schema, adapter)?;
    }
    registry.register_static(name, arity, adapter);
    registry.allow_builtin(name)?;
    Ok(())
}

fn load_metadata_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let value = args.first().cloned().unwrap_or(Value::Null);
    let credential_id = match required_string(map_get(&value, "credential_id"), "credential_id") {
        Ok(value) => value,
        Err(error) => return return_json(error),
    };
    if let Err(error) = check_policy(&state, map_get(&value, "policy_handle")) {
        return return_json(error);
    }
    match state.store.load_metadata(&credential_id) {
        Ok(metadata) => return_json(json!({
            "ok": true,
            "metadata": metadata_json(&metadata)
        })),
        Err(error) => return_json(store_error(&error)),
    }
}

fn save_if_generation_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let value = args.first().cloned().unwrap_or(Value::Null);
    let request = match parse_request(&state, &value) {
        Ok(request) => request,
        Err(error) => return return_json(error),
    };
    match state.store.save_if_generation(request) {
        Ok(SaveOutcome::Committed { metadata }) => return_json(json!({
            "ok": true,
            "outcome": "committed",
            "metadata": metadata_json(&metadata)
        })),
        Ok(SaveOutcome::Adopted { metadata }) => return_json(json!({
            "ok": true,
            "outcome": "adopted",
            "metadata": metadata_json(&metadata)
        })),
        Err(error) => return_json(store_error(&error)),
    }
}

fn access_handle_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    handle_adapter(vm, args, SecretSlotKind::Access)
}

fn refresh_handle_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    handle_adapter(vm, args, SecretSlotKind::Refresh)
}

fn handle_adapter(vm: &mut Vm, args: &[Value], kind: SecretSlotKind) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let value = args.first().cloned().unwrap_or(Value::Null);
    let credential_id = match required_string(map_get(&value, "credential_id"), "credential_id") {
        Ok(value) => value,
        Err(error) => return return_json(error),
    };
    let generation = match required_u64(map_get(&value, "generation"), "generation") {
        Ok(value) => value,
        Err(error) => return return_json(error),
    };
    let policy_generation =
        match required_u64(map_get(&value, "policy_generation"), "policy_generation") {
            Ok(value) => value,
            Err(error) => return return_json(error),
        };
    let run_id = match required_string(map_get(&value, "run_id"), "run_id") {
        Ok(value) => value,
        Err(error) => return return_json(error),
    };
    if policy_generation != state.policy_generation {
        return return_json(bridge_error(
            "policy_stale_generation",
            "policy generation does not match the host snapshot",
        ));
    }
    if run_id != state.run_id {
        return return_json(bridge_error(
            "run_provenance",
            "request run provenance does not match the host run",
        ));
    }
    if let Err(error) = check_policy(&state, map_get(&value, "policy_handle")) {
        return return_json(error);
    }
    match kind {
        SecretSlotKind::Access => {
            match state.store.issue_access_handle(
                &credential_id,
                generation,
                policy_generation,
                &run_id,
            ) {
                Ok(handle) => mint_access_handle(&state, handle),
                Err(error) => return_json(store_error(&error)),
            }
        }
        SecretSlotKind::Refresh => {
            match state.store.issue_refresh_handle(
                &credential_id,
                generation,
                policy_generation,
                &run_id,
            ) {
                Ok(handle) => mint_refresh_handle(&state, handle),
                Err(error) => return_json(store_error(&error)),
            }
        }
    }
}

fn mint_access_handle(
    state: &AuthFixtureState,
    handle: OpaqueAccessHandle,
) -> VmResult<CallOutcome> {
    let generation = handle.generation();
    match state.policies.opaques().mint(handle.class(), handle) {
        Ok(minted) => return_handle(ACCESS_HANDLE_CLASS, generation, minted.to_vm_value()),
        Err(error) => return_json(opaque_error_json(error)),
    }
}

fn mint_refresh_handle(
    state: &AuthFixtureState,
    handle: OpaqueRefreshHandle,
) -> VmResult<CallOutcome> {
    let generation = handle.generation();
    match state.policies.opaques().mint(handle.class(), handle) {
        Ok(minted) => return_handle(REFRESH_HANDLE_CLASS, generation, minted.to_vm_value()),
        Err(error) => return_json(opaque_error_json(error)),
    }
}

fn delete_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let value = args.first().cloned().unwrap_or(Value::Null);
    let credential_id = match required_string(map_get(&value, "credential_id"), "credential_id") {
        Ok(value) => value,
        Err(error) => return return_json(error),
    };
    let expected_generation = match required_u64(
        map_get(&value, "expected_generation"),
        "expected_generation",
    ) {
        Ok(value) => value,
        Err(error) => return return_json(error),
    };
    if let Err(error) = check_policy(&state, map_get(&value, "policy_handle")) {
        return return_json(error);
    }
    match state.store.delete(&credential_id, expected_generation) {
        Ok(metadata) => return_json(json!({
            "ok": true,
            "metadata": metadata_json(&metadata)
        })),
        Err(error) => return_json(store_error(&error)),
    }
}

fn check_handle_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let Some(value) = args.first() else {
        return return_json(bridge_error("handle_invalid", "handle is missing"));
    };
    let op = args
        .get(1)
        .and_then(|intent| map_get(intent, "op"))
        .and_then(|value| match value {
            Value::String(value) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or("validate");
    let Some(opaque) = state.policies.opaques().from_vm_value(value) else {
        return return_json(bridge_error(
            "handle_invalid",
            "handle is not a host-owned opaque value",
        ));
    };
    if opaque.class() == ACCESS_HANDLE_CLASS {
        let Some(handle) = opaque.downcast_arc::<OpaqueAccessHandle>() else {
            return return_json(bridge_error(
                "handle_invalid",
                "access handle is not owned by this fixture run",
            ));
        };
        return apply_access_intent(&handle, op);
    }
    if opaque.class() == REFRESH_HANDLE_CLASS {
        let Some(handle) = opaque.downcast_arc::<OpaqueRefreshHandle>() else {
            return return_json(bridge_error(
                "handle_invalid",
                "refresh handle is not owned by this fixture run",
            ));
        };
        return apply_refresh_intent(&handle, op);
    }
    return_json(bridge_error(
        "handle_invalid",
        "opaque value has the wrong handle class",
    ))
}

fn apply_access_intent(handle: &OpaqueAccessHandle, op: &str) -> VmResult<CallOutcome> {
    let result = match op {
        "validate" => handle.validate(),
        "consume" => handle.consume(),
        "expire" => {
            handle.force_expire();
            handle.validate()
        }
        "mismatch" => handle.validate_binding(
            handle.credential_id(),
            handle.generation().saturating_add(1),
            0,
            "",
        ),
        _ => Err(AuthStoreError::HandleInvalid {
            credential_id: handle.credential_id().to_string(),
            kind: "access".to_string(),
        }),
    };
    match result {
        Ok(()) => return_json(json!({ "ok": true, "handle_class": ACCESS_HANDLE_CLASS })),
        Err(error) => return_json(store_error(&error)),
    }
}

fn apply_refresh_intent(handle: &OpaqueRefreshHandle, op: &str) -> VmResult<CallOutcome> {
    let result = match op {
        "validate" => handle.validate(),
        "consume" => handle.consume(),
        "expire" => {
            handle.force_expire();
            handle.validate()
        }
        "mismatch" => handle.validate_binding(
            handle.credential_id(),
            handle.generation().saturating_add(1),
            0,
            "",
        ),
        _ => Err(AuthStoreError::HandleInvalid {
            credential_id: handle.credential_id().to_string(),
            kind: "refresh".to_string(),
        }),
    };
    match result {
        Ok(()) => return_json(json!({ "ok": true, "handle_class": REFRESH_HANDLE_CLASS })),
        Err(error) => return_json(store_error(&error)),
    }
}

fn parse_request(
    state: &AuthFixtureState,
    value: &Value,
) -> Result<SaveCredentialRequest, JsonValue> {
    let credential_id = required_string(map_get(value, "credential_id"), "credential_id")?;
    let credential = CredentialId::new(credential_id.clone())
        .map_err(|_| bridge_error("invalid_credential", "credential ID is invalid"))?;
    let expected_generation =
        required_u64(map_get(value, "expected_generation"), "expected_generation")?;
    let policy_generation = required_u64(map_get(value, "policy_generation"), "policy_generation")?;
    if policy_generation != state.policy_generation {
        return Err(bridge_error(
            "policy_stale_generation",
            "policy generation does not match the host snapshot",
        ));
    }
    let run_id = required_string(map_get(value, "run_id"), "run_id")?;
    if run_id != state.run_id {
        return Err(bridge_error(
            "run_provenance",
            "request run provenance does not match the host run",
        ));
    }
    check_policy(state, map_get(value, "policy_handle"))?;
    let metadata = parse_metadata(map_get(value, "metadata"), &credential, expected_generation)?;
    let access_slot = parse_slot(
        state,
        map_get(value, "access_slot"),
        SecretSlotKind::Access,
        &credential_id,
        expected_generation,
        policy_generation,
        &run_id,
    )?;
    let refresh = parse_refresh(
        state,
        map_get(value, "refresh"),
        &credential_id,
        expected_generation,
        policy_generation,
        &run_id,
    )?;
    Ok(SaveCredentialRequest::new(
        credential,
        expected_generation,
        policy_generation,
        run_id,
        metadata,
        access_slot,
        refresh,
    ))
}

fn parse_metadata(
    value: Option<&Value>,
    credential_id: &CredentialId,
    generation: u64,
) -> Result<CredentialConfig, JsonValue> {
    let value = value.ok_or_else(|| bridge_error("invalid_metadata", "metadata is missing"))?;
    if map_get(value, "extra_field").is_some() {
        return Err(bridge_error(
            "invalid_metadata",
            "metadata contains unknown fields",
        ));
    }
    let _ = credential_id;
    Ok(CredentialConfig {
        provider: required_string(map_get(value, "provider"), "provider")?,
        kind: required_string(map_get(value, "kind"), "kind")?,
        source: required_string(map_get(value, "source"), "source")?,
        token_type: required_string(map_get(value, "token_type"), "token_type")?,
        expires_at_ms: required_u64(map_get(value, "expires_at_ms"), "expires_at_ms")?,
        scopes: parse_scopes(map_get(value, "scopes"))?,
        account_id: optional_string(map_get(value, "account_id"), "account_id")?,
        generation,
        status: required_string(map_get(value, "status"), "status")?,
        last_refresh_at_ms: optional_u64(
            map_get(value, "last_refresh_at_ms"),
            "last_refresh_at_ms",
        )?,
        has_refresh_token: false,
    })
}

fn parse_refresh(
    state: &AuthFixtureState,
    value: Option<&Value>,
    credential_id: &str,
    generation: u64,
    policy_generation: u64,
    run_id: &str,
) -> Result<RefreshSecretAction, JsonValue> {
    let value = value.ok_or_else(|| bridge_error("invalid_request", "refresh action missing"))?;
    let action = required_string(map_get(value, "action"), "refresh.action")?;
    match action.as_str() {
        "preserve" => Ok(RefreshSecretAction::Preserve),
        "clear" => Ok(RefreshSecretAction::Clear),
        "replace" => Ok(RefreshSecretAction::Replace(parse_slot(
            state,
            map_get(value, "slot"),
            SecretSlotKind::Refresh,
            credential_id,
            generation,
            policy_generation,
            run_id,
        )?)),
        _ => Err(bridge_error(
            "invalid_request",
            "refresh action is not recognized",
        )),
    }
}

fn parse_slot(
    state: &AuthFixtureState,
    value: Option<&Value>,
    kind: SecretSlotKind,
    credential_id: &str,
    generation: u64,
    policy_generation: u64,
    run_id: &str,
) -> Result<OpaqueSecretSlot, JsonValue> {
    let value =
        value.ok_or_else(|| bridge_error("secret_slot_provenance", "secret slot is missing"))?;
    let Some(opaque) = state.policies.opaques().from_vm_value(value) else {
        return Err(bridge_error(
            "secret_slot_provenance",
            "secret slot is not a host-owned opaque value",
        ));
    };
    if opaque.class() != SECRET_SLOT_CLASS {
        return Err(bridge_error(
            "secret_slot_provenance",
            "opaque value has the wrong secret-slot class",
        ));
    }
    let Some(payload) = opaque.downcast_arc::<FixtureSlotPayload>() else {
        return Err(bridge_error(
            "secret_slot_provenance",
            "opaque secret slot is not owned by this fixture run",
        ));
    };
    payload
        .slot
        .validate_for_request(kind, credential_id, generation, policy_generation, run_id)
        .map_err(|error| store_error(&error))?;
    Ok(payload.slot.clone())
}

fn check_policy(
    state: &AuthFixtureState,
    value: Option<&Value>,
) -> Result<OpaquePolicyHandle, JsonValue> {
    let value =
        value.ok_or_else(|| bridge_error("policy_handle_invalid", "policy handle is missing"))?;
    let Some(handle) = OpaquePolicyHandle::from_vm_value(state.policies.opaques(), value) else {
        return Err(bridge_error(
            "policy_handle_invalid",
            "policy handle is not host-owned",
        ));
    };
    state
        .policies
        .check_policy(
            &handle,
            &PolicyIntent {
                op: "inspect".to_string(),
                policy_generation: Some(state.policy_generation),
                ..PolicyIntent::default()
            },
        )
        .map_err(|error| policy_error(&error))?;
    Ok(handle)
}

fn state(vm: &mut Vm) -> Result<AuthFixtureState, JsonValue> {
    vm.host_context()
        .module_state::<AuthFixtureState>()
        .cloned()
        .ok_or_else(|| bridge_error("backend_unavailable", "auth fixture host is unbound"))
}

fn metadata_json(metadata: &AuthMetadata) -> JsonValue {
    json!({
        "credential_id": metadata.credential_id,
        "provider": metadata.provider,
        "kind": metadata.kind,
        "source": metadata.source,
        "token_type": metadata.token_type,
        "expires_at_ms": metadata.expires_at_ms,
        "scopes": metadata.scopes,
        "account_id": metadata.account_id,
        "generation": metadata.generation,
        "status": metadata.status,
        "last_refresh_at_ms": metadata.last_refresh_at_ms,
        "has_refresh_token": metadata.has_refresh_token
    })
}

fn store_error(error: &AuthStoreError) -> JsonValue {
    json!({
        "ok": false,
        "error": {
            "code": error.code(),
            "message": error.to_string()
        }
    })
}

fn policy_error(error: &ConfigFileError) -> JsonValue {
    json!({
        "ok": false,
        "error": {
            "code": error.code(),
            "message": error.to_string()
        }
    })
}

fn bridge_error(code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "error": {"code": code, "message": message}
    })
}

fn opaque_error(error: OpaqueError) -> String {
    match error {
        OpaqueError::LiveHandleLimit => "opaque live handle limit reached".to_string(),
        OpaqueError::PrototypeIdSpaceExhausted => "opaque prototype id space exhausted".to_string(),
    }
}

fn opaque_error_json(error: OpaqueError) -> JsonValue {
    bridge_error("opaque_handle_limit", &opaque_error(error))
}

fn required_string(value: Option<&Value>, field: &str) -> Result<String, JsonValue> {
    match value {
        Some(Value::String(value)) => Ok(value.to_string()),
        _ => Err(bridge_error(
            "invalid_request",
            &format!("{field} must be a string"),
        )),
    }
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, JsonValue> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.to_string())),
        _ => Err(bridge_error(
            "invalid_metadata",
            &format!("{field} must be a string or null"),
        )),
    }
}

fn required_u64(value: Option<&Value>, field: &str) -> Result<u64, JsonValue> {
    match value {
        Some(Value::Int(value)) if *value >= 0 => Ok(*value as u64),
        _ => Err(bridge_error(
            "invalid_request",
            &format!("{field} must be a nonnegative integer"),
        )),
    }
}

fn optional_u64(value: Option<&Value>, field: &str) -> Result<Option<u64>, JsonValue> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Int(value)) if *value >= 0 => Ok(Some(*value as u64)),
        _ => Err(bridge_error(
            "invalid_metadata",
            &format!("{field} must be a nonnegative integer or null"),
        )),
    }
}

fn parse_scopes(value: Option<&Value>) -> Result<Vec<String>, JsonValue> {
    let Some(Value::Array(values)) = value else {
        return Err(bridge_error("invalid_metadata", "scopes must be an array"));
    };
    values
        .iter()
        .map(|value| match value {
            Value::String(value) => Ok(value.to_string()),
            _ => Err(bridge_error(
                "invalid_metadata",
                "scope labels must be strings",
            )),
        })
        .collect()
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Value::String(candidate) if candidate.as_ref() == key => Some(value),
            _ => None,
        })
}

fn replace_map_value(context: &mut Value, key: &str, replacement: Value) {
    if let Value::Map(entries) = context {
        let mut found = false;
        let mut values: Vec<_> = entries
            .iter()
            .map(|(candidate, value)| {
                if matches!(candidate, Value::String(candidate) if candidate.as_ref() == key) {
                    found = true;
                    (candidate.clone(), replacement.clone())
                } else {
                    (candidate.clone(), value.clone())
                }
            })
            .collect();
        if !found {
            values.push((Value::string(key), replacement));
        }
        *context = Value::map(values);
    }
}

fn return_handle(class: &str, generation: u64, handle: Value) -> VmResult<CallOutcome> {
    return_value(Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("handle_class"), Value::string(class)),
        (
            Value::string("generation"),
            Value::Int(i64::try_from(generation).unwrap_or(i64::MAX)),
        ),
        (Value::string("handle"), handle),
    ]))
}

fn return_json(value: JsonValue) -> VmResult<CallOutcome> {
    return_value(json_to_vm_value(&value))
}

fn return_value(value: Value) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(value)))
}

fn fixture_program() -> Result<Arc<Program>, String> {
    static PROGRAM: OnceLock<Result<Arc<Program>, String>> = OnceLock::new();
    match PROGRAM.get_or_init(|| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/store_entry.rss");
        let source = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let options =
            CompileSourceFileOptions::default().with_host_api_catalog(auth_store_fixture_catalog());
        compile_source_at_path_with_flavor_and_options(
            &path,
            &source,
            SourceFlavor::RustScript,
            options,
        )
        .map(|compiled| Arc::new(compiled.program))
        .map_err(|error| error.to_string())
    }) {
        Ok(program) => Ok(Arc::clone(program)),
        Err(error) => Err(error.clone()),
    }
}

fn drive_root_frame(vm: &mut Vm) -> Result<(), String> {
    loop {
        match vm.run() {
            Ok(VmStatus::Halted) => return Ok(()),
            Ok(VmStatus::Waiting(_)) => vm
                .wait_for_host_op_blocking_with_cancel(|| false)
                .map_err(|error| error.to_string())?,
            Ok(VmStatus::Yielded) => {
                return Err("auth store fixture root frame yielded unexpectedly".to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
