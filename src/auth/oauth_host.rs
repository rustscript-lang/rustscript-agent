//! Fixture-only host for the generic RSS OAuth entry.
//!
//! `oauth::*` functions here are **not** production agent host functions.

use std::collections::BTreeMap;
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
use crate::auth::oauth::{
    BoundedPublicOAuthIntent, CALLBACK_HANDLE_CLASS, CODE_HANDLE_CLASS, CallbackMode,
    CredentialUse, DEVICE_HANDLE_CLASS, OAuthError, OAuthFlowKind, OAuthHost,
    OpaqueAuthorizationCodeHandle, OpaqueCallbackHandle, OpaqueDeviceSessionHandle,
    OpaqueVerifierHandle, ProviderRequest, RawCallbackInput, STATE_HANDLE_CLASS, ScriptedBrowser,
    ScriptedCallback, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport, TrustedEndpoint,
    TrustedTransportPolicy, VERIFIER_HANDLE_CLASS,
};
use crate::auth::store::{
    ACCESS_HANDLE_CLASS, AuthMetadata, AuthStore, AuthStoreError, OpaqueAccessHandle,
    OpaqueRefreshHandle, OpaqueSecretSlot, REFRESH_HANDLE_CLASS, RefreshSecretAction,
    SaveCredentialRequest, SecretSlotKind,
};
use crate::auth::token::CredentialId;
use crate::config_file::{
    AdmittedTransportView, AgentPaths, ConfigFileError, OpaquePolicyHandle, PolicyIntent,
    PolicyOwner,
};
use crate::domain::{json_to_vm_value, vm_value_to_json};
use crate::host_opaque::{OpaqueError, OpaqueRegistry};

const OAUTH_PKCE_BEGIN: &str = "oauth::pkce_begin";
const OAUTH_CALLBACK_WAIT: &str = "oauth::callback_wait";
const OAUTH_TRANSPORT: &str = "oauth::transport";
const AUTH_LOAD_METADATA: &str = "auth::load_metadata";
const AUTH_SAVE_IF_GENERATION: &str = "auth::save_if_generation";
const AUTH_REFRESH_HANDLE: &str = "auth::refresh_handle";
const AUTH_CHECK_HANDLE: &str = "auth::check_handle";
const SECRET_SLOT_CLASS: &str = "OpaqueSecretSlot";
const FIXTURE_RUN_DEADLINE: Duration = Duration::from_secs(60);
const AUTH_CODE: &str = "SYNTHETIC_AUTH_CODE";

#[derive(Clone)]
struct FixtureSlotPayload {
    slot: OpaqueSecretSlot,
}

#[derive(Clone)]
struct OAuthFixtureState {
    store: AuthStore,
    policies: Arc<PolicyOwner>,
    oauth: Arc<OAuthHost>,
    scenario: String,
    cancel: Arc<ScriptedCancel>,
}

/// Fixture-only host for the real RSS OAuth entry.
pub struct OAuthFixtureHost {
    home: PathBuf,
    store: AuthStore,
    opaques: Arc<OpaqueRegistry>,
    policies: Arc<PolicyOwner>,
    policy_handle: OpaquePolicyHandle,
    oauth: Arc<OAuthHost>,
    transport: Arc<ScriptedHttpsTransport>,
    cancel: Arc<ScriptedCancel>,
}

impl OAuthFixtureHost {
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
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let callback = Arc::new(ScriptedCallback::new());
        let browser = Arc::new(ScriptedBrowser::new());
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let oauth = Arc::new(OAuthHost::new(
            Arc::clone(&transport) as Arc<_>,
            Arc::clone(&callback) as Arc<_>,
            Arc::clone(&browser) as Arc<_>,
            Arc::clone(&clock) as Arc<_>,
            Arc::clone(&cancel) as Arc<_>,
        ));
        Ok(Self {
            home,
            store,
            opaques,
            policies,
            policy_handle: snapshot.policy_handle,
            oauth,
            transport,
            cancel,
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
        self.invoke_context(self.context_for(kind)?, kind)
    }

    pub fn run_json_with_policy_value(
        &self,
        kind: &str,
        policy_value: Value,
    ) -> Result<JsonValue, String> {
        let mut context = self.context_for(kind)?;
        replace_map_value(&mut context, "policy_handle", policy_value);
        Ok(vm_value_to_json(&self.invoke_context(context, kind)?))
    }

    pub fn run_json_with_injected_handle(
        &self,
        kind: &str,
        handle: Value,
    ) -> Result<JsonValue, String> {
        let mut context = self.context_for(kind)?;
        replace_map_value(&mut context, "injected_handle", handle);
        Ok(vm_value_to_json(&self.invoke_context(context, kind)?))
    }

    pub fn map_field(value: &Value, key: &str) -> Option<Value> {
        map_get(value, key).cloned()
    }

    fn context_for(&self, kind: &str) -> Result<Value, String> {
        let provenance = self
            .policy_handle
            .provenance()
            .ok_or_else(|| "policy handle payload is unavailable".to_string())?;
        Ok(Value::map(vec![
            (Value::string("kind"), Value::string(kind)),
            (Value::string("credential_id"), Value::string("primary")),
            (
                Value::string("expected_generation"),
                Value::Int(
                    i64::try_from(
                        self.store
                            .load_metadata("primary")
                            .map(|metadata| metadata.generation)
                            .unwrap_or(0),
                    )
                    .unwrap_or(i64::MAX),
                ),
            ),
            (
                Value::string("policy_handle"),
                self.policy_handle.to_vm_value(),
            ),
            (Value::string("now_ms"), Value::Int(1_900_000_000_000)),
            (Value::string("skew_seconds"), Value::Int(120)),
            (
                Value::string("expires_at_ms"),
                Value::Int(if kind == "refresh_due" {
                    1_000
                } else {
                    2_000_000_000_000
                }),
            ),
            (Value::string("attempt"), Value::Int(2)),
            (
                Value::string("max_polls"),
                Value::Int(if kind == "device_timeout" { 2 } else { 8 }),
            ),
            (
                Value::string("run_id"),
                Value::string(provenance.run_id.as_str()),
            ),
        ]))
    }

    fn invoke_context(&self, context: Value, kind: &str) -> Result<Value, String> {
        self.queue_script(kind);
        let program = fixture_program()?;
        let catalog = oauth_fixture_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        register_host_functions(&mut registry, catalog.as_ref())
            .map_err(|error| error.to_string())?;
        let mut vm = Vm::try_new_shared(program).map_err(|error| error.to_string())?;
        registry
            .bind_vm_cached(&mut vm)
            .map_err(|error| error.to_string())?;
        vm.host_context().set_module_state(OAuthFixtureState {
            store: self.store.clone(),
            policies: Arc::clone(&self.policies),
            oauth: Arc::clone(&self.oauth),
            scenario: kind.to_string(),
            cancel: Arc::clone(&self.cancel),
        });
        drive_root_frame(&mut vm)?;
        let callable = vm
            .resolve_exported_callable("run")
            .map_err(|_| "oauth RSS entry `run` is missing".to_string())?;
        vm.invoke_callable(callable, &[context])
            .map_err(|error| error.to_string())
    }

    fn queue_script(&self, kind: &str) {
        match kind {
            "login_browser" | "login_manual" | "secrets_absent" | "callback" => {
                self.transport.push_json(
                    200,
                    json!({
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "access_token": "SYNTHETIC_ROTATED_ACCESS",
                        "refresh_token": "SYNTHETIC_ROTATED_REFRESH",
                        "scope": "scope.synthetic"
                    }),
                );
            }
            "classify_401" => {
                self.transport
                    .push_json(401, json!({"error": "invalid_grant"}));
            }
            "classify_429" => {
                self.transport
                    .push_json(429, json!({"error": "rate_limit"}));
            }
            "classify_5xx" => {
                self.transport
                    .push_json(503, json!({"error": "unavailable"}));
            }
            "transport_malformed" => self.transport.push_raw(200, "not-json{"),
            "transport_oversized" => self.transport.push_raw(200, &"x".repeat(70 * 1024)),
            "refresh_send" | "refresh_save" | "code_replay" => {
                self.transport.push_json(
                    200,
                    json!({
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "access_token": "SYNTHETIC_ROTATED_ACCESS",
                        "refresh_token": "SYNTHETIC_ROTATED_REFRESH"
                    }),
                );
            }
            "device_login" | "device_replay" => {
                self.queue_device_start();
                self.queue_token_success();
            }
            "device_pending_success" => {
                self.queue_device_start();
                self.transport
                    .push_json(400, json!({"error": "authorization_pending"}));
                self.queue_token_success();
            }
            "device_slow_down" => {
                self.queue_device_start();
                self.transport.push_json(400, json!({"error": "slow_down"}));
                self.queue_token_success();
            }
            "device_timeout" => {
                self.queue_device_start();
                self.transport
                    .push_json(400, json!({"error": "authorization_pending"}));
                self.transport
                    .push_json(400, json!({"error": "authorization_pending"}));
            }
            "device_denied" => {
                self.queue_device_start();
                self.transport
                    .push_json(400, json!({"error": "access_denied"}));
            }
            "device_cancel" | "device_serialized" | "device_start" => {
                self.queue_device_start();
            }
            _ => {}
        }
    }

    fn queue_device_start(&self) {
        self.transport.push_json(
            200,
            json!({
                "device_code": "SYNTHETIC_DEVICE_ID",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://auth.example.test/device",
                "expires_in": 900,
                "interval": 5
            }),
        );
    }

    fn queue_token_success(&self) {
        self.transport.push_json(
            200,
            json!({
                "token_type": "Bearer",
                "expires_in": 3600,
                "access_token": "SYNTHETIC_ROTATED_ACCESS",
                "refresh_token": "SYNTHETIC_ROTATED_REFRESH",
                "scope": "scope.synthetic"
            }),
        );
    }
}

impl Drop for OAuthFixtureHost {
    fn drop(&mut self) {
        self.policies.clear();
        self.opaques.clear();
    }
}

/// Test-only catalog that exposes the Task 3 OAuth bridge plus Task 2 save.
pub fn oauth_fixture_catalog() -> Arc<HostApiCatalog> {
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
        let unknown = HostTypeSchema::Unknown;
        builder.function(HostFunctionSchema::with_return(
            OAUTH_PKCE_BEGIN,
            vec![
                HostParamSchema::value("policy_handle", unknown.clone()),
                HostParamSchema::value("public_intent", unknown.clone()),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            OAUTH_CALLBACK_WAIT,
            vec![HostParamSchema::value("callback_handle", unknown.clone())],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            OAUTH_TRANSPORT,
            vec![
                HostParamSchema::value("request", unknown.clone()),
                HostParamSchema::value("credential_use", unknown.clone()),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            AUTH_LOAD_METADATA,
            vec![HostParamSchema::value("request", unknown.clone())],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            AUTH_SAVE_IF_GENERATION,
            vec![HostParamSchema::value("request", unknown.clone())],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            AUTH_REFRESH_HANDLE,
            vec![HostParamSchema::value("request", unknown.clone())],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            AUTH_CHECK_HANDLE,
            vec![
                HostParamSchema::value("handle", unknown.clone()),
                HostParamSchema::value("intent", unknown),
            ],
            response,
        ));
        Arc::new(builder.build().expect("oauth fixture catalog must build"))
    }))
}

fn register_host_functions(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
) -> VmResult<()> {
    register_named(registry, catalog, OAUTH_PKCE_BEGIN, 2, pkce_begin_adapter)?;
    register_named(
        registry,
        catalog,
        OAUTH_CALLBACK_WAIT,
        1,
        callback_wait_adapter,
    )?;
    register_named(registry, catalog, OAUTH_TRANSPORT, 2, transport_adapter)?;
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
        AUTH_REFRESH_HANDLE,
        1,
        refresh_handle_adapter,
    )?;
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

fn pkce_begin_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let policy_value = args.first().cloned().unwrap_or(Value::Null);
    let intent_value = args.get(1).cloned().unwrap_or(Value::Null);
    let policy = match admitted_policy(&state, Some(&policy_value), "pkce") {
        Ok(policy) => policy,
        Err(error) => return return_json(error),
    };
    let intent = match parse_intent(&intent_value) {
        Ok(intent) => intent,
        Err(error) => return return_json(error),
    };
    match state.oauth.pkce_begin(&policy, intent) {
        Ok(begun) => mint_begin(&state, begun),
        Err(error) => return_json(oauth_error(&error)),
    }
}

fn callback_wait_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let value = args.first().cloned().unwrap_or(Value::Null);
    let Some(handle) = decode_callback(&state, &value) else {
        return return_json(bridge_error(
            "handle_invalid",
            "callback handle is not host-owned",
        ));
    };
    script_callback(&state, &handle);
    match state.oauth.callback_wait(&handle) {
        Ok(waited) => mint_callback(&state, waited.code_handle),
        Err(error) => return_json(oauth_error(&error)),
    }
}

fn transport_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = match state(vm) {
        Ok(state) => state,
        Err(error) => return return_json(error),
    };
    let request_value = args.first().cloned().unwrap_or(Value::Null);
    let use_value = args.get(1).cloned().unwrap_or(Value::Null);
    let policy_value = map_get(&request_value, "policy_handle");
    let policy = match admitted_policy(&state, policy_value, "transport") {
        Ok(policy) => policy,
        Err(error) => return return_json(error),
    };
    let request = match parse_provider_request(&request_value) {
        Ok(request) => request,
        Err(error) => return return_json(error),
    };
    let credential_use = match parse_credential_use(&state, &use_value) {
        Ok(credential_use) => credential_use,
        Err(error) => return return_json(error),
    };
    match state.oauth.transport(&policy, request, credential_use) {
        Ok(response) => {
            if state.scenario == "device_cancel" {
                state.cancel.cancel();
            }
            mint_transport(&state, response)
        }
        Err(error) => return_json(oauth_error(&error)),
    }
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
    if let Err(error) = admitted_policy(&state, map_get(&value, "policy_handle"), "load") {
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
    let request = match parse_save(&state, &value) {
        Ok(request) => request,
        Err(error) => return return_json(error),
    };
    match state.store.save_if_generation(request) {
        Ok(outcome) => match outcome {
            crate::auth::store::SaveOutcome::Committed { metadata }
            | crate::auth::store::SaveOutcome::Adopted { metadata } => return_json(json!({
                "ok": true,
                "outcome": "committed",
                "metadata": metadata_json(&metadata)
            })),
        },
        Err(error) => return_json(store_error(&error)),
    }
}

fn refresh_handle_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
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
    let policy = match admitted_policy(&state, map_get(&value, "policy_handle"), "refresh") {
        Ok(policy) => policy,
        Err(error) => return return_json(error),
    };
    match state.store.issue_refresh_handle_until(
        &credential_id,
        expected_generation,
        policy.generation,
        &policy.run_id,
        policy.deadline,
    ) {
        Ok(handle) => match state.policies.opaques().mint(handle.class(), handle) {
            Ok(minted) => return_handle(REFRESH_HANDLE_CLASS, minted.to_vm_value()),
            Err(error) => return_json(opaque_error_json(error)),
        },
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
    if opaque.class() == REFRESH_HANDLE_CLASS {
        let Some(handle) = opaque.downcast_arc::<OpaqueRefreshHandle>() else {
            return return_json(bridge_error("handle_invalid", "refresh handle is invalid"));
        };
        let result = match op {
            "validate" => handle.validate(),
            "consume" => handle.consume(),
            _ => Err(AuthStoreError::HandleInvalid {
                credential_id: handle.credential_id().to_string(),
                kind: "refresh".to_string(),
            }),
        };
        return match result {
            Ok(()) => return_json(json!({ "ok": true, "handle_class": REFRESH_HANDLE_CLASS })),
            Err(error) => return_json(store_error(&error)),
        };
    }
    if opaque.class() == ACCESS_HANDLE_CLASS {
        let Some(handle) = opaque.downcast_arc::<OpaqueAccessHandle>() else {
            return return_json(bridge_error("handle_invalid", "access handle is invalid"));
        };
        let result = match op {
            "validate" => handle.validate(),
            "consume" => handle.consume(),
            _ => Err(AuthStoreError::HandleInvalid {
                credential_id: handle.credential_id().to_string(),
                kind: "access".to_string(),
            }),
        };
        return match result {
            Ok(()) => return_json(json!({ "ok": true, "handle_class": ACCESS_HANDLE_CLASS })),
            Err(error) => return_json(store_error(&error)),
        };
    }
    return_json(bridge_error(
        "handle_invalid",
        "opaque value has the wrong handle class",
    ))
}

fn script_callback(state: &OAuthFixtureState, handle: &OpaqueCallbackHandle) {
    match state.scenario.as_str() {
        "login_browser" | "login_manual" | "secrets_absent" | "callback" | "callback_duplicate"
        | "code_replay" | "code_serialized" => {
            let _ = state.oauth.inject_matching_callback(handle, AUTH_CODE);
        }
        "callback_mismatch" => {
            let _ = state.oauth.inject_callback(
                handle,
                RawCallbackInput::Query {
                    state: "forged-state".to_string(),
                    code: AUTH_CODE.to_string(),
                },
            );
        }
        "timeout" => {
            let _ = state
                .oauth
                .inject_callback(handle, RawCallbackInput::Timeout);
        }
        "cancel" => {
            state.cancel.cancel();
            let _ = state
                .oauth
                .inject_callback(handle, RawCallbackInput::Cancelled);
        }
        _ => {}
    }
}

fn mint_begin(
    state: &OAuthFixtureState,
    begun: crate::auth::oauth::PkceBeginEnvelope,
) -> VmResult<CallOutcome> {
    let callback = match state
        .policies
        .opaques()
        .mint(CALLBACK_HANDLE_CLASS, begun.callback_handle)
    {
        Ok(value) => value.to_vm_value(),
        Err(error) => return return_json(opaque_error_json(error)),
    };
    let verifier = match state
        .policies
        .opaques()
        .mint(VERIFIER_HANDLE_CLASS, begun.verifier_handle)
    {
        Ok(value) => value.to_vm_value(),
        Err(error) => return return_json(opaque_error_json(error)),
    };
    let oauth_state = match state
        .policies
        .opaques()
        .mint(STATE_HANDLE_CLASS, begun.state_handle)
    {
        Ok(value) => value.to_vm_value(),
        Err(error) => return return_json(opaque_error_json(error)),
    };
    return_value(Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (
            Value::string("authorization_url"),
            Value::string(&begun.authorization_url),
        ),
        (
            Value::string("redirect_uri"),
            Value::string(&begun.redirect_uri),
        ),
        (
            Value::string("code_challenge"),
            Value::string(&begun.code_challenge),
        ),
        (
            Value::string("code_challenge_method"),
            Value::string(&begun.code_challenge_method),
        ),
        (Value::string("callback_handle"), callback),
        (Value::string("verifier_handle"), verifier),
        (Value::string("state_handle"), oauth_state),
    ]))
}

fn mint_callback(
    state: &OAuthFixtureState,
    code_handle: Option<OpaqueAuthorizationCodeHandle>,
) -> VmResult<CallOutcome> {
    let handle = match code_handle {
        Some(handle) => match state.policies.opaques().mint(CODE_HANDLE_CLASS, handle) {
            Ok(value) => value.to_vm_value(),
            Err(error) => return return_json(opaque_error_json(error)),
        },
        None => Value::Null,
    };
    return_value(Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("code_handle"), handle),
    ]))
}

fn mint_transport(
    state: &OAuthFixtureState,
    response: crate::auth::oauth::SanitizedProviderResponse,
) -> VmResult<CallOutcome> {
    let access = mint_slot(state, response.access_slot)?;
    let refresh = mint_slot(state, response.refresh_slot)?;
    let device = match response.device_handle {
        Some(handle) => match state.policies.opaques().mint(DEVICE_HANDLE_CLASS, handle) {
            Ok(value) => value.to_vm_value(),
            Err(error) => return return_json(opaque_error_json(error)),
        },
        None => Value::Null,
    };
    return_value(Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (
            Value::string("status"),
            Value::Int(i64::from(response.status)),
        ),
        (
            Value::string("body"),
            json_to_vm_value(&response.body_without_secret_fields),
        ),
        (
            Value::string("retry_after_ms"),
            response
                .retry_after_ms
                .map(|value| Value::Int(i64::try_from(value).unwrap_or(i64::MAX)))
                .unwrap_or(Value::Null),
        ),
        (Value::string("access_slot"), access),
        (Value::string("refresh_slot"), refresh),
        (Value::string("device_handle"), device),
    ]))
}

fn mint_slot(
    state: &OAuthFixtureState,
    slot: Option<OpaqueSecretSlot>,
) -> Result<Value, rustscript_vm::VmError> {
    match slot {
        Some(slot) => match state
            .policies
            .opaques()
            .mint(SECRET_SLOT_CLASS, FixtureSlotPayload { slot })
        {
            Ok(value) => Ok(value.to_vm_value()),
            Err(error) => {
                let _ = error;
                Ok(Value::Null)
            }
        },
        None => Ok(Value::Null),
    }
}

fn parse_intent(value: &Value) -> Result<BoundedPublicOAuthIntent, JsonValue> {
    let flow = match required_string(map_get(value, "flow"), "flow")?.as_str() {
        "device_code" => OAuthFlowKind::DeviceCode,
        _ => OAuthFlowKind::AuthorizationCodePkce,
    };
    let callback_mode =
        match required_string(map_get(value, "callback_mode"), "callback_mode")?.as_str() {
            "browser" => CallbackMode::Browser,
            "none" => CallbackMode::None,
            _ => CallbackMode::Manual,
        };
    let mut public_query = BTreeMap::new();
    if let Some(Value::Map(entries)) = map_get(value, "public_query") {
        for (key, nested) in entries.iter() {
            if let (Value::String(key), Value::String(nested)) = (key, nested) {
                public_query.insert(key.to_string(), nested.to_string());
            }
        }
    }
    let mut scopes = Vec::new();
    if let Some(Value::Array(values)) = map_get(value, "scopes") {
        for value in values.iter() {
            if let Value::String(value) = value {
                scopes.push(value.to_string());
            }
        }
    }
    Ok(BoundedPublicOAuthIntent {
        flow,
        callback_mode,
        path: required_string(map_get(value, "path"), "path")?,
        scopes,
        public_query,
        credential_id: required_string(map_get(value, "credential_id"), "credential_id")
            .unwrap_or_else(|_| "primary".to_string()),
    })
}

fn parse_provider_request(value: &Value) -> Result<ProviderRequest, JsonValue> {
    let mut public_headers = BTreeMap::new();
    if let Some(Value::Map(entries)) = map_get(value, "public_headers") {
        for (key, nested) in entries.iter() {
            if let (Value::String(key), Value::String(nested)) = (key, nested) {
                public_headers.insert(key.to_string(), nested.to_string());
            }
        }
    }
    Ok(ProviderRequest {
        method: required_string(map_get(value, "method"), "method")?,
        path: required_string(map_get(value, "path"), "path")?,
        public_headers,
        public_body: required_string(map_get(value, "public_body"), "public_body")
            .unwrap_or_default(),
        credential_id: required_string(map_get(value, "credential_id"), "credential_id")
            .unwrap_or_else(|_| "primary".to_string()),
    })
}

fn parse_credential_use(
    state: &OAuthFixtureState,
    value: &Value,
) -> Result<CredentialUse, JsonValue> {
    let kind =
        required_string(map_get(value, "kind"), "kind").unwrap_or_else(|_| "none".to_string());
    match kind.as_str() {
        "none" | "" => Ok(CredentialUse::None),
        "refresh" => {
            let handle = decode_refresh(state, map_get(value, "handle").unwrap_or(&Value::Null))?;
            Ok(CredentialUse::Refresh(handle))
        }
        "authorization_code" => {
            let code = decode_code(state, map_get(value, "code").unwrap_or(&Value::Null))?;
            let verifier =
                decode_verifier(state, map_get(value, "verifier").unwrap_or(&Value::Null))?;
            Ok(CredentialUse::AuthorizationCode { code, verifier })
        }
        "device" => {
            let handle = decode_device(state, map_get(value, "handle").unwrap_or(&Value::Null))?;
            Ok(CredentialUse::Device(handle))
        }
        _ => Err(bridge_error(
            "invalid_request",
            "credential_use kind is not recognized",
        )),
    }
}

fn parse_save(
    state: &OAuthFixtureState,
    value: &Value,
) -> Result<SaveCredentialRequest, JsonValue> {
    let credential_id = required_string(map_get(value, "credential_id"), "credential_id")?;
    let credential = CredentialId::new(credential_id.clone())
        .map_err(|_| bridge_error("invalid_credential", "credential ID is invalid"))?;
    let expected_generation =
        required_u64(map_get(value, "expected_generation"), "expected_generation")?;
    let policy = admitted_policy(state, map_get(value, "policy_handle"), "save")?;
    let metadata_value = map_get(value, "metadata")
        .ok_or_else(|| bridge_error("invalid_metadata", "metadata is missing"))?;
    let metadata = CredentialConfig {
        provider: required_string(map_get(metadata_value, "provider"), "provider")?,
        kind: required_string(map_get(metadata_value, "kind"), "kind")?,
        source: required_string(map_get(metadata_value, "source"), "source")?,
        token_type: required_string(map_get(metadata_value, "token_type"), "token_type")?,
        expires_at_ms: required_u64(map_get(metadata_value, "expires_at_ms"), "expires_at_ms")?,
        scopes: parse_scopes(map_get(metadata_value, "scopes"))?,
        account_id: optional_string(map_get(metadata_value, "account_id"), "account_id")?,
        generation: expected_generation,
        status: required_string(map_get(metadata_value, "status"), "status")?,
        last_refresh_at_ms: optional_u64(
            map_get(metadata_value, "last_refresh_at_ms"),
            "last_refresh_at_ms",
        )?,
        has_refresh_token: true,
    };
    let access_slot = parse_slot(
        state,
        map_get(value, "access_slot"),
        SecretSlotKind::Access,
        &credential_id,
        expected_generation,
        policy.generation,
        &policy.run_id,
    )?;
    let refresh = match map_get(value, "refresh") {
        Some(refresh) => {
            match required_string(map_get(refresh, "action"), "refresh.action")?.as_str() {
                "preserve" => RefreshSecretAction::Preserve,
                "clear" => RefreshSecretAction::Clear,
                _ => RefreshSecretAction::Replace(parse_slot(
                    state,
                    map_get(refresh, "slot"),
                    SecretSlotKind::Refresh,
                    &credential_id,
                    expected_generation,
                    policy.generation,
                    &policy.run_id,
                )?),
            }
        }
        None => RefreshSecretAction::Preserve,
    };
    Ok(SaveCredentialRequest::new(
        credential,
        expected_generation,
        policy.generation,
        policy.run_id,
        metadata,
        access_slot,
        refresh,
    ))
}

fn parse_slot(
    state: &OAuthFixtureState,
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

fn parse_scopes(value: Option<&Value>) -> Result<Vec<String>, JsonValue> {
    let Some(Value::Array(values)) = value else {
        return Ok(Vec::new());
    };
    Ok(values
        .iter()
        .filter_map(|value| match value {
            Value::String(value) => Some(value.to_string()),
            _ => None,
        })
        .collect())
}

fn decode_callback(state: &OAuthFixtureState, value: &Value) -> Option<OpaqueCallbackHandle> {
    let opaque = state.policies.opaques().from_vm_value(value)?;
    if opaque.class() != CALLBACK_HANDLE_CLASS {
        return None;
    }
    opaque
        .downcast_arc::<OpaqueCallbackHandle>()
        .map(|handle| (*handle).clone())
}

fn decode_code(
    state: &OAuthFixtureState,
    value: &Value,
) -> Result<OpaqueAuthorizationCodeHandle, JsonValue> {
    let opaque = state
        .policies
        .opaques()
        .from_vm_value(value)
        .ok_or_else(|| {
            bridge_error(
                "handle_invalid",
                "authorization code handle is not host-owned",
            )
        })?;
    opaque
        .downcast_arc::<OpaqueAuthorizationCodeHandle>()
        .map(|handle| (*handle).clone())
        .ok_or_else(|| bridge_error("handle_invalid", "authorization code handle is invalid"))
}

fn decode_verifier(
    state: &OAuthFixtureState,
    value: &Value,
) -> Result<OpaqueVerifierHandle, JsonValue> {
    let opaque = state
        .policies
        .opaques()
        .from_vm_value(value)
        .ok_or_else(|| bridge_error("handle_invalid", "verifier handle is not host-owned"))?;
    opaque
        .downcast_arc::<OpaqueVerifierHandle>()
        .map(|handle| (*handle).clone())
        .ok_or_else(|| bridge_error("handle_invalid", "verifier handle is invalid"))
}

fn decode_refresh(
    state: &OAuthFixtureState,
    value: &Value,
) -> Result<OpaqueRefreshHandle, JsonValue> {
    let opaque = state
        .policies
        .opaques()
        .from_vm_value(value)
        .ok_or_else(|| bridge_error("handle_invalid", "refresh handle is not host-owned"))?;
    opaque
        .downcast_arc::<OpaqueRefreshHandle>()
        .map(|handle| (*handle).clone())
        .ok_or_else(|| bridge_error("handle_invalid", "refresh handle is invalid"))
}

fn decode_device(
    state: &OAuthFixtureState,
    value: &Value,
) -> Result<OpaqueDeviceSessionHandle, JsonValue> {
    let opaque = state
        .policies
        .opaques()
        .from_vm_value(value)
        .ok_or_else(|| bridge_error("handle_invalid", "device handle is not host-owned"))?;
    if opaque.class() != DEVICE_HANDLE_CLASS {
        return Err(bridge_error(
            "handle_invalid",
            "device handle class mismatch",
        ));
    }
    opaque
        .downcast_arc::<OpaqueDeviceSessionHandle>()
        .map(|handle| (*handle).clone())
        .ok_or_else(|| bridge_error("handle_invalid", "device handle is invalid"))
}

fn admitted_policy(
    state: &OAuthFixtureState,
    value: Option<&Value>,
    op: &str,
) -> Result<TrustedTransportPolicy, JsonValue> {
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
                op: op.to_string(),
                ..PolicyIntent::default()
            },
        )
        .map_err(|error| policy_error(&error))?;
    let view = state
        .policies
        .admitted_transport(&handle)
        .map_err(|error| policy_error(&error))?;
    Ok(trusted_policy(view))
}

fn trusted_policy(view: AdmittedTransportView) -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: view.generation,
        run_id: view.run_id,
        deadline: view.deadline,
        endpoints: view
            .endpoints
            .into_iter()
            .map(|(authority, path_prefix)| TrustedEndpoint {
                authority,
                path_prefix,
            })
            .collect(),
        allowed_header_names: view.allowed_header_names,
    }
}

fn state(vm: &mut Vm) -> Result<OAuthFixtureState, JsonValue> {
    vm.host_context()
        .module_state::<OAuthFixtureState>()
        .cloned()
        .ok_or_else(|| bridge_error("backend_unavailable", "oauth fixture host is unbound"))
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

fn oauth_error(error: &OAuthError) -> JsonValue {
    json!({
        "ok": false,
        "error": {
            "code": error.code(),
            "message": error.to_string()
        }
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

fn opaque_error_json(error: OpaqueError) -> JsonValue {
    let message = match error {
        OpaqueError::LiveHandleLimit => "opaque live handle limit reached",
        OpaqueError::PrototypeIdSpaceExhausted => "opaque prototype id space exhausted",
    };
    bridge_error("opaque_handle_limit", message)
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

fn return_handle(class: &str, handle: Value) -> VmResult<CallOutcome> {
    return_value(Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("handle_class"), Value::string(class)),
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/oauth_flow.rss");
        let source = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let options =
            CompileSourceFileOptions::default().with_host_api_catalog(oauth_fixture_catalog());
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
                return Err("oauth fixture root frame yielded unexpectedly".to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
