use rustscript_agent::auth::host::auth_host_catalog;
use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceHandle, ResourceResult,
};
use rustscript_vm::{
    CallOutcome, CallReturn, CompileSourceFileOptions, HostApiBuilder, HostFunctionRegistry,
    HostFunctionSchema, HostParamSchema, HostResourceType, HostTypeSchema, ResourceTypeKey,
    SourceFlavor, Value, Vm, VmError, VmResult, VmStatus, catalog_import_schemas,
    catalog_named_struct_schemas, compile_source_at_path_with_flavor_and_options,
};
use serde_json::{Value as Json, json};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const CREDENTIAL_ID: &str = "scripted-codex";
const DEVICE_PRIVATE: &str = "SCRIPTED_DEVICE_PRIVATE_c671";
const CODE_PRIVATE: &str = "SCRIPTED_CODE_PRIVATE_1a84";
const VERIFIER_PRIVATE: &str = "SCRIPTED_VERIFIER_PRIVATE_9bd0";
const ACCESS_PRIVATE: &str = "SCRIPTED_ACCESS_PRIVATE_3e52";
const REFRESH_PRIVATE: &str = "SCRIPTED_REFRESH_PRIVATE_4f73";

#[derive(Clone, Debug)]
enum Receipt {
    Clock(usize),
    Request {
        method: String,
        path: String,
        content_type: String,
        body: String,
        usage: String,
    },
    Wait(i64),
    Instruction {
        verification_url: String,
        user_code: String,
        expires_in_seconds: i64,
    },
    Save {
        refresh_action: String,
        has_refresh_slot: bool,
    },
    Cleanup(u64),
}

#[derive(Clone)]
enum ClockStep {
    Current,
    At(i64),
    Failure(&'static str),
}

#[derive(Clone)]
struct ResponseSpec {
    status: i64,
    body: String,
    retry_after_ms: Option<i64>,
    device: bool,
    code: bool,
    verifier: bool,
    access: bool,
    refresh: bool,
    failure: Option<&'static str>,
}

impl ResponseSpec {
    fn start(body: Json) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            retry_after_ms: None,
            device: true,
            code: false,
            verifier: false,
            access: false,
            refresh: false,
            failure: None,
        }
    }

    fn poll(status: i64) -> Self {
        Self {
            status,
            body: "{}".to_string(),
            retry_after_ms: None,
            device: false,
            code: status == 200,
            verifier: status == 200,
            access: false,
            refresh: false,
            failure: None,
        }
    }

    fn exchange(body: Json, refresh: bool) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            retry_after_ms: None,
            device: false,
            code: false,
            verifier: false,
            access: true,
            refresh,
            failure: None,
        }
    }
}

#[derive(Clone, Default)]
struct Plan {
    responses: VecDeque<ResponseSpec>,
    clock: VecDeque<ClockStep>,
    wait_failure: Option<(usize, &'static str)>,
    save_failure: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceClass {
    Device,
    Code,
    Verifier,
    Secret,
}

#[derive(Clone, Copy)]
struct IssuedResource {
    owner: u64,
    handle: ResourceHandle,
    class: ResourceClass,
}

#[derive(Default)]
struct Inner {
    plan: Plan,
    now_ms: i64,
    clock_calls: usize,
    wait_calls: usize,
    policies: HashMap<i64, u64>,
    resources: Vec<IssuedResource>,
    receipts: Vec<Receipt>,
    cleanup_calls: usize,
}

#[derive(Clone, Default)]
struct HarnessState(Arc<Mutex<Inner>>);

macro_rules! resource_type {
    ($name:ident, $key:literal, $description:literal) => {
        struct $name {
            owner: u64,
            private_payload: &'static str,
        }

        impl HostResource for $name {
            fn resource_type_key() -> Option<ResourceTypeKey> {
                Some(ResourceTypeKey::new(Self::KEY).expect("test resource key"))
            }

            fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
                let _private_material = (self.owner, self.private_payload);
                Ok(CloseProgress::Ready)
            }
        }

        impl HostResourceType for $name {
            const KEY: &'static str = $key;
            const DESCRIPTION: &'static str = $description;
        }
    };
}

resource_type!(PolicyResource, "auth.policy", "Scripted policy resource");
resource_type!(
    DeviceResource,
    "oauth.device_session",
    "Scripted device resource"
);
resource_type!(
    CodeResource,
    "oauth.authorization_code",
    "Scripted authorization code resource"
);
resource_type!(
    VerifierResource,
    "oauth.verifier",
    "Scripted verifier resource"
);
resource_type!(
    SecretResource,
    "auth.secret_slot",
    "Scripted secret slot resource"
);

struct UnrelatedResource;

impl HostResource for UnrelatedResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(Self::KEY).expect("unrelated test resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for UnrelatedResource {
    const KEY: &'static str = "test.scripted_unrelated";
    const DESCRIPTION: &'static str = "Unrelated scripted-host resource";
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(name, value)| (Value::string(name), value))
            .collect(),
    )
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected typed record")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing typed field {name}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(fields) = value else {
        return None;
    };
    fields.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn text(value: &Value) -> &str {
    let Value::String(value) = value else {
        panic!("expected string value")
    };
    value
}

fn integer(value: &Value) -> i64 {
    let Value::Int(value) = value else {
        panic!("expected integer value")
    };
    *value
}

fn state(vm: &mut Vm) -> VmResult<HarnessState> {
    vm.host_context()
        .module_state::<HarnessState>()
        .cloned()
        .ok_or_else(|| VmError::HostError("scripted_state_missing".into()))
}

fn response_error(code: &'static str) -> Value {
    record(vec![
        ("code", Value::string(code)),
        ("cancelled", Value::Bool(code == "policy_inactive")),
        (
            "deadline_exceeded",
            Value::Bool(code == "wait_deadline_exceeded"),
        ),
        ("revoked", Value::Bool(false)),
    ])
}

fn result_envelope(ok: bool, error: Option<&'static str>, value: Value) -> Value {
    record(vec![
        ("ok", Value::Bool(ok)),
        ("error", error.map(response_error).unwrap_or(Value::Null)),
        ("value", value),
    ])
}

fn push_resource<T>(vm: &mut Vm, resource: T) -> VmResult<ResourceHandle>
where
    T: HostResource + HostResourceType,
{
    vm.host_context()
        .push_resource(resource)
        .map(|token| token.handle())
        .map_err(|_| VmError::HostError("scripted_resource_issue_failed".into()))
}

fn value_for_handle(handle: ResourceHandle) -> Value {
    Value::Int(handle.raw() as i64)
}

fn issue_policy(vm: &mut Vm, state: &HarnessState, owner: u64) -> Value {
    let handle = push_resource(
        vm,
        PolicyResource {
            owner,
            private_payload: "SCRIPTED_POLICY_PRIVATE_0d2c",
        },
    )
    .expect("issue actual policy resource-table entry");
    state
        .0
        .lock()
        .expect("scripted state")
        .policies
        .insert(handle.raw() as i64, owner);
    value_for_handle(handle)
}

fn issue_transient(
    vm: &mut Vm,
    state: &HarnessState,
    owner: u64,
    class: ResourceClass,
) -> VmResult<Value> {
    let handle = match class {
        ResourceClass::Device => push_resource(
            vm,
            DeviceResource {
                owner,
                private_payload: DEVICE_PRIVATE,
            },
        )?,
        ResourceClass::Code => push_resource(
            vm,
            CodeResource {
                owner,
                private_payload: CODE_PRIVATE,
            },
        )?,
        ResourceClass::Verifier => push_resource(
            vm,
            VerifierResource {
                owner,
                private_payload: VERIFIER_PRIVATE,
            },
        )?,
        ResourceClass::Secret => {
            let private_payload = if state
                .0
                .lock()
                .expect("scripted state")
                .resources
                .iter()
                .any(|entry| entry.class == ResourceClass::Secret && entry.owner == owner)
            {
                REFRESH_PRIVATE
            } else {
                ACCESS_PRIVATE
            };
            push_resource(
                vm,
                SecretResource {
                    owner,
                    private_payload,
                },
            )?
        }
    };
    state
        .0
        .lock()
        .expect("scripted state")
        .resources
        .push(IssuedResource {
            owner,
            handle,
            class,
        });
    Ok(value_for_handle(handle))
}

fn policy_owner(state: &HarnessState, value: &Value) -> VmResult<u64> {
    let raw = integer(value);
    state
        .0
        .lock()
        .expect("scripted state")
        .policies
        .get(&raw)
        .copied()
        .ok_or_else(|| VmError::HostError("scripted_policy_provenance".into()))
}

fn issued_owner(state: &HarnessState, value: &Value, class: ResourceClass) -> Option<u64> {
    let raw = integer(value);
    state
        .0
        .lock()
        .expect("scripted state")
        .resources
        .iter()
        .find(|entry| entry.handle.raw() as i64 == raw && entry.class == class)
        .map(|entry| entry.owner)
}

fn run_receipt(state: &HarnessState, receipt: Receipt) {
    state
        .0
        .lock()
        .expect("scripted state")
        .receipts
        .push(receipt);
}

fn headers_content_type(value: &Value) -> String {
    let Value::Array(headers) = value else {
        return String::new();
    };
    headers
        .iter()
        .find_map(|header| {
            let name = text(field(header, "name"));
            (name == "content-type").then(|| text(field(header, "value")).to_owned())
        })
        .unwrap_or_default()
}

fn next_response(state: &HarnessState) -> ResponseSpec {
    state
        .0
        .lock()
        .expect("scripted state")
        .plan
        .responses
        .pop_front()
        .unwrap_or(ResponseSpec {
            status: 599,
            body: String::new(),
            retry_after_ms: None,
            device: false,
            code: false,
            verifier: false,
            access: false,
            refresh: false,
            failure: Some("transport_error"),
        })
}

fn response_value(
    vm: &mut Vm,
    state: &HarnessState,
    owner: u64,
    response: &ResponseSpec,
) -> VmResult<Value> {
    let device = if response.device && response.failure.is_none() {
        issue_transient(vm, state, owner, ResourceClass::Device)?
    } else {
        Value::Null
    };
    let access = if response.access && response.failure.is_none() {
        issue_transient(vm, state, owner, ResourceClass::Secret)?
    } else {
        Value::Null
    };
    let refresh = if response.refresh && response.failure.is_none() {
        issue_transient(vm, state, owner, ResourceClass::Secret)?
    } else {
        Value::Null
    };
    Ok(record(vec![
        ("ok", Value::Bool(response.failure.is_none())),
        ("error", Value::Null),
        ("status", Value::Int(response.status)),
        ("public_headers", Value::array(Vec::new())),
        ("body_without_secret_fields", Value::string(&response.body)),
        (
            "retry_after_ms",
            response
                .retry_after_ms
                .map(Value::Int)
                .unwrap_or(Value::Null),
        ),
        ("access_slot", access),
        ("refresh_slot", refresh),
        ("device_handle", device),
    ]))
}

fn transport_adapter(vm: &mut Vm, args: &[Value], mode: TransportMode) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let request = args
        .first()
        .ok_or_else(|| VmError::HostError("request_missing".into()))?;
    let use_value = args
        .get(1)
        .ok_or_else(|| VmError::HostError("usage_missing".into()))?;
    let owner = policy_owner(&state, field(request, "policy_handle"))?;
    let path = text(field(request, "path")).to_owned();
    let method = text(field(request, "method")).to_owned();
    let body = text(field(request, "public_body")).to_owned();
    let usage = text(field(use_value, "kind")).to_owned();
    if mode == TransportMode::Capture
        && let Some(device) = optional_field(use_value, "device_handle")
        && !matches!(device, Value::Null)
        && issued_owner(&state, device, ResourceClass::Device) != Some(owner)
    {
        return Err(VmError::HostError("scripted_device_provenance".into()));
    }
    if usage == "code_verifier" {
        for (name, class) in [
            ("code_handle", ResourceClass::Code),
            ("verifier_handle", ResourceClass::Verifier),
        ] {
            if optional_field(use_value, name)
                .is_none_or(|value| issued_owner(&state, value, class) != Some(owner))
            {
                return Err(VmError::HostError("scripted_pair_provenance".into()));
            }
        }
    }
    run_receipt(
        &state,
        Receipt::Request {
            method,
            path,
            content_type: headers_content_type(field(request, "public_headers")),
            body,
            usage,
        },
    );
    let response = next_response(&state);
    let mut value = response_value(vm, &state, owner, &response)?;
    if mode == TransportMode::Capture {
        let code_handle = if response.code && response.failure.is_none() {
            issue_transient(vm, &state, owner, ResourceClass::Code)?
        } else {
            Value::Null
        };
        let verifier_handle = if response.verifier && response.failure.is_none() {
            issue_transient(vm, &state, owner, ResourceClass::Verifier)?
        } else {
            Value::Null
        };
        let inner_ok = matches!(field(&value, "ok"), Value::Bool(true));
        let inner_error = optional_field(&value, "error")
            .cloned()
            .unwrap_or(Value::Null);
        value = record(vec![
            ("ok", Value::Bool(inner_ok)),
            ("error", inner_error),
            ("response", value),
            ("code_handle", code_handle),
            ("verifier_handle", verifier_handle),
        ]);
        let error = (!inner_ok).then_some("transport_error");
        Ok(CallOutcome::Return(CallReturn::One(result_envelope(
            inner_ok, error, value,
        ))))
    } else {
        let ok = matches!(field(&value, "ok"), Value::Bool(true));
        let error = (!ok).then_some("transport_error");
        Ok(CallOutcome::Return(CallReturn::One(result_envelope(
            ok, error, value,
        ))))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    Direct,
    Capture,
}

fn transport_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    transport_adapter(vm, args, TransportMode::Direct)
}

fn transport_capture_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    transport_adapter(vm, args, TransportMode::Capture)
}

fn transport_payload_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    transport_adapter(vm, args, TransportMode::Direct)
}

fn now_ms_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let policy = args
        .first()
        .ok_or_else(|| VmError::HostError("policy_missing".into()))?;
    let _owner = policy_owner(&state, policy)?;
    let (index, step, fallback) = {
        let mut inner = state.0.lock().expect("scripted state");
        let index = inner.clock_calls;
        inner.clock_calls += 1;
        let step = inner.plan.clock.pop_front().unwrap_or(ClockStep::Current);
        let fallback = inner.now_ms;
        (index, step, fallback)
    };
    run_receipt(&state, Receipt::Clock(index));
    match step {
        ClockStep::Failure(code) => Ok(CallOutcome::Return(CallReturn::One(result_envelope(
            false,
            Some(code),
            Value::Null,
        )))),
        ClockStep::At(value) => {
            state.0.lock().expect("scripted state").now_ms = value;
            Ok(CallOutcome::Return(CallReturn::One(result_envelope(
                true,
                None,
                Value::Int(value),
            ))))
        }
        ClockStep::Current => Ok(CallOutcome::Return(CallReturn::One(result_envelope(
            true,
            None,
            Value::Int(fallback),
        )))),
    }
}

fn wait_ms_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let policy = args
        .first()
        .ok_or_else(|| VmError::HostError("policy_missing".into()))?;
    let _owner = policy_owner(&state, policy)?;
    let millis = integer(
        args.get(1)
            .ok_or_else(|| VmError::HostError("wait_missing".into()))?,
    );
    let failure = {
        let mut inner = state.0.lock().expect("scripted state");
        let index = inner.wait_calls;
        inner.wait_calls += 1;
        let failure = inner
            .plan
            .wait_failure
            .filter(|(at, _)| *at == index)
            .map(|(_, code)| code);
        inner.receipts.push(Receipt::Wait(millis));
        if failure.is_none() {
            inner.now_ms = inner.now_ms.saturating_add(millis);
        }
        failure
    };
    Ok(CallOutcome::Return(CallReturn::One(record(vec![
        ("ok", Value::Bool(failure.is_none())),
        ("error", failure.map(response_error).unwrap_or(Value::Null)),
    ]))))
}

fn json_field_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let policy = args
        .first()
        .ok_or_else(|| VmError::HostError("policy_missing".into()))?;
    let _owner = policy_owner(&state, policy)?;
    let source = text(
        args.get(1)
            .ok_or_else(|| VmError::HostError("json_missing".into()))?,
    );
    let pointer = text(
        args.get(2)
            .ok_or_else(|| VmError::HostError("pointer_missing".into()))?,
    );
    let document: Json = match serde_json::from_str(source) {
        Ok(value) => value,
        Err(_) => {
            return Ok(CallOutcome::Return(CallReturn::One(result_envelope(
                false,
                Some("public_json_invalid"),
                Value::Null,
            ))));
        }
    };
    let selected = document.pointer(pointer);
    let parsed = match selected {
        None => public_json_value(
            "missing",
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        Some(Json::Null) => public_json_value(
            "null",
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        Some(Json::String(value)) => public_json_value(
            "string",
            Value::string(value),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        Some(Json::Bool(value)) => public_json_value(
            "bool",
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Bool(*value),
            Value::Null,
        ),
        Some(Json::Number(value)) if value.as_i64().is_some() => public_json_value(
            "int",
            Value::Null,
            Value::Int(value.as_i64().unwrap()),
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        Some(Json::Number(value)) if value.as_f64().is_some() => public_json_value(
            "float",
            Value::Null,
            Value::Null,
            Value::Float(value.as_f64().unwrap()),
            Value::Null,
            Value::Null,
        ),
        Some(Json::Number(_)) => {
            return Ok(CallOutcome::Return(CallReturn::One(result_envelope(
                false,
                Some("public_json_number_out_of_range"),
                Value::Null,
            ))));
        }
        Some(Json::Array(values)) => public_json_value(
            "array",
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Int(values.len() as i64),
        ),
        Some(Json::Object(values)) => public_json_value(
            "object",
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Int(values.len() as i64),
        ),
    };
    Ok(CallOutcome::Return(CallReturn::One(result_envelope(
        true, None, parsed,
    ))))
}

fn public_json_value(
    kind: &str,
    string_value: Value,
    int_value: Value,
    float_value: Value,
    bool_value: Value,
    length: Value,
) -> Value {
    record(vec![
        ("kind", Value::string(kind)),
        ("string_value", string_value),
        ("int_value", int_value),
        ("float_value", float_value),
        ("bool_value", bool_value),
        ("length", length),
    ])
}

fn save_if_generation_result(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let request = args
        .first()
        .ok_or_else(|| VmError::HostError("save_missing".into()))?;
    let owner = policy_owner(&state, field(request, "policy_handle"))?;
    let access = field(request, "access_slot");
    if issued_owner(&state, access, ResourceClass::Secret) != Some(owner) {
        return Err(VmError::HostError("scripted_slot_provenance".into()));
    }
    let refresh_slot = optional_field(request, "refresh_slot");
    let has_refresh_slot = refresh_slot.is_some_and(|value| !matches!(value, Value::Null));
    if has_refresh_slot
        && issued_owner(
            &state,
            refresh_slot.expect("present refresh slot"),
            ResourceClass::Secret,
        ) != Some(owner)
    {
        return Err(VmError::HostError("scripted_refresh_provenance".into()));
    }
    let refresh_action = text(field(request, "refresh_action")).to_owned();
    run_receipt(
        &state,
        Receipt::Save {
            refresh_action,
            has_refresh_slot,
        },
    );
    let failure = state.0.lock().expect("scripted state").plan.save_failure;
    if let Some(code) = failure {
        return Ok(CallOutcome::Return(CallReturn::One(result_envelope(
            false,
            Some(code),
            Value::Null,
        ))));
    }
    let metadata = field(request, "metadata");
    let expected_generation = integer(field(request, "expected_generation"));
    let saved_metadata = record(vec![
        ("credential_id", field(request, "credential_id").clone()),
        ("provider", field(metadata, "provider").clone()),
        ("kind", field(metadata, "kind").clone()),
        ("source", field(metadata, "source").clone()),
        ("token_type", field(metadata, "token_type").clone()),
        ("expires_at_ms", field(metadata, "expires_at_ms").clone()),
        ("scopes", field(metadata, "scopes").clone()),
        (
            "account_id",
            optional_field(metadata, "account_id")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        ("generation", Value::Int(expected_generation + 1)),
        ("status", field(metadata, "status").clone()),
        (
            "last_refresh_at_ms",
            optional_field(metadata, "last_refresh_at_ms")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        ("has_refresh_token", Value::Bool(has_refresh_slot)),
    ]);
    let saved = record(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("metadata", saved_metadata),
        ("outcome", Value::string("committed")),
    ]);
    Ok(CallOutcome::Return(CallReturn::One(result_envelope(
        true, None, saved,
    ))))
}

fn close_transient(vm: &mut Vm, entry: IssuedResource) -> VmResult<()> {
    let result = match entry.class {
        ResourceClass::Device => vm
            .host_context()
            .close_resource::<DeviceResource>(entry.handle, ResourceCloseReason::Requested),
        ResourceClass::Code => vm
            .host_context()
            .close_resource::<CodeResource>(entry.handle, ResourceCloseReason::Requested),
        ResourceClass::Verifier => vm
            .host_context()
            .close_resource::<VerifierResource>(entry.handle, ResourceCloseReason::Requested),
        ResourceClass::Secret => vm
            .host_context()
            .close_resource::<SecretResource>(entry.handle, ResourceCloseReason::Requested),
    };
    result
        .map(|_| ())
        .map_err(|_| VmError::HostError("scripted_cleanup_failed".into()))
}

fn cleanup_transients(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let policy = args
        .first()
        .ok_or_else(|| VmError::HostError("policy_missing".into()))?;
    let owner = policy_owner(&state, policy)?;
    let entries = {
        let mut inner = state.0.lock().expect("scripted state");
        inner.cleanup_calls += 1;
        inner.receipts.push(Receipt::Cleanup(owner));
        let (owned, other): (Vec<_>, Vec<_>) = inner
            .resources
            .drain(..)
            .partition(|entry| entry.owner == owner);
        inner.resources = other;
        owned
    };
    for entry in entries {
        close_transient(vm, entry)?;
    }
    Ok(CallOutcome::Return(CallReturn::One(Value::Null)))
}

fn emit_instruction(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = state(vm)?;
    let verification_url = text(
        args.first()
            .ok_or_else(|| VmError::HostError("callback_arg_missing".into()))?,
    )
    .to_owned();
    let user_code = text(
        args.get(1)
            .ok_or_else(|| VmError::HostError("callback_arg_missing".into()))?,
    )
    .to_owned();
    let expires_in_seconds = integer(
        args.get(2)
            .ok_or_else(|| VmError::HostError("callback_arg_missing".into()))?,
    );
    run_receipt(
        &state,
        Receipt::Instruction {
            verification_url,
            user_code,
            expires_in_seconds,
        },
    );
    Ok(CallOutcome::Return(CallReturn::One(Value::Null)))
}

fn register_exact(
    registry: &mut HostFunctionRegistry,
    catalog: &rustscript_vm::HostApiCatalog,
    name: &str,
    arity: u8,
    handler: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) {
    let schemas = catalog_import_schemas(catalog, name);
    assert!(
        !schemas.is_empty(),
        "catalog import schema exists for {name}"
    );
    for schema in schemas {
        registry
            .register_exact_static(name, arity, schema, handler)
            .unwrap_or_else(|error| panic!("register exact {name}: {error}"));
    }
    registry.authorize_registered_builtin_import(name);
}

fn catalog() -> Arc<rustscript_vm::HostApiCatalog> {
    static CATALOG: OnceLock<Arc<rustscript_vm::HostApiCatalog>> = OnceLock::new();
    Arc::clone(CATALOG.get_or_init(|| {
        let base = auth_host_catalog();
        let mut builder = HostApiBuilder::new();
        for resource in base.resources() {
            builder.resource(resource.clone());
        }
        for structure in base.structs() {
            builder.named_struct(structure.clone());
        }
        for function in base.functions() {
            builder.function(function.clone());
        }
        builder.function(HostFunctionSchema::with_return(
            "test::emit_instruction",
            vec![
                HostParamSchema::value("verification_url", HostTypeSchema::String),
                HostParamSchema::value("user_code", HostTypeSchema::String),
                HostParamSchema::value("expires_in_seconds", HostTypeSchema::Int),
            ],
            HostTypeSchema::Null,
        ));
        Arc::new(builder.build().expect("restricted scripted test catalog"))
    }))
}

fn compiled_program() -> Arc<rustscript_vm::Program> {
    static PROGRAM: OnceLock<Arc<rustscript_vm::Program>> = OnceLock::new();
    Arc::clone(PROGRAM.get_or_init(|| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/codex_device/scripted_entry.rss");
        let source = fs::read_to_string(&path).expect("scripted RSS entry fixture");
        let compiled = compile_source_at_path_with_flavor_and_options(
            &path,
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(catalog()),
        )
        .unwrap_or_else(|error| panic!("compile actual scripted RSS wrapper: {error}"));
        Arc::new(compiled.program)
    }))
}

fn scripted_vm(plan: Plan) -> (Vm, HarnessState, Value, ResourceHandle, Value) {
    let catalog = catalog();
    let mut registry = HostFunctionRegistry::restricted();
    registry
        .install_named_struct_schemas(catalog_named_struct_schemas(catalog.as_ref()))
        .expect("install exact catalog host struct bodies");
    for (name, arity, handler) in [
        (
            "oauth::now_ms_result",
            1,
            now_ms_result as fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
        ),
        ("oauth::wait_ms_result", 2, wait_ms_result),
        ("oauth::transport_result", 2, transport_result),
        (
            "oauth::transport_capture_result",
            4,
            transport_capture_result,
        ),
        (
            "oauth::transport_payload_result",
            3,
            transport_payload_result,
        ),
        ("oauth::public_json_field_result", 3, json_field_result),
        (
            "auth::save_if_generation_result",
            1,
            save_if_generation_result,
        ),
        ("auth::cleanup_transients", 1, cleanup_transients),
        ("test::emit_instruction", 3, emit_instruction),
    ] {
        register_exact(&mut registry, catalog.as_ref(), name, arity, handler);
    }
    registry
        .allow_builtin("json::encode")
        .expect("authorize only RSS JSON encoder");
    let mut vm = Vm::new_shared(compiled_program());
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted exact scripted adapters");
    let state = HarnessState(Arc::new(Mutex::new(Inner {
        plan,
        now_ms: 1_000,
        ..Inner::default()
    })));
    vm.host_context().set_module_state(state.clone());
    assert!(matches!(
        vm.run().expect("scripted wrapper root"),
        VmStatus::Halted
    ));
    let policy = issue_policy(&mut vm, &state, 1);
    let _secondary_policy = issue_policy(&mut vm, &state, 2);
    let secondary_device =
        issue_transient(&mut vm, &state, 2, ResourceClass::Device).expect("second owner resource");
    let unrelated = push_resource(&mut vm, UnrelatedResource).expect("unrelated live resource");
    (vm, state, policy, unrelated, secondary_device)
}

fn provider_with(auth_id: &str, flow: &str) -> Value {
    let oauth = record(vec![
        ("flow", Value::string(flow)),
        ("issuer", Value::string("https://auth.example.test")),
        ("client_id", Value::string("synthetic-public-client")),
        (
            "device_user_code_path",
            Value::string("/api/accounts/deviceauth/usercode"),
        ),
        (
            "device_poll_path",
            Value::string("/api/accounts/deviceauth/token"),
        ),
        ("authorization_path", Value::string("/codex/device")),
        (
            "token_endpoint",
            Value::string("https://auth.example.test/oauth/token"),
        ),
        (
            "redirect_uri",
            Value::string("https://auth.example.test/deviceauth/callback"),
        ),
        ("refresh_skew_seconds", Value::Int(0)),
    ]);
    record(vec![
        ("name", Value::string("fixture-provider")),
        ("protocol", Value::string("codex-responses")),
        (
            "base_url",
            Value::string("https://api.example.test/backend"),
        ),
        ("auth", Value::string(auth_id)),
        ("oauth", oauth),
    ])
}

fn provider() -> Value {
    provider_with(CREDENTIAL_ID, "codex-device")
}

fn login_with(
    vm: &mut Vm,
    policy: &Value,
    provider: Value,
    credential_id: &str,
    expected_generation: i64,
) -> Result<Value, VmError> {
    let callable = vm
        .resolve_exported_callable("run")
        .expect("typed RSS wrapper export");
    vm.invoke_callable(
        callable,
        &[
            policy.clone(),
            provider,
            Value::string(credential_id),
            Value::Int(expected_generation),
        ],
    )
}

fn login(vm: &mut Vm, policy: &Value, expected_generation: i64) -> Result<Value, VmError> {
    login_with(vm, policy, provider(), CREDENTIAL_ID, expected_generation)
}

fn happy_plan(refresh: bool) -> Plan {
    Plan {
        responses: VecDeque::from([
            ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74", "interval":1})),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":3600,"token_type":"Bearer"}), refresh),
        ]),
        ..Plan::default()
    }
}

fn request_receipts(receipts: &[Receipt]) -> Vec<(String, String, String, String, String)> {
    receipts
        .iter()
        .filter_map(|receipt| match receipt {
            Receipt::Request {
                method,
                path,
                content_type,
                body,
                usage,
            } => Some((
                method.clone(),
                path.clone(),
                content_type.clone(),
                body.clone(),
                usage.clone(),
            )),
            _ => None,
        })
        .collect()
}

fn wait_receipts(receipts: &[Receipt]) -> Vec<i64> {
    receipts
        .iter()
        .filter_map(|receipt| match receipt {
            Receipt::Wait(millis) => Some(*millis),
            _ => None,
        })
        .collect()
}

fn assert_terminal_resources(
    vm: &mut Vm,
    state: &HarnessState,
    unrelated: ResourceHandle,
    secondary_device: &Value,
) {
    let (other_handle, tracked) = {
        let inner = state.0.lock().expect("scripted state");
        assert_eq!(inner.cleanup_calls, 1, "RSS performs one terminal cleanup");
        assert_eq!(
            inner.resources.len(),
            1,
            "other owner's transient remains tracked"
        );
        let other = inner.resources[0];
        assert_eq!(other.owner, 2);
        assert_eq!(other.class, ResourceClass::Device);
        assert_eq!(other.handle.raw() as i64, integer(secondary_device));
        (other.handle, inner.resources.len())
    };
    assert_eq!(tracked, 1);
    assert_eq!(vm.host_context().resource_count(), 4);
    vm.host_context()
        .borrow_resource_with_key::<DeviceResource>(
            other_handle,
            &ResourceTypeKey::new(DeviceResource::KEY).expect("device key"),
        )
        .expect("owner-two device resource remains live");
    vm.host_context()
        .borrow_resource_with_key::<UnrelatedResource>(
            unrelated,
            &ResourceTypeKey::new(UnrelatedResource::KEY).expect("unrelated key"),
        )
        .expect("unrelated resource remains live");
}

#[test]
fn actual_rss_happy_path_uses_typed_queue_and_cleans_only_its_owner() {
    let (mut vm, state, policy, unrelated, secondary_device) = scripted_vm(happy_plan(true));
    let result = login(&mut vm, &policy, 0).expect("invoke actual imported RSS login");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(field(&result, "code"), &Value::string("ok"));
    let metadata = field(&result, "metadata");
    assert_eq!(field(metadata, "ok"), &Value::Bool(true));
    assert_eq!(
        field(field(metadata, "metadata"), "generation"),
        &Value::Int(1)
    );
    assert_eq!(
        field(field(metadata, "metadata"), "provider"),
        &Value::string("fixture-provider")
    );
    assert_eq!(
        field(field(metadata, "metadata"), "has_refresh_token"),
        &Value::Bool(true)
    );

    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    let instruction = receipts
        .iter()
        .position(|receipt| matches!(receipt, Receipt::Instruction { .. }))
        .expect("one typed instruction callback");
    let poll = receipts
        .iter()
        .position(|receipt| matches!(receipt, Receipt::Request { path, .. } if path == "/api/accounts/deviceauth/token"))
        .expect("actual RSS poll request");
    assert!(instruction < poll, "instruction precedes the first poll");
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt, Receipt::Instruction { .. }))
            .count(),
        1
    );
    let requests = request_receipts(&receipts);
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].0, "POST");
    assert_eq!(requests[0].1, "/api/accounts/deviceauth/usercode");
    assert_eq!(requests[0].2, "application/json");
    assert_eq!(
        serde_json::from_str::<Json>(&requests[0].3).expect("public start JSON"),
        json!({"client_id":"synthetic-public-client"})
    );
    assert_eq!(requests[0].4, "none");
    assert_eq!(requests[1].0, "POST");
    assert_eq!(requests[1].1, "/api/accounts/deviceauth/token");
    assert_eq!(requests[1].2, "application/json");
    assert_eq!(
        serde_json::from_str::<Json>(&requests[1].3).expect("public poll JSON"),
        json!({"user_code":"SYNTHETIC-CODE-74"})
    );
    assert_eq!(requests[1].4, "device_session");
    assert_eq!(requests[2].0, "POST");
    assert_eq!(requests[2].1, "/oauth/token");
    assert_eq!(requests[2].2, "application/x-www-form-urlencoded");
    assert_eq!(
        requests[2].3,
        "grant_type=authorization_code&client_id=synthetic-public-client"
    );
    assert_eq!(requests[2].4, "code_verifier");
    assert!(wait_receipts(&receipts).is_empty());
    let instruction = receipts
        .iter()
        .find_map(|receipt| match receipt {
            Receipt::Instruction {
                verification_url,
                user_code,
                expires_in_seconds,
            } => Some((verification_url, user_code, expires_in_seconds)),
            _ => None,
        })
        .expect("typed instruction values");
    assert_eq!(instruction.0, "https://auth.example.test/codex/device");
    assert_eq!(instruction.1, "SYNTHETIC-CODE-74");
    assert_eq!(*instruction.2, 900);
    assert!(receipts.iter().any(|receipt| matches!(
        receipt,
        Receipt::Save { refresh_action, has_refresh_slot: true }
            if refresh_action == "replace"
    )));
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt, Receipt::Save { .. }))
            .count(),
        1
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt, Receipt::Cleanup(1)))
            .count(),
        1
    );
    assert_eq!(
        issued_owner(&state, &secondary_device, ResourceClass::Device),
        Some(2)
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary_device);
    let rendered = format!("{result:?}{receipts:?}");
    for marker in [
        DEVICE_PRIVATE,
        CODE_PRIVATE,
        VERIFIER_PRIVATE,
        ACCESS_PRIVATE,
        REFRESH_PRIVATE,
    ] {
        assert!(
            !rendered.contains(marker),
            "private resource material remains private"
        );
    }
}

fn run_plan(
    plan: Plan,
) -> (
    Vm,
    HarnessState,
    Value,
    ResourceHandle,
    Value,
    Result<Value, VmError>,
) {
    let (mut vm, state, policy, unrelated, secondary_device) = scripted_vm(plan);
    let result = login(&mut vm, &policy, 0);
    (vm, state, policy, unrelated, secondary_device, result)
}

fn result_code(result: &Value) -> &str {
    text(field(result, "code"))
}

#[test]
fn pending_403_and_404_wait_selected_interval_before_repolling() {
    let plan = Plan {
        responses: VecDeque::from([
            ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74", "interval":2})),
            ResponseSpec::poll(403),
            ResponseSpec::poll(404),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":3600}), false),
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("pending flow returns typed result");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert_eq!(wait_receipts(&receipts), vec![2_000, 2_000]);
    assert_eq!(
        request_receipts(&receipts)
            .iter()
            .map(|entry| entry.1.as_str())
            .collect::<Vec<_>>(),
        vec![
            "/api/accounts/deviceauth/usercode",
            "/api/accounts/deviceauth/token",
            "/api/accounts/deviceauth/token",
            "/api/accounts/deviceauth/token",
            "/oauth/token",
        ]
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt, Receipt::Instruction { .. }))
            .count(),
        1
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn interval_defaults_and_canonical_values_select_expected_waits() {
    let cases = [
        ("absent", None, 5_000),
        ("integer", Some(json!(2)), 2_000),
        ("string", Some(json!("3")), 3_000),
        ("trimmed", Some(json!(" 4 ")), 4_000),
        ("zero string", Some(json!("0")), 1_000),
        ("zero integer", Some(json!(0)), 1_000),
        ("upper integer clamp", Some(json!(i64::MAX)), 60_000),
        (
            "large string clamp",
            Some(json!("99999999999999999999")),
            60_000,
        ),
    ];
    for (label, interval, expected_wait) in cases {
        let mut start = json!({"user_code":"SYNTHETIC-CODE-74"});
        if let Some(value) = interval {
            start["interval"] = value;
        }
        let plan = Plan {
            responses: VecDeque::from([
                ResponseSpec::start(start),
                ResponseSpec::poll(403),
                ResponseSpec::poll(200),
                ResponseSpec::exchange(json!({"expires_in":3600}), false),
            ]),
            ..Plan::default()
        };
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.expect("interval flow typed result");
        assert_eq!(field(&result, "ok"), &Value::Bool(true), "case {label}");
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert_eq!(
            wait_receipts(&receipts),
            vec![expected_wait],
            "case {label}"
        );
        let instruction = receipts.iter().find_map(|receipt| match receipt {
            Receipt::Instruction {
                expires_in_seconds, ..
            } => Some(expires_in_seconds),
            _ => None,
        });
        assert_eq!(
            instruction,
            Some(&900i64),
            "missing start expiry uses remaining flow lifetime"
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}

#[test]
fn malformed_interval_types_and_noncanonical_text_stop_before_poll() {
    let invalid = [
        json!(true),
        json!(1.5),
        json!({"seconds":1}),
        json!([1]),
        json!(-1),
        json!("01"),
        json!("not-a-number"),
        json!("9".repeat(33)),
        Json::Null,
    ];
    for interval in invalid {
        let plan = Plan {
            responses: VecDeque::from([ResponseSpec::start(json!({
                "user_code":"SYNTHETIC-CODE-74",
                "interval": interval,
            }))]),
            ..Plan::default()
        };
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.expect("malformed interval is a typed RSS result");
        assert_eq!(result_code(&result), "invalid_start_response");
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert_eq!(request_receipts(&receipts).len(), 1);
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Instruction { .. }))
        );
        assert!(wait_receipts(&receipts).is_empty());
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}

#[test]
fn start_alias_status_and_shape_errors_are_static_and_never_poll() {
    let mut not_found = ResponseSpec::start(json!({"error":"private-provider-message"}));
    not_found.status = 404;
    not_found.device = false;
    let mut rejected = ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1}));
    rejected.status = 500;
    let mut transport_failure = ResponseSpec::start(json!({}));
    transport_failure.failure = Some("transport_error");
    let cases = [
        (not_found, "device_login_unavailable"),
        (transport_failure, "start_transport_failed"),
        (
            ResponseSpec::start(json!({"interval":1})),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(json!({"user_code":"CODE WITH SPACE","interval":1})),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(
                json!({"user_code":"FIRST-CODE","usercode":"SECOND-CODE","interval":1}),
            ),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(json!({"user_code":7,"usercode":"LEGACY-CODE","interval":1})),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(
                json!({"user_code":"SYNTHETIC-CODE-74","interval":1,"expires_in":0}),
            ),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(
                json!({"user_code":"SYNTHETIC-CODE-74","interval":1,"expires_in":-1}),
            ),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(
                json!({"user_code":"SYNTHETIC-CODE-74","interval":1,"expires_in":"900"}),
            ),
            "invalid_start_response",
        ),
        (
            ResponseSpec::start(
                json!({"user_code":"SYNTHETIC-CODE-74","interval":1,"expires_in":1.5}),
            ),
            "invalid_start_response",
        ),
        (rejected, "start_rejected"),
    ];
    for (start, expected_code) in cases {
        let plan = Plan {
            responses: VecDeque::from([start]),
            ..Plan::default()
        };
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.expect("start response returns typed failure");
        assert_eq!(result_code(&result), expected_code);
        assert!(!text(field(&result, "message")).contains("private-provider-message"));
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert_eq!(request_receipts(&receipts).len(), 1);
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Instruction { .. }))
        );
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }

    let mut missing_handle = ResponseSpec::start(
        json!({"user_code":"LEGACY-CODE","usercode":"LEGACY-CODE","interval":" 0 "}),
    );
    missing_handle.device = false;
    let plan = Plan {
        responses: VecDeque::from([missing_handle]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("missing opaque start handle result");
    assert_eq!(result_code(&result), "invalid_start_response");
    assert_eq!(
        request_receipts(&state.0.lock().expect("receipts").receipts).len(),
        1
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn legacy_usercode_alias_and_missing_expiry_use_typed_instruction() {
    let plan = Plan {
        responses: VecDeque::from([
            ResponseSpec::start(json!({"usercode":"LEGACY-CODE","interval":"0"})),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":3600}), false),
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("legacy alias reaches actual RSS success path");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert!(wait_receipts(&receipts).is_empty());
    assert_eq!(request_receipts(&receipts).len(), 3);
    assert!(receipts.iter().any(|receipt| matches!(
        receipt,
        Receipt::Instruction { user_code, expires_in_seconds: 900, .. }
            if user_code == "LEGACY-CODE"
    )));
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn absent_start_expiry_uses_deadline_remaining_after_start() {
    let plan = Plan {
        clock: VecDeque::from([ClockStep::At(1_000), ClockStep::At(200_000)]),
        responses: VecDeque::from([
            ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":3600}), false),
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("valid start response reaches terminal state");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    let announced = receipts.iter().find_map(|receipt| match receipt {
        Receipt::Instruction {
            expires_in_seconds, ..
        } => Some(*expires_in_seconds),
        _ => None,
    });
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    assert_eq!(
        announced,
        Some(701),
        "absent expiry must use remaining fixed deadline"
    );
}

#[test]
fn start_instruction_expiry_is_capped_by_remaining_fixed_deadline() {
    let plan = Plan {
        clock: VecDeque::from([ClockStep::At(1_000), ClockStep::At(200_000)]),
        responses: VecDeque::from([
            ResponseSpec::start(
                json!({"user_code":"SYNTHETIC-CODE-74","interval":1,"expires_in":900}),
            ),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":3600}), false),
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("valid start response reaches terminal state");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    let announced = receipts.iter().find_map(|receipt| match receipt {
        Receipt::Instruction {
            expires_in_seconds, ..
        } => Some(*expires_in_seconds),
        _ => None,
    });
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    assert_eq!(
        announced,
        Some(701),
        "instruction lifetime must not exceed deadline remaining after start"
    );
}

#[test]
fn retry_after_backoff_caps_and_pending_resets_to_base_interval() {
    let mut retry_after = ResponseSpec::poll(429);
    retry_after.retry_after_ms = Some(90_000);
    let responses = vec![
        ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":2})),
        retry_after,
        ResponseSpec::poll(429),
        ResponseSpec::poll(404),
        ResponseSpec::poll(429),
        ResponseSpec::poll(429),
        ResponseSpec::poll(429),
        ResponseSpec::poll(429),
        ResponseSpec::poll(429),
        ResponseSpec::poll(429),
        ResponseSpec::poll(200),
        ResponseSpec::exchange(json!({"expires_in":3600}), false),
    ];
    let plan = Plan {
        responses: VecDeque::from(responses),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("bounded retry reaches scripted success");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert_eq!(
        wait_receipts(&receipts),
        vec![
            60_000, 8_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000
        ]
    );
    assert_eq!(request_receipts(&receipts).len(), 12);
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn fifteen_minute_deadline_clamps_wait_and_prevents_a_late_poll() {
    let mut responses = vec![ResponseSpec::start(
        json!({"user_code":"SYNTHETIC-CODE-74","interval":60}),
    )];
    responses.extend((0..15).map(|_| ResponseSpec::poll(403)));
    let plan = Plan {
        responses: VecDeque::from(responses),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("deadline returns a typed timeout");
    assert_eq!(result_code(&result), "timeout");
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert_eq!(
        request_receipts(&receipts).len(),
        16,
        "start plus fifteen polls, no late poll"
    );
    assert_eq!(wait_receipts(&receipts), vec![60_000; 15]);
    assert!(
        receipts
            .iter()
            .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn retry_after_backoff_waits_are_clamped_to_the_original_deadline() {
    let mut first_429 = ResponseSpec::poll(429);
    first_429.retry_after_ms = Some(90_000);
    let mut second_429 = ResponseSpec::poll(429);
    second_429.retry_after_ms = Some(90_000);
    let plan = Plan {
        clock: VecDeque::from([
            ClockStep::At(1_000),
            ClockStep::At(1_000),
            ClockStep::At(1_000),
            ClockStep::At(1_000),
            ClockStep::Current,
            ClockStep::At(900_000),
        ]),
        responses: VecDeque::from([
            ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
            first_429,
            second_429,
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("retry deadline returns typed timeout");
    assert_eq!(result_code(&result), "timeout");
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert_eq!(wait_receipts(&receipts), vec![60_000, 1_000]);
    assert_eq!(
        request_receipts(&receipts).len(),
        3,
        "no request starts after deadline"
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

fn clock_indices(receipts: &[Receipt]) -> Vec<usize> {
    receipts
        .iter()
        .filter_map(|receipt| match receipt {
            Receipt::Clock(index) => Some(*index),
            _ => None,
        })
        .collect()
}

#[test]
fn bound_clock_rejects_start_overflow_backward_time_and_start_deadline() {
    let cases = [
        (
            vec![ClockStep::At(i64::MAX)],
            Vec::new(),
            "clock_unavailable",
            0usize,
            0usize,
        ),
        (
            vec![ClockStep::At(1_000), ClockStep::At(901_000)],
            vec![ResponseSpec::start(
                json!({"user_code":"SYNTHETIC-CODE-74","interval":1}),
            )],
            "timeout",
            1,
            0,
        ),
        (
            vec![
                ClockStep::At(1_000),
                ClockStep::Current,
                ClockStep::Current,
                ClockStep::Current,
                ClockStep::At(999),
            ],
            vec![
                ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                ResponseSpec::poll(200),
            ],
            "clock_unavailable",
            2,
            1,
        ),
    ];
    for (clock, responses, expected_code, expected_requests, expected_instructions) in cases {
        let plan = Plan {
            clock: VecDeque::from(clock),
            responses: VecDeque::from(responses),
            ..Plan::default()
        };
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.expect("policy clock boundary returns typed result");
        assert_eq!(result_code(&result), expected_code);
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert_eq!(request_receipts(&receipts).len(), expected_requests);
        let indices = clock_indices(&receipts);
        assert_eq!(indices, (0..indices.len()).collect::<Vec<_>>());
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| matches!(receipt, Receipt::Instruction { .. }))
                .count(),
            expected_instructions
        );
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}

#[test]
fn cancellation_at_each_boundary_stops_later_stages_and_still_cleans() {
    let cases = [
        (
            Plan {
                clock: VecDeque::from([ClockStep::Failure("policy_inactive")]),
                ..Plan::default()
            },
            "cancelled_or_inactive",
            0usize,
            0usize,
        ),
        (
            Plan {
                responses: VecDeque::from([
                    ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                    ResponseSpec::poll(403),
                ]),
                wait_failure: Some((0, "policy_inactive")),
                ..Plan::default()
            },
            "cancelled_or_inactive",
            2,
            1,
        ),
        (
            Plan {
                responses: VecDeque::from([
                    ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                    ResponseSpec::poll(200),
                ]),
                clock: VecDeque::from([
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Failure("policy_inactive"),
                ]),
                ..Plan::default()
            },
            "cancelled_or_inactive",
            2,
            0,
        ),
        (
            Plan {
                responses: VecDeque::from([
                    ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                    ResponseSpec::poll(200),
                    ResponseSpec::exchange(json!({"expires_in":3600}), false),
                ]),
                clock: VecDeque::from([
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Current,
                    ClockStep::Failure("policy_inactive"),
                ]),
                ..Plan::default()
            },
            "cancelled_or_inactive",
            3,
            0,
        ),
        (
            Plan {
                responses: VecDeque::from([
                    ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                    ResponseSpec::poll(403),
                ]),
                wait_failure: Some((0, "wait_deadline_exceeded")),
                ..Plan::default()
            },
            "deadline_or_inactive",
            2,
            1,
        ),
    ];
    for (plan, expected_code, expected_requests, expected_waits) in cases {
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.expect("cancelled stage returns typed result");
        assert_eq!(result_code(&result), expected_code);
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert_eq!(request_receipts(&receipts).len(), expected_requests);
        assert_eq!(wait_receipts(&receipts).len(), expected_waits);
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
        );
        assert!(
            text(field(&result, "message")).contains("cancelled")
                || expected_code == "deadline_or_inactive"
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}

#[test]
fn pending_poll_rejects_other_status_and_incomplete_or_forbidden_resources() {
    let mut missing_code = ResponseSpec::poll(200);
    missing_code.code = false;
    let mut missing_verifier = ResponseSpec::poll(200);
    missing_verifier.verifier = false;
    let mut access_at_poll = ResponseSpec::poll(200);
    access_at_poll.access = true;
    let mut device_at_poll = ResponseSpec::poll(200);
    device_at_poll.device = true;
    let mut failed_transport = ResponseSpec::poll(200);
    failed_transport.failure = Some("transport_error");
    let cases = [
        (ResponseSpec::poll(500), "poll_rejected"),
        (missing_code, "invalid_poll_response"),
        (missing_verifier, "invalid_poll_response"),
        (access_at_poll, "invalid_poll_response"),
        (device_at_poll, "invalid_poll_response"),
        (failed_transport, "poll_transport_failed"),
    ];
    for (poll, expected_code) in cases {
        let plan = Plan {
            responses: VecDeque::from([
                ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                poll,
            ]),
            ..Plan::default()
        };
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.unwrap_or_else(|error| panic!("case {expected_code}: {error:?}"));
        assert_eq!(result_code(&result), expected_code);
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert_eq!(request_receipts(&receipts).len(), 2);
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}

#[test]
fn exchange_is_one_shot_and_rejects_failures_missing_access_and_bad_tokens() {
    let mut transport_failure = ResponseSpec::exchange(json!({"expires_in":3600}), false);
    transport_failure.failure = Some("transport_error");
    let mut rejected = ResponseSpec::exchange(json!({"expires_in":3600}), true);
    rejected.status = 429;
    let mut missing_access = ResponseSpec::exchange(json!({"expires_in":3600}), false);
    missing_access.access = false;
    let cases = [
        (transport_failure, "exchange_transport_failed"),
        (rejected, "exchange_rejected"),
        (missing_access, "invalid_token_response"),
        (
            ResponseSpec::exchange(json!({"token_type":"Bearer"}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":0}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":-1}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":"3600"}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":1.5}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":3600,"token_type":"Basic"}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":3600,"token_type":true}), false),
            "invalid_token_response",
        ),
        (
            ResponseSpec::exchange(json!({"expires_in":i64::MAX}), false),
            "invalid_token_response",
        ),
    ];
    for (exchange, expected_code) in cases {
        let plan = Plan {
            responses: VecDeque::from([
                ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
                ResponseSpec::poll(200),
                exchange,
            ]),
            ..Plan::default()
        };
        let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
        let result = result.expect("exchange outcome remains guest-readable");
        assert_eq!(result_code(&result), expected_code);
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        let requests = request_receipts(&receipts);
        assert_eq!(requests.len(), 3, "exchange is never retried");
        assert_eq!(requests[2].1, "/oauth/token");
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
        );
        let public = format!("{result:?}{receipts:?}");
        for marker in [
            DEVICE_PRIVATE,
            CODE_PRIVATE,
            VERIFIER_PRIVATE,
            ACCESS_PRIVATE,
            REFRESH_PRIVATE,
        ] {
            assert!(
                !public.contains(marker),
                "private exchange material is not rendered"
            );
        }
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}

#[test]
fn refresh_absent_clears_and_save_rejection_stays_static() {
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(happy_plan(false));
    let result = result.expect("login without refresh succeeds");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let envelope = field(&result, "metadata");
    assert!(
        optional_field(envelope, "metadata").is_some(),
        "refresh-absent metadata envelope: {envelope:?}"
    );
    assert_eq!(
        field(field(envelope, "metadata"), "has_refresh_token"),
        &Value::Bool(false)
    );
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert!(receipts.iter().any(|receipt| matches!(
        receipt,
        Receipt::Save { refresh_action, has_refresh_slot: false }
            if refresh_action == "clear"
    )));
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);

    let mut plan = happy_plan(true);
    plan.save_failure = Some("save_rejected");
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(plan);
    let result = result.expect("save rejection is a typed login result");
    assert_eq!(result_code(&result), "save_failed");
    assert!(optional_field(&result, "metadata").is_none_or(|value| matches!(value, Value::Null)));
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert_eq!(request_receipts(&receipts).len(), 3);
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt, Receipt::Save { .. }))
            .count(),
        1
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn expiry_addition_is_checked_at_the_integer_boundary() {
    let max = i64::MAX;
    let initial = max - 900_000;
    let boundary_plan = Plan {
        clock: VecDeque::from([ClockStep::At(initial)]),
        responses: VecDeque::from([
            ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":900}), false),
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(boundary_plan);
    let result = result.expect("representable expiry reaches save");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    let saved = field(field(&result, "metadata"), "metadata");
    assert_eq!(field(saved, "expires_at_ms"), &Value::Int(max));
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);

    let overflow_plan = Plan {
        clock: VecDeque::from([ClockStep::At(initial)]),
        responses: VecDeque::from([
            ResponseSpec::start(json!({"user_code":"SYNTHETIC-CODE-74","interval":1})),
            ResponseSpec::poll(200),
            ResponseSpec::exchange(json!({"expires_in":901}), false),
        ]),
        ..Plan::default()
    };
    let (mut vm, state, _, unrelated, secondary, result) = run_plan(overflow_plan);
    let result = result.expect("expiry overflow is invalid token response");
    assert_eq!(result_code(&result), "invalid_token_response");
    let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
    assert!(
        receipts
            .iter()
            .all(|receipt| !matches!(receipt, Receipt::Save { .. }))
    );
    assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
}

#[test]
fn invalid_public_request_stops_before_network_and_still_cleans() {
    let cases = [
        (
            provider_with("another-credential", "codex-device"),
            CREDENTIAL_ID,
            0,
            "invalid_provider_config",
        ),
        (provider(), CREDENTIAL_ID, -1, "invalid_provider_config"),
        (
            provider_with(CREDENTIAL_ID, "authorization-code"),
            CREDENTIAL_ID,
            0,
            "invalid_provider_config",
        ),
    ];
    for (request_provider, credential_id, generation, expected_code) in cases {
        let (mut vm, state, policy, unrelated, secondary) = scripted_vm(Plan::default());
        let result = login_with(
            &mut vm,
            &policy,
            request_provider,
            credential_id,
            generation,
        )
        .expect("invalid public input returns typed result");
        assert_eq!(result_code(&result), expected_code);
        let receipts = state.0.lock().expect("scripted receipts").receipts.clone();
        assert!(request_receipts(&receipts).is_empty());
        assert!(
            receipts
                .iter()
                .all(|receipt| !matches!(receipt, Receipt::Instruction { .. }))
        );
        assert_terminal_resources(&mut vm, &state, unrelated, &secondary);
    }
}
