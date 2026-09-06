//! Stage A config host catalog: `config::load_snapshot` and the fixture
//! `config::check_policy` probe. Trusted policy stays host-side.

use rustscript_vm::{
    CallOutcome, CallReturn, HostApiBuilder, HostApiCatalog, HostFunctionRegistry,
    HostFunctionSchema, HostParamSchema, HostTypeSchema, Value, Vm, VmResult,
    catalog_import_schemas,
};
use serde_json::{Value as JsonValue, json};

use crate::config_file::{
    ConfigFileError, OpaquePolicyHandle, PolicyIntent, check_policy, load_snapshot,
};
use crate::domain::{json_to_vm_value, vm_value_to_json};

pub const CONFIG_LOAD_SNAPSHOT: &str = "config::load_snapshot";
pub const CONFIG_CHECK_POLICY: &str = "config::check_policy";

pub fn register_catalog_functions(builder: &mut HostApiBuilder, response: HostTypeSchema) {
    builder.function(HostFunctionSchema::with_return(
        CONFIG_LOAD_SNAPSHOT,
        vec![HostParamSchema::value("host_home", HostTypeSchema::String)],
        response.clone(),
    ));
    builder.function(HostFunctionSchema::with_return(
        CONFIG_CHECK_POLICY,
        vec![
            HostParamSchema::value("policy_handle", HostTypeSchema::Unknown),
            HostParamSchema::value("intent", HostTypeSchema::Unknown),
        ],
        response,
    ));
}

pub fn register_host_functions(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
) -> VmResult<()> {
    register_named(
        registry,
        catalog,
        CONFIG_LOAD_SNAPSHOT,
        1,
        load_snapshot_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CONFIG_CHECK_POLICY,
        2,
        check_policy_adapter,
    )?;
    Ok(())
}

fn register_named(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
    name: &str,
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

fn load_snapshot_adapter(_vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let host_home = match args.first() {
        Some(Value::String(value)) => value.to_string(),
        _ => {
            return return_json(error_envelope(&ConfigFileError::HomeInvalid {
                reason: "host_home must be a string".to_string(),
            }));
        }
    };
    match load_snapshot(&host_home) {
        Ok(snapshot) => return_json(snapshot_envelope(&snapshot)),
        Err(error) => return_json(error_envelope(&error)),
    }
}

fn check_policy_adapter(_vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let handle = match parse_handle(args.first()) {
        Ok(handle) => handle,
        Err(error) => return return_json(error_envelope(&error)),
    };
    let intent = parse_intent(args.get(1));
    match check_policy(&handle, &intent) {
        Ok(_) => return_json(json!({ "ok": true })),
        Err(error) => return_json(error_envelope(&error)),
    }
}

fn parse_handle(value: Option<&Value>) -> Result<OpaquePolicyHandle, ConfigFileError> {
    let json = value.map(vm_value_to_json).unwrap_or(JsonValue::Null);
    let class = json.get("class").and_then(JsonValue::as_str);
    let id = json.get("id").and_then(JsonValue::as_str);
    if class != Some("OpaquePolicyHandle") {
        return Err(ConfigFileError::PolicyHandleInvalid);
    }
    let id = id.ok_or(ConfigFileError::PolicyHandleInvalid)?;
    Ok(OpaquePolicyHandle::from_id(id))
}

fn parse_intent(value: Option<&Value>) -> PolicyIntent {
    let json = value.map(vm_value_to_json).unwrap_or(JsonValue::Null);
    PolicyIntent {
        op: json
            .get("op")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        path: json
            .get("path")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        write: json
            .get("write")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        name: json
            .get("name")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        policy_generation: json.get("policy_generation").and_then(JsonValue::as_u64),
    }
}

fn snapshot_envelope(snapshot: &crate::config_file::ConfigSnapshotEnvelope) -> JsonValue {
    let public_config = serde_json::to_value(&snapshot.public_config).unwrap_or(JsonValue::Null);
    let credential_refs = JsonValue::Array(
        snapshot
            .credential_refs
            .iter()
            .map(|id| json!({ "id": id }))
            .collect(),
    );
    let summary = serde_json::to_value(&snapshot.policy_summary).unwrap_or(JsonValue::Null);
    json!({
        "ok": true,
        "public_config": public_config,
        "credential_refs": credential_refs,
        "policy_handle": {
            "class": snapshot.policy_handle.class(),
            "id": snapshot.policy_handle.id(),
        },
        "policy_generation": snapshot.policy_generation,
        "policy_summary": summary,
    })
}

fn error_envelope(error: &ConfigFileError) -> JsonValue {
    let mut error_object = json!({
        "code": error.code(),
        "message": error.to_string(),
    });
    if let Some(path) = error.path() {
        error_object["path"] = JsonValue::String(path);
    }
    json!({
        "ok": false,
        "error": error_object,
    })
}

fn return_json(value: JsonValue) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(json_to_vm_value(
        &value,
    ))))
}
