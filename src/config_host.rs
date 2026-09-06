//! Stage A config/auth fixture host.
//!
//! `config::load_snapshot` / `config::check_policy` are **not** production agent
//! host functions. They exist only on [`config_fixture_catalog`] and are bound
//! by [`ConfigFixtureHost`], which injects a host-native `HostHome` before RSS
//! runs. RSS cannot supply or override the home path.

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

use crate::config_file::{
    ConfigFileError, ConfigSnapshotEnvelope, OpaquePolicyHandle, PolicyIntent, PolicyOwner,
    PolicyProbe,
};
use crate::domain::{json_to_vm_value, vm_value_to_json};
use crate::host_opaque::{OpaqueError, OpaqueRegistry};

const CONFIG_LOAD_SNAPSHOT: &str = "config::load_snapshot";
const CONFIG_CHECK_POLICY: &str = "config::check_policy";
const HOST_HOME_CLASS: &str = "HostHome";
const FIXTURE_RUN_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
struct BoundHostHome {
    path: PathBuf,
}

#[derive(Clone)]
struct ConfigFixtureState {
    home: PathBuf,
    policies: Arc<PolicyOwner>,
}

/// Test-only catalog that exposes the Stage A config bridge.
pub fn config_fixture_catalog() -> Arc<HostApiCatalog> {
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
        Arc::new(builder.build().expect("config fixture catalog must build"))
    }))
}

pub(crate) fn register_catalog_functions(builder: &mut HostApiBuilder, response: HostTypeSchema) {
    builder.function(HostFunctionSchema::with_return(
        CONFIG_LOAD_SNAPSHOT,
        vec![HostParamSchema::value("host_home", HostTypeSchema::Unknown)],
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

pub(crate) fn register_host_functions(
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

/// Compiles `rss/auth/config_entry.rss` against the fixture catalog and runs
/// it with a host-bound home. Production [`crate::AgentRunner`] never sees this
/// surface.
pub struct ConfigFixtureHost {
    home: PathBuf,
    opaques: Arc<OpaqueRegistry>,
    policies: Arc<PolicyOwner>,
}

impl ConfigFixtureHost {
    pub fn bind(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let opaques = OpaqueRegistry::new();
        let policies =
            PolicyOwner::new(Arc::clone(&opaques), Instant::now() + FIXTURE_RUN_DEADLINE);
        Self {
            home,
            opaques,
            policies,
        }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn load_snapshot(&self) -> Result<ConfigSnapshotEnvelope, ConfigFileError> {
        self.policies.load_snapshot(&self.home)
    }

    pub fn check_policy(
        &self,
        handle: &OpaquePolicyHandle,
        intent: &PolicyIntent,
    ) -> Result<PolicyProbe, ConfigFileError> {
        self.policies.check_policy(handle, intent)
    }

    pub fn run(&self, kind: &str) -> Result<Value, String> {
        let program = fixture_program()?;
        let catalog = config_fixture_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        register_host_functions(&mut registry, catalog.as_ref())
            .map_err(|error| error.to_string())?;
        let mut vm = Vm::try_new_shared(program).map_err(|error| error.to_string())?;
        registry
            .bind_vm_cached(&mut vm)
            .map_err(|error| error.to_string())?;
        vm.host_context().set_module_state(ConfigFixtureState {
            home: self.home.clone(),
            policies: Arc::clone(&self.policies),
        });
        drive_root_frame(&mut vm)?;
        let callable = vm
            .resolve_exported_callable("run")
            .map_err(|_| "config fixture entry `run` is missing".to_string())?;
        let host_home = self
            .opaques
            .mint(
                HOST_HOME_CLASS,
                BoundHostHome {
                    path: self.home.clone(),
                },
            )
            .map_err(|error| match error {
                OpaqueError::LiveHandleLimit => "opaque live handle limit reached".to_string(),
                OpaqueError::PrototypeIdSpaceExhausted => {
                    "opaque prototype id space exhausted".to_string()
                }
            })?
            .to_vm_value();
        let context = Value::map(vec![
            (Value::string("kind"), Value::string(kind)),
            (Value::string("host_home"), host_home),
        ]);
        vm.invoke_callable(callable, &[context])
            .map_err(|error| error.to_string())
    }
}

impl Drop for ConfigFixtureHost {
    fn drop(&mut self) {
        self.policies.clear();
        self.opaques.clear();
    }
}

fn fixture_program() -> Result<Arc<Program>, String> {
    static PROGRAM: OnceLock<Result<Arc<Program>, String>> = OnceLock::new();
    match PROGRAM.get_or_init(|| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/config_entry.rss");
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => return Err(error.to_string()),
        };
        let options =
            CompileSourceFileOptions::default().with_host_api_catalog(config_fixture_catalog());
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
            Ok(VmStatus::Waiting(_)) => {
                vm.wait_for_host_op_blocking_with_cancel(|| false)
                    .map_err(|error| error.to_string())?;
            }
            Ok(VmStatus::Yielded) => {
                return Err("config fixture root frame yielded unexpectedly".to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
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

fn load_snapshot_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let (bound_home, policies) = {
        let context = vm.host_context();
        match context.module_state::<ConfigFixtureState>() {
            Some(state) => (state.home.clone(), Arc::clone(&state.policies)),
            None => {
                return return_json(error_envelope(&ConfigFileError::HomeInvalid {
                    reason: "config fixture host home is not bound".to_string(),
                    path: None,
                }));
            }
        }
    };
    if matches!(args.first(), Some(Value::String(_))) {
        return return_json(error_envelope(&ConfigFileError::HomeInvalid {
            reason: "RSS cannot supply or override host_home".to_string(),
            path: Some(bound_home),
        }));
    }
    let Some(bound) = args
        .first()
        .and_then(|value| policies.opaques().from_vm_value(value))
        .filter(|value| value.class() == HOST_HOME_CLASS)
        .and_then(|value| value.downcast_arc::<BoundHostHome>())
        .map(|home| (*home).clone())
    else {
        return return_json(error_envelope(&ConfigFileError::HomeInvalid {
            reason: "host_home must be the host-bound HostHome".to_string(),
            path: Some(bound_home),
        }));
    };
    if bound.path != bound_home {
        return return_json(error_envelope(&ConfigFileError::HomeInvalid {
            reason: "host_home does not match the bound home".to_string(),
            path: Some(bound_home),
        }));
    }
    match policies.load_snapshot(&bound_home) {
        Ok(snapshot) => return_value(snapshot_to_vm_value(&snapshot)),
        Err(error) => return_json(error_envelope(&error)),
    }
}

fn check_policy_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let policies = {
        let context = vm.host_context();
        match context.module_state::<ConfigFixtureState>() {
            Some(state) => Arc::clone(&state.policies),
            None => {
                return return_json(error_envelope(&ConfigFileError::PolicyHandleInvalid));
            }
        }
    };
    let handle = match args
        .first()
        .and_then(|value| OpaquePolicyHandle::from_vm_value(policies.opaques(), value))
    {
        Some(handle) => handle,
        None => {
            return return_json(error_envelope(&ConfigFileError::PolicyHandleInvalid));
        }
    };
    let intent = parse_intent(args.get(1));
    match policies.check_policy(&handle, &intent) {
        Ok(probe) => return_json(json!({ "ok": probe.ok })),
        Err(error) => return_json(error_envelope(&error)),
    }
}

fn snapshot_to_vm_value(snapshot: &ConfigSnapshotEnvelope) -> Value {
    Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (
            Value::string("public_config"),
            json_to_vm_value(&json!(snapshot.public_config)),
        ),
        (
            Value::string("credential_refs"),
            json_to_vm_value(&json!(snapshot.credential_refs)),
        ),
        (
            Value::string("policy_summary"),
            json_to_vm_value(&json!(snapshot.policy_summary)),
        ),
        (
            Value::string("policy_handle"),
            snapshot.policy_handle.to_vm_value(),
        ),
        (
            Value::string("policy_handle_class"),
            Value::string(snapshot.policy_handle.class()),
        ),
        (
            Value::string("policy_generation"),
            Value::Int(i64::try_from(snapshot.policy_generation).unwrap_or(i64::MAX)),
        ),
    ])
}

fn parse_intent(value: Option<&Value>) -> PolicyIntent {
    let JsonValue::Object(fields) = value.map(vm_value_to_json).unwrap_or(JsonValue::Null) else {
        return PolicyIntent::default();
    };
    PolicyIntent {
        op: fields
            .get("op")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string(),
        path: fields
            .get("path")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        write: fields
            .get("write")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        name: fields
            .get("name")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        policy_generation: fields.get("policy_generation").and_then(JsonValue::as_u64),
    }
}

fn error_envelope(error: &ConfigFileError) -> JsonValue {
    json!({
        "ok": false,
        "error": {
            "code": error.code(),
            "message": error.to_string(),
            "path": error.path(),
        }
    })
}

fn return_json(value: JsonValue) -> VmResult<CallOutcome> {
    return_value(json_to_vm_value(&value))
}

fn return_value(value: Value) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(value)))
}
