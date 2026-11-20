//! Stage A config/auth fixture host.
//!
//! `config::load_snapshot` / `config::check_policy` are **not** production agent
//! host functions. They exist only on [`config_fixture_catalog`] and are bound
//! by [`ConfigFixtureHost`], which injects a host-native `HostHome` before RSS
//! runs. RSS cannot supply or override the home path.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustscript_vm::resource::{CloseProgress, HostResource, ResourceCloseReason, ResourceResult};
use rustscript_vm::{
    CallOutcome, CallReturn, CompileSourceFileOptions, HostApiCatalog, HostFunctionDescriptor,
    HostFunctionRegistry, HostFunctionSchema, HostModuleDescriptor, HostParamSchema,
    HostResourceType, HostResourceTypeMeta, HostStructField, HostTypeSchema, Program,
    ResourceTypeKey, SourceFlavor, Value, Vm, VmResult, VmStatus,
    compile_source_at_path_with_flavor_and_options,
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
const POLICY_RESOURCE_KEY: &str = "config_fixture.policy_handle";
const FIXTURE_RUN_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
struct BoundHostHome {
    path: PathBuf,
}

struct FixturePolicyResource {
    handle: Option<OpaquePolicyHandle>,
}

impl HostResource for FixturePolicyResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(POLICY_RESOURCE_KEY).expect("static policy key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for FixturePolicyResource {
    const KEY: &'static str = POLICY_RESOURCE_KEY;
    const DESCRIPTION: &'static str = "Fixture policy handle bound to its native owner";
}

fn policy_resource_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<FixturePolicyResource>()
}

fn policy_resource() -> HostTypeSchema {
    HostTypeSchema::Resource(ResourceTypeKey::new(POLICY_RESOURCE_KEY).expect("static policy key"))
}

fn named(name: &str, fields: Vec<(&str, HostTypeSchema)>) -> HostTypeSchema {
    HostTypeSchema::named_struct(
        name,
        fields
            .into_iter()
            .map(|(name, ty)| HostStructField::new(name, ty))
            .collect(),
    )
}

fn error_type() -> HostTypeSchema {
    named(
        "ConfigFixtureError",
        vec![
            ("code", HostTypeSchema::String),
            ("message", HostTypeSchema::String),
            ("path", HostTypeSchema::String),
        ],
    )
}

fn snapshot_type() -> HostTypeSchema {
    named(
        "ConfigSnapshotEnvelope",
        vec![
            ("ok", HostTypeSchema::Bool),
            ("error", error_type()),
            (
                "public_config",
                named(
                    "FixturePublicConfig",
                    vec![
                        (
                            "model",
                            named(
                                "FixtureModel",
                                vec![
                                    ("provider", HostTypeSchema::String),
                                    ("model", HostTypeSchema::String),
                                ],
                            ),
                        ),
                        (
                            "agent",
                            named("FixtureAgent", vec![("source", HostTypeSchema::String)]),
                        ),
                    ],
                ),
            ),
            (
                "credential_refs",
                HostTypeSchema::Array(Box::new(HostTypeSchema::String)),
            ),
            (
                "policy_summary",
                named(
                    "FixturePolicySummary",
                    vec![
                        (
                            "providers",
                            HostTypeSchema::Array(Box::new(HostTypeSchema::String)),
                        ),
                        ("policy_generation", HostTypeSchema::Int),
                    ],
                ),
            ),
            ("policy_handle", policy_resource()),
            ("policy_handle_class", HostTypeSchema::String),
            ("policy_generation", HostTypeSchema::Int),
        ],
    )
}

fn probe_type() -> HostTypeSchema {
    named(
        "ConfigPolicyProbe",
        vec![("ok", HostTypeSchema::Bool), ("error", error_type())],
    )
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
        crate::runtime::host_compose::compose_with_standard(&[config_fixture_module()])
    }))
}

const CONFIG_FIXTURE_FUNCTIONS: &[fn() -> HostFunctionDescriptor] = &[
    config_load_snapshot_descriptor,
    config_check_policy_descriptor,
];

pub fn config_fixture_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "config_fixture",
        functions: CONFIG_FIXTURE_FUNCTIONS,
        resources: &[policy_resource_meta],
    }
}

fn stack_desc(
    name: &'static str,
    params: Vec<HostParamSchema>,
    output: HostTypeSchema,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> HostFunctionDescriptor {
    let schema = HostFunctionSchema::with_return(name, params, output);
    let effects = rustscript_vm::vm::host_extension::guest_resource_effects(&schema);
    let mut descriptor = crate::runtime::host_compose::static_stack_descriptor(schema, adapter);
    descriptor.effects = effects;
    descriptor
}

fn config_load_snapshot_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CONFIG_LOAD_SNAPSHOT,
        vec![HostParamSchema::value("host_home", HostTypeSchema::Unknown)],
        snapshot_type(),
        load_snapshot_adapter,
    )
}

fn config_check_policy_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CONFIG_CHECK_POLICY,
        vec![
            HostParamSchema::value("policy_handle", HostTypeSchema::Unknown),
            HostParamSchema::value("intent", HostTypeSchema::Unknown),
        ],
        probe_type(),
        check_policy_adapter,
    )
}

pub(crate) fn register_host_functions(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
) -> VmResult<()> {
    config_fixture_module().install_from_catalog(registry, catalog)?;
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
        let mut vm = Vm::new_shared(program);
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
                crate::runtime::host_wait::wait_for_host_op_blocking_with_cancel(vm, || false)
                    .map_err(|error| error.to_string())?;
            }
            Ok(VmStatus::Yielded) => {
                return Err("config fixture root frame yielded unexpectedly".to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn load_snapshot_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let (bound_home, policies) = {
        let context = vm.host_context();
        match context.module_state::<ConfigFixtureState>() {
            Some(state) => (state.home.clone(), Arc::clone(&state.policies)),
            None => {
                return snapshot_error(
                    vm,
                    &ConfigFileError::HomeInvalid {
                        reason: "config fixture host home is not bound".to_string(),
                        path: None,
                    },
                );
            }
        }
    };
    if matches!(args.first(), Some(Value::String(_))) {
        return snapshot_error(
            vm,
            &ConfigFileError::HomeInvalid {
                reason: "RSS cannot supply or override host_home".to_string(),
                path: Some(bound_home),
            },
        );
    }
    let Some(bound) = args
        .first()
        .and_then(|value| policies.opaques().from_vm_value(value))
        .filter(|value| value.class() == HOST_HOME_CLASS)
        .and_then(|value| value.downcast_arc::<BoundHostHome>())
        .map(|home| (*home).clone())
    else {
        return snapshot_error(
            vm,
            &ConfigFileError::HomeInvalid {
                reason: "host_home must be the host-bound HostHome".to_string(),
                path: Some(bound_home),
            },
        );
    };
    if bound.path != bound_home {
        return snapshot_error(
            vm,
            &ConfigFileError::HomeInvalid {
                reason: "host_home does not match the bound home".to_string(),
                path: Some(bound_home),
            },
        );
    }
    match policies.load_snapshot(&bound_home) {
        Ok(snapshot) => snapshot_to_vm_value(vm, &snapshot).and_then(return_value),
        Err(error) => snapshot_error(vm, &error),
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
    let handle = args.first().and_then(|value| {
        let Value::Int(raw) = value else {
            return None;
        };
        let raw = u64::try_from(*raw).ok()?;
        let token = rustscript_vm::resource::ResourceHandle::from_raw(raw).ok()?;
        let context = vm.host_context();
        context
            .borrow_resource_with_key::<FixturePolicyResource>(
                token,
                &ResourceTypeKey::new(POLICY_RESOURCE_KEY).expect("static policy key"),
            )
            .ok()?
            .handle
            .clone()
    });
    let Some(handle) = handle else {
        return return_json(error_envelope(&ConfigFileError::PolicyHandleInvalid));
    };
    let intent = parse_intent(args.get(1));
    match policies.check_policy(&handle, &intent) {
        Ok(probe) => return_json(
            json!({ "ok": probe.ok, "error": { "code": "", "message": "", "path": "" } }),
        ),
        Err(error) => return_json(error_envelope(&error)),
    }
}

fn issue_policy_resource(vm: &mut Vm, handle: Option<OpaquePolicyHandle>) -> VmResult<Value> {
    let resource = vm
        .host_context()
        .push_resource(FixturePolicyResource { handle })
        .map_err(|error| rustscript_vm::VmError::HostError(error.to_string()))?;
    Ok(Value::Int(resource.handle().raw() as i64))
}

fn snapshot_error(vm: &mut Vm, error: &ConfigFileError) -> VmResult<CallOutcome> {
    let policy_handle = issue_policy_resource(vm, None)?;
    let mut fields = vec![
        (
            Value::string("public_config"),
            json_to_vm_value(&json!({
                "model": { "provider": "", "model": "" },
                "agent": { "source": "" }
            })),
        ),
        (Value::string("credential_refs"), Value::array(vec![])),
        (
            Value::string("policy_summary"),
            json_to_vm_value(&json!({ "providers": [], "policy_generation": 0 })),
        ),
        (Value::string("policy_handle"), policy_handle),
        (
            Value::string("policy_handle_class"),
            Value::string("OpaquePolicyHandle"),
        ),
        (Value::string("policy_generation"), Value::Int(0)),
    ];
    let envelope = json_to_vm_value(&error_envelope(error));
    if let Value::Map(values) = envelope {
        fields.extend(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    return_value(Value::map(fields))
}

fn snapshot_to_vm_value(vm: &mut Vm, snapshot: &ConfigSnapshotEnvelope) -> VmResult<Value> {
    let handle = issue_policy_resource(vm, Some(snapshot.policy_handle.clone()))?;
    Ok(Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (
            Value::string("error"),
            json_to_vm_value(&json!({ "code": "", "message": "", "path": "" })),
        ),
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
        (Value::string("policy_handle"), handle),
        (
            Value::string("policy_handle_class"),
            Value::string(snapshot.policy_handle.class()),
        ),
        (
            Value::string("policy_generation"),
            Value::Int(i64::try_from(snapshot.policy_generation).unwrap_or(i64::MAX)),
        ),
    ]))
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
            "path": error.path().unwrap_or_default(),
        }
    })
}

fn return_json(value: JsonValue) -> VmResult<CallOutcome> {
    return_value(json_to_vm_value(&value))
}

fn return_value(value: Value) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(value)))
}
