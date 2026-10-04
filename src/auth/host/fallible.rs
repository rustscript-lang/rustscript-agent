use rustscript_vm::{
    CallOutcome, CallReturn, HostFunctionDescriptor, HostResourceType, HostTypeSchema, Value, Vm,
    VmError, VmResult,
};
use std::time::Instant;

use super::{
    Owner, borrow, desc, error, field, key, named, object, opt, policy_owner_for_cleanup, result,
};

const STATIC_ERROR_CODES: &[&str] = &[
    "access_unavailable",
    "already_bound",
    "authority_denied",
    "backend_unavailable",
    "callback_cancelled",
    "callback_result_invalid",
    "callback_timeout",
    "callback_unavailable",
    "cancelled",
    "capture_intent_invalid",
    "clock_unavailable",
    "config_invalid",
    "corrupt_file",
    "credential_not_admitted",
    "credential_not_found",
    "credential_unavailable",
    "credential_use_unsupported",
    "deadline_exceeded",
    "delete_rejected",
    "device_session_invalid",
    "file_too_large",
    "finite_deadline_required",
    "generation_conflict",
    "generation_overflow",
    "handle_expired",
    "handle_invalid",
    "handle_provenance",
    "handle_replayed",
    "handle_revoked",
    "header_denied",
    "host_unbound",
    "insecure_permissions",
    "invalid_credential",
    "invalid_credential_id",
    "invalid_generation",
    "invalid_headers",
    "invalid_intent",
    "invalid_metadata",
    "invalid_path",
    "invalid_request",
    "io_error",
    "lock_error",
    "malformed_response",
    "metadata_invalid",
    "method_denied",
    "mutation_inactive",
    "non_regular_file",
    "oauth_callback_mode_unsupported",
    "oauth_flow_unsupported",
    "oauth_intent_invalid",
    "oauth_intent_too_large",
    "oauth_path_denied",
    "oauth_unavailable",
    "owner_mismatch",
    "path_denied",
    "payload_intent_invalid",
    "pkce_entropy",
    "pkce_invalid_verifier",
    "policy_inactive",
    "public_json_invalid",
    "public_json_number_out_of_range",
    "public_json_pointer_invalid",
    "public_json_too_deep",
    "public_json_too_large",
    "refresh_action_invalid",
    "refresh_unavailable",
    "request_too_large",
    "resource_invalid",
    "resource_limit",
    "resource_unavailable",
    "response_handle_unsupported",
    "response_too_large",
    "save_rejected",
    "secret_slot_expired",
    "secret_slot_invalid",
    "secret_slot_provenance",
    "secret_slot_replayed",
    "serialization_error",
    "slot_close_failed",
    "slot_invalid",
    "slot_owner_mismatch",
    "slot_provenance_invalid",
    "state_mismatch",
    "symlink_rejected",
    "transport_endpoint_ambiguous",
    "transport_endpoint_invalid",
    "transport_endpoint_unavailable",
    "transport_error",
    "transport_unavailable",
    "ui_instruction_invalid",
    "ui_sink_closed",
    "ui_sink_full",
    "ui_unavailable",
    "wait_deadline_exceeded",
    "wait_out_of_range",
];

pub(super) fn failure_type() -> HostTypeSchema {
    named(
        "AuthBridgeFailure",
        vec![
            ("code", HostTypeSchema::String),
            ("cancelled", HostTypeSchema::Bool),
            ("deadline_exceeded", HostTypeSchema::Bool),
            ("revoked", HostTypeSchema::Bool),
        ],
    )
}

pub(super) fn result_type(name: &str, value_type: HostTypeSchema) -> HostTypeSchema {
    named(
        name,
        vec![
            ("ok", HostTypeSchema::Bool),
            ("error", opt(failure_type())),
            ("value", opt(value_type)),
        ],
    )
}

pub(super) fn transport_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::transport_result",
        vec![
            borrow("request", super::transport_request_type()),
            borrow("credential_use", super::transport_use_type()),
        ],
        result_type("TransportResultEnvelope", super::transport_response_type()),
        transport_result_call,
    )
}

fn transport_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().ok_or_else(|| error("invalid_request"))?;
    let policy = field(request, "policy_handle")?;
    let owner = policy_owner_for_cleanup(vm, policy)?;
    let outcome = super::transport_call(vm, args);
    wrap_value(owner, outcome)
}

pub(super) fn transport_payload_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::transport_payload_result",
        vec![
            borrow("request", super::transport_request_type()),
            borrow("credential_use", super::transport_use_type()),
            super::param("payload", super::payload::intent_type()),
        ],
        result_type("TransportResultEnvelope", super::transport_response_type()),
        transport_payload_result_call,
    )
}

fn transport_payload_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = request_owner(vm, args)?;
    let outcome = super::transport_payload_call(vm, args);
    wrap_value(owner, outcome)
}

pub(super) fn transport_capture_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::transport_capture_result",
        vec![
            borrow("request", super::transport_request_type()),
            borrow("credential_use", super::transport_use_type()),
            super::param("payload", super::payload::intent_type()),
            super::param("capture", super::capture::intent_type()),
        ],
        result_type(
            "TransportCaptureResultEnvelope",
            super::capture::envelope_type(),
        ),
        transport_capture_result_call,
    )
}

fn transport_capture_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = request_owner(vm, args)?;
    let outcome = super::transport_capture_call(vm, args);
    wrap_value(owner, outcome)
}

pub(super) fn save_if_generation_result_desc() -> HostFunctionDescriptor {
    desc(
        "auth::save_if_generation_result",
        vec![borrow("request", super::save_type())],
        result_type("AuthSaveResultEnvelope", super::metadata_envelope()),
        save_if_generation_result_call,
    )
}

pub(super) fn load_metadata_result_desc() -> HostFunctionDescriptor {
    desc(
        "auth::load_metadata_result",
        vec![
            super::param("credential_id", HostTypeSchema::String),
            borrow("policy_handle", key(super::Policy::KEY)),
        ],
        result_type("AuthMetadataResultEnvelope", super::metadata_envelope()),
        load_metadata_result_call,
    )
}

fn load_metadata_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let policy = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let owner = policy_owner_for_cleanup(vm, policy)?;
    let outcome = super::metadata_result_call(vm, args);
    wrap_value(owner, outcome)
}

pub(super) fn delete_result_desc() -> HostFunctionDescriptor {
    desc(
        "auth::delete_result",
        vec![
            super::param("credential_id", HostTypeSchema::String),
            borrow("policy_handle", key(super::Policy::KEY)),
        ],
        result_type("AuthDeleteResultEnvelope", super::mutation_envelope()),
        delete_result_call,
    )
}

fn delete_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let policy = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let owner = policy_owner_for_cleanup(vm, policy)?;
    let outcome = super::delete_call(vm, args);
    wrap_value(owner, outcome)
}

fn save_if_generation_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = request_owner(vm, args)?;
    let outcome = super::save_call(vm, args);
    wrap_value(owner, outcome)
}

pub(super) fn now_ms_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::now_ms_result",
        vec![borrow("policy_handle", key(super::Policy::KEY))],
        result_type("OAuthNowResultEnvelope", HostTypeSchema::Int),
        now_ms_result_call,
    )
}

fn now_ms_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = policy_owner(vm, args)?;
    let outcome = super::timing::now_ms_call(vm, args);
    wrap_value(owner, outcome)
}

pub(super) fn wait_ms_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::wait_ms_result",
        vec![
            borrow("policy_handle", key(super::Policy::KEY)),
            super::param("millis", HostTypeSchema::Int),
        ],
        named(
            "OAuthWaitResultEnvelope",
            vec![("ok", HostTypeSchema::Bool), ("error", opt(failure_type()))],
        ),
        wait_ms_result_call,
    )
}

fn wait_ms_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = policy_owner(vm, args)?;
    let outcome = super::timing::wait_ms_call(vm, args);
    wrap_without_value(owner, outcome)
}

pub(super) fn emit_device_instruction_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::emit_device_instruction_result",
        vec![
            super::param("verification_url", HostTypeSchema::String),
            super::param("user_code", HostTypeSchema::String),
            super::param("expires_in_seconds", HostTypeSchema::Int),
        ],
        named(
            "DeviceInstructionResultEnvelope",
            vec![
                ("ok", HostTypeSchema::Bool),
                ("value", opt(HostTypeSchema::Bool)),
                ("error", opt(failure_type())),
            ],
        ),
        emit_device_instruction_result_call,
    )
}

fn emit_device_instruction_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = match super::bound(vm) {
        Ok(owner) => owner,
        Err(VmError::HostError(code)) => return device_instruction_failure(None, &code),
        Err(failure) => return Err(failure),
    };
    match super::cli_io::emit_device_instruction_call(vm, args, &owner) {
        Ok(CallOutcome::Return(CallReturn::One(Value::Bool(true)))) => result(object(vec![
            ("ok", Value::Bool(true)),
            ("value", Value::Bool(true)),
            ("error", Value::Null),
        ])),
        Ok(_) => Err(VmError::InvalidFrameState(
            "device instruction adapter returned an unexpected outcome",
        )),
        Err(VmError::HostError(code)) => device_instruction_failure(Some(&owner), &code),
        Err(failure) => Err(failure),
    }
}

fn device_instruction_failure(owner: Option<&Owner>, code: &str) -> VmResult<CallOutcome> {
    let failure = owner
        .map(|owner| failure_value(owner, code))
        .unwrap_or_else(|| {
            let code = recognized_code(code);
            object(vec![
                ("code", Value::string(code)),
                ("cancelled", Value::Bool(false)),
                ("deadline_exceeded", Value::Bool(false)),
                ("revoked", Value::Bool(false)),
            ])
        });
    result(object(vec![
        ("ok", Value::Bool(false)),
        ("value", Value::Null),
        ("error", failure),
    ]))
}

pub(super) fn public_json_field_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::public_json_field_result",
        vec![
            borrow("policy_handle", key(super::Policy::KEY)),
            super::param("json_text", HostTypeSchema::String),
            super::param("pointer", HostTypeSchema::String),
        ],
        result_type(
            "PublicJsonFieldResultEnvelope",
            super::public_json::public_json_field_type(),
        ),
        public_json_field_result_call,
    )
}

fn public_json_field_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = policy_owner(vm, args)?;
    let outcome = super::public_json::public_json_field_call(vm, args);
    wrap_value(owner, outcome)
}

fn request_owner(vm: &mut Vm, args: &[Value]) -> VmResult<std::sync::Arc<Owner>> {
    let request = args.first().ok_or_else(|| error("invalid_request"))?;
    let policy = field(request, "policy_handle")?;
    policy_owner_for_cleanup(vm, policy)
}

fn policy_owner(vm: &mut Vm, args: &[Value]) -> VmResult<std::sync::Arc<Owner>> {
    let policy = args.first().ok_or_else(|| error("invalid_request"))?;
    policy_owner_for_cleanup(vm, policy)
}

fn recognized_code(code: &str) -> &'static str {
    STATIC_ERROR_CODES
        .iter()
        .copied()
        .find(|known| *known == code)
        .unwrap_or("host_failure")
}

fn failure_value(owner: &Owner, code: &str) -> Value {
    let code = recognized_code(code);
    object(vec![
        ("code", Value::string(code)),
        (
            "cancelled",
            Value::Bool(
                owner.cancellation.token().is_cancelled()
                    || matches!(code, "cancelled" | "callback_cancelled"),
            ),
        ),
        (
            "deadline_exceeded",
            Value::Bool(
                Instant::now() >= owner.deadline
                    || matches!(code, "deadline_exceeded" | "wait_deadline_exceeded"),
            ),
        ),
        (
            "revoked",
            Value::Bool(
                owner.revoked.load(std::sync::atomic::Ordering::Acquire)
                    || code == "handle_revoked",
            ),
        ),
    ])
}

fn wrap_value(
    owner: std::sync::Arc<Owner>,
    outcome: VmResult<CallOutcome>,
) -> VmResult<CallOutcome> {
    match outcome {
        Ok(CallOutcome::Return(CallReturn::One(value))) => result(object(vec![
            ("ok", Value::Bool(true)),
            ("error", Value::Null),
            ("value", value),
        ])),
        Err(VmError::HostError(code)) => result(object(vec![
            ("ok", Value::Bool(false)),
            ("error", failure_value(&owner, &code)),
            ("value", Value::Null),
        ])),
        Err(failure) => Err(failure),
        Ok(_) => Err(VmError::InvalidFrameState(
            "auth bridge adapter returned an unexpected outcome",
        )),
    }
}

fn wrap_without_value(
    owner: std::sync::Arc<Owner>,
    outcome: VmResult<CallOutcome>,
) -> VmResult<CallOutcome> {
    match outcome {
        Ok(CallOutcome::Return(CallReturn::One(Value::Null))) => result(object(vec![
            ("ok", Value::Bool(true)),
            ("error", Value::Null),
        ])),
        Ok(CallOutcome::Return(CallReturn::One(_))) | Ok(_) => Err(VmError::InvalidFrameState(
            "auth wait adapter returned an unexpected value",
        )),
        Err(VmError::HostError(code)) => result(object(vec![
            ("ok", Value::Bool(false)),
            ("error", failure_value(&owner, &code)),
        ])),
        Err(failure) => Err(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::super::timing::WaitProbe;
    use crate::auth::host::{AuthHost, auth_host_catalog};
    use crate::auth::oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    };
    use crate::runtime::RunCancellation;
    use crate::runtime::cancellation::CancellationReason;
    use rustscript_vm::resource::ResourceCloseReason;
    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmError, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    struct TempHome(PathBuf);

    impl TempHome {
        fn new(label: &str) -> Self {
            let base =
                PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
            let path = base.join(format!(
                "fallible-wait-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("create private auth home");
            let fixtures =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
            let source = fs::read_to_string(fixtures.join("config.yaml"))
                .expect("read config fixture")
                .replace("auth.openai.com", "auth.example.test");
            fs::write(path.join("config.yaml"), source).expect("write .test config");
            let auth = fs::read_to_string(fixtures.join("auth.yaml"))
                .expect("read auth fixture")
                .replace("1788440000000", "1900000000000");
            fs::write(path.join("auth.yaml"), auth).expect("write auth fixture");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
                for name in ["config.yaml", "auth.yaml"] {
                    fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                        .expect("fixture file mode");
                }
            }
            Self(path)
        }

        fn use_test_endpoint(&self) {
            let config = fs::read_to_string(self.0.join("config.yaml"))
                .expect("read config fixture")
                .replace("auth.openai.com", "auth.example.test");
            fs::write(self.0.join("config.yaml"), config).expect("write synthetic .test config");
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn field(value: &Value, name: &str) -> Value {
        let Value::Map(entries) = value else {
            panic!("expected typed RSS map, got {value:?}");
        };
        entries
            .iter()
            .find_map(|(key, value)| match key {
                Value::String(key) if key.as_ref() == name => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
    }

    fn compiled_vm(probe: mpsc::Sender<()>) -> Vm {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/fallible_contract.rss");
        let source = fs::read_to_string(&path).expect("read actual fallible RSS contract");
        let catalog = auth_host_catalog();
        let compiled = compile_source_at_path_with_flavor_and_options(
            &path,
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
        )
        .expect("compile actual fallible RSS");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        let registration_home = TempHome::new("registration");
        AuthHost::new(
            registration_home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("registration host")
        .register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind restricted registry");
        vm.host_context().set_module_state(WaitProbe {
            ready: Mutex::new(Some(probe)),
        });
        assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
        vm
    }

    fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, VmError> {
        let callable = vm.resolve_exported_callable(name).expect("RSS export");
        vm.invoke_callable(callable, args)
    }

    fn native_auth(
        home: &TempHome,
        cancellation: RunCancellation,
        transport: Arc<ScriptedHttpsTransport>,
    ) -> Arc<AuthHost> {
        Arc::new(
            AuthHost::new(home.0.clone(), cancellation)
                .expect("native auth host")
                .with_oauth_host(Arc::new(OAuthHost::new(
                    transport,
                    Arc::new(ScriptedCallback::new()),
                    Arc::new(ScriptedBrowser::new()),
                    Arc::new(ScriptedClock::new(1_900_000_000_000)),
                    Arc::new(ScriptedCancel::new()),
                ))),
        )
    }

    fn device_response(transport: &ScriptedHttpsTransport, marker: &str) {
        transport.push_raw(
            200,
            &format!(
                r#"{{"device_code":"{marker}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
            ),
        );
    }

    fn start_device(vm: &mut Vm, policy: &Value) {
        let started = invoke(vm, "start_device_result", std::slice::from_ref(policy))
            .expect("native device issuance result");
        assert_eq!(field(&started, "ok"), Value::Bool(true));
    }

    fn bind_policy(auth: &AuthHost, vm: &mut Vm) -> Value {
        let context = auth.bind_vm(vm).expect("bind native owner");
        invoke(vm, "snapshot", &[field(&context, "host_home")]).expect("native policy snapshot")
    }

    #[test]
    fn fallible_result_wait_cancellation_allows_rss_transient_cleanup() {
        let home = TempHome::new("cancel-cleanup");
        home.use_test_endpoint();
        let transport = Arc::new(ScriptedHttpsTransport::new());
        device_response(&transport, "WAIT_DEVICE_PRIVATE_10ac");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let auth = native_auth(&home, cancellation.clone(), transport.clone());
        let (probe_tx, probe_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker_auth = Arc::clone(&auth);
        let worker_transport = Arc::clone(&transport);
        let worker = thread::spawn(move || {
            let mut vm = compiled_vm(probe_tx);
            let policy = bind_policy(&worker_auth, &mut vm);
            let started = invoke(
                &mut vm,
                "start_device_result",
                std::slice::from_ref(&policy),
            );
            let waited = vm.resolve_exported_callable("wait_result").map(|callable| {
                vm.invoke_callable(callable, &[policy.clone(), Value::Int(10_000)])
            });
            let cleaned = vm
                .resolve_exported_callable("cleanup")
                .map(|callable| vm.invoke_callable(callable, std::slice::from_ref(&policy)));
            let cleaned_again = vm
                .resolve_exported_callable("cleanup")
                .map(|callable| vm.invoke_callable(callable, std::slice::from_ref(&policy)));
            result_tx
                .send((
                    started,
                    waited,
                    cleaned,
                    cleaned_again,
                    vm.host_context().resource_count(),
                    worker_transport.take_sent().len(),
                ))
                .expect("return result observations");
        });
        probe_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("real wait entered its first polling interval");
        cancellation.request(CancellationReason::Requested);
        let (started, waited, cleaned, cleaned_again, resources, sends) = result_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("cancelled wait and cleanup return");
        worker.join().expect("wait worker");
        let started = started.expect("native device start");
        assert_eq!(field(&started, "ok"), Value::Bool(true));
        let waited = waited.expect("RSS wait result").expect("typed wait result");
        assert_eq!(field(&waited, "ok"), Value::Bool(false));
        let failure = field(&waited, "error");
        assert_eq!(field(&failure, "code"), Value::string("policy_inactive"));
        assert_eq!(field(&failure, "cancelled"), Value::Bool(true));
        assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(false));
        assert_eq!(field(&failure, "revoked"), Value::Bool(false));
        assert_eq!(
            cleaned
                .expect("cleanup export")
                .expect("cleanup inactive owner"),
            Value::Null
        );
        assert_eq!(
            cleaned_again
                .expect("repeat cleanup export")
                .expect("repeat cleanup"),
            Value::Null
        );
        assert_eq!(resources, 2);
        assert_eq!(sends, 1);
        assert_eq!(
            auth.fixture_live_oauth_flow_count()
                .expect("native flow count"),
            0
        );
    }

    #[test]
    fn fallible_results_report_wait_deadline_and_elapsed_owner_deadline() {
        let home = TempHome::new("deadline");
        home.use_test_endpoint();
        let (probe, _ready) = mpsc::channel();
        let mut vm = compiled_vm(probe);
        let transport = Arc::new(ScriptedHttpsTransport::new());
        device_response(&transport, "DEADLINE_DEVICE_PRIVATE_5d1a");
        let auth = native_auth(
            &home,
            RunCancellation::with_timeout(Duration::from_millis(500)),
            transport.clone(),
        );
        let policy = bind_policy(&auth, &mut vm);
        start_device(&mut vm, &policy);

        let too_long = invoke(
            &mut vm,
            "wait_result",
            &[policy.clone(), Value::Int(60_000)],
        )
        .expect("immediate wait-deadline result");
        assert_eq!(field(&too_long, "ok"), Value::Bool(false));
        let wait_error = field(&too_long, "error");
        assert_eq!(
            field(&wait_error, "code"),
            Value::string("wait_deadline_exceeded")
        );
        assert_eq!(field(&wait_error, "deadline_exceeded"), Value::Bool(true));
        assert_eq!(field(&wait_error, "cancelled"), Value::Bool(false));
        assert_eq!(field(&wait_error, "revoked"), Value::Bool(false));
        let before_deadline = invoke(&mut vm, "now_result", std::slice::from_ref(&policy))
            .expect("owner stays active after overlong requested wait");
        assert_eq!(field(&before_deadline, "ok"), Value::Bool(true));

        thread::sleep(Duration::from_millis(550));
        let expired = invoke(&mut vm, "now_result", std::slice::from_ref(&policy))
            .expect("elapsed owner deadline is a readable result");
        assert_eq!(field(&expired, "ok"), Value::Bool(false));
        let expired_error = field(&expired, "error");
        assert_eq!(
            field(&expired_error, "code"),
            Value::string("policy_inactive")
        );
        assert_eq!(
            field(&expired_error, "deadline_exceeded"),
            Value::Bool(true)
        );
        assert_eq!(field(&expired_error, "cancelled"), Value::Bool(false));
        assert_eq!(field(&expired_error, "revoked"), Value::Bool(false));
        assert_eq!(
            invoke(&mut vm, "cleanup", std::slice::from_ref(&policy))
                .expect("cleanup after elapsed owner deadline"),
            Value::Null
        );
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_eq!(transport.take_sent().len(), 1);
    }

    #[test]
    fn fallible_wait_reports_revocation_and_cleanup_remains_authorized() {
        let home = TempHome::new("revoked");
        home.use_test_endpoint();
        let (probe, _ready) = mpsc::channel();
        let mut vm = compiled_vm(probe);
        let transport = Arc::new(ScriptedHttpsTransport::new());
        device_response(&transport, "REVOKED_DEVICE_PRIVATE_1c63");
        let auth = native_auth(
            &home,
            RunCancellation::with_timeout(Duration::from_secs(30)),
            transport.clone(),
        );
        let policy = bind_policy(&auth, &mut vm);
        start_device(&mut vm, &policy);
        auth.revoke();

        let revoked = invoke(&mut vm, "wait_result", &[policy.clone(), Value::Int(0)])
            .expect("revoked wait result");
        assert_eq!(field(&revoked, "ok"), Value::Bool(false));
        let failure = field(&revoked, "error");
        assert_eq!(field(&failure, "code"), Value::string("policy_inactive"));
        assert_eq!(field(&failure, "revoked"), Value::Bool(true));
        assert_eq!(field(&failure, "cancelled"), Value::Bool(false));
        assert_eq!(
            invoke(&mut vm, "cleanup", std::slice::from_ref(&policy))
                .expect("cleanup remains authorized after revoke"),
            Value::Null
        );
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_eq!(transport.take_sent().len(), 1);
    }

    #[test]
    fn stale_policy_remains_a_trap_without_changing_a_live_auth_resource() {
        let home = TempHome::new("stale-policy");
        let (probe, _ready) = mpsc::channel();
        let mut vm = compiled_vm(probe);
        let auth = AuthHost::new(
            home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("stale-policy host");
        let policy = bind_policy(&auth, &mut vm);
        let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy))
            .expect("native access handle");
        let policy_handle = super::super::handle(&policy).expect("policy handle");
        vm.host_context()
            .close_resource::<super::super::Policy>(policy_handle, ResourceCloseReason::Requested)
            .expect("close stale policy resource");

        assert!(invoke(&mut vm, "now_result", std::slice::from_ref(&policy)).is_err());
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_eq!(
            invoke(&mut vm, "close_access", &[access]).expect("live access remains closable"),
            Value::Null
        );
        assert_eq!(vm.host_context().resource_count(), 1);
    }
}
