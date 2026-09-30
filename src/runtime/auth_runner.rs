//! In-memory, auth-only entry compilation and execution.
//!
//! Import admission is an embedding boundary: Core owns RSS parsing, source
//! semantics, and host-module loading. This runner rejects every structured
//! import path outside the auth host module's single-root catalog before
//! asking Core to compile source.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_vm::{
    CapabilityProfile, CompileSourceFileOptions, HostApiCatalog, HostFunctionRegistry,
    InvocationError, InvocationItem, InvocationPoll, ParserDialect, SharedParserOptions,
    SourceFlavor, UsePathSegment, Value, Vm, VmStatus, VmYieldReason,
    compile_source_with_flavor_and_options, parse_source_with_dialect,
};

use crate::auth::host::{AuthHost, auth_host_catalog, auth_host_module};
use crate::auth::oauth::OAuthHost;
use crate::runtime::cancellation::CancellationReason;
use crate::runtime::host_wait::wait_for_host_op_blocking_with_cancel;
use crate::runtime::rss_runner::{
    MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL, RUN_EPOCH_DEADLINE_TICKS, RunCancellation,
};

const AUTH_ENTRY_ARITY: usize = 2;
const COMMAND_FIELD_MAX_BYTES: usize = 2048;
const VM_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

struct AuthEntryParserDialect;

impl ParserDialect for AuthEntryParserDialect {
    fn allow_let_mut_binding(&self) -> bool {
        true
    }

    fn allow_macro_calls(&self) -> bool {
        true
    }

    fn allow_plus_equal_operator(&self) -> bool {
        true
    }

    fn allow_for_in_loop(&self) -> bool {
        true
    }
}

static AUTH_ENTRY_PARSER_DIALECT: AuthEntryParserDialect = AuthEntryParserDialect;

/// Generic command carrier. RSS owns the meaning of every field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCommandInput {
    pub operation: String,
    pub provider: Option<String>,
    pub credential_id: Option<String>,
}

/// Fixed, redacted failure categories for the auth RSS boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthEntryError {
    SourceTooLarge,
    SourceInvalid,
    ImportDenied,
    CompileFailed,
    InvalidInput,
    DeadlineRequired,
    Cancelled(CancellationReason),
    FuelExhausted,
    NoEntry,
    EntryArity,
    RegistrySetup,
    HostSetup,
    VmSetup,
    EpochSetup,
    HomeBind,
    HomeCarrier,
    VmCleanup,
    RootExecution,
    Invocation,
    OutputInvalid,
}

impl AuthEntryError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SourceTooLarge => "auth_source_too_large",
            Self::SourceInvalid => "auth_source_invalid",
            Self::ImportDenied => "auth_import_denied",
            Self::CompileFailed => "auth_compile_failed",
            Self::InvalidInput => "auth_input_invalid",
            Self::DeadlineRequired => "auth_deadline_required",
            Self::Cancelled(_) => "auth_cancelled",
            Self::FuelExhausted => "auth_fuel_exhausted",
            Self::NoEntry => "auth_entry_missing",
            Self::EntryArity => "auth_entry_arity",
            Self::RegistrySetup => "auth_registry_setup_failed",
            Self::HostSetup => "auth_host_setup_failed",
            Self::VmSetup => "auth_vm_setup_failed",
            Self::EpochSetup => "auth_epoch_setup_failed",
            Self::HomeBind => "auth_home_bind_failed",
            Self::HomeCarrier => "auth_home_carrier_invalid",
            Self::VmCleanup => "auth_vm_cleanup_failed",
            Self::RootExecution => "auth_root_failed",
            Self::Invocation => "auth_invocation_failed",
            Self::OutputInvalid => "auth_output_invalid",
        }
    }
}

impl Display for AuthEntryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AuthEntryError {}

/// Compiled RSS source admitted against only the auth host catalog.
pub struct AuthEntryRunner {
    program: rustscript_vm::Program,
    catalog: Arc<HostApiCatalog>,
}

/// Disarms the run's epoch watcher on success, error, setup failure, or unwind.
struct CancellationDisarm<'a>(&'a RunCancellation);

impl Drop for CancellationDisarm<'_> {
    fn drop(&mut self) {
        self.0.disarm();
    }
}

/// Revokes all host-home and policy resources when this invocation exits.
struct AuthHostRevoke<'a>(&'a AuthHost);

impl Drop for AuthHostRevoke<'_> {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

/// Resets and drains a one-shot VM on every normal or unwinding exit.
/// Core's `Vm::drop` cancels outstanding work as a last resort, but it does not
/// report whether async bridge cancellation reached quiescence.
struct VmDrainGuard<'a> {
    vm: &'a mut Vm,
    finished: bool,
}

impl<'a> VmDrainGuard<'a> {
    fn new(vm: &'a mut Vm) -> Self {
        Self {
            vm,
            finished: false,
        }
    }

    fn vm(&mut self) -> &mut Vm {
        self.vm
    }

    fn drain(&mut self) -> Result<(), AuthEntryError> {
        if self.finished {
            return Ok(());
        }
        if self.vm.reset_for_reuse().is_err() {
            self.finished = true;
            return Err(AuthEntryError::VmCleanup);
        }
        let deadline = Instant::now()
            .checked_add(VM_DRAIN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        loop {
            let mut context = Context::from_waker(Waker::noop());
            match self.vm.poll_reset_for_reuse(&mut context) {
                Poll::Ready(Ok(())) => {
                    self.finished = true;
                    return Ok(());
                }
                Poll::Ready(Err(_)) => {
                    self.finished = true;
                    return Err(AuthEntryError::VmCleanup);
                }
                Poll::Pending if Instant::now() >= deadline => {
                    self.finished = true;
                    return Err(AuthEntryError::VmCleanup);
                }
                Poll::Pending => thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

impl Drop for VmDrainGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.drain()));
        }
    }
}

impl AuthEntryRunner {
    /// Parse the full bounded source without loading files, then compile only
    /// after every structured `use` path passes the single-root allowlist.
    pub fn from_source(source: &str) -> Result<Self, AuthEntryError> {
        if source.len() > MAX_AGENT_SOURCE_BYTES {
            return Err(AuthEntryError::SourceTooLarge);
        }
        preflight_imports(source)?;

        let catalog = auth_host_catalog();
        let compiled = compile_source_with_flavor_and_options(
            source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
        )
        .map_err(|_| AuthEntryError::CompileFailed)?;
        Ok(Self {
            program: compiled.program,
            catalog,
        })
    }

    /// Run `run(home, command)` with a fresh host, VM, resource arena, and
    /// finite cancellation watcher for this invocation.
    pub fn run(
        &self,
        home: PathBuf,
        input: AuthCommandInput,
        cancellation: &RunCancellation,
        oauth: Option<Arc<OAuthHost>>,
    ) -> Result<Value, AuthEntryError> {
        let invocation_cancellation = cancellation.child();
        let _cancellation_guard = CancellationDisarm(&invocation_cancellation);
        validate_input(&input)?;
        ensure_finite_active(&invocation_cancellation)?;
        self.run_inner(home, input, &invocation_cancellation, oauth)
    }

    fn run_inner(
        &self,
        home: PathBuf,
        input: AuthCommandInput,
        cancellation: &RunCancellation,
        oauth: Option<Arc<OAuthHost>>,
    ) -> Result<Value, AuthEntryError> {
        let auth_host = AuthHost::new(home, cancellation.clone())
            .map_err(|_| setup_failure(cancellation, AuthEntryError::HostSetup))?;
        let auth_host = match oauth {
            Some(oauth) => auth_host.with_oauth_host(oauth),
            None => auth_host,
        };
        let _revoke_guard = AuthHostRevoke(&auth_host);

        let registry = restricted_auth_registry(&auth_host, self.catalog.as_ref())
            .map_err(|error| setup_failure(cancellation, error))?;
        let mut vm = Vm::try_new(self.program.clone())
            .map_err(|_| setup_failure(cancellation, AuthEntryError::VmSetup))?;
        let mut vm_drain = VmDrainGuard::new(&mut vm);
        let execution = {
            let vm = vm_drain.vm();
            (|| {
                vm.set_epoch_check_interval(RUN_EPOCH_CHECK_INTERVAL)
                    .map_err(|_| setup_failure(cancellation, AuthEntryError::EpochSetup))?;
                vm.set_epoch_deadline(RUN_EPOCH_DEADLINE_TICKS)
                    .map_err(|_| setup_failure(cancellation, AuthEntryError::EpochSetup))?;
                registry
                    .bind_vm_cached(vm)
                    .map_err(|_| setup_failure(cancellation, AuthEntryError::RegistrySetup))?;

                // Bind the trusted host-home resource before the source root can run.
                let bound = auth_host
                    .bind_vm(vm)
                    .map_err(|_| setup_failure(cancellation, AuthEntryError::HomeBind))?;
                let home_resource = map_field(&bound, "host_home")
                    .cloned()
                    .ok_or_else(|| setup_failure(cancellation, AuthEntryError::HomeCarrier))?;
                ensure_finite_active(cancellation)?;
                cancellation.arm(vm.epoch_handle());
                ensure_finite_active(cancellation)?;

                drive_root_frame(vm, cancellation)?;
                ensure_finite_active(cancellation)?;
                let callable = vm
                    .resolve_exported_callable("run")
                    .map_err(|_| setup_failure(cancellation, AuthEntryError::NoEntry))?;
                let arity = callable_arity(&self.program, &callable)
                    .ok_or_else(|| setup_failure(cancellation, AuthEntryError::NoEntry))?;
                if arity != AUTH_ENTRY_ARITY {
                    return Err(setup_failure(cancellation, AuthEntryError::EntryArity));
                }

                invoke_entry(vm, callable, home_resource, input, cancellation)
            })()
        };
        let drain = vm_drain.drain();
        match execution {
            Err(error) => Err(error),
            Ok(value) => drain.map(|()| value),
        }
    }
}

fn preflight_imports(source: &str) -> Result<(), AuthEntryError> {
    let ir = parse_source_with_dialect(
        source,
        &AUTH_ENTRY_PARSER_DIALECT,
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: true,
        },
    )
    .map_err(|_| AuthEntryError::SourceInvalid)?;

    let mut host_roots = BTreeSet::new();
    for descriptor in auth_host_module().descriptors() {
        if let Some((root, _)) = descriptor.schema.name.split_once("::") {
            host_roots.insert(root.to_owned());
        }
    }

    for declaration in ir.use_declarations {
        match declaration.path.as_slice() {
            [UsePathSegment::Ident(root)] if host_roots.contains(root) => {}
            _ => return Err(AuthEntryError::ImportDenied),
        }
    }
    Ok(())
}

fn restricted_auth_registry(
    auth_host: &AuthHost,
    catalog: &HostApiCatalog,
) -> Result<HostFunctionRegistry, AuthEntryError> {
    let mut registry = HostFunctionRegistry::empty();
    registry.set_capability_profile(CapabilityProfile::deny_all());
    auth_host
        .register(&mut registry, catalog)
        .map_err(|_| AuthEntryError::RegistrySetup)?;
    registry.set_capability_profile(CapabilityProfile::deny_all());
    for descriptor in auth_host_module().descriptors() {
        registry.authorize_registered_builtin_import(&descriptor.schema.name);
    }
    Ok(registry)
}

fn validate_input(input: &AuthCommandInput) -> Result<(), AuthEntryError> {
    for value in [
        Some(input.operation.as_str()),
        input.provider.as_deref(),
        input.credential_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > COMMAND_FIELD_MAX_BYTES || value.chars().any(char::is_control) {
            return Err(AuthEntryError::InvalidInput);
        }
    }
    Ok(())
}

fn ensure_finite_active(cancellation: &RunCancellation) -> Result<(), AuthEntryError> {
    if cancellation.has_deadline_overflow() || cancellation.deadline_instant().is_none() {
        return Err(AuthEntryError::DeadlineRequired);
    }
    if let Some(reason) = cancellation.requested() {
        return Err(AuthEntryError::Cancelled(reason));
    }
    if cancellation.deadline_passed() {
        return Err(AuthEntryError::Cancelled(CancellationReason::Deadline));
    }
    Ok(())
}

fn map_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn callable_arity(program: &rustscript_vm::Program, callable: &Value) -> Option<usize> {
    let Value::Callable(callable) = callable else {
        return None;
    };
    program
        .callable_prototypes
        .get(callable.prototype_id as usize)
        .map(|prototype| prototype.arity as usize)
}

fn cancellation_reason(cancellation: &RunCancellation) -> Option<CancellationReason> {
    cancellation.requested().or_else(|| {
        cancellation
            .deadline_passed()
            .then_some(CancellationReason::Deadline)
    })
}

fn setup_failure(cancellation: &RunCancellation, fallback: AuthEntryError) -> AuthEntryError {
    cancellation_reason(cancellation)
        .map(AuthEntryError::Cancelled)
        .unwrap_or(fallback)
}

fn root_yield_error(vm: &Vm, cancellation: &RunCancellation) -> AuthEntryError {
    match vm.last_yield_reason() {
        Some(VmYieldReason::Fuel) => AuthEntryError::FuelExhausted,
        Some(VmYieldReason::Epoch) => AuthEntryError::Cancelled(
            cancellation_reason(cancellation).unwrap_or(CancellationReason::Deadline),
        ),
        _ => AuthEntryError::RootExecution,
    }
}

fn drive_root_frame(vm: &mut Vm, cancellation: &RunCancellation) -> Result<(), AuthEntryError> {
    loop {
        if let Some(reason) = cancellation_reason(cancellation) {
            return Err(AuthEntryError::Cancelled(reason));
        }
        match vm.run() {
            Ok(VmStatus::Halted) => return Ok(()),
            Ok(VmStatus::Waiting(_)) => {
                wait_for_host_op_blocking_with_cancel(vm, || {
                    cancellation_reason(cancellation).is_some()
                })
                .map_err(|_| setup_failure(cancellation, AuthEntryError::RootExecution))?;
            }
            Ok(VmStatus::Yielded) => return Err(root_yield_error(vm, cancellation)),
            Err(_) => return Err(setup_failure(cancellation, AuthEntryError::RootExecution)),
        }
    }
}

fn command_value(input: AuthCommandInput) -> Value {
    Value::map(vec![
        (Value::string("operation"), Value::string(input.operation)),
        (
            Value::string("provider"),
            input.provider.map(Value::string).unwrap_or(Value::Null),
        ),
        (
            Value::string("credential_id"),
            input
                .credential_id
                .map(Value::string)
                .unwrap_or(Value::Null),
        ),
    ])
}

fn invoke_entry(
    vm: &mut Vm,
    callable: Value,
    home: Value,
    input: AuthCommandInput,
    cancellation: &RunCancellation,
) -> Result<Value, AuthEntryError> {
    let mut invocation = vm
        .start_invocation(callable, vec![home, command_value(input)])
        .map_err(|_| setup_failure(cancellation, AuthEntryError::Invocation))?;
    loop {
        if let Some(reason) = cancellation_reason(cancellation) {
            invocation
                .cancel(reason)
                .map_err(|_| AuthEntryError::Cancelled(reason))?;
        }
        match invocation
            .poll_next()
            .map_err(|_| setup_failure(cancellation, AuthEntryError::Invocation))?
        {
            InvocationPoll::Pending => thread::sleep(Duration::from_millis(1)),
            InvocationPoll::Ready(Some(Ok(InvocationItem::Event(_)))) => {
                return Err(setup_failure(cancellation, AuthEntryError::Invocation));
            }
            InvocationPoll::Ready(Some(Ok(InvocationItem::Complete(value)))) => {
                validate_output(&value)?;
                return Ok(value);
            }
            InvocationPoll::Ready(Some(Err(InvocationError::Cancelled(reason)))) => {
                return Err(AuthEntryError::Cancelled(reason));
            }
            InvocationPoll::Ready(Some(Err(InvocationError::DeadlineReached { .. }))) => {
                return Err(AuthEntryError::Cancelled(CancellationReason::Deadline));
            }
            InvocationPoll::Ready(Some(Err(InvocationError::OutOfFuel { .. }))) => {
                return Err(AuthEntryError::FuelExhausted);
            }
            InvocationPoll::Ready(Some(Err(_))) | InvocationPoll::Ready(None) => {
                return Err(setup_failure(cancellation, AuthEntryError::Invocation));
            }
        }
    }
}

fn validate_output(value: &Value) -> Result<(), AuthEntryError> {
    let Value::Map(fields) = value else {
        return Err(AuthEntryError::OutputInvalid);
    };
    if fields.len() < 4 || fields.len() > 6 {
        return Err(AuthEntryError::OutputInvalid);
    }
    let Some(ok) = map_field(value, "ok") else {
        return Err(AuthEntryError::OutputInvalid);
    };
    let Some(operation) = map_field(value, "operation") else {
        return Err(AuthEntryError::OutputInvalid);
    };
    let Some(generation) = map_field(value, "generation") else {
        return Err(AuthEntryError::OutputInvalid);
    };
    let Some(status) = map_field(value, "status") else {
        return Err(AuthEntryError::OutputInvalid);
    };
    let credential_id = map_field(value, "credential_id");
    let error = map_field(value, "error");
    let scalar_string = |value: &Value| matches!(value, Value::String(_));
    if !matches!(ok, Value::Bool(_))
        || !scalar_string(operation)
        || credential_id.is_some_and(|value| {
            !(matches!(value, Value::Null) || scalar_string(value))
        })
        || !matches!(generation, Value::Int(n) if *n >= 0)
        || !scalar_string(status)
        || error.is_some_and(|value| !(matches!(value, Value::Null) || scalar_string(value)))
        || fields.iter().any(|(key, _)| {
            !matches!(key, Value::String(name) if ["ok", "operation", "credential_id", "generation", "status", "error"].contains(&name.as_str()))
        })
    {
        return Err(AuthEntryError::OutputInvalid);
    }
    Ok(())
}
