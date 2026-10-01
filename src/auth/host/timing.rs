//! Policy-bound wall-clock and cancellable wait host primitives.

use super::{
    CallOutcome, HostFunctionDescriptor, HostResourceType, HostTypeSchema, Policy, Value, Vm,
    VmResult, borrow, borrowed, desc, error, key, param, result,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_WAIT_MS: i64 = 60_000;
const WAIT_CHUNK: Duration = Duration::from_millis(10);

#[cfg(test)]
struct WaitProbe {
    ready: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

pub(super) fn now_ms_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::now_ms",
        vec![borrow("policy_handle", key(Policy::KEY))],
        HostTypeSchema::Int,
        now_ms_call,
    )
}

pub(super) fn wait_ms_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::wait_ms",
        vec![
            borrow("policy_handle", key(Policy::KEY)),
            param("millis", HostTypeSchema::Int),
        ],
        HostTypeSchema::Null,
        wait_ms_call,
    )
}

fn now_ms_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = borrowed::<Policy>(vm, args.first().ok_or_else(|| error("invalid_request"))?)?;
    owner.check()?;
    let now_ms = match &owner.oauth {
        Some(oauth) => {
            i64::try_from(oauth.clock_now_ms()).map_err(|_| error("clock_unavailable"))?
        }
        None => {
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| error("clock_unavailable"))?;
            i64::try_from(duration.as_millis()).map_err(|_| error("clock_unavailable"))?
        }
    };
    owner.check()?;
    result(Value::Int(now_ms))
}

#[cfg(test)]
fn notify_wait_probe(vm: &mut Vm) {
    let ready = vm
        .host_context()
        .module_state::<WaitProbe>()
        .and_then(|probe| {
            probe
                .ready
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        });
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
}

fn wait_ms_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = borrowed::<Policy>(vm, args.first().ok_or_else(|| error("invalid_request"))?)?;
    owner.check()?;
    let Value::Int(millis) = args.get(1).ok_or_else(|| error("invalid_request"))? else {
        return Err(error("invalid_request"));
    };
    if !(0..=MAX_WAIT_MS).contains(millis) {
        return Err(error("wait_out_of_range"));
    }
    let target = Instant::now()
        .checked_add(Duration::from_millis(*millis as u64))
        .ok_or_else(|| error("wait_out_of_range"))?;
    if target > owner.deadline {
        return Err(error("wait_deadline_exceeded"));
    }
    if *millis > 0 {
        while Instant::now() < target {
            owner.check()?;
            let now = Instant::now();
            if now >= target {
                break;
            }
            let remaining_target = target.duration_since(now);
            let remaining_deadline = owner.deadline.saturating_duration_since(now);
            let sleep_for = WAIT_CHUNK.min(remaining_target).min(remaining_deadline);
            if sleep_for.is_zero() {
                owner.check()?;
            }
            #[cfg(test)]
            notify_wait_probe(vm);
            thread::sleep(sleep_for);
        }
    }
    owner.check()?;
    result(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::host::{AuthHost, auth_host_catalog};
    use crate::auth::oauth::{
        OAuthCancel, OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    };
    use crate::runtime::RunCancellation;
    use crate::runtime::cancellation::CancellationReason;
    use rustscript_vm::resource::ResourceCloseReason;
    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, VmError, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, mpsc};

    const TIMING_SOURCE: &str = include_str!("../../../rss/auth/timing_contract.rss");

    struct TempHome(PathBuf);

    impl TempHome {
        fn new(label: &str) -> Self {
            let base = PathBuf::from(
                std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"),
            );
            let path = base.join(format!(
                "oauth-timing-unit-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("create private auth home");
            let fixtures =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
            fs::copy(fixtures.join("config.yaml"), path.join("config.yaml"))
                .expect("copy config fixture");
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
    }

    impl AsRef<Path> for TempHome {
        fn as_ref(&self) -> &Path {
            &self.0
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/timing_contract.rss");
        let catalog = auth_host_catalog();
        let compiled = compile_source_at_path_with_flavor_and_options(
            &path,
            TIMING_SOURCE,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
        )
        .expect("compile real timing RSS");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        let registration_home = TempHome::new("registration");
        AuthHost::new(
            registration_home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("registration host")
        .register(&mut registry, catalog.as_ref())
        .expect("register exact timing catalog");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind exact catalog");
        vm.host_context().set_module_state(WaitProbe {
            ready: Mutex::new(Some(probe)),
        });
        assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
        vm
    }

    fn vm_and_policy(host: &AuthHost, probe: mpsc::Sender<()>) -> (Vm, Value, Value) {
        let mut vm = compiled_vm(probe);
        let bound = host.bind_vm(&mut vm).expect("bind run owner");
        let home = field(&bound, "host_home");
        let snapshot = vm
            .resolve_exported_callable("snapshot")
            .expect("snapshot export");
        let policy = vm
            .invoke_callable(snapshot, std::slice::from_ref(&home))
            .expect("load owner policy");
        (vm, home, policy)
    }

    fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, VmError> {
        let callable = vm.resolve_exported_callable(name).expect("RSS export");
        vm.invoke_callable(callable, args)
    }

    fn oauth(cancel: Arc<ScriptedCancel>) -> Arc<OAuthHost> {
        Arc::new(OAuthHost::new(
            Arc::new(ScriptedHttpsTransport::new()),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            cancel,
        ))
    }

    struct WaitWorkerGuard {
        join: Option<std::thread::JoinHandle<()>>,
        rescue: RunCancellation,
    }

    impl WaitWorkerGuard {
        fn join(mut self) {
            self.join
                .take()
                .expect("worker join handle")
                .join()
                .expect("bounded wait worker");
        }
    }

    impl Drop for WaitWorkerGuard {
        fn drop(&mut self) {
            if let Some(join) = self.join.take() {
                self.rescue.request(CancellationReason::Requested);
                let _ = join.join();
            }
        }
    }

    fn start_wait_worker(
        host: Arc<AuthHost>,
        rescue: RunCancellation,
    ) -> (
        mpsc::Receiver<()>,
        mpsc::Receiver<VmResult<Value>>,
        WaitWorkerGuard,
    ) {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let (mut vm, _, policy) = vm_and_policy(&host, ready_tx);
            let wait = vm.resolve_exported_callable("wait").expect("wait export");
            let result = vm.invoke_callable(wait, &[policy, Value::Int(10_000)]);
            let _ = result_tx.send(result);
        });
        (
            ready_rx,
            result_rx,
            WaitWorkerGuard {
                join: Some(join),
                rescue,
            },
        )
    }

    #[test]
    fn requested_cancellation_interrupts_wait_without_affecting_sibling_owner() {
        let global_cancel = Arc::new(ScriptedCancel::new());
        let shared_oauth = oauth(Arc::clone(&global_cancel));
        let cancellation_a = RunCancellation::with_timeout(Duration::from_secs(30));
        let cancellation_b = RunCancellation::with_timeout(Duration::from_secs(30));
        let home_a = TempHome::new("owner-a");
        let home_b = TempHome::new("owner-b");
        let host_a = Arc::new(
            AuthHost::new(home_a.0.clone(), cancellation_a.clone())
                .expect("owner A host")
                .with_oauth_host(Arc::clone(&shared_oauth)),
        );
        let host_b = AuthHost::new(home_b.0.clone(), cancellation_b)
            .expect("owner B host")
            .with_oauth_host(shared_oauth);
        let (ready_rx, result_rx, worker) =
            start_wait_worker(Arc::clone(&host_a), cancellation_a.clone());

        ready_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("wait entered first sleep before cancellation");
        cancellation_a.request(CancellationReason::Requested);
        let result = result_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("requested cancellation observed within bounded rescue");
        assert!(
            matches!(&result, Err(VmError::HostError(code)) if code == "policy_inactive"),
            "unexpected wait result: {result:?}"
        );
        assert_eq!(
            cancellation_a.requested(),
            Some(CancellationReason::Requested)
        );

        let (mut vm_b, _, policy_b) = vm_and_policy(&host_b, mpsc::channel().0);
        let before_resources = vm_b.host_context().resource_count();
        let wait_b = vm_b.resolve_exported_callable("wait").expect("wait export");
        assert_eq!(
            vm_b.invoke_callable(wait_b, &[policy_b, Value::Int(0)])
                .expect("sibling owner remains active"),
            Value::Null
        );
        assert_eq!(vm_b.host_context().resource_count(), before_resources);
        assert!(!global_cancel.is_cancelled());
        worker.join();
    }

    #[test]
    fn revoke_interrupts_wait_without_affecting_sibling_owner() {
        let global_cancel = Arc::new(ScriptedCancel::new());
        let shared_oauth = oauth(Arc::clone(&global_cancel));
        let cancellation_a = RunCancellation::with_timeout(Duration::from_secs(30));
        let home_a = TempHome::new("revoke-owner-a");
        let home_b = TempHome::new("revoke-owner-b");
        let host_a = Arc::new(
            AuthHost::new(home_a.0.clone(), cancellation_a.clone())
                .expect("owner A host")
                .with_oauth_host(Arc::clone(&shared_oauth)),
        );
        let host_b = AuthHost::new(
            home_b.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("owner B host")
        .with_oauth_host(shared_oauth);
        let (ready_rx, result_rx, worker) =
            start_wait_worker(Arc::clone(&host_a), cancellation_a.clone());

        ready_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("wait entered first sleep before revoke");
        host_a.revoke();
        let result = result_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("revocation observed within bounded rescue");
        assert!(
            matches!(&result, Err(VmError::HostError(code)) if code == "policy_inactive"),
            "unexpected wait result: {result:?}"
        );
        assert_eq!(cancellation_a.requested(), None);

        let (mut vm_b, _, policy_b) = vm_and_policy(&host_b, mpsc::channel().0);
        let before_resources = vm_b.host_context().resource_count();
        let wait_b = vm_b.resolve_exported_callable("wait").expect("wait export");
        assert_eq!(
            vm_b.invoke_callable(wait_b, &[policy_b, Value::Int(0)])
                .expect("sibling owner remains active"),
            Value::Null
        );
        assert_eq!(vm_b.host_context().resource_count(), before_resources);
        assert!(!global_cancel.is_cancelled());
        worker.join();
    }

    #[test]
    fn clock_rejects_home_resource_as_a_policy() {
        let home = TempHome::new("wrong-class");
        let host = AuthHost::new(
            home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("auth host");
        let (mut vm, host_home, _) = vm_and_policy(&host, mpsc::channel().0);
        assert!(invoke(&mut vm, "now", &[host_home]).is_err());
    }

    #[test]
    fn wait_rejects_a_closed_policy_resource() {
        let home = TempHome::new("closed-policy");
        let host = AuthHost::new(
            home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("auth host");
        let (mut vm, _, policy) = vm_and_policy(&host, mpsc::channel().0);
        vm.host_context()
            .close_resource::<Policy>(
                super::super::handle(&policy).expect("policy handle"),
                ResourceCloseReason::Requested,
            )
            .expect("close policy resource");
        let failure = invoke(&mut vm, "wait", &[policy, Value::Int(0)])
            .expect_err("closed policy must be rejected");
        assert!(
            failure.to_string().contains("resource"),
            "unexpected error: {failure}"
        );
    }

    #[test]
    fn clock_rejects_a_valid_policy_handle_without_bound_owner() {
        let home = TempHome::new("unbound-owner");
        let host = AuthHost::new(
            home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("auth host");
        let (mut source_vm, _, source_policy) = vm_and_policy(&host, mpsc::channel().0);
        let owner = borrowed::<Policy>(&mut source_vm, &source_policy).expect("source owner");
        let mut unbound_vm = compiled_vm(mpsc::channel().0);
        let unbound_policy = super::super::issue(&mut unbound_vm, Policy { owner })
            .expect("insert valid policy without Bound scope");
        let failure = invoke(&mut unbound_vm, "now", &[unbound_policy])
            .expect_err("unbound policy must be rejected");
        assert!(
            matches!(&failure, VmError::HostError(code) if code == "host_unbound"),
            "unexpected error: {failure}"
        );
    }

    #[test]
    fn wait_rejects_a_policy_handle_from_another_vm_arena() {
        let home = TempHome::new("foreign-arena");
        let host = AuthHost::new(
            home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("auth host");
        let (mut source_vm, _, foreign_policy) = vm_and_policy(&host, mpsc::channel().0);
        let mut other_vm = compiled_vm(mpsc::channel().0);
        let failure = invoke(&mut other_vm, "wait", &[foreign_policy, Value::Int(0)])
            .expect_err("foreign arena handle must be rejected");
        assert!(
            failure.to_string().contains("resource_handle_wrong_table"),
            "foreign arena must fail closed: {failure}"
        );
        assert_eq!(source_vm.host_context().resource_count(), 2);
        assert_eq!(other_vm.host_context().resource_count(), 0);
    }

    #[test]
    fn clock_rejects_a_policy_owned_by_a_different_bound_owner() {
        let home_a = TempHome::new("foreign-owner-a");
        let home_b = TempHome::new("foreign-owner-b");
        let host_a = AuthHost::new(
            home_a.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("owner A host");
        let host_b = AuthHost::new(
            home_b.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
        )
        .expect("owner B host");
        let (mut vm_a, _, policy_a) = vm_and_policy(&host_a, mpsc::channel().0);
        let owner_a = borrowed::<Policy>(&mut vm_a, &policy_a).expect("owner A policy");
        let (mut vm_b, _, _) = vm_and_policy(&host_b, mpsc::channel().0);
        let foreign_policy =
            super::super::issue(&mut vm_b, Policy { owner: owner_a }).expect("foreign policy");
        let failure = invoke(&mut vm_b, "now", &[foreign_policy])
            .expect_err("foreign owner policy must be rejected");
        assert!(
            matches!(&failure, VmError::HostError(code) if code == "owner_mismatch"),
            "unexpected error: {failure}"
        );
    }
}
