use rustscript_agent::{
    RunCancellation,
    auth::host::{AuthHost, auth_host_catalog},
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

fn fixture_home() -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
    let home = root.join(format!(
        "auth-resource-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&home).expect("home");
    #[cfg(unix)]
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("config");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("auth")
        .replace("1788440000000", "1900000000000");
    fs::write(home.join("auth.yaml"), auth).expect("auth fixture");
    #[cfg(unix)]
    for name in ["config.yaml", "auth.yaml"] {
        fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600)).expect("file mode");
    }
    home
}
fn vm_for(source: &str) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .expect("compile RSS");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host")
    .register(&mut registry, auth_host_catalog().as_ref())
    .expect("register");
    registry.bind_vm_cached(&mut vm).expect("bind");
    assert!(matches!(vm.run().expect("root"), VmStatus::Halted));
    vm
}
fn home_arg(context: Value) -> Value {
    if let Value::Map(entries) = context {
        entries
            .iter()
            .find_map(|(k, v)| {
                if matches!(k,Value::String(s) if s.as_ref()=="host_home") {
                    Some(v.clone())
                } else {
                    None
                }
            })
            .expect("home")
    } else {
        panic!("context")
    }
}
fn run(vm: &mut Vm, args: &[Value]) -> Value {
    let callable = vm.resolve_exported_callable("run").expect("export");
    vm.invoke_callable(callable, args).expect("invoke")
}
#[test]
fn rss_config_snapshot_is_bound_to_host_home() {
    let mut vm = vm_for(
        "use config; pub fn run(host_home: resource<auth.host_home>) -> array<string> { let snapshot = config::load_snapshot(&host_home); snapshot.credential_refs }",
    );
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = home_arg(host.bind_vm(&mut vm).expect("bind home"));
    let value = run(&mut vm, std::slice::from_ref(&home));
    assert!(format!("{value:?}").contains("fixture-codex"));
    assert!(!format!("{value:?}").contains("SYNTHETIC_ACCESS_TOKEN"));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(run(&mut vm, &[home]), value);
    assert_eq!(vm.host_context().resource_count(), 2);
}
#[test]
fn rss_metadata_access_refresh_and_delete_use_admitted_policy() {
    let source = r#"use config; use auth;
        pub fn run(home: resource<auth.host_home>) -> int {
          let snapshot = config::load_snapshot(&home);
          let policy = snapshot.policy_handle;
          let metadata = auth::load_metadata("fixture-codex", &policy);
          let generation: int = metadata.metadata.generation;
          let access = auth::access_handle("fixture-codex", generation, &policy);
          let refresh = auth::refresh_handle("fixture-codex", generation, &policy);
          auth::close_access(&access.handle);
          auth::close_refresh(&refresh.handle);
          let deleted = auth::delete("fixture-codex", &policy);
          if deleted.deleted => { generation } else => { 0 }
        }"#;
    let mut vm = vm_for(source);
    let home = fixture_home();
    let host = AuthHost::new(
        home.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let arg = home_arg(host.bind_vm(&mut vm).expect("bind home"));
    assert_eq!(run(&mut vm, &[arg]), Value::Int(4));
    assert!(
        !fs::read_to_string(home.join("auth.yaml"))
            .expect("auth")
            .contains("SYNTHETIC_ACCESS_TOKEN")
    );
}

#[cfg(feature = "config-fixture")]
const SAVE_SOURCE: &str = r#"use config; use auth;
      pub fn run(home: resource<auth.host_home>, access: resource<auth.secret_slot>, refresh: resource<auth.secret_slot>) -> int {
        let policy = config::load_snapshot(&home).policy_handle;
        let saved = auth::save_if_generation({
          credential_id: "fixture-codex", expected_generation: 4, policy_handle: policy,
          metadata: { provider: "openai-codex", kind: "oauth", source: "test", token_type: "Bearer",
            expires_at_ms: 1900000000000, scopes: [], account_id: "synthetic",
            generation: 4, status: "active", last_refresh_at_ms: 1790000000000,
            has_refresh_token: true },
          access_slot: access, refresh_action: "replace", refresh_slot: refresh
        });
        saved.metadata.generation
      }"#;

#[cfg(feature = "config-fixture")]
#[test]
fn rss_save_uses_host_slots_and_cas_without_returning_secret() {
    let mut vm = vm_for(SAVE_SOURCE);
    let home = fixture_home();
    let host = AuthHost::new(
        home.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let entry = home_arg(host.bind_vm(&mut vm).expect("bind home"));
    let access = host
        .fixture_slot(
            &mut vm,
            "fixture-codex",
            4,
            false,
            "SYNTHETIC_BRIDGE_ACCESS",
        )
        .expect("access slot");
    let refresh = host
        .fixture_slot(
            &mut vm,
            "fixture-codex",
            4,
            true,
            "SYNTHETIC_BRIDGE_REFRESH",
        )
        .expect("refresh slot");
    let args = [entry, access, refresh];
    assert_eq!(run(&mut vm, &args), Value::Int(5));
    assert_eq!(vm.host_context().resource_count(), 2);
    let contents = fs::read_to_string(home.join("auth.yaml")).expect("persisted");
    assert!(contents.contains("SYNTHETIC_BRIDGE_ACCESS"));
    assert!(contents.contains("SYNTHETIC_BRIDGE_REFRESH"));
    let callable = vm.resolve_exported_callable("run").expect("export");
    let failure = vm
        .invoke_callable(callable, &args)
        .expect_err("replay must fail");
    assert!(!failure.to_string().contains("SYNTHETIC_BRIDGE_ACCESS"));
    assert!(!failure.to_string().contains("SYNTHETIC_BRIDGE_REFRESH"));
}

#[cfg(feature = "config-fixture")]
#[test]
fn rss_save_rejects_wrong_generation_slot_without_writing() {
    let mut vm = vm_for(SAVE_SOURCE);
    let home = fixture_home();
    let host = AuthHost::new(
        home.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let entry = home_arg(host.bind_vm(&mut vm).expect("bind"));
    let bad = host
        .fixture_slot(&mut vm, "fixture-codex", 3, false, "SYNTHETIC_WRONG_GEN")
        .expect("slot");
    let refresh = host
        .fixture_slot(
            &mut vm,
            "fixture-codex",
            4,
            true,
            "SYNTHETIC_REFRESH_CANDIDATE",
        )
        .expect("slot");
    let previous = fs::read(home.join("auth.yaml")).expect("previous");
    let callable = vm.resolve_exported_callable("run").expect("export");
    let failure = vm
        .invoke_callable(callable, &[entry, bad, refresh])
        .expect_err("generation mismatch");
    assert!(!failure.to_string().contains("SYNTHETIC_WRONG_GEN"));
    assert_eq!(
        fs::read(home.join("auth.yaml")).expect("unchanged"),
        previous
    );
}

#[test]
fn refresh_issue_is_single_flight_for_one_credential() {
    let source = "use config; use auth; pub fn run(home: resource<auth.host_home>) -> resource<auth.refresh> { let p = config::load_snapshot(&home).policy_handle; auth::refresh_handle(\"fixture-codex\", 4, &p).handle }";
    let mut vm = vm_for(source);
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = home_arg(host.bind_vm(&mut vm).expect("bind"));
    let first = run(&mut vm, std::slice::from_ref(&home));
    assert!(matches!(first, Value::Int(_)));
    let callable = vm.resolve_exported_callable("run").expect("export");
    let failure = vm
        .invoke_callable(callable, &[home])
        .expect_err("single flight");
    assert!(!failure.to_string().contains("SYNTHETIC_REFRESH_TOKEN"));
}

#[test]
fn unbound_and_foreign_vm_home_have_no_credential_effect() {
    let source = "use config; use auth; pub fn run(home: resource<auth.host_home>) -> int { let p = config::load_snapshot(&home).policy_handle; auth::delete(\"fixture-codex\", &p); 1 }";
    let home = fixture_home();
    let initial = fs::read(home.join("auth.yaml")).expect("auth");
    let mut unbound = vm_for(source);
    let callable = unbound.resolve_exported_callable("run").expect("export");
    assert!(unbound.invoke_callable(callable, &[Value::Int(1)]).is_err());
    let mut origin = vm_for(source);
    let host = AuthHost::new(
        home.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let foreign = home_arg(host.bind_vm(&mut origin).expect("origin"));
    let mut target = vm_for(source);
    host.bind_vm(&mut target).expect("target");
    let callable = target.resolve_exported_callable("run").expect("export");
    assert!(target.invoke_callable(callable, &[foreign]).is_err());
    assert_eq!(fs::read(home.join("auth.yaml")).expect("auth"), initial);
}

#[test]
fn scope_reset_invalidates_old_home_resource() {
    let source = "use config; pub fn run(home: resource<auth.host_home>) -> int { config::load_snapshot(&home).policy_generation }";
    let mut vm = vm_for(source);
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = home_arg(host.bind_vm(&mut vm).expect("bind"));
    assert_eq!(run(&mut vm, std::slice::from_ref(&home)), Value::Int(1));
    vm.reset_for_reuse().expect("reset");
    assert!(matches!(vm.run().expect("root"), VmStatus::Halted));
    let callable = vm.resolve_exported_callable("run").expect("export");
    assert!(vm.invoke_callable(callable, &[home]).is_err());
}

#[test]
fn revoked_run_cannot_use_home_or_policy() {
    let source = "use config; pub fn run(home: resource<auth.host_home>) -> int { config::load_snapshot(&home).policy_generation }";
    let mut vm = vm_for(source);
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let home = home_arg(host.bind_vm(&mut vm).expect("bind"));
    assert_eq!(run(&mut vm, std::slice::from_ref(&home)), Value::Int(1));
    host.revoke();
    let callable = vm.resolve_exported_callable("run").expect("export");
    assert!(vm.invoke_callable(callable, &[home]).is_err());
}

#[test]
fn reload_changes_only_future_vm_admission() {
    let source = "use config; use auth; pub fn run(home: resource<auth.host_home>, id: string) -> int { let p = config::load_snapshot(&home).policy_handle; auth::load_metadata(id, &p).metadata.generation }";
    let mut old = vm_for(source);
    let home = fixture_home();
    let host = AuthHost::new(
        home.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let old_home = home_arg(host.bind_vm(&mut old).expect("old bind"));
    let config = fs::read_to_string(home.join("config.yaml"))
        .expect("config")
        .replace("auth: fixture-codex", "auth: second");
    fs::write(home.join("config.yaml"), config).expect("update config");
    let auth = fs::read_to_string(home.join("auth.yaml"))
        .expect("auth")
        .replace("fixture-codex:", "second:");
    fs::write(home.join("auth.yaml"), auth).expect("update auth");
    assert_eq!(host.reload().expect("reload"), 2);
    let callable = old.resolve_exported_callable("run").expect("export");
    let failure = old
        .invoke_callable(callable, &[old_home, Value::string("second")])
        .expect_err("old admission must not widen");
    assert!(failure.to_string().contains("credential_not_admitted"));
    let mut fresh = vm_for(source);
    let fresh_home = home_arg(host.bind_vm(&mut fresh).expect("new bind"));
    assert_eq!(
        run(&mut fresh, &[fresh_home, Value::string("second")]),
        Value::Int(4)
    );
}

#[cfg(feature = "config-fixture")]
#[test]
fn live_resource_budget_releases_closed_slots() {
    let mut vm = vm_for(
        "use auth; pub fn run(slot: resource<auth.secret_slot>) -> int { auth::close_slot(&slot); 1 }",
    );
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    host.bind_vm(&mut vm).expect("bind");
    let mut slots = Vec::new();
    for _ in 0..63 {
        slots.push(
            host.fixture_slot(&mut vm, "fixture-codex", 4, false, "SYNTHETIC_SLOT")
                .expect("within budget"),
        );
    }
    assert_eq!(vm.host_context().resource_count(), 64);
    assert!(
        host.fixture_slot(&mut vm, "fixture-codex", 4, false, "SYNTHETIC_SLOT")
            .is_err()
    );
    assert_eq!(run(&mut vm, &[slots.pop().expect("last")]), Value::Int(1));
    assert_eq!(vm.host_context().resource_count(), 63);
    host.fixture_slot(&mut vm, "fixture-codex", 4, false, "SYNTHETIC_SLOT")
        .expect("capacity reused");
}

#[test]
fn cancellation_and_deadline_reject_bound_home() {
    let source = "use config; pub fn run(home: resource<auth.host_home>) -> int { config::load_snapshot(&home).policy_generation }";
    let mut vm = vm_for(source);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let host = AuthHost::new(fixture_home(), cancellation.clone()).expect("host");
    let home = home_arg(host.bind_vm(&mut vm).expect("bind"));
    cancellation.request(rustscript_agent::CancellationReason::Deadline);
    let callable = vm.resolve_exported_callable("run").expect("export");
    assert!(vm.invoke_callable(callable, &[home]).is_err());
    assert!(AuthHost::new(fixture_home(), RunCancellation::new()).is_err());
    let expired = RunCancellation::with_timeout(Duration::from_millis(0));
    assert!(AuthHost::new(fixture_home(), expired).is_err());
}

#[test]
fn resource_serialization_and_scalar_policy_are_rejected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let source = "use config; pub fn run(home: resource<auth.host_home>) -> string { let p = config::load_snapshot(&home); json::encode(p.policy_handle) }";
    assert!(
        compile_source_at_path_with_flavor_and_options(
            &path,
            source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog())
        )
        .is_err()
    );
    let source = "use auth; pub fn run() -> int { auth::load_metadata(\"fixture-codex\", 42); 1 }";
    assert!(
        compile_source_at_path_with_flavor_and_options(
            &path,
            source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog())
        )
        .is_err()
    );
}
