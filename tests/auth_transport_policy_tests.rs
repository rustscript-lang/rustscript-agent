use rustscript_agent::{
    RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::TrustedEndpoint,
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const SOURCE: &str = "use config; pub fn run(home: resource<auth.host_home>) -> resource<auth.policy> { config::load_snapshot(&home).policy_handle }";

fn fixture_home() -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
    let home = root.join(format!(
        "transport-policy-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&home).expect("private home");
    #[cfg(unix)]
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("config");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("auth fixture")
        .replace("1788440000000", "1900000000000");
    fs::write(home.join("auth.yaml"), auth).expect("auth");
    #[cfg(unix)]
    for name in ["config.yaml", "auth.yaml"] {
        fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600)).expect("file mode");
    }
    home
}

fn vm_for() -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        SOURCE,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .expect("compile real RSS file");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host")
    .register(&mut registry, auth_host_catalog().as_ref())
    .expect("register");
    registry.bind_vm_cached(&mut vm).expect("bind registry");
    assert!(matches!(vm.run().expect("root"), VmStatus::Halted));
    vm
}

fn policy(vm: &mut Vm, host: &AuthHost) -> Value {
    let context = host.bind_vm(vm).expect("bind home");
    let Value::Map(entries) = context else {
        panic!("context")
    };
    let home = entries
        .iter()
        .find_map(|(k, v)| {
            matches!(k, Value::String(s) if s.as_ref() == "host_home").then(|| v.clone())
        })
        .expect("home");
    let callable = vm.resolve_exported_callable("run").expect("export");
    vm.invoke_callable(callable, &[home])
        .expect("RSS snapshot policy")
}

fn endpoints(entries: &[(&str, &str)]) -> Vec<TrustedEndpoint> {
    entries
        .iter()
        .map(|(authority, path_prefix)| TrustedEndpoint {
            authority: (*authority).to_string(),
            path_prefix: (*path_prefix).to_string(),
        })
        .collect()
}

#[test]
fn trusted_policy_uses_only_frozen_credential_endpoints_and_owner_identity() {
    let mut vm = vm_for();
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let issued = policy(&mut vm, &host);
    let before = Instant::now();
    let trusted = host
        .trusted_transport_policy(&mut vm, &issued, "fixture-codex")
        .expect("policy");
    assert_eq!(trusted.generation, 1);
    assert!(!trusted.run_id.is_empty());
    assert!(trusted.deadline > before);
    assert!(trusted.deadline <= before + Duration::from_secs(30));
    assert_eq!(
        trusted.allowed_header_names,
        BTreeSet::from(["accept".to_string(), "content-type".to_string()])
    );
    assert_eq!(
        trusted.endpoints,
        endpoints(&[
            ("chatgpt.com", "/backend-api/codex"),
            ("auth.openai.com", "/oauth/token"),
            ("auth.openai.com", "/codex/device"),
            ("auth.openai.com", "/api/accounts/deviceauth/usercode"),
            ("auth.openai.com", "/api/accounts/deviceauth/token"),
        ])
    );
    let alias = issued.clone();
    let again = host
        .trusted_transport_policy(&mut vm, &alias, "fixture-codex")
        .expect("same VM borrow alias");
    assert_eq!(again.run_id, trusted.run_id);
    assert_eq!(again.deadline, trusted.deadline);
}

#[test]
fn policy_rejects_unadmitted_ids_wrong_host_and_unissued_resources() {
    let mut vm = vm_for();
    let home = fixture_home();
    let host = AuthHost::new(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let issued = policy(&mut vm, &host);
    for id in ["unlisted", "", "../fixture-codex"] {
        assert!(
            host.trusted_transport_policy(&mut vm, &issued, id).is_err(),
            "unauthorized ID: {id}"
        );
    }
    let foreign = AuthHost::new(home, RunCancellation::with_timeout(Duration::from_secs(30)))
        .expect("foreign");
    assert!(
        foreign
            .trusted_transport_policy(&mut vm, &issued, "fixture-codex")
            .is_err()
    );
    for fake in [
        Value::Int(0),
        Value::Int(-1),
        Value::Int(i64::MAX),
        Value::string("forged"),
    ] {
        assert!(
            host.trusted_transport_policy(&mut vm, &fake, "fixture-codex")
                .is_err()
        );
    }
}

#[test]
fn policy_rejects_cross_vm_copies_and_reset_handles() {
    let mut origin = vm_for();
    let host = AuthHost::new(
        fixture_home(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let issued = policy(&mut origin, &host);
    let mut target = vm_for();
    let target_policy = policy(&mut target, &host);
    assert!(
        host.trusted_transport_policy(&mut target, &issued, "fixture-codex")
            .is_err()
    );
    assert!(
        host.trusted_transport_policy(&mut origin, &target_policy, "fixture-codex")
            .is_err()
    );
    let first = host
        .trusted_transport_policy(&mut origin, &issued, "fixture-codex")
        .expect("original");
    origin.reset_for_reuse().expect("reset VM scope");
    assert!(matches!(origin.run().expect("root"), VmStatus::Halted));
    assert!(
        host.trusted_transport_policy(&mut origin, &issued, "fixture-codex")
            .is_err()
    );
    let fresh = policy(&mut origin, &host);
    let second = host
        .trusted_transport_policy(&mut origin, &fresh, "fixture-codex")
        .expect("new owner");
    assert_ne!(first.run_id, second.run_id);
    assert!(
        host.trusted_transport_policy(&mut origin, &issued, "fixture-codex")
            .is_err()
    );
}

#[test]
fn reload_keeps_existing_policy_frozen_and_new_bind_sees_new_credential() {
    let home = fixture_home();
    let host = AuthHost::new(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    let mut old_vm = vm_for();
    let old_handle = policy(&mut old_vm, &host);
    let old = host
        .trusted_transport_policy(&mut old_vm, &old_handle, "fixture-codex")
        .expect("old");
    let config_path = home.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .expect("config")
        .replace("auth: fixture-codex", "auth: new-credential")
        .replace(
            "https://chatgpt.com/backend-api/codex",
            "https://new.example.test/v2",
        );
    fs::write(&config_path, config).expect("rewrite config");
    let auth_path = home.join("auth.yaml");
    fs::write(
        &auth_path,
        fs::read_to_string(&auth_path)
            .expect("auth")
            .replace("fixture-codex:", "new-credential:"),
    )
    .expect("rewrite auth");
    assert_eq!(host.reload().expect("reload"), 2);
    let frozen = host
        .trusted_transport_policy(&mut old_vm, &old_handle, "fixture-codex")
        .expect("frozen");
    assert_eq!(frozen.endpoints, old.endpoints);
    assert_eq!(frozen.run_id, old.run_id);
    assert_eq!(frozen.generation, old.generation);
    assert!(
        host.trusted_transport_policy(&mut old_vm, &old_handle, "new-credential")
            .is_err()
    );
    let mut new_vm = vm_for();
    let new_handle = policy(&mut new_vm, &host);
    let new = host
        .trusted_transport_policy(&mut new_vm, &new_handle, "new-credential")
        .expect("new");
    assert_eq!(new.generation, 2);
    assert_ne!(new.run_id, frozen.run_id);
    assert!(new.endpoints.contains(&TrustedEndpoint {
        authority: "new.example.test".into(),
        path_prefix: "/v2".into()
    }));
    assert!(!new.endpoints.contains(&TrustedEndpoint {
        authority: "chatgpt.com".into(),
        path_prefix: "/backend-api/codex".into()
    }));
    assert!(
        host.trusted_transport_policy(&mut new_vm, &new_handle, "fixture-codex")
            .is_err()
    );
}

#[test]
fn revoked_cancelled_and_expired_owners_cannot_derive_transport() {
    for invalidate in ["revoke", "cancel", "expire"] {
        let mut vm = vm_for();
        let cancellation = RunCancellation::with_timeout(if invalidate == "expire" {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(30)
        });
        let host = AuthHost::new(fixture_home(), cancellation.clone()).expect("host");
        let issued = policy(&mut vm, &host);
        let active = host
            .trusted_transport_policy(&mut vm, &issued, "fixture-codex")
            .expect("active");
        match invalidate {
            "revoke" => host.revoke(),
            "cancel" => cancellation.request(rustscript_agent::CancellationReason::Requested),
            "expire" => std::thread::sleep(
                active.deadline.saturating_duration_since(Instant::now())
                    + Duration::from_millis(5),
            ),
            _ => unreachable!(),
        }
        assert!(
            host.trusted_transport_policy(&mut vm, &issued, "fixture-codex")
                .is_err(),
            "{invalidate}"
        );
    }
}

fn add_provider(home: &Path, name: &str, base_url: &str, id: &str, oauth: &str) {
    let path = home.join("config.yaml");
    let config = fs::read_to_string(&path).expect("config");
    let extra = format!(
        "  {name}:\n    protocol: synthetic\n    base_url: {base_url}\n    auth: {id}\n{oauth}"
    );
    let config = config.replace("workspaces:\n", &format!("{extra}workspaces:\n"));
    assert_ne!(config, fs::read_to_string(&path).expect("original"));
    fs::write(path, config).expect("extra provider");
}

#[test]
fn multiple_credentials_do_not_aggregate_authorities_and_issuer_falls_back_to_base() {
    let home = fixture_home();
    let auth_path = home.join("auth.yaml");
    let original = fs::read_to_string(&auth_path).expect("auth");
    let second = original.replace("fixture-codex:", "fixture-second:");
    fs::write(
        &auth_path,
        format!(
            "{original}{}",
            second
                .strip_prefix("version: 1\ncredentials:\n")
                .expect("credential entry")
        ),
    )
    .expect("auth with second ID");
    add_provider(
        &home,
        "other",
        "https://other.example.test:8443/api",
        "fixture-second",
        "    oauth:\n      authorization_path: /signin\n",
    );
    let host =
        AuthHost::new(home, RunCancellation::with_timeout(Duration::from_secs(30))).expect("host");
    let mut vm = vm_for();
    let issued = policy(&mut vm, &host);
    let first = host
        .trusted_transport_policy(&mut vm, &issued, "fixture-codex")
        .expect("first");
    let second = host
        .trusted_transport_policy(&mut vm, &issued, "fixture-second")
        .expect("second");
    assert_eq!(
        second.endpoints,
        endpoints(&[
            ("other.example.test:8443", "/api"),
            ("other.example.test:8443", "/signin")
        ])
    );
    assert!(
        first
            .endpoints
            .iter()
            .all(|e| e.authority != "other.example.test:8443")
    );
    assert_eq!(first.run_id, second.run_id);
    assert_eq!(first.deadline, second.deadline);
}

#[test]
fn same_credential_multi_provider_cross_authority_overlap_is_denied() {
    for conflicting_path in ["/backend-api/codex", "/backend-api/codex/child"] {
        let home = fixture_home();
        add_provider(
            &home,
            "another",
            &format!("https://another.example.test{conflicting_path}"),
            "fixture-codex",
            "",
        );
        let host = AuthHost::new(home, RunCancellation::with_timeout(Duration::from_secs(30)))
            .expect("host");
        let mut vm = vm_for();
        let issued = policy(&mut vm, &host);
        let failure = host
            .trusted_transport_policy(&mut vm, &issued, "fixture-codex")
            .expect_err("cross-authority overlap");
        assert!(failure.to_string().contains("transport_endpoint_ambiguous"));
    }
}

#[test]
fn same_credential_duplicate_endpoint_on_same_authority_is_deduplicated() {
    let home = fixture_home();
    add_provider(
        &home,
        "another",
        "https://chatgpt.com/backend-api/codex",
        "fixture-codex",
        "",
    );
    let host =
        AuthHost::new(home, RunCancellation::with_timeout(Duration::from_secs(30))).expect("host");
    let mut vm = vm_for();
    let issued = policy(&mut vm, &host);
    let trusted = host
        .trusted_transport_policy(&mut vm, &issued, "fixture-codex")
        .expect("same authority");
    assert_eq!(
        trusted
            .endpoints
            .iter()
            .filter(|e| e.authority == "chatgpt.com" && e.path_prefix == "/backend-api/codex")
            .count(),
        1
    );
}
