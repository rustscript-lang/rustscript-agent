use super::*;
use crate::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, effects::ResourceQuota};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::Ordering,
};

#[tokio::test(flavor = "multi_thread")]
async fn managed_fresh_startup_census_is_quota_bounded_not_incidental_clock_bounded() {
    let path = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("census-{}", uuid::Uuid::new_v4().simple()));
    let source = path.join("source");
    let home = path.join("home");
    fs::create_dir_all(source.join("a/b/empty")).unwrap();
    fs::create_dir(&home).unwrap();
    for directory in [&path, &home] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for index in 0..64 {
        fs::write(source.join(format!("a/b/f{index}")), b"retained-bytes").unwrap();
    }
    fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",source.display(),source.display())).unwrap();
    fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600)).unwrap();
    let managed = ManagedWorkspaceConfig {
        source_root: source,
        quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
        retention: Default::default(),
    };
    let config = AgentGatewayConfig {
        managed_workspace: Some(managed.clone()),
        ..Default::default()
    };
    let database = path.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &database)
        .unwrap()
        .with_workspace_home(&home);
    let run = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: serde_json::json!({"message":"retain a nontrivial tree"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    drop(run);
    state.service().shutdown().await.unwrap();
    drop(state);
    let persistence = GatewayPersistence::open(&config, &database).unwrap();
    persistence.load().unwrap();
    let store = path.join(".gateway.sqlite.effects");
    let root = ConfinedFsRoot::new(&store).unwrap();
    let store_id = fs::read_to_string(store.join("store-id")).unwrap();
    let objects = persistence.managed_object_census().unwrap();
    assert_eq!(objects.len(), 1);
    let tree = store.join("trees").join(&objects[0].object_id);
    let mut census = StartupCensus::new();
    census.deadline = EffectDeadline::at(Instant::now());
    assert!(census.deadline.check().is_err());
    let reopened =
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census);
    assert!(
        reopened.is_ok(),
        "a complete within-quota retained tree must reopen even with an expired incidental startup clock: {:?}",
        reopened.err()
    );
    assert!(
        census.checks.load(Ordering::Acquire) > 64,
        "the fresh physical FD traversal must really run"
    );
    // Live invocation scanning still requires its original finite deadline.
    let descriptor = ConfinedFsRoot::new(&tree)
        .unwrap()
        .duplicate_descriptor()
        .unwrap();
    assert!(
        tree_store::copy_tree_from_fd(
            &descriptor,
            &path.join("expired-copy"),
            &managed.quota,
            &EffectCancellation::default(),
            &census.deadline,
            true,
        )
        .is_err()
    );
    for quota in [
        ResourceQuota::new(1, 1048576, 16).unwrap(),
        ResourceQuota::new(1000, 1, 16).unwrap(),
        ResourceQuota::new(1000, 1048576, 1).unwrap(),
    ] {
        let mut tighter = managed.clone();
        tighter.quota = quota;
        assert!(
            ManagedObjectLeaseRegistry::open(&tighter, &root, &persistence, &store_id, &census)
                .is_err()
        );
    }
    let unknown = format!("tree-{}", uuid::Uuid::new_v4().simple());
    let unknown_path = store.join("trees").join(&unknown);
    fs::create_dir(&unknown_path).unwrap();
    fs::write(unknown_path.join("orphan"), b"unknown").unwrap();
    let registry =
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census)
            .unwrap();
    assert!(registry.state.lock().entries[&unknown].unknown);
    assert_eq!(registry.state.lock().used.objects, 2);
    let charged = registry.state.lock().used.bytes;
    drop(registry);
    let mut tight = managed.clone();
    tight.retention.max_objects = 1;
    assert!(
        ManagedObjectLeaseRegistry::open(&tight, &root, &persistence, &store_id, &census).is_err()
    );
    tight = managed.clone();
    tight.retention.max_bytes = charged - 1;
    assert!(
        ManagedObjectLeaseRegistry::open(&tight, &root, &persistence, &store_id, &census).is_err()
    );
    symlink("/outside", unknown_path.join("link")).unwrap();
    assert!(
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census)
            .is_err()
    );
    fs::remove_file(unknown_path.join("link")).unwrap();
    fs::write(unknown_path.join("bad."), b"bad").unwrap();
    assert!(
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census)
            .is_err()
    );
    fs::remove_file(unknown_path.join("bad.")).unwrap();
    fs::hard_link(unknown_path.join("orphan"), path.join("outside-hardlink")).unwrap();
    assert!(
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census)
            .is_err()
    );
    fs::remove_file(path.join("outside-hardlink")).unwrap();
    fs::set_permissions(tree.join("a/b"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(tree.join("a/b/extra-empty"), b"").unwrap();
    assert!(
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census)
            .is_err(),
        "entry-count mismatch is corruption even with identical byte totals"
    );
    fs::remove_file(tree.join("a/b/extra-empty")).unwrap();
    let file = tree.join("a/b/f0");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, b"corrupt-size").unwrap();
    assert!(
        ManagedObjectLeaseRegistry::open(&managed, &root, &persistence, &store_id, &census)
            .is_err(),
        "physical/durable mismatch cannot be accepted"
    );
    assert!(unknown_path.join("orphan").exists());
    assert_eq!(
        fs::read(&file).unwrap(),
        b"corrupt-size",
        "census never deletes or repairs evidence"
    );
    persistence.shutdown();
}
