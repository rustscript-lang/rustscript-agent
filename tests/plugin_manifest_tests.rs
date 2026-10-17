//! Strict plugin manifest and immutable package-store boundary.
//!
//! These tests exercise the real parser and store. Schema agreement lives in
//! `plugin_schema_sync_tests`; activation and control-plane storage are absent.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::plugins::{
    InstallAuthorization, PackageStore, PluginErrorKind, PublisherKey, parse_plugin_manifest,
};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> FixtureDir {
    let root =
        PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
    let dir = root.join(format!(
        "plugin-manifest-{}-{}-{}",
        std::process::id(),
        label,
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir)
        .unwrap_or_else(|err| panic!("fixture {} must be a new directory: {err}", dir.display()));
    FixtureDir { path: dir }
}

struct FixtureDir {
    path: PathBuf,
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

impl std::ops::Deref for FixtureDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

fn pure_manifest() -> String {
    r#"format: rustscript.plugin/v1
id: org.rustscript.lib.text
version: 1.0.0
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: normalize.rss
  export: normalize
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    normalize:
      direct: []
      delegated: []
"#
    .to_string()
}

fn write_manifest() -> String {
    r#"format: rustscript.plugin/v1
id: org.rustscript.tools.files
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: invoke.rss
  export: invoke
dependencies: []
capabilities:
  - workspace.read
  - workspace.write
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
        - kind: workspace.fs.write
          scope: bound_workspace
          recovery: checkpoint
      delegated: []
state:
  scope: run
  schema: 1
"#
    .to_string()
}

fn assert_kind(
    result: Result<impl std::fmt::Debug, rustscript_agent::plugins::PluginError>,
    kind: PluginErrorKind,
) {
    let err = result.expect_err("boundary must reject");
    assert_eq!(err.kind, kind, "{err:?}");
}

fn effect_manifest(id: &str, capability: &str, kind: &str, scope: &str, recovery: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: invoke.rss
  export: invoke
dependencies: []
capabilities:
  - {capability}
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: {kind}
          scope: {scope}
          recovery: {recovery}
      delegated: []
"#
    )
}

#[test]
fn duplicate_manifest_field_is_rejected() {
    let yaml = pure_manifest().replace(
        "format: rustscript.plugin/v1\n",
        "format: rustscript.plugin/v1\nformat: rustscript.plugin/v1\n",
    );
    assert_kind(
        parse_plugin_manifest(&yaml),
        PluginErrorKind::DuplicateField,
    );
}

#[test]
fn yaml_alias_tag_and_merge_are_rejected_before_json() {
    assert_kind(
        parse_plugin_manifest("anchor: &a 1\nformat: *a\n"),
        PluginErrorKind::YamlAlias,
    );
    assert_kind(
        parse_plugin_manifest("format: !!str rustscript.plugin/v1\n"),
        PluginErrorKind::YamlTag,
    );
    assert_kind(
        parse_plugin_manifest("<<: {format: rustscript.plugin/v1}\n"),
        PluginErrorKind::YamlMerge,
    );
}

#[test]
fn missing_effects_unknown_effect_and_forged_recovery_are_rejected() {
    let missing = pure_manifest().replace(
        "effects:\n  contract: agent.effects/v1\n  entries:\n    normalize:\n      direct: []\n      delegated: []\n",
        "",
    );
    assert_kind(
        parse_plugin_manifest(&missing),
        PluginErrorKind::MissingEffects,
    );
    let unknown = write_manifest().replace("workspace.fs.write", "filesystem");
    assert_kind(
        parse_plugin_manifest(&unknown),
        PluginErrorKind::UnknownEffect,
    );
    let forged = write_manifest().replace(
        "kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint",
        "kind: delivery.send\n          scope: bound_delivery\n          recovery: checkpoint",
    );
    assert_kind(
        parse_plugin_manifest(&forged),
        PluginErrorKind::ForgedRecovery,
    );
}

#[test]
fn remote_write_and_process_spawn_cannot_claim_checkpoint_recovery() {
    let remote = effect_manifest(
        "org.rustscript.tools.remote",
        "remote.write",
        "remote.write",
        "bound_run",
        "checkpoint",
    );
    assert_kind(
        parse_plugin_manifest(&remote),
        PluginErrorKind::ForgedRecovery,
    );
    let process = effect_manifest(
        "org.rustscript.tools.proc",
        "process.spawn",
        "process.spawn",
        "bound_process",
        "checkpoint",
    );
    assert_kind(
        parse_plugin_manifest(&process),
        PluginErrorKind::ForgedRecovery,
    );
    let replay = effect_manifest(
        "org.rustscript.tools.clock",
        "clock.read",
        "clock.read",
        "bound_run",
        "replay",
    );
    assert_kind(
        parse_plugin_manifest(&replay),
        PluginErrorKind::ForgedRecovery,
    );
    assert!(
        parse_plugin_manifest(&effect_manifest(
            "org.rustscript.tools.remote",
            "remote.write",
            "remote.write",
            "bound_run",
            "none",
        ))
        .is_ok()
    );
    assert!(
        parse_plugin_manifest(&effect_manifest(
            "org.rustscript.tools.proc",
            "process.spawn",
            "process.spawn",
            "bound_process",
            "none",
        ))
        .is_ok()
    );
}

#[test]
fn extra_public_effect_entry_is_rejected() {
    let extra = pure_manifest().replace(
        "    normalize:\n      direct: []\n      delegated: []\n",
        "    normalize:\n      direct: []\n      delegated: []\n    other:\n      direct: []\n      delegated: []\n",
    );
    assert_kind(
        parse_plugin_manifest(&extra),
        PluginErrorKind::UncoveredExport,
    );
}

#[test]
fn uncovered_export_and_unknown_security_field_are_rejected() {
    let uncovered = pure_manifest().replace("normalize:", "other:");
    assert_kind(
        parse_plugin_manifest(&uncovered),
        PluginErrorKind::UncoveredExport,
    );
    let unknown = pure_manifest().replace(
        "host_abi: agent.cap/v1\n",
        "host_abi: agent.cap/v1\ngrant: true\n",
    );
    assert_kind(
        parse_plugin_manifest(&unknown),
        PluginErrorKind::UnknownField,
    );
}

#[test]
fn path_escape_in_entry_is_rejected() {
    let escaped = pure_manifest().replace("path: normalize.rss", "path: ../secret.rss");
    assert_kind(parse_plugin_manifest(&escaped), PluginErrorKind::PathEscape);
}

#[test]
fn explicit_empty_effects_and_restricted_write_entry_are_accepted() {
    let pure = parse_plugin_manifest(&pure_manifest()).expect("pure entry");
    let entry = &pure.effects.entries["normalize"];
    assert!(entry.direct.is_empty());
    assert!(entry.delegated.is_empty());
    assert_eq!(pure.publisher, "org.rustscript");
    let write = parse_plugin_manifest(&write_manifest()).expect("restricted write");
    assert_eq!(write.effects.entries["invoke"].direct.len(), 2);
    assert_eq!(write.state.as_ref().unwrap().scope, "run");
    assert!(
        write
            .declared_capabilities()
            .iter()
            .all(|cap: &String| cap.starts_with("workspace."))
    );
}

fn publisher_key() -> (Ed25519KeyPair, PublisherKey) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key = PublisherKey {
        publisher: "org.rustscript".to_string(),
        verifying_key: pair.public_key().as_ref().to_vec(),
    };
    (pair, key)
}

fn write_package(dir: &Path, manifest: &str, files: &[(&str, &str)]) {
    fs::write(dir.join("manifest.yaml"), manifest).unwrap();
    for (name, body) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }
}

fn signed_auth(key: PublisherKey) -> InstallAuthorization {
    InstallAuthorization {
        admin: true,
        accepted_publishers: vec![key],
        unsigned_dev_space: None,
    }
}

#[test]
fn missing_publisher_authorization_is_rejected() {
    let root = temp_dir("store");
    let store = PackageStore::open(root.join("store")).unwrap();
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let unauthorized = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: None,
    };
    assert_kind(
        store.install(&package, &unauthorized),
        PluginErrorKind::PublisherUnauthorized,
    );
}

#[test]
fn symlink_package_install_is_rejected() {
    let root = temp_dir("symlink");
    let store = PackageStore::open(root.join("store")).unwrap();
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let (_pair, key) = publisher_key();
    let link = root.join("linked-pkg");
    std::os::unix::fs::symlink(&package, &link).unwrap();
    assert_kind(
        store.install(&link, &signed_auth(key)),
        PluginErrorKind::SymlinkDenied,
    );
}

#[test]
fn signed_overwrite_is_rejected() {
    let root = temp_dir("overwrite");
    let store = PackageStore::open(root.join("store")).unwrap();
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let (pair, key) = publisher_key();
    let signature = pair.sign(&store.signature_payload(&package).unwrap());
    fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
    let first = store.install(&package, &signed_auth(key.clone())).unwrap();
    assert_eq!(
        first.trust,
        rustscript_agent::plugins::PackageTrust::AcceptedPublisher
    );
    assert_eq!(first.declared_capabilities(), Vec::<String>::new());
    fs::write(
        package.join("normalize.rss"),
        "pub fn normalize(value: int) -> int { value + 1 }\n",
    )
    .unwrap();
    let signature = pair.sign(&store.signature_payload(&package).unwrap());
    fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
    assert_kind(
        store.install(&package, &signed_auth(key)),
        PluginErrorKind::VersionOverwrite,
    );
}

#[test]
fn fixture_cleanup_does_not_reuse_or_delete_a_sibling() {
    let tmp =
        PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
    let sibling = tmp.join(format!("preexisting-sibling-{}", std::process::id()));
    fs::write(&sibling, b"keep").unwrap();
    let first = temp_dir("reentry");
    let first_path = first.to_path_buf();
    let second = temp_dir("reentry");
    assert_ne!(first_path, second.to_path_buf());
    drop(first);
    assert!(
        !first_path.exists(),
        "owned cleanup removes only the fixture"
    );
    assert_eq!(fs::read(&sibling).unwrap(), b"keep");
    let third = temp_dir("reentry");
    assert_ne!(third.to_path_buf(), first_path);
    let _ = fs::remove_file(&sibling);
}

#[test]
fn unsigned_dev_import_stays_inside_granted_space_and_does_not_gain_capability() {
    let root = temp_dir("dev");
    let dev = root.join("dev-space");
    let package = dev.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &write_manifest(),
        &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
    );
    let store = PackageStore::open(root.join("store")).unwrap();
    let outside = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(root.join("other")),
    };
    fs::create_dir_all(root.join("other")).unwrap();
    assert_kind(
        store.install(&package, &outside),
        PluginErrorKind::PublisherUnauthorized,
    );
    let granted = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(dev),
    };
    let revision = store.install(&package, &granted).unwrap();
    assert_eq!(
        revision.trust,
        rustscript_agent::plugins::PackageTrust::DevUnsigned
    );
    assert_eq!(
        revision.declared_capabilities(),
        vec!["workspace.read".to_string(), "workspace.write".to_string()]
    );
    assert!(revision.artifact_id.starts_with("pkg-"));
}

fn artifact_dir(store_root: &Path, artifact_id: &str) -> PathBuf {
    store_root.join("artifacts").join(artifact_id)
}

#[test]
fn load_rejects_source_replaced_after_install() {
    let root = temp_dir("replace-source");
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let store_root = root.join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let granted = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(root.to_path_buf()),
    };
    let revision = store.install(&package, &granted).unwrap();
    fs::write(
        artifact_dir(&store_root, &revision.artifact_id).join("sources/normalize.rss"),
        "pub fn normalize(value: int) -> int { 0 }\n",
    )
    .unwrap();
    assert!(
        store.load_installed().is_err(),
        "replaced store bytes must not load as the installed artifact"
    );
}

#[test]
fn load_rejects_manifest_symlink_substitution() {
    let root = temp_dir("manifest-symlink");
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let store_root = root.join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let granted = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(root.to_path_buf()),
    };
    let revision = store.install(&package, &granted).unwrap();
    let dir = artifact_dir(&store_root, &revision.artifact_id);
    let manifest = dir.join("manifest.yaml");
    let real = dir.join("manifest.yaml.real");
    fs::rename(&manifest, &real).unwrap();
    std::os::unix::fs::symlink(&real, &manifest).unwrap();
    assert!(
        store.load_installed().is_err(),
        "manifest symlink must not be followed"
    );
}

#[test]
fn replaced_trust_label_does_not_become_publisher_proof() {
    let root = temp_dir("trust-label");
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let store_root = root.join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let granted = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(root.to_path_buf()),
    };
    let revision = store.install(&package, &granted).unwrap();
    fs::write(
        artifact_dir(&store_root, &revision.artifact_id).join("trust"),
        "accepted-publisher",
    )
    .unwrap();
    match store.load_installed() {
        Ok(packages) => assert_eq!(
            packages[0].trust,
            rustscript_agent::plugins::PackageTrust::DevUnsigned
        ),
        Err(err) => assert_eq!(err.kind, PluginErrorKind::PublisherUnauthorized),
    }
}

#[test]
fn preexisting_artifact_is_not_reused_without_byte_equality() {
    let root = temp_dir("preseed");
    let package = root.join("pkg");
    fs::create_dir_all(&package).unwrap();
    write_package(
        &package,
        &pure_manifest(),
        &[(
            "normalize.rss",
            "pub fn normalize(value: int) -> int { value }\n",
        )],
    );
    let store_root = root.join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let granted = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(root.to_path_buf()),
    };
    let revision = store.install(&package, &granted).unwrap();
    fs::write(
        artifact_dir(&store_root, &revision.artifact_id).join("sources/normalize.rss"),
        "pub fn normalize(value: int) -> int { 9 }\n",
    )
    .unwrap();
    assert!(
        store.install(&package, &granted).is_err(),
        "existing object must not be reused when its bytes differ"
    );
}
