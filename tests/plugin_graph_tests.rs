//! Dependency lock, effect closure, and real closed RSS entry preparation.
//!
//! Service activation and control-plane storage are not part of this slice.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::plugins::{
    InstallAuthorization, InstalledPackage, PackageRequirement, PackageStore, PackageTrust,
    PluginErrorKind, PublisherKey, ResolveRequest, parse_plugin_manifest, resolve_installed,
};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> FixtureDir {
    let root =
        PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
    let dir = root.join(format!(
        "plugin-graph-{}-{}-{}",
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

fn assert_kind(err: rustscript_agent::plugins::PluginError, kind: PluginErrorKind) {
    assert_eq!(err.kind, kind, "{err:?}");
    assert!(
        !err.chain.is_empty(),
        "typed error must carry a chain: {err:?}"
    );
}

struct Signer {
    pair: Ed25519KeyPair,
    key: PublisherKey,
}

fn signer() -> Signer {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key = PublisherKey {
        publisher: "org.rustscript".to_string(),
        verifying_key: pair.public_key().as_ref().to_vec(),
    };
    Signer { pair, key }
}

fn auth(signer: &Signer, dev: Option<PathBuf>) -> InstallAuthorization {
    InstallAuthorization {
        admin: true,
        accepted_publishers: vec![signer.key.clone()],
        unsigned_dev_space: dev,
    }
}

fn library_manifest(id: &str, version: &str, export: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: {version}
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: {export}.rss
  export: {export}
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    {export}:
      direct: []
      delegated: []
"#
    )
}

fn tool_manifest(id: &str, version: &str, deps: &str, effects: &str, capabilities: &str) -> String {
    let capabilities = if capabilities.is_empty() {
        "capabilities: []\n".to_string()
    } else {
        format!("capabilities:\n{capabilities}")
    };
    let dependencies = if deps.is_empty() {
        "dependencies: []\n".to_string()
    } else {
        format!("dependencies:\n{deps}")
    };
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: {version}
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: invoke.rss
  export: invoke
{dependencies}{capabilities}effects:
  contract: agent.effects/v1
  entries:
    invoke:
{effects}state:
  scope: run
  schema: 1
"#
    )
}

fn write_signed(
    store: &PackageStore,
    signer: &Signer,
    dir: &Path,
    manifest: &str,
    files: &[(&str, &str)],
) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), manifest).unwrap();
    for (name, body) in files {
        fs::write(dir.join(name), body).unwrap();
    }
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer, None)).unwrap();
}

#[test]
fn missing_conflict_and_cycle_return_minimal_chains() {
    let root = temp_dir("errors");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    write_signed(
        &store,
        &signer,
        &root.join("lib1"),
        &library_manifest("org.rustscript.lib.text", "1.0.0", "length"),
        &[(
            "length.rss",
            "pub fn length(value: string) -> int { value.length }\n",
        )],
    );
    write_signed(
        &store,
        &signer,
        &root.join("lib2"),
        &library_manifest("org.rustscript.lib.text", "2.0.0", "length"),
        &[(
            "length.rss",
            "pub fn length(value: string) -> int { value.length }\n",
        )],
    );
    let low = tool_manifest(
        "org.rustscript.tools.low",
        "1.0.0",
        "  - alias: text\n    id: org.rustscript.lib.text\n    version: \">=1.0.0, <2.0.0\"\n",
        "      direct: []\n      delegated: []\n",
        "",
    );
    let high = tool_manifest(
        "org.rustscript.tools.high",
        "1.0.0",
        "  - alias: text\n    id: org.rustscript.lib.text\n    version: \">=2.0.0, <3.0.0\"\n",
        "      direct: []\n      delegated: []\n",
        "",
    );
    write_signed(
        &store,
        &signer,
        &root.join("low"),
        &low,
        &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
    );
    write_signed(
        &store,
        &signer,
        &root.join("high"),
        &high,
        &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
    );
    let missing = store.resolve(&ResolveRequest {
        roots: vec![PackageRequirement {
            id: "org.rustscript.missing".to_string(),
            version: "1.0.0".to_string(),
        }],
        host_runtime: "0.1.0".to_string(),
    });
    assert_kind(missing.unwrap_err(), PluginErrorKind::MissingDependency);

    let conflict = store.resolve(&ResolveRequest {
        roots: vec![
            PackageRequirement {
                id: "org.rustscript.tools.low".to_string(),
                version: "1.0.0".to_string(),
            },
            PackageRequirement {
                id: "org.rustscript.tools.high".to_string(),
                version: "1.0.0".to_string(),
            },
        ],
        host_runtime: "0.1.0".to_string(),
    });
    let err = conflict.unwrap_err();
    assert_kind(err.clone(), PluginErrorKind::Conflict);
    let chain = err.chain.join("\n");
    assert!(chain.contains("org.rustscript.lib.text"), "{chain}");
    assert!(
        chain.contains("<2.0.0") && chain.contains(">=2.0.0"),
        "{chain}"
    );

    let left = tool_manifest(
        "org.rustscript.tools.left",
        "1.0.0",
        "  - alias: right\n    id: org.rustscript.tools.right\n    version: \"1.0.0\"\n",
        "      direct: []\n      delegated:\n        - dependency: right\n          entry: invoke\n          allow: []\n",
        "",
    );
    let right = tool_manifest(
        "org.rustscript.tools.right",
        "1.0.0",
        "  - alias: left\n    id: org.rustscript.tools.left\n    version: \"1.0.0\"\n",
        "      direct: []\n      delegated:\n        - dependency: left\n          entry: invoke\n          allow: []\n",
        "",
    );
    write_signed(
        &store,
        &signer,
        &root.join("left"),
        &left,
        &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
    );
    write_signed(
        &store,
        &signer,
        &root.join("right"),
        &right,
        &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
    );
    let cycle = store.resolve(&ResolveRequest {
        roots: vec![PackageRequirement {
            id: "org.rustscript.tools.left".to_string(),
            version: "1.0.0".to_string(),
        }],
        host_runtime: "0.1.0".to_string(),
    });
    assert_kind(cycle.unwrap_err(), PluginErrorKind::Cycle);
}

#[test]
fn duplicate_version_candidates_are_ambiguous() {
    let manifest = parse_plugin_manifest(&library_manifest(
        "org.rustscript.lib.text",
        "1.0.0",
        "length",
    ))
    .unwrap();
    let sources = BTreeMap::from([(
        "length.rss".to_string(),
        b"pub fn length(value: string) -> int { value.length }\n".to_vec(),
    )]);
    let packages = vec![
        InstalledPackage::new("pkg-a", manifest.clone(), sources.clone()),
        InstalledPackage::new("pkg-b", manifest, sources),
    ];
    let err = resolve_installed(
        &packages,
        &ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.lib.text".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        },
    )
    .unwrap_err();
    assert_kind(err, PluginErrorKind::Ambiguous);
}

#[test]
fn install_order_does_not_change_the_lock_and_closure_is_exact() {
    let signer = signer();
    let build = |label: &str, order: &[&str]| {
        let root = temp_dir(label);
        let store = PackageStore::open(root.join("store")).unwrap();
        let files = BTreeMap::from([
            (
                "text",
                (
                    library_manifest("org.rustscript.lib.text", "1.0.0", "length"),
                    vec![(
                        "length.rss",
                        "pub fn length(value: string) -> int { value.length }\n",
                    )],
                ),
            ),
            (
                "files",
                (
                    tool_manifest(
                        "org.rustscript.tools.files",
                        "1.0.0",
                        "",
                        "      direct:\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint\n      delegated: []\n",
                        "  - workspace.write\n",
                    ),
                    vec![(
                        "invoke.rss",
                        "pub fn invoke(token: string) -> map {\n    cap::fs_write_atomic(token, \"a.txt\", \"*\", bytes::from_utf8(\"hi\"))\n}\n",
                    )],
                ),
            ),
            (
                "caller",
                (
                    tool_manifest(
                        "org.rustscript.tools.caller",
                        "1.0.0",
                        "  - alias: text\n    id: org.rustscript.lib.text\n    version: \">=1.0.0, <2.0.0\"\n  - alias: files\n    id: org.rustscript.tools.files\n    version: \"1.0.0\"\n",
                        "      direct: []\n      delegated:\n        - dependency: files\n          entry: invoke\n          allow:\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: checkpoint\n",
                        "",
                    ),
                    vec![(
                        "invoke.rss",
                        "pub fn invoke(value: string) -> int { value.length }\n",
                    )],
                ),
            ),
        ]);
        for name in order {
            let (manifest, sources) = &files[name];
            write_signed(&store, &signer, &root.join(name), manifest, sources);
        }
        let lock = store
            .resolve(&ResolveRequest {
                roots: vec![PackageRequirement {
                    id: "org.rustscript.tools.caller".to_string(),
                    version: "1.0.0".to_string(),
                }],
                host_runtime: "0.1.0".to_string(),
            })
            .unwrap();
        let closure = lock.closure_kinds("org.rustscript.tools.caller", "invoke");
        assert_eq!(closure, vec!["workspace.fs.write".to_string()]);
        assert!(lock.semantic_yaml().contains("relation: plugin"));
        assert!(lock.semantic_yaml().contains("relation: library"));
        lock.semantic_yaml()
    };
    let forward = build("forward", &["text", "files", "caller"]);
    let reverse = build("reverse", &["caller", "files", "text"]);
    assert_eq!(forward, reverse);
}

#[test]
fn lock_persists_caller_entry_alias_requirement_and_distinct_provenance() {
    let root = temp_dir("edge-fields");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    write_signed(
        &store,
        &signer,
        &root.join("files"),
        &tool_manifest(
            "org.rustscript.tools.files",
            "1.2.3",
            "",
            "      direct:\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint\n      delegated: []\n",
            "  - workspace.write\n",
        ),
        &[(
            "invoke.rss",
            "pub fn invoke(token: string) -> map {\n    cap::fs_write_atomic(token, \"a.txt\", \"*\", bytes::from_utf8(\"hi\"))\n}\n",
        )],
    );
    write_signed(
        &store,
        &signer,
        &root.join("caller"),
        &tool_manifest(
            "org.rustscript.tools.caller",
            "1.0.0",
            "  - alias: files\n    id: org.rustscript.tools.files\n    version: \">=1.0.0, <2.0.0\"\n",
            "      direct: []\n      delegated:\n        - dependency: files\n          entry: invoke\n          allow:\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: checkpoint\n",
            "",
        ),
        &[(
            "invoke.rss",
            "pub fn invoke(value: string) -> int { value.length }\n",
        )],
    );
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.caller".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let yaml = lock.semantic_yaml();
    assert!(yaml.contains("alias: files"), "{yaml}");
    assert!(yaml.contains("from_entry: invoke"), "{yaml}");
    assert!(yaml.contains("to_entry: invoke"), "{yaml}");
    assert!(
        yaml.contains("version_requirement: \">=1.0.0, <2.0.0\""),
        "{yaml}"
    );
    assert!(yaml.contains("to_version: 1.2.3"), "{yaml}");
    assert!(yaml.contains("scope: bound_workspace"), "{yaml}");
    assert!(
        !yaml.lines().any(|line| line.trim() == "via: delegated"),
        "{yaml}"
    );
}

#[test]
fn prepare_does_not_compile_store_bytes_replaced_after_install() {
    let root = temp_dir("prepare-replaced");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    let source = "pub fn invoke(value: int) -> int { value + 1 }\n";
    write_signed(
        &store,
        &signer,
        &root.join("tool"),
        &tool_manifest(
            "org.rustscript.tools.pure",
            "1.0.0",
            "",
            "      direct: []\n      delegated: []\n",
            "",
        ),
        &[("invoke.rss", source)],
    );
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.pure".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let artifact = root
        .join("store/artifacts")
        .join(&lock.packages[0].artifact_id);
    fs::write(
        artifact.join("sources/invoke.rss"),
        "pub fn invoke(value: int) -> int { 0 }\n",
    )
    .unwrap();
    let prepared = store.prepare(&lock).unwrap();
    assert_eq!(
        prepared.captured_source("org.rustscript.tools.pure", "invoke.rss"),
        Some(source.as_bytes()),
        "prepare must compile the verified capture, not the replaced store bytes"
    );
}

#[test]
fn undeclared_transitive_effect_is_rejected() {
    let root = temp_dir("transitive");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    write_signed(
        &store,
        &signer,
        &root.join("files"),
        &tool_manifest(
            "org.rustscript.tools.files",
            "1.0.0",
            "",
            "      direct:\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint\n      delegated: []\n",
            "  - workspace.write\n",
        ),
        &[(
            "invoke.rss",
            "pub fn invoke(token: string) -> map {\n    cap::fs_write_atomic(token, \"a.txt\", \"*\", bytes::from_utf8(\"hi\"))\n}\n",
        )],
    );
    write_signed(
        &store,
        &signer,
        &root.join("caller"),
        &tool_manifest(
            "org.rustscript.tools.caller",
            "1.0.0",
            "  - alias: files\n    id: org.rustscript.tools.files\n    version: \"1.0.0\"\n",
            "      direct: []\n      delegated:\n        - dependency: files\n          entry: invoke\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n",
            "",
        ),
        &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
    );
    let err = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.caller".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap_err();
    assert_kind(err, PluginErrorKind::UndeclaredTransitiveEffect);
}

#[test]
fn prepare_rejects_undeclared_direct_effect_unauthorized_host_and_pure_disguise() {
    let root = temp_dir("prepare-deny");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    write_signed(
        &store,
        &signer,
        &root.join("disguise"),
        &tool_manifest(
            "org.rustscript.tools.disguise",
            "1.0.0",
            "",
            "      direct: []\n      delegated: []\n",
            "",
        ),
        &[(
            "invoke.rss",
            "pub fn invoke(token: string) -> map {\n    cap::fs_write_atomic(token, \"a.txt\", \"*\", bytes::from_utf8(\"hi\"))\n}\n",
        )],
    );
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.disguise".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    assert_eq!(
        store.prepare(&lock).unwrap_err().kind,
        PluginErrorKind::UndeclaredDirectEffect
    );

    write_signed(
        &store,
        &signer,
        &root.join("sqlite"),
        &tool_manifest(
            "org.rustscript.tools.sqlite",
            "1.0.0",
            "",
            "      direct: []\n      delegated: []\n",
            "",
        ),
        &[(
            "invoke.rss",
            "use sqlite;\npub fn invoke(value: int) -> int { value }\n",
        )],
    );
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.sqlite".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    assert_eq!(
        store.prepare(&lock).unwrap_err().kind,
        PluginErrorKind::UnauthorizedHostImport
    );
}

#[test]
fn prepare_uses_captured_source_and_compiles_the_closed_entry() {
    let root = temp_dir("prepare-ok");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    let source = "pub fn invoke(value: int) -> int { value + 1 }\n";
    let dir = root.join("tool");
    write_signed(
        &store,
        &signer,
        &dir,
        &tool_manifest(
            "org.rustscript.tools.pure",
            "1.0.0",
            "",
            "      direct: []\n      delegated: []\n",
            "",
        ),
        &[("invoke.rss", source)],
    );
    fs::write(
        dir.join("invoke.rss"),
        "pub fn invoke(value: int) -> int { 0 }\n",
    )
    .unwrap();
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.pure".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let prepared = store.prepare(&lock).unwrap();
    assert_eq!(
        prepared.captured_source("org.rustscript.tools.pure", "invoke.rss"),
        Some(source.as_bytes())
    );
    assert!(
        prepared
            .entry_callable("org.rustscript.tools.pure")
            .is_some()
    );
    assert_eq!(
        prepared.trust("org.rustscript.tools.pure"),
        Some(PackageTrust::AcceptedPublisher)
    );
}

#[test]
fn plugin_import_cannot_bypass_the_broker_boundary() {
    let root = temp_dir("bypass");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    write_signed(
        &store,
        &signer,
        &root.join("files"),
        &tool_manifest(
            "org.rustscript.tools.files",
            "1.0.0",
            "",
            "      direct:\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint\n      delegated: []\n",
            "  - workspace.write\n",
        ),
        &[(
            "invoke.rss",
            "pub fn invoke(token: string) -> map {\n    cap::fs_write_atomic(token, \"a.txt\", \"*\", bytes::from_utf8(\"hi\"))\n}\n",
        )],
    );
    write_signed(
        &store,
        &signer,
        &root.join("caller"),
        &tool_manifest(
            "org.rustscript.tools.caller",
            "1.0.0",
            "  - alias: files\n    id: org.rustscript.tools.files\n    version: \"1.0.0\"\n",
            "      direct: []\n      delegated:\n        - dependency: files\n          entry: invoke\n          allow:\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: checkpoint\n",
            "",
        ),
        &[(
            "invoke.rss",
            "use files::invoke::{invoke};\npub fn invoke(token: string) -> map { invoke(token) }\n",
        )],
    );
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.caller".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    assert_eq!(
        store.prepare(&lock).unwrap_err().kind,
        PluginErrorKind::PluginBoundaryBypass
    );
}

fn prepare_policy_source(
    manifest: &str,
    source: &str,
) -> Result<(), rustscript_agent::plugins::PluginError> {
    parse_plugin_manifest(manifest)?;
    let root = temp_dir("completion-policy");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    write_signed(
        &store,
        &signer,
        &root.join("package"),
        manifest,
        &[("invoke.rss", source)],
    );
    let lock = store.resolve(&ResolveRequest {
        roots: vec![PackageRequirement {
            id: "org.rustscript.tools.policy".to_string(),
            version: "1.0.0".to_string(),
        }],
        host_runtime: "0.1.0".to_string(),
    })?;
    store.prepare(&lock).map(|_| ())
}

#[test]
fn signed_tool_wait_requires_declared_bound_run_clock() {
    let source = "pub fn invoke(value: int) -> int { agent::sleep_ms(value) }\n";
    let manifest = tool_manifest(
        "org.rustscript.tools.policy",
        "1.0.0",
        "",
        "      direct:\n        - kind: clock.read\n          scope: bound_run\n          recovery: none\n      delegated: []\n",
        "  - clock.read\n",
    );
    prepare_policy_source(&manifest, source).unwrap();
    let undeclared = tool_manifest(
        "org.rustscript.tools.policy",
        "1.0.0",
        "",
        "      direct: []\n      delegated: []\n",
        "",
    );
    assert_kind(
        prepare_policy_source(&undeclared, source).unwrap_err(),
        PluginErrorKind::UndeclaredDirectEffect,
    );
    assert_kind(
        prepare_policy_source(
            &manifest.replace("scope: bound_run", "scope: bound_workspace"),
            source,
        )
        .unwrap_err(),
        PluginErrorKind::UnknownEffect,
    );
}

#[test]
fn signed_completion_protocol_is_role_fenced_and_generic_artifacts_stay_denied() {
    let manifest = tool_manifest(
        "org.rustscript.tools.policy",
        "1.0.0",
        "",
        "      direct: []\n      delegated: []\n",
        "",
    );
    let result = "pub fn invoke(token: string) -> map { cap::artifact_put_result(token, bytes::from_utf8(\"result\"), {}) }\n";
    prepare_policy_source(&manifest, result).unwrap();
    let library = manifest
        .replace("kind: tool", "kind: library")
        .replace("contract: agent.tool/v1", "contract: agent.library/v1");
    let harness = manifest
        .replace("kind: tool", "kind: harness")
        .replace("contract: agent.tool/v1", "contract: agent.harness/v1");
    for source in [
        result,
        "pub fn invoke(value: map) -> map { agent_runtime::tool_prepare(value) }\n",
        "pub fn invoke(token: string) -> map { agent_runtime::tool_commit(token, {}) }\n",
        "pub fn invoke(value: int) -> int { agent::sleep_ms(value) }\n",
    ] {
        // Harness packages are not an installable role in this manifest contract.
        assert_kind(
            prepare_policy_source(&harness, source).unwrap_err(),
            PluginErrorKind::UnknownField,
        );
        assert_kind(
            prepare_policy_source(&library, source).unwrap_err(),
            PluginErrorKind::UnauthorizedHostImport,
        );
    }
    for source in [
        "pub fn invoke(token: string) -> map { cap::artifact_put(token, bytes::from_utf8(\"result\"), {}) }\n",
        "pub fn invoke(token: string) -> map { cap::artifact_get(token, \"id\") }\n",
        "pub fn invoke(token: string) -> map { cap::artifact_reference(token, \"id\") }\n",
    ] {
        assert_kind(
            prepare_policy_source(&manifest, source).unwrap_err(),
            PluginErrorKind::UnauthorizedHostImport,
        );
    }
}

#[test]
fn resolver_budget_is_a_typed_error() {
    let mut packages = Vec::new();
    for version in 0..33 {
        let manifest = parse_plugin_manifest(&library_manifest(
            "org.rustscript.lib.text",
            &format!("1.0.{version}"),
            "length",
        ))
        .unwrap();
        packages.push(InstalledPackage::new(
            &format!("pkg-{version}"),
            manifest,
            BTreeMap::from([(
                "length.rss".to_string(),
                b"pub fn length(value: string) -> int { value.length }\n".to_vec(),
            )]),
        ));
    }
    let err = resolve_installed(
        &packages,
        &ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.lib.text".to_string(),
                version: ">=1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, PluginErrorKind::BudgetExceeded);
    assert!(
        err.chain
            .iter()
            .any(|item: &String| item.contains("versions_per_package")),
        "{err:?}"
    );
}
