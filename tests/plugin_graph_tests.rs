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
fn shared_constraint_backtracks_across_later_roots() {
    let root = temp_dir("shared-backtrack");
    let store = PackageStore::open(root.join("store")).unwrap();
    let signer = signer();
    for version in ["1.0.0", "2.0.0"] {
        write_signed(
            &store,
            &signer,
            &root.join(version),
            &library_manifest("org.rustscript.lib.shared", version, "length"),
            &[(
                "length.rss",
                "pub fn length(value: string) -> int { value.length }\n",
            )],
        );
    }
    for (name, requirement) in [("a", ">=1.0.0, <3.0.0"), ("b", "^1.0.0")] {
        write_signed(
            &store,
            &signer,
            &root.join(name),
            &tool_manifest(
                &format!("org.rustscript.tools.{name}"),
                "1.0.0",
                &format!(
                    "  - alias: shared\n    id: org.rustscript.lib.shared\n    version: \"{requirement}\"\n"
                ),
                "      direct: []\n      delegated: []\n",
                "",
            ),
            &[("invoke.rss", "pub fn invoke(value: int) -> int { value }\n")],
        );
    }
    let request = ResolveRequest {
        roots: ["a", "b"]
            .iter()
            .map(|name| PackageRequirement {
                id: format!("org.rustscript.tools.{name}"),
                version: "1.0.0".to_string(),
            })
            .collect(),
        host_runtime: "0.1.0".to_string(),
    };
    let lock = store.resolve(&request);
    assert!(
        lock.is_ok(),
        "shared constraints have a complete solution: {lock:?}"
    );
    let lock = lock.unwrap();
    assert_eq!(lock.packages.len(), 3);
    let shared = lock
        .packages
        .iter()
        .find(|package| package.id == "org.rustscript.lib.shared")
        .unwrap();
    assert_eq!(shared.version, "1.0.0");
    assert_eq!(lock.edges.len(), 2);
    for edge in &lock.edges {
        assert_eq!(edge.to, shared.id);
        assert_eq!(edge.to_version, shared.version);
        assert_eq!(edge.to_artifact_id, shared.artifact_id);
    }
    let mut packages = store.load_installed().unwrap();
    let only_a = ResolveRequest {
        roots: vec![request.roots[0].clone()],
        ..request.clone()
    };
    let greedy = resolve_installed(&packages, &only_a).unwrap();
    assert_eq!(
        greedy
            .packages
            .iter()
            .find(|package| package.id == shared.id)
            .unwrap()
            .version,
        "2.0.0"
    );
    for reverse_packages in [false, true] {
        if reverse_packages {
            packages.reverse();
        }
        for reverse_roots in [false, true] {
            let mut permuted = request.clone();
            if reverse_roots {
                permuted.roots.reverse();
            }
            assert_eq!(
                resolve_installed(&packages, &permuted)
                    .unwrap()
                    .semantic_yaml(),
                lock.semantic_yaml()
            );
        }
    }
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

fn graph_package(name: &str, version: &str, deps: &[(&str, &str)]) -> InstalledPackage {
    let dependencies = deps.iter().enumerate().map(|(index, (target, requirement))| {
        format!("  - alias: dep{index}\n    id: org.rustscript.tools.{target}\n    version: \"{requirement}\"\n")
    }).collect::<String>();
    let manifest = parse_plugin_manifest(&tool_manifest(
        &format!("org.rustscript.tools.{name}"),
        version,
        &dependencies,
        "      direct: []\n      delegated: []\n",
        "",
    ))
    .unwrap();
    InstalledPackage::new(
        &format!("pkg-{name}-{version}"),
        manifest,
        BTreeMap::from([(
            "invoke.rss".to_string(),
            b"pub fn invoke(value: int) -> int { value }\n".to_vec(),
        )]),
    )
}

fn graph_request(names: &[&str]) -> ResolveRequest {
    ResolveRequest {
        roots: names
            .iter()
            .map(|name| PackageRequirement {
                id: format!("org.rustscript.tools.{name}"),
                version: "*".to_string(),
            })
            .collect(),
        host_runtime: "0.1.0".to_string(),
    }
}

#[test]
fn parent_candidate_backtracks_without_stale_dependencies_or_bounds() {
    let mut packages = vec![
        graph_package("a", "2.0.0", &[("c", "^2"), ("stale", "*")]),
        graph_package("a", "1.0.0", &[("c", "^1")]),
        graph_package("b", "1.0.0", &[("c", "^1")]),
        graph_package("c", "1.0.0", &[]),
        graph_package("c", "2.0.0", &[]),
        graph_package("stale", "1.0.0", &[("orphan", "*")]),
        graph_package("orphan", "1.0.0", &[]),
    ];
    for package in &mut packages {
        let (effects, capabilities) = match package.manifest.id.as_str() {
            "org.rustscript.tools.c" => (
                "      direct:\n        - kind: clock.read\n          scope: bound_run\n          recovery: none\n      delegated: []\n",
                "  - clock.read\n",
            ),
            "org.rustscript.tools.a" | "org.rustscript.tools.b" => (
                "      direct: []\n      delegated:\n        - dependency: dep0\n          entry: invoke\n          allow:\n            - kind: clock.read\n              scope: bound_run\n              recovery: none\n",
                "",
            ),
            "org.rustscript.tools.stale" => (
                "      direct:\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint\n      delegated: []\n",
                "  - workspace.write\n",
            ),
            _ => continue,
        };
        let deps = package
            .manifest
            .dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "  - alias: {}\n    id: {}\n    version: \"{}\"\n",
                    dependency.alias, dependency.id, dependency.version,
                )
            })
            .collect::<String>();
        package.manifest = parse_plugin_manifest(&tool_manifest(
            &package.manifest.id,
            &package.manifest.version,
            &deps,
            effects,
            capabilities,
        ))
        .unwrap();
    }
    let request = graph_request(&["a", "b"]);
    let high = resolve_installed(&packages, &graph_request(&["a"])).unwrap();
    assert_eq!(high.packages.len(), 4);
    assert!(high.semantic_yaml().contains("workspace.fs.write"));
    let lock = resolve_installed(&packages, &request).unwrap();
    assert_eq!(
        lock.packages
            .iter()
            .map(|package| (package.id.as_str(), package.version.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("org.rustscript.tools.a", "1.0.0"),
            ("org.rustscript.tools.b", "1.0.0"),
            ("org.rustscript.tools.c", "1.0.0"),
        ]
    );
    assert_eq!(lock.edges.len(), 2);
    assert_eq!(lock.closure.len(), 3);
    assert!(lock.closure.iter().all(|entry| entry.effects.len() == 1));
    for entry in &lock.closure {
        let effect = &entry.effects[0];
        assert_eq!(effect.kind, "clock.read");
        assert_eq!(effect.scope, "bound_run");
        assert_eq!(effect.recovery, "none");
        assert_eq!(effect.via.callee_package, "org.rustscript.tools.c");
        assert_eq!(effect.via.callee_version, "1.0.0");
        assert_eq!(effect.via.caller_package, entry.package);
        assert_eq!(
            effect.via.relation,
            if entry.package == "org.rustscript.tools.c" {
                "direct"
            } else {
                "plugin"
            }
        );
    }
    assert!(!lock.semantic_yaml().contains("workspace.fs.write"));
    assert!(!lock.semantic_yaml().contains("stale"));
    assert!(!lock.semantic_yaml().contains("orphan"));
    let mut permuted = packages.clone();
    permuted.reverse();
    for package in &mut permuted {
        package.manifest.dependencies.reverse();
    }
    assert_eq!(
        resolve_installed(&permuted, &graph_request(&["b", "a"]))
            .unwrap()
            .semantic_yaml(),
        lock.semantic_yaml()
    );
}

#[test]
fn work_budget_is_not_refunded_when_later_roots_reject_candidates() {
    let mut packages = Vec::new();
    let names = (0..12)
        .map(|index| format!("a{index:02}"))
        .collect::<Vec<_>>();
    for name in &names {
        for version in ["1.0.0", "2.0.0"] {
            packages.push(graph_package(name, version, &[]));
        }
    }
    packages.push(graph_package("z", "1.0.0", &[("a00", "^3")]));
    let mut roots = names.iter().map(String::as_str).collect::<Vec<_>>();
    roots.push("z");
    let error = resolve_installed(&packages, &graph_request(&roots)).unwrap_err();
    assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
    assert_eq!(error.chain, vec!["decision_nodes"]);
}

#[test]
fn exhausted_work_reports_budget_even_at_a_conflict_boundary() {
    let packages = vec![
        graph_package("a", "1.0.0", &[]),
        graph_package("b", "1.0.0", &[]),
    ];
    // 1364 enqueues + two four-unit first visits + 1361 two-unit
    // selected checks + a final two-unit conflicting check = 4096.
    let mut request = graph_request(&["a"]);
    request.roots.extend(graph_request(&vec!["b"; 1362]).roots);
    request.roots.push(PackageRequirement {
        id: "org.rustscript.tools.b".to_string(),
        version: "^2".to_string(),
    });
    let error = resolve_installed(&packages, &request).unwrap_err();
    assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
    assert_eq!(error.chain, vec!["decision_nodes"]);
}

#[test]
fn unsatisfiable_shared_constraints_keep_both_requirements_in_the_chain() {
    let packages = vec![
        graph_package("a", "2.0.0", &[("c", "^2")]),
        graph_package("a", "1.0.0", &[("c", "^1")]),
        graph_package("b", "1.0.0", &[("c", "^3")]),
        graph_package("c", "1.0.0", &[]),
        graph_package("c", "2.0.0", &[]),
        graph_package("c", "3.0.0", &[]),
    ];
    let error = resolve_installed(&packages, &graph_request(&["a", "b"])).unwrap_err();
    assert_eq!(error.kind, PluginErrorKind::Conflict);
    assert_eq!(
        error.chain,
        vec![
            "org.rustscript.tools.a requires org.rustscript.tools.c ^2",
            "org.rustscript.tools.b requires org.rustscript.tools.c ^3",
        ]
    );
}

#[test]
fn shared_nodes_are_rechecked_for_depth_on_every_access_path() {
    for prefix_len in [14, 15] {
        let mut packages = vec![
            graph_package("a", "1.0.0", &[("tail", "*")]),
            graph_package("tail", "1.0.0", &[]),
        ];
        for index in 0..prefix_len {
            let target = if index + 1 == prefix_len {
                "a".to_string()
            } else {
                format!("z{:02}", index + 1)
            };
            packages.push(graph_package(
                &format!("z{index:02}"),
                "1.0.0",
                &[(&target, "*")],
            ));
        }
        let result = resolve_installed(&packages, &graph_request(&["a", "z00"]));
        if prefix_len == 14 {
            assert_eq!(result.unwrap().packages.len(), 16);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
            assert_eq!(error.chain, vec!["depth"]);
        }
    }
}

#[test]
fn structural_candidate_failures_can_use_a_legal_parent_alternative() {
    for failure in ["missing", "cycle", "depth", "edges", "packages"] {
        let mut packages = vec![graph_package("a", "1.0.0", &[])];
        let high = match failure {
            "missing" => graph_package("a", "2.0.0", &[("absent", "*")]),
            "cycle" => {
                packages.push(graph_package("b", "1.0.0", &[("a", "*")]));
                graph_package("a", "2.0.0", &[("b", "*")])
            }
            "depth" => {
                for index in 0..16 {
                    let next = format!("d{:02}", index + 1);
                    let deps = if index == 15 {
                        vec![]
                    } else {
                        vec![(next.as_str(), "*")]
                    };
                    packages.push(graph_package(&format!("d{index:02}"), "1.0.0", &deps));
                }
                graph_package("a", "2.0.0", &[("d00", "*")])
            }
            "edges" => {
                packages.push(graph_package("leaf", "1.0.0", &[]));
                graph_package("a", "2.0.0", &vec![("leaf", "*"); 257])
            }
            "packages" => {
                let names = (0..64)
                    .map(|index| format!("p{index:02}"))
                    .collect::<Vec<_>>();
                for name in &names {
                    packages.push(graph_package(name, "1.0.0", &[]));
                }
                let deps = names
                    .iter()
                    .map(|name| (name.as_str(), "*"))
                    .collect::<Vec<_>>();
                graph_package("a", "2.0.0", &deps)
            }
            _ => unreachable!(),
        };
        packages.push(high);
        let request = graph_request(&["a"]);
        let lock = resolve_installed(&packages, &request).unwrap();
        assert_eq!(lock.packages.len(), 1, "{failure}");
        assert_eq!(lock.packages[0].version, "1.0.0", "{failure}");
        assert!(lock.edges.is_empty(), "{failure}");
        assert_eq!(lock.closure.len(), 1, "{failure}");
        // Without the alternative, preserve the actual structural diagnostic.
        packages.retain(|package| {
            !(package.manifest.id == "org.rustscript.tools.a"
                && package.manifest.version == "1.0.0")
        });
        let error = resolve_installed(&packages, &request).unwrap_err();
        match failure {
            "missing" => assert_kind(error, PluginErrorKind::MissingDependency),
            "cycle" => {
                assert_eq!(error.kind, PluginErrorKind::Cycle);
                assert_eq!(
                    error.chain,
                    vec![
                        "org.rustscript.tools.a",
                        "org.rustscript.tools.b",
                        "org.rustscript.tools.a"
                    ]
                );
            }
            bound => {
                assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
                assert_eq!(error.chain, vec![bound]);
            }
        }
    }
}

#[test]
fn package_edge_and_version_limits_accept_the_boundary() {
    let names = (0..65)
        .map(|index| format!("p{index:02}"))
        .collect::<Vec<_>>();
    let mut packages = names
        .iter()
        .map(|name| graph_package(name, "1.0.0", &[]))
        .collect::<Vec<_>>();
    let roots = names.iter().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        resolve_installed(&packages, &graph_request(&roots[..64]))
            .unwrap()
            .packages
            .len(),
        64
    );
    let error = resolve_installed(&packages, &graph_request(&roots)).unwrap_err();
    assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
    assert_eq!(error.chain, vec!["packages"]);
    for count in [256, 257] {
        let graph = vec![
            graph_package("a", "1.0.0", &vec![("leaf", "*"); count]),
            graph_package("leaf", "1.0.0", &[]),
        ];
        let result = resolve_installed(&graph, &graph_request(&["a"]));
        if count == 256 {
            assert_eq!(result.unwrap().edges.len(), 256);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
            assert_eq!(error.chain, vec!["edges"]);
        }
    }
    packages = (0..32)
        .map(|index| graph_package("a", &format!("1.0.{index}"), &[]))
        .collect();
    assert_eq!(
        resolve_installed(&packages, &graph_request(&["a"]))
            .unwrap()
            .packages[0]
            .version,
        "1.0.31"
    );
}

#[test]
fn repeated_selected_checks_share_the_same_finite_work_budget() {
    let packages = vec![graph_package("a", "1.0.0", &[])];
    assert!(resolve_installed(&packages, &graph_request(&vec!["a"; 1364])).is_ok());
    let error = resolve_installed(&packages, &graph_request(&vec!["a"; 1365])).unwrap_err();
    assert_eq!(error.kind, PluginErrorKind::BudgetExceeded);
    assert_eq!(error.chain, vec!["decision_nodes"]);
}

#[test]
fn host_compatibility_and_duplicate_metadata_remain_fail_closed() {
    let low = graph_package("a", "1.0.0", &[]);
    let mut high = graph_package("a", "2.0.0", &[]);
    high.manifest = parse_plugin_manifest(
        &tool_manifest(
            "org.rustscript.tools.a",
            "2.0.0",
            "",
            "      direct: []\n      delegated: []\n",
            "",
        )
        .replace(">=0.1.0, <0.2.0", ">=0.2.0, <0.3.0"),
    )
    .unwrap();
    assert_eq!(
        resolve_installed(&[low.clone(), high.clone()], &graph_request(&["a"]))
            .unwrap()
            .packages[0]
            .version,
        "1.0.0"
    );
    assert_kind(
        resolve_installed(&[high], &graph_request(&["a"])).unwrap_err(),
        PluginErrorKind::ContractIncompatible,
    );
    let duplicate = low.clone();
    let packages = vec![
        graph_package("parent", "1.0.0", &[]),
        graph_package("parent", "2.0.0", &[("a", "*")]),
        low,
        duplicate,
    ];
    assert_kind(
        resolve_installed(&packages, &graph_request(&["parent"])).unwrap_err(),
        PluginErrorKind::Ambiguous,
    );
}

#[test]
fn effect_authority_failure_does_not_fallback_to_a_pure_candidate() {
    let mut high = graph_package("a", "2.0.0", &[]);
    high.manifest = parse_plugin_manifest(&tool_manifest(
        "org.rustscript.tools.a", "2.0.0",
        "  - alias: writer\n    id: org.rustscript.tools.writer\n    version: \"*\"\n",
        "      direct: []\n      delegated:\n        - dependency: writer\n          entry: invoke\n          allow: []\n", "",
    )).unwrap();
    let mut writer = graph_package("writer", "1.0.0", &[]);
    writer.manifest = parse_plugin_manifest(&tool_manifest(
        "org.rustscript.tools.writer", "1.0.0", "",
        "      direct:\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: checkpoint\n      delegated: []\n", "  - workspace.write\n",
    )).unwrap();
    let packages = vec![graph_package("a", "1.0.0", &[]), high, writer];
    assert_kind(
        resolve_installed(&packages, &graph_request(&["a"])).unwrap_err(),
        PluginErrorKind::UndeclaredTransitiveEffect,
    );
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
