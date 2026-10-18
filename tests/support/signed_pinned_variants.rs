//! Minimal signed-package preparation fixture for the six-variant acceptance.
//! Reuses original RSS bytes; never changes host policy or tool business logic.

use std::fs;
use std::path::PathBuf;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::plugins::{
    GraphLock, HOST_RUNTIME, InstallAuthorization, PackageRequirement, PackageStore, PublisherKey,
    ResolveRequest,
};

pub fn signed_search_variant() -> (PackageStore, GraphLock) {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"))
        .join(format!("six-search-{}", uuid::Uuid::new_v4()));
    let package = root.join("package-a");
    fs::create_dir_all(&package).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [&root, &package] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let authorization = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".to_string(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let store = PackageStore::open(root.join("packages")).unwrap();
    fs::write(
        package.join("manifest.yaml"),
        r#"format: rustscript.plugin/v1
id: org.rustscript.tools.varianta
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: run.rss
  export: run
dependencies: []
capabilities:
  - workspace.read
  - clock.read
effects:
  contract: agent.effects/v1
  entries:
    run:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
        - kind: clock.read
          scope: bound_run
          recovery: none
      delegated: []
"#,
    )
    .unwrap();
    // Exact shipped leaf/types: do not trim overflow branches to evade charging.
    fs::write(
        package.join("types.rss"),
        include_bytes!("../../rss/tools/types.rss"),
    )
    .unwrap();
    fs::write(
        package.join("leaf.rss"),
        include_bytes!("../../rss/tools/search_files.rss"),
    )
    .unwrap();
    fs::write(
        package.join("run.rss"),
        r#"use self::leaf::{invoke};
use self::types as types;

pub fn run(context: map) -> map {
    let mut changed: map = context;
    let mut arguments: map = types::map_map(context, "arguments");
    arguments.pattern = "alpha.txt";
    changed.arguments = arguments;
    invoke(changed)
}
"#,
    )
    .unwrap();
    let signature = pair.sign(&store.signature_payload(&package).unwrap());
    fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(&package, &authorization).unwrap();
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.varianta".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: HOST_RUNTIME.to_string(),
        })
        .unwrap();
    (store, lock)
}
