//! Signed wrappers vary inputs while retaining the shipped business/type bytes.
use std::{fs, path::Path, sync::Arc};

use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rustscript_agent::plugins::{
    GraphLock, HOST_RUNTIME, InstallAuthorization, PackageArtifactRef, PackageRequirement,
    PackageStore, PublisherKey, ResolveRequest,
};

pub fn artifact_refs(lock: &GraphLock) -> Vec<PackageArtifactRef> {
    lock.packages
        .iter()
        .map(|p| PackageArtifactRef {
            package_id: p.id.clone(),
            version: p.version.clone(),
            kind: p.kind.clone(),
            artifact_id: p.artifact_id.clone(),
        })
        .collect()
}

pub fn install_pair(
    root: &Path,
    tool: &str,
    overflow: bool,
) -> (Arc<PackageStore>, GraphLock, GraphLock) {
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let leaf: &[u8] = match tool {
        "search_files" => include_bytes!("../../rss/tools/search_files.rss"),
        "write_file" => include_bytes!("../../rss/tools/write_file.rss"),
        "patch" => include_bytes!("../../rss/tools/patch.rss"),
        "terminal" => include_bytes!("../../rss/tools/terminal.rss"),
        "process" => include_bytes!("../../rss/tools/process.rss"),
        _ => panic!("unexpected tool"),
    };
    let mut locks = Vec::new();
    for variant in ["a", "b"] {
        let id = format!("org.rustscript.tools.effect{variant}");
        let package = root.join(format!("package-{variant}"));
        fs::create_dir_all(&package).unwrap();
        let (capabilities, effects) = if matches!(tool, "terminal" | "process") {
            (
                "  - process.spawn\n  - clock.read\n",
                "        - kind: process.spawn\n          scope: bound_process\n          recovery: none\n",
            )
        } else if tool == "search_files" {
            (
                "  - workspace.read\n  - clock.read\n",
                "        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n",
            )
        } else {
            (
                "  - workspace.read\n  - workspace.write\n  - clock.read\n",
                "        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n",
            )
        };
        fs::write(package.join("manifest.yaml"), format!("format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n{capabilities}effects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n{effects}        - kind: clock.read\n          scope: bound_run\n          recovery: none\n      delegated: []\n")).unwrap();
        fs::write(package.join("leaf.rss"), leaf).unwrap();
        fs::write(
            package.join("types.rss"),
            include_bytes!("../../rss/tools/types.rss"),
        )
        .unwrap();
        let marker = variant.to_ascii_uppercase();
        let change = match tool {
            "search_files" if overflow => "arguments.pattern = \"*\";".to_string(),
            "search_files" => format!("arguments.pattern = \"{variant}*.txt\";"),
            "write_file" => format!("arguments.content = \"{marker}-write\\n\";"),
            "patch" => format!("arguments.new_string = \"{marker}-patch\";"),
            "terminal" if overflow => format!(
                "arguments.argv = [\"/bin/printf\", \"{marker}-{}\\n\"];",
                "x".repeat(1200)
            ),
            "terminal" => format!("arguments.argv = [\"/bin/printf\", \"{marker}-terminal\\n\"];"),
            "process" if overflow => format!(
                "if types::map_string(arguments, \"action\", \"\") == \"write\" {{ arguments.data = \"{marker}-{}\\n\"; }}",
                "x".repeat(1200)
            ),
            "process" => format!(
                "if types::map_string(arguments, \"action\", \"\") == \"write\" {{ arguments.data = \"{marker}-stdin\\n\"; }}"
            ),
            _ => unreachable!(),
        };
        let extra_import = if tool == "process" {
            fs::write(
                package.join("terminal.rss"),
                include_bytes!("../../rss/tools/terminal.rss"),
            )
            .unwrap();
            "use self::terminal as terminal;\n"
        } else {
            ""
        };
        let invoke = if tool == "process" {
            "if types::map_string(prepare, \"name\", \"\") == \"terminal\" => { terminal::invoke(changed) } else => { leaf::invoke(changed) }"
        } else {
            "leaf::invoke(changed)"
        };
        let config = if overflow && matches!(tool, "terminal" | "process") {
            "changed.config = { max_output_bytes: 800, max_stream_bytes: 4096 };"
        } else if overflow {
            "changed.config = { max_tool_output_bytes: 512 };"
        } else {
            ""
        };
        let source = format!(
            "use self::leaf as leaf;\nuse self::types as types;\n{extra_import}pub fn run(context: map) -> map {{\n    let mut changed: map = context;\n    let prepare: map = types::map_map(context, \"prepare\");\n    let mut arguments: map = types::map_map(context, \"arguments\");\n    {change}\n    changed.arguments = arguments;\n    {config}\n    {invoke}\n}}\n"
        );
        fs::write(package.join("run.rss"), source).unwrap();
        let signature = pair.sign(&store.signature_payload(&package).unwrap());
        fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
        store.install(&package, &auth).unwrap();
        let lock = store
            .resolve(&ResolveRequest {
                roots: vec![PackageRequirement {
                    id: id.clone(),
                    version: "1.0.0".into(),
                }],
                host_runtime: HOST_RUNTIME.into(),
            })
            .unwrap();
        let prepared = store.prepare(&lock).unwrap();
        assert_eq!(prepared.captured_source(&id, "leaf.rss").unwrap(), leaf);
        assert_eq!(
            prepared.captured_source(&id, "types.rss").unwrap(),
            include_bytes!("../../rss/tools/types.rss")
        );
        assert_eq!(
            prepared.trust(&id),
            Some(rustscript_agent::plugins::PackageTrust::AcceptedPublisher)
        );
        locks.push(lock);
    }
    (store, locks.remove(0), locks.remove(0))
}
