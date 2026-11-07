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
                harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: id.clone(),
                },
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

#[allow(dead_code)]
pub fn stage_write_pair(root: &Path) -> (InstallAuthorization, String, String, String) {
    let scratch = PackageStore::open(root.join(".sign-scratch")).unwrap();
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
    for (name, id, marker, state) in [
        ("package-a", "org.rustscript.tools.effecta", "A-write", ""),
        ("package-b", "org.rustscript.tools.effectb", "B-write", ""),
        (
            "package-state",
            "org.rustscript.tools.effectstate",
            "S-write",
            "state:\n  scope: run\n  schema: 1\n",
        ),
    ] {
        let package = root.join(name);
        fs::create_dir_all(&package).unwrap();
        fs::write(
            package.join("manifest.yaml"),
            format!(
                "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n{state}"
            ),
        )
        .unwrap();
        fs::write(package.join("run.rss"), write_tool_source(marker)).unwrap();
        if state.is_empty() {
            fs::write(
                package.join("catalog.rss"),
                include_bytes!("../../rss/tools/types.rss"),
            )
            .unwrap();
        }
        let signature = pair.sign(&scratch.signature_payload(&package).unwrap());
        fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
    }
    (
        auth,
        "package-a".into(),
        "package-b".into(),
        "package-state".into(),
    )
}

#[allow(dead_code)]
fn write_tool_source(marker: &str) -> String {
    format!(
        r#"
fn map_string(value: map, key: string, fallback: string) -> string {{
    let mut result: string = fallback;
    if value.has(key) {{
        if type(value[key]) == "string" {{
            let coerced: string = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_map(value: map, key: string) -> map {{
    let mut result: map = {{}};
    if value.has(key) {{
        if type(value[key]) == "map" {{
            let coerced: map = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_int(value: map, key: string, fallback: int) -> int {{
    let mut result: int = fallback;
    if value.has(key) {{
        if type(value[key]) == "int" {{
            let coerced: int = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_bool(value: map, key: string, fallback: bool) -> bool {{
    let mut result: bool = fallback;
    if value.has(key) {{
        if type(value[key]) == "bool" {{
            let coerced: bool = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn fail_result(value: map) -> map {{
    let error: map = map_map(value, "error");
    let code: string = map_string(error, "code", "read_failed");
    let message: string = map_string(error, "message", "read failed");
    let err: map = {{ code: code, message: message }};
    {{ ok: false, content: "", data: {{}}, error: err, truncated: false, artifacts: [] }}
}}

fn commit_result(token: string, result: map) -> map {{
    let committed: map = agent_runtime::tool_commit(token, result);
    if map_string(committed, "kind", "") == "committed" => {{
        map_map(committed, "result")
    }} else if map_bool(committed, "ok", false) == false => {{
        committed
    }} else => {{
        result
    }}
}}

fn read_file_call(context: map, prepare: map) -> map {{
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if map_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {{
            commit_result(token, fail_result(meta))
        }} else => {{
            let file_len: int = map_int(meta, "len", 0);
            let read: map = cap::fs_read_range(token, path, 0, file_len);
            if map_bool(read, "ok", false) == false => {{
                commit_result(token, fail_result(read))
            }} else => {{
                let text: string = bytes::to_utf8(read.bytes);
                let result: map = {{ ok: true, content: text, data: {{}}, error: null, truncated: false, artifacts: [] }};
                commit_result(token, result)
            }}
        }}
    }}
}}

fn write_file_call(context: map, prepare: map) -> map {{
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if map_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let payload: bytes = bytes::from_utf8("{marker}\n");
        let written: map = cap::fs_write_atomic(token, path, "*", payload);
        if map_bool(written, "ok", false) == false => {{
            written
        }} else => {{
            let meta: map = cap::fs_metadata(token, path);
            if map_bool(meta, "ok", false) == false => {{
                meta
            }} else => {{
                let file_len: int = map_int(meta, "len", 0);
                let read: map = cap::fs_read_range(token, path, 0, file_len);
                if map_bool(read, "ok", false) == false => {{
                    read
                }} else => {{
                    let text: string = bytes::to_utf8(read.bytes);
                    let result: map = {{ ok: true, content: text, data: {{}}, error: null, truncated: false, artifacts: [] }};
                    commit_result(token, result)
                }}
            }}
        }}
    }}
}}

pub fn run(context: map) -> map {{
    let prepare: map = map_map(context, "prepare");
    let name: string = map_string(prepare, "name", "");
    if name == "read_file" => {{
        read_file_call(context, prepare)
    }} else if name == "write_file" => {{
        write_file_call(context, prepare)
    }} else => {{
        let err: map = {{ code: "tool_not_supported", message: "signed fixture rejects undeclared tool name" }};
        {{ ok: false, content: "", data: {{}}, error: err, truncated: false, artifacts: [] }}
    }}
}}
"#,
    )
}

// ---- T16 legal tool+leaf graph fixture ----
pub const LIBRARY_TOOL_ID: &str = "org.rustscript.tools.casread";
pub const LIBRARY_TOOL_DIR: &str = "package-casread";
pub const LIBRARY_LEAF_DIR: &str = "package-casleaf";

pub fn stage_library_pair(root: &Path) -> InstallAuthorization {
    let scratch = PackageStore::open(root.join(".sign-scratch")).unwrap();
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
    let leaf_manifest = "format: rustscript.plugin/v1\nid: org.rustscript.lib.castext\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n";
    let tool_manifest = "format: rustscript.plugin/v1\nid: org.rustscript.tools.casread\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: org.rustscript.lib.castext\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n";
    let leaf_source = "pub fn format(value: string) -> string { \"lib:\" + value }\n";
    let tool_source = include_str!("library_tool_source.rss");
    let catalog = include_bytes!("../../rss/tools/types.rss");
    for (dir, manifest, files) in [
        (
            LIBRARY_LEAF_DIR,
            leaf_manifest,
            vec![("format.rss", leaf_source.as_bytes())],
        ),
        (
            LIBRARY_TOOL_DIR,
            tool_manifest,
            vec![
                ("run.rss", tool_source.as_bytes()),
                ("catalog.rss", catalog),
            ],
        ),
    ] {
        let package = root.join(dir);
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("manifest.yaml"), manifest).unwrap();
        for (name, body) in files {
            fs::write(package.join(name), body).unwrap();
        }
        let payload = scratch.signature_payload(&package).unwrap();
        fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
    }
    auth
}
