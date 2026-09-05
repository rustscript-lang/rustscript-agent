//! Task 0F architecture tests: RSS owns static tool dispatch.
//!
//! These tests inspect the production source/module graph *and* exercise the
//! real host catalog / agent compile path. They must fail while any native
//! tool domain remains.

use std::fs;
use std::path::{Path, PathBuf};

use rustscript_agent::{AgentConfig, AgentRunner, agent_host_catalog, bundled_tool_entries};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!("read {}: {error}", dir.display());
    });
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn production_src_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk_rs_files(&crate_root().join("src"), &mut files);
    files.sort();
    files
}

fn is_module_declaration(line: &str, name: &str) -> bool {
    let trimmed = line.trim();
    trimmed == format!("pub mod {name};")
        || trimmed == format!("mod {name};")
        || trimmed == format!("pub(crate) mod {name};")
}

#[test]
fn production_src_tools_directory_is_absent() {
    let tools = crate_root().join("src/tools");
    assert!(
        !tools.exists(),
        "native tool domain must be deleted; found {}",
        tools.display()
    );
}

#[test]
fn production_lib_does_not_declare_tools_module() {
    let lib = fs::read_to_string(crate_root().join("src/lib.rs")).expect("src/lib.rs");
    let declared = lib.lines().any(|line| is_module_declaration(line, "tools"));
    assert!(
        !declared,
        "src/lib.rs must not declare a tools module:\n{lib}"
    );
}

#[test]
fn production_host_catalog_has_no_name_keyed_tool_dispatch() {
    let catalog = agent_host_catalog();
    let names: Vec<&str> = catalog
        .functions()
        .iter()
        .map(|schema| schema.name.as_str())
        .collect();
    let dispatch = names
        .iter()
        .copied()
        .filter(|name| name.contains("tool_dispatch") || *name == "agent::tool_dispatch")
        .collect::<Vec<_>>();
    assert!(
        dispatch.is_empty(),
        "host catalog still exposes name-keyed tool dispatch: {dispatch:?} (full={names:?})"
    );
    for required in [
        "agent_runtime::tool_prepare",
        "agent_runtime::tool_commit",
        "cap::fs_read_range",
        "cap::process_spawn",
        "cap::artifact_put",
        "agent::control_check",
        "agent::provider_call",
    ] {
        assert!(
            names.contains(&required),
            "missing generic host function {required}; have {names:?}"
        );
    }
}

#[test]
fn production_rust_has_no_native_tool_executor_domain() {
    let mut hits = Vec::new();
    for path in production_src_files() {
        let text = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("read {}: {error}", path.display());
        });
        for needle in [
            "NativeToolExecutor",
            "NativeToolRegistry",
            "builtin_tool_registry",
            "BUILTIN_TOOL_ORDER",
            "agent::tool_dispatch",
            "NativeExecutorContract",
            "DispatchContext",
        ] {
            if text.contains(needle) {
                hits.push(format!("{}: {needle}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "native tool domain remnants remain:\n{}",
        hits.join("\n")
    );
}

#[test]
fn production_rust_does_not_match_public_tool_names_for_execution() {
    let mut hits = Vec::new();
    let patterns = [
        "\"read_file\" =>",
        "\"search_files\" =>",
        "\"write_file\" =>",
        "\"patch\" =>",
        "\"terminal\" =>",
        "\"process\" =>",
        "NativeToolExecutor::ReadFile",
        "NativeToolExecutor::SearchFiles",
        "NativeToolExecutor::WriteFile",
        "NativeToolExecutor::Patch",
        "NativeToolExecutor::Terminal",
        "NativeToolExecutor::Process",
    ];
    for path in production_src_files() {
        let text = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("read {}: {error}", path.display());
        });
        for needle in patterns {
            if text.contains(needle) {
                hits.push(format!("{}: {needle}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "public-name execution dispatch remains in production Rust:\n{}",
        hits.join("\n")
    );
}

#[test]
fn production_agent_calls_rss_tools_dispatch() {
    let main = fs::read_to_string(crate_root().join("rss/agent/main.rss"))
        .expect("rss/agent/main.rss must exist");
    assert!(
        main.contains("tools::dispatch"),
        "production agent must invoke tools::dispatch; source:\n{main}"
    );
    assert!(
        !main.contains("agent::tool_dispatch"),
        "production agent must not invoke agent::tool_dispatch"
    );
}

#[test]
fn production_rss_dispatch_module_exists() {
    let path = crate_root().join("rss/tools/dispatch.rss");
    assert!(
        path.is_file(),
        "rss/tools/dispatch.rss must exist at {}",
        path.display()
    );
}

#[test]
fn production_agent_compiles_dispatch_and_tool_modules_from_file() {
    let path = crate_root().join("rss/agent/main.rss");
    AgentRunner::from_file(&path, AgentConfig::default()).unwrap_or_else(|error| {
        panic!("production agent must compile dispatch + tool modules from file: {error}");
    });
}

#[test]
fn production_registry_exposes_six_public_tools() {
    let names: Vec<String> = bundled_tool_entries()
        .into_iter()
        .map(|entry| entry.descriptor.name.clone())
        .collect();
    assert_eq!(
        names,
        [
            "read_file",
            "search_files",
            "write_file",
            "patch",
            "terminal",
            "process"
        ]
    );
}
