//! Task 0F architecture tests: RSS owns static tool dispatch.
//!
//! These tests exercise the real host catalog, RSS dispatch wiring and the
//! production compile/registry path. The executable route coverage lives in
//! `tests/rss_tool_dispatch_tests.rs`; the source-shape assertions that
//! duplicated it were development scaffolding and are not retained.

use std::fs;
use std::path::PathBuf;

use rustscript_agent::{AgentConfig, AgentRunner, agent_host_catalog, bundled_tool_entries};
use rustscript_vm::{
    ParserDialect, SharedParserOptions, UsePathSegment, parse_source_with_dialect,
};

struct AgentParserDialect;

impl ParserDialect for AgentParserDialect {
    fn allow_let_mut_binding(&self) -> bool {
        true
    }

    fn allow_macro_calls(&self) -> bool {
        true
    }

    fn allow_plus_equal_operator(&self) -> bool {
        true
    }

    fn allow_for_in_loop(&self) -> bool {
        true
    }
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
fn production_agent_calls_rss_tools_dispatch() {
    let main = fs::read_to_string(crate_root().join("rss/agent/main.rss"))
        .expect("rss/agent/main.rss must exist");
    static DIALECT: AgentParserDialect = AgentParserDialect;
    let ir = parse_source_with_dialect(
        &main,
        &DIALECT,
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: true,
            import_scan_mode: true,
        },
    )
    .expect("production agent must parse");
    let imported = ir.use_declarations.iter().any(|declaration| {
        matches!(
            declaration.path.as_slice(),
            [
                UsePathSegment::Super,
                UsePathSegment::Ident(tools),
                UsePathSegment::Ident(dispatch),
            ] if tools == "tools" && dispatch == "dispatch"
        )
    });
    assert!(
        imported,
        "production agent must import super::tools::dispatch; source:\n{main}"
    );
    assert!(
        !main.contains("agent::tool_dispatch"),
        "production agent must not invoke agent::tool_dispatch"
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
