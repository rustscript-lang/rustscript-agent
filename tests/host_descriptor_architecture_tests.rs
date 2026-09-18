//! Architecture guards for Task 11: frozen-core host descriptors.
//!
//! These tests fail until agent host modules stop using manual catalog loops,
//! `register_named` / `register_exact_static` install tables, and copied
//! standard HTTP/SQLite schemas.

use std::fs;
use std::path::PathBuf;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_production_source(relative: &str) -> String {
    let text = fs::read_to_string(crate_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"));
    strip_cfg_test_modules(&text)
}

fn strip_cfg_test_modules(source: &str) -> String {
    let mut out = String::new();
    let mut skip_depth = 0usize;
    let mut pending_cfg_test = false;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if skip_depth == 0 && trimmed.starts_with("#[cfg(test)]") {
            pending_cfg_test = true;
            continue;
        }
        if pending_cfg_test {
            if trimmed.starts_with("mod ") && trimmed.contains('{') {
                skip_depth = 1;
                pending_cfg_test = false;
                continue;
            }
            if trimmed.starts_with("mod ") {
                pending_cfg_test = false;
                continue;
            }
            pending_cfg_test = false;
        }
        if skip_depth > 0 {
            skip_depth += trimmed.matches('{').count();
            skip_depth = skip_depth.saturating_sub(trimmed.matches('}').count());
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

const HOST_PRODUCTION_SOURCES: &[&str] = &[
    "src/runtime/agent_host.rs",
    "src/runtime/rss_runner.rs",
    "src/auth/oauth_host.rs",
    "src/auth/store_host.rs",
    "src/config_host.rs",
];

#[test]
fn host_modules_do_not_use_register_named_or_exact_static_tables() {
    for relative in HOST_PRODUCTION_SOURCES {
        let text = read_production_source(relative);
        assert!(
            !text.contains("fn register_named("),
            "{relative} still declares register_named"
        );
        assert!(
            !text.contains("register_exact_static("),
            "{relative} still calls register_exact_static"
        );
        assert!(
            !text.contains("registry.register_static("),
            "{relative} still calls register_static"
        );
    }
}

#[test]
fn host_catalogs_do_not_copy_standard_schemas_in_loops() {
    for relative in HOST_PRODUCTION_SOURCES {
        let text = read_production_source(relative);
        assert!(
            !text.contains("for resource in standard.resources()"),
            "{relative} still copies standard resources by hand"
        );
        assert!(
            !text.contains("for function in standard.functions()"),
            "{relative} still copies standard functions by hand"
        );
    }
}

#[test]
fn host_modules_install_through_descriptors() {
    for relative in [
        "src/runtime/agent_host.rs",
        "src/auth/oauth_host.rs",
        "src/auth/store_host.rs",
        "src/config_host.rs",
    ] {
        let text = read_production_source(relative);
        assert!(
            text.contains("HostModuleDescriptor") || text.contains("install_from_catalog"),
            "{relative} must compose a HostModuleDescriptor and install_from_catalog"
        );
    }
}

#[test]
fn rss_runner_composes_standard_http_and_sqlite_modules() {
    let text = read_production_source("src/runtime/rss_runner.rs");
    assert!(
        text.contains("standard_catalog_modules")
            || text.contains("register_http_builtin_module_from_catalog"),
        "rss_runner must compose frozen standard HTTP/SQLite modules"
    );
    assert!(
        !text.contains("builder.function(HostFunctionSchema"),
        "rss_runner must not hand-write host function schemas"
    );
}
