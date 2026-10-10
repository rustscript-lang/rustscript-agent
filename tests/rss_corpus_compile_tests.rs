//! Programmatic RSS corpus: every bundled `.rss` file must compile.
//!
//! Every discovered source compiles through the real Core compile API with a
//! real host catalog: only the three historical fixture entry files use their
//! config-fixture catalogs, everything else (including all other auth
//! contract/helper modules) uses the public production agent catalog.
//! Compile failures are fatal — there is no accepted-error path.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustscript_vm::{
    CompileSourceFileOptions, SourceFlavor, compile_source_at_path_with_flavor_and_options,
    host_api::HostApiCatalog,
};

/// Exact fixture entry paths, relative to the crate root. Only these use
/// config-fixture catalogs; every other discovered source is production.
const OAUTH_FLOW_ENTRY: &str = "rss/auth/oauth_flow.rss";
const STORE_ENTRY_ENTRY: &str = "rss/auth/store_entry.rss";
const CONFIG_ENTRY_ENTRY: &str = "rss/auth/config_entry.rss";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rss(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!("read {}: {error}", dir.display());
    });
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rss(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rss") {
            out.push(path);
        }
    }
}

fn all_rss_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rss(&crate_root().join("rss"), &mut files);
    collect_rss(&crate_root().join("examples"), &mut files);
    files.sort();
    files
}

fn relative_rss(path: &Path) -> String {
    path.strip_prefix(crate_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(not(feature = "config-fixture"))]
fn is_fixture_entry(relative: &str) -> bool {
    relative == OAUTH_FLOW_ENTRY || relative == STORE_ENTRY_ENTRY || relative == CONFIG_ENTRY_ENTRY
}

#[cfg(feature = "config-fixture")]
fn catalog_for(relative: &str) -> Arc<HostApiCatalog> {
    match relative {
        OAUTH_FLOW_ENTRY => rustscript_agent::config_fixture::oauth_fixture_catalog(),
        STORE_ENTRY_ENTRY => rustscript_agent::config_fixture::auth_store_fixture_catalog(),
        CONFIG_ENTRY_ENTRY => rustscript_agent::config_fixture::config_fixture_catalog(),
        _ => rustscript_agent::agent_host_catalog(),
    }
}

fn compile_with_catalog(path: &Path, relative: &str, catalog: Arc<HostApiCatalog>) {
    let source = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("read {relative}: {error}");
    });
    let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog);
    compile_source_at_path_with_flavor_and_options(
        path,
        &source,
        SourceFlavor::RustScript,
        options,
    )
    .unwrap_or_else(|error| {
        panic!("{relative} must compile: {error}");
    });
    println!("compiled {relative}");
}

#[test]
fn bundled_rss_corpus_compiles() {
    let files = all_rss_files();
    assert!(!files.is_empty(), "bundled RSS corpus must not be empty");

    let mut compiled = 0usize;
    #[cfg(not(feature = "config-fixture"))]
    let mut omitted: Vec<String> = Vec::new();

    for path in &files {
        let relative = relative_rss(path);
        #[cfg(feature = "config-fixture")]
        {
            compile_with_catalog(path, &relative, catalog_for(&relative));
            compiled += 1;
        }
        #[cfg(not(feature = "config-fixture"))]
        {
            if is_fixture_entry(&relative) {
                omitted.push(relative);
                continue;
            }
            compile_with_catalog(path, &relative, rustscript_agent::agent_host_catalog());
            compiled += 1;
        }
    }

    println!(
        "rss corpus discovered={} compiled={}",
        files.len(),
        compiled
    );
    #[cfg(not(feature = "config-fixture"))]
    println!("rss corpus fixture-only omitted={omitted:?}");
}
