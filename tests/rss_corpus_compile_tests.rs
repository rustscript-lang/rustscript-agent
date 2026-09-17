//! Programmatic RSS corpus: every bundled `.rss` file must compile.
//!
//! Auth/config/oauth entries use the config-fixture catalogs; every other
//! file compiles through the production restricted agent catalog. Compile
//! failures are fatal — there is no accepted-error path.

use std::fs;
use std::path::{Path, PathBuf};

use rustscript_agent::{AgentConfig, AgentRunner};

const EXPECTED_RSS_CORPUS_LEN: usize = 49;

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

fn is_config_fixture_rss(path: &Path) -> bool {
    path.strip_prefix(crate_root().join("rss").join("auth"))
        .is_ok()
}

fn compile_production_rss(path: &Path) {
    AgentRunner::from_file(path, AgentConfig::default()).unwrap_or_else(|error| {
        panic!(
            "{} must compile with the production catalog: {error}",
            relative_rss(path)
        );
    });
}

#[cfg(feature = "config-fixture")]
fn compile_fixture_rss(path: &Path) {
    use rustscript_vm::{
        CompileSourceFileOptions, SourceFlavor, compile_source_at_path_with_flavor_and_options,
    };

    let source = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("read {}: {error}", relative_rss(path));
    });
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let catalog = match name {
        "oauth_flow.rss" => rustscript_agent::config_fixture::oauth_fixture_catalog(),
        "store_entry.rss" => rustscript_agent::config_fixture::auth_store_fixture_catalog(),
        "config_entry.rss" => rustscript_agent::config_fixture::config_fixture_catalog(),
        other => panic!(
            "{} is under rss/auth but has no fixture catalog mapping ({other})",
            relative_rss(path)
        ),
    };
    let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog);
    compile_source_at_path_with_flavor_and_options(
        path,
        &source,
        SourceFlavor::RustScript,
        options,
    )
    .unwrap_or_else(|error| {
        panic!(
            "{} must compile with its fixture catalog: {error}",
            relative_rss(path)
        );
    });
}

#[test]
fn bundled_rss_corpus_has_exact_count_and_compiles() {
    let files = all_rss_files();
    let relative: Vec<String> = files.iter().map(|path| relative_rss(path)).collect();
    assert_eq!(
        files.len(),
        EXPECTED_RSS_CORPUS_LEN,
        "bundled RSS corpus must contain exactly {EXPECTED_RSS_CORPUS_LEN} files, got {}: {relative:?}",
        files.len()
    );

    for path in &files {
        if is_config_fixture_rss(path) {
            #[cfg(feature = "config-fixture")]
            compile_fixture_rss(path);
            #[cfg(not(feature = "config-fixture"))]
            {
                assert!(
                    path.is_file(),
                    "{} must remain in the corpus",
                    relative_rss(path)
                );
            }
        } else {
            compile_production_rss(path);
        }
    }
}
