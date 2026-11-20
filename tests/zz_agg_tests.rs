//! Temporary diagnostic: aggregate bundled corpus compile results.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustscript_vm::{
    CompileSourceFileOptions, SourceFlavor, compile_source_at_path_with_flavor_and_options,
    host_api::HostApiCatalog,
};

fn collect_rss(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rss(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rss") {
            out.push(path);
        }
    }
}

#[test]
fn aggregate_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rss(&root.join("rss"), &mut files);
    collect_rss(&root.join("examples"), &mut files);
    files.sort();
    let catalog: Arc<HostApiCatalog> = rustscript_agent::agent_host_catalog();
    let mut failures: Vec<String> = Vec::new();
    for path in &files {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let source = fs::read_to_string(path).expect("read source");
        let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone());
        if let Err(error) = compile_source_at_path_with_flavor_and_options(
            path,
            &source,
            SourceFlavor::RustScript,
            options,
        ) {
            failures.push(format!("{relative} :: {error}"));
        }
    }
    for failure in &failures {
        println!("FAIL {failure}");
    }
    println!(
        "TOTAL {} OK {} FAIL {}",
        files.len(),
        files.len() - failures.len(),
        failures.len()
    );
}
