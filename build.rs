//! Compile-time public RSS asset inventory. Admission and permissions are separate.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};

const MAX_FILES: usize = 256;
const MAX_DEPTH: usize = 16;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

// Exclude only the existing default-corpus fixtures.
const FIXTURE_EXCLUSIONS: &[&str] = &[
    "rss/auth/oauth_flow.rss",
    "rss/auth/store_entry.rss",
    "rss/auth/config_entry.rss",
];

fn fail(message: &str) -> ! {
    panic!("task9 RSS catalog: {message}");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set"));
    let rss_root = manifest_dir.join("rss");

    let root = fs::canonicalize(&rss_root).unwrap_or_else(|error| {
        fail(&format!(
            "rss root {} is unreadable: {error}",
            rss_root.display()
        ))
    });
    if !root.is_dir() {
        fail("rss root is not a directory");
    }
    println!("cargo:rerun-if-changed={}", rss_root.display());

    let mut assets: Vec<Asset> = Vec::new();
    let mut total_bytes: u64 = 0;
    walk(&root, &root, &mut assets, &mut total_bytes);

    if assets.len() > MAX_FILES {
        fail("catalog exceeds the file count bound");
    }
    assets.sort_by(|left, right| left.key.cmp(&right.key));
    for pair in assets.windows(2) {
        if pair[0].key == pair[1].key {
            fail(&format!("catalog contains a duplicate key {}", pair[0].key));
        }
    }

    let mut generated = String::new();
    generated.push_str(
        "pub fn bundled_rss_sources() -> &'static [(&'static str, &'static str)] {\n    &[\n",
    );
    for asset in &assets {
        let _ = writeln!(
            generated,
            "        ({:?}, include_str!({:?})),",
            asset.key, asset.absolute
        );
    }
    generated.push_str("    ]\n}\n");

    fs::write(out_dir.join("bundled_rss_sources.rs"), generated)
        .expect("write generated RSS catalog");
}

struct Asset {
    key: String,
    absolute: String,
}

fn walk(root: &Path, dir: &Path, assets: &mut Vec<Asset>, total_bytes: &mut u64) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|error| fail(&format!("read_dir {} failed: {error}", dir.display())))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| fail(&format!("read_dir entry failed: {error}")))
                .path()
        })
        .collect();
    entries.sort();

    for path in entries {
        let link_meta = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| fail(&format!("stat {} failed: {error}", path.display())));
        if link_meta.file_type().is_symlink() {
            fail(&format!("rss tree contains a symlink: {}", path.display()));
        }
        if link_meta.is_dir() {
            walk(root, &path, assets, total_bytes);
            continue;
        }
        if !link_meta.is_file() {
            fail(&format!(
                "rss tree contains a non-regular entry: {}",
                path.display()
            ));
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rss") {
            continue;
        }

        let key = relative_key(root, &path);
        if FIXTURE_EXCLUSIONS.contains(&key.as_str()) {
            continue;
        }
        if assets.len() >= MAX_FILES {
            fail("catalog exceeds the file count bound");
        }

        let canonical = fs::canonicalize(&path).unwrap_or_else(|error| {
            fail(&format!("canonicalize {} failed: {error}", path.display()))
        });
        if !canonical.starts_with(root) {
            fail(&format!(
                "asset escapes the rss root: {}",
                canonical.display()
            ));
        }
        let size = fs::metadata(&canonical)
            .unwrap_or_else(|error| {
                fail(&format!("metadata {} failed: {error}", canonical.display()))
            })
            .len();
        if size > MAX_FILE_BYTES {
            fail(&format!("asset {} exceeds the per-file byte bound", key));
        }
        let next_total = total_bytes
            .checked_add(size)
            .unwrap_or_else(|| fail("catalog byte total overflowed"));
        if next_total > MAX_TOTAL_BYTES {
            fail("catalog exceeds the total byte bound");
        }
        *total_bytes = next_total;

        let absolute = canonical
            .to_str()
            .unwrap_or_else(|| fail(&format!("asset path is not UTF-8: {}", key)))
            .to_owned();
        println!("cargo:rerun-if-changed={}", canonical.display());
        assets.push(Asset { key, absolute });
    }
}

fn relative_key(root: &Path, path: &Path) -> String {
    let relative = path
        .strip_prefix(root.parent().unwrap_or(root))
        .unwrap_or_else(|_| {
            fail(&format!(
                "asset is outside the crate root: {}",
                path.display()
            ))
        });
    if root.parent().unwrap_or(root) == root {
        fail("rss root has no crate-relative parent");
    }
    let mut components: Vec<String> = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            fail(&format!(
                "asset path has a non-normal component: {}",
                path.display()
            ));
        };
        let part = part
            .to_str()
            .unwrap_or_else(|| fail(&format!("asset path is not UTF-8: {}", path.display())));
        if part.is_empty() || part.contains('\\') || part.chars().any(char::is_control) {
            fail(&format!(
                "asset path has an invalid component: {}",
                path.display()
            ));
        }
        components.push(part.to_owned());
    }
    if components.first().map(String::as_str) != Some("rss") {
        fail(&format!("asset is not under rss/: {}", path.display()));
    }
    if components.len() > MAX_DEPTH {
        fail(&format!(
            "asset exceeds the depth bound: {}",
            path.display()
        ));
    }
    components.join("/")
}
