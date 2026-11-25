use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let base = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "release-packaging-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove stale release packaging scratch");
        }
        fs::create_dir_all(&path).expect("create release packaging scratch");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fake_binaries(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    fs::create_dir_all(&bin).expect("create fake binary directory");
    fs::write(bin.join("rustscript-agent"), b"fake runner\n").expect("write fake runner");
    fs::write(bin.join("rustscript-agent-gateway"), b"fake gateway\n").expect("write fake gateway");
    bin
}

fn run_packager(tag: &str, binary_dir: &Path, output_dir: &Path) -> Output {
    Command::new("python3")
        .arg(repo().join("scripts/package_linux_release.py"))
        .arg("--tag")
        .arg(tag)
        .arg("--binary-dir")
        .arg(binary_dir)
        .arg("--output-dir")
        .arg(output_dir)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .current_dir(repo())
        .output()
        .expect("run Linux release packager")
}

fn walk_files(root: &Path, extension: &str) -> Vec<PathBuf> {
    fn visit(root: &Path, directory: &Path, extension: &str, paths: &mut Vec<PathBuf>) {
        let mut entries = fs::read_dir(directory)
            .expect("read production asset directory")
            .map(|entry| entry.expect("read production asset entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let metadata = fs::symlink_metadata(&path).expect("stat production asset");
            assert!(
                !metadata.file_type().is_symlink(),
                "production asset must not be a symlink"
            );
            if metadata.is_dir() {
                visit(root, &path, extension, paths);
            } else if metadata.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some(extension)
            {
                paths.push(
                    path.strip_prefix(root)
                        .expect("asset below root")
                        .to_path_buf(),
                );
            }
        }
    }

    let mut paths = Vec::new();
    visit(root, root, extension, &mut paths);
    paths.sort();
    paths
}

fn archive_entries(archive: &Path) -> Vec<Value> {
    let program = r#"
import json
import sys
import tarfile

rows = []
with tarfile.open(sys.argv[1], "r:gz") as archive:
    for member in archive.getmembers():
        row = {
            "name": member.name,
            "mode": member.mode,
            "kind": "file" if member.isfile() else "dir" if member.isdir() else "other",
        }
        if member.isfile() and member.name.endswith("/MANIFEST.txt"):
            row["text"] = archive.extractfile(member).read().decode("utf-8")
        rows.append(row)
print(json.dumps(rows))
"#;
    let output = Command::new("python3")
        .args(["-c", program])
        .arg(archive)
        .output()
        .expect("inspect release archive");
    assert!(
        output.status.success(),
        "archive inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("archive inspection JSON")
}

#[test]
fn package_contains_exact_relocatable_production_inventory_and_modes() {
    let scratch = Scratch::new("inventory");
    let binary_dir = fake_binaries(&scratch.0);
    let output_dir = scratch.0.join("out");
    fs::create_dir(&output_dir).expect("create package output directory");

    let output = run_packager("v0.1.0", &binary_dir, &output_dir);
    assert!(
        output.status.success(),
        "packager failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let archive_name = "rustscript-agent-v0.1.0-x86_64-unknown-linux-gnu.tar.gz";
    let archive = output_dir.join(archive_name);
    assert!(archive.is_file(), "expected exact release archive name");
    let output_files = fs::read_dir(&output_dir)
        .expect("read package output directory")
        .map(|entry| entry.expect("read package output entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(output_files, [archive.file_name().unwrap()]);

    let root = archive_name.strip_suffix(".tar.gz").unwrap();
    let entries = archive_entries(&archive);
    let files = entries
        .iter()
        .filter(|entry| entry["kind"] == "file")
        .collect::<Vec<_>>();
    assert!(
        entries.iter().all(|entry| {
            let name = entry["name"].as_str().expect("archive path is text");
            name == root || name.starts_with(&format!("{root}/"))
        }),
        "every entry must stay below the archive root"
    );

    let mut expected = BTreeSet::from([
        "bin/rustscript-agent".to_string(),
        "bin/rustscript-agent-gateway".to_string(),
        "README.md".to_string(),
        "LICENSE".to_string(),
        "CHANGELOG.md".to_string(),
        "MANIFEST.txt".to_string(),
        "share/rustscript-agent/examples/config.yaml".to_string(),
        "share/rustscript-agent/examples/auth.yaml".to_string(),
    ]);

    let rss = walk_files(&repo().join("rss"), "rss");
    assert_eq!(rss.len(), 87, "production RSS inventory changed");
    for relative in rss {
        expected.insert(format!(
            "share/rustscript-agent/rss/{}",
            relative.to_string_lossy()
        ));
    }
    for relative in walk_files(&repo().join("schemas"), "yaml") {
        expected.insert(format!(
            "share/rustscript-agent/schemas/{}",
            relative.to_string_lossy()
        ));
    }
    for relative in walk_files(&repo().join("examples"), "rss") {
        expected.insert(format!(
            "share/rustscript-agent/examples/{}",
            relative.to_string_lossy()
        ));
    }

    let actual = files
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .expect("file path is text")
                .strip_prefix(&format!("{root}/"))
                .expect("file is below archive root")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "archive file inventory must be exact");

    for entry in &files {
        let name = entry["name"].as_str().unwrap();
        let expected_mode = if name.ends_with("/bin/rustscript-agent")
            || name.ends_with("/bin/rustscript-agent-gateway")
        {
            0o755
        } else {
            0o644
        };
        assert_eq!(entry["mode"].as_u64(), Some(expected_mode));
    }

    let manifest = files
        .iter()
        .find(|entry| entry["name"].as_str().unwrap().ends_with("/MANIFEST.txt"))
        .and_then(|entry| entry["text"].as_str())
        .expect("manifest text");
    let manifest_paths = manifest.lines().map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(manifest_paths, expected.iter().cloned().collect::<Vec<_>>());
    assert!(manifest.ends_with('\n'));

    for forbidden in ["tests/", ".github/", "target/", "state.db", "credential"] {
        assert!(
            entries
                .iter()
                .all(|entry| !entry["name"].as_str().unwrap().contains(forbidden)),
            "archive contains forbidden marker {forbidden}"
        );
    }
    let repository = repo();
    let checkout = repository.to_string_lossy();
    assert!(
        entries
            .iter()
            .all(|entry| !entry["name"].as_str().unwrap().contains(checkout.as_ref()))
    );
}

#[test]
fn repeated_packaging_produces_identical_archive_bytes() {
    let scratch = Scratch::new("deterministic");
    let binary_dir = fake_binaries(&scratch.0);
    let first = scratch.0.join("first");
    let second = scratch.0.join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();

    let first_output = run_packager("v0.1.0", &binary_dir, &first);
    let second_output = run_packager("v0.1.0", &binary_dir, &second);
    assert!(first_output.status.success());
    assert!(second_output.status.success());

    let name = "rustscript-agent-v0.1.0-x86_64-unknown-linux-gnu.tar.gz";
    assert_eq!(
        fs::read(first.join(name)).unwrap(),
        fs::read(second.join(name)).unwrap(),
        "deterministic archives must compare byte-for-byte"
    );
}

#[test]
fn tag_must_exactly_match_the_cargo_package_version() {
    let scratch = Scratch::new("tag");
    let binary_dir = fake_binaries(&scratch.0);
    let output_dir = scratch.0.join("out");
    fs::create_dir(&output_dir).unwrap();

    let output = run_packager("v9.9.9", &binary_dir, &output_dir);
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("does not match package version 'v0.1.0'"));
    assert_eq!(fs::read_dir(output_dir).unwrap().count(), 0);
}

#[test]
fn missing_binary_is_rejected_without_an_archive() {
    let scratch = Scratch::new("missing");
    let binary_dir = fake_binaries(&scratch.0);
    fs::remove_file(binary_dir.join("rustscript-agent-gateway")).unwrap();
    let output_dir = scratch.0.join("out");
    fs::create_dir(&output_dir).unwrap();

    let output = run_packager("v0.1.0", &binary_dir, &output_dir);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing binary rustscript-agent-gateway")
    );
    assert_eq!(fs::read_dir(output_dir).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn symlinked_binary_is_rejected_without_an_archive() {
    let scratch = Scratch::new("symlink");
    let binary_dir = fake_binaries(&scratch.0);
    let runner = binary_dir.join("rustscript-agent");
    fs::remove_file(&runner).unwrap();
    std::os::unix::fs::symlink("rustscript-agent-gateway", &runner).unwrap();
    let output_dir = scratch.0.join("out");
    fs::create_dir(&output_dir).unwrap();

    let output = run_packager("v0.1.0", &binary_dir, &output_dir);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not be a symlink"));
    assert_eq!(fs::read_dir(output_dir).unwrap().count(), 0);
}

#[test]
fn release_workflow_is_tag_only_linux_scoped_and_idempotent() {
    let workflow = fs::read_to_string(repo().join(".github/workflows/release.yml"))
        .expect("release workflow must exist");

    assert!(workflow.contains("tags:\n      - 'v*'"));
    assert!(!workflow.contains("pull_request:"));
    assert!(!workflow.contains("branches:"));
    assert!(!workflow.contains("schedule:"));
    assert!(workflow.contains("permissions:\n  contents: write"));
    assert_eq!(
        workflow.matches("runs-on:").count(),
        1,
        "one release job only"
    );
    assert!(workflow.contains("runs-on: ubuntu-latest"));
    assert!(!workflow.contains("matrix:"));
    assert!(!workflow.contains("macos"));
    assert!(!workflow.contains("windows"));
    assert!(!workflow.contains("aarch64"));

    assert!(workflow.contains("actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"));
    assert!(workflow.contains("dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30"));
    assert!(!workflow.contains("uses: actions/checkout@v"));
    assert!(workflow.contains("toolchain: '1.99.1'"));
    assert!(workflow.contains("target: x86_64-unknown-linux-gnu"));
    assert!(workflow.contains(
        "cargo build --release --locked --target x86_64-unknown-linux-gnu --bin rustscript-agent --bin rustscript-agent-gateway"
    ));
    assert!(workflow.contains("cargo test --locked --all-features --test release_packaging_tests"));

    assert!(workflow.contains("git show -s --format=%ct \"$GITHUB_SHA\""));
    assert!(workflow.contains("SOURCE_DATE_EPOCH"));
    assert!(workflow.contains("scripts/package_linux_release.py"));
    assert!(workflow.contains("--binary-dir target/x86_64-unknown-linux-gnu/release"));
    assert!(workflow.contains("--output-dir dist"));
    assert!(workflow.contains("mktemp -d"));
    assert!(workflow.contains("tar -xzf"));
    assert!(workflow.contains("MANIFEST.txt"));
    assert!(workflow.contains("GITHUB_WORKSPACE"));

    assert!(workflow.contains("NOTES=docs/releases/${VERSION}.md"));
    assert!(workflow.contains("TITLE=\"rustscript-agent ${TAG}\""));
    assert!(workflow.contains("PRERELEASE=false"));
    assert!(workflow.contains("== *-*"));
    assert!(workflow.contains("gh release view"));
    assert!(workflow.contains("gh release edit"));
    assert!(workflow.contains("gh release upload"));
    assert!(workflow.contains("--clobber"));
    assert!(workflow.contains("gh release create"));
    assert!(workflow.contains("--verify-tag"));
    assert!(workflow.contains("--notes-file \"$NOTES\""));
    assert!(workflow.contains("--prerelease=\"$PRERELEASE\""));
}

#[test]
fn v0_1_0_release_notes_preserve_distribution_and_platform_boundaries() {
    let notes = fs::read_to_string(repo().join("docs/releases/v0.1.0.md"))
        .expect("v0.1.0 release notes must exist");
    for required in [
        "rustscript-agent v0.1.0",
        "rustscript-agent-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
        "11c9ee908a29365bd02573311f56e9308eb7dbe6",
        "source-only",
        "crates.io",
        "Confined read/list filesystem inspection requires Unix",
        "Confined mutation and publication currently require Linux",
        "Scheduled durable job execution is not implemented",
        "Parallel tool dispatch and subagent fan-out are not implemented",
        "no native TLS listener",
    ] {
        assert!(notes.contains(required), "release notes omit {required:?}");
    }
}
