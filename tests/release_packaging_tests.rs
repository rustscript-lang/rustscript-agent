use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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

fn run_verifier(archive: &Path, tag: &str, binary_dir: &Path, forbidden: &str) -> Output {
    Command::new("python3")
        .arg(repo().join("scripts/package_linux_release.py"))
        .arg("--verify-archive")
        .arg(archive)
        .arg("--tag")
        .arg(tag)
        .arg("--binary-dir")
        .arg(binary_dir)
        .arg("--forbid-byte-string")
        .arg(forbidden)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .current_dir(repo())
        .output()
        .expect("run Linux release verifier")
}

fn classify_prerelease(tag: &str) -> Output {
    Command::new("python3")
        .arg(repo().join("scripts/package_linux_release.py"))
        .arg("--tag")
        .arg(tag)
        .arg("--print-prerelease")
        .current_dir(repo())
        .output()
        .expect("classify release tag")
}

fn inventory_lines(name: &str) -> Vec<String> {
    let text = fs::read_to_string(repo().join("release").join(name))
        .unwrap_or_else(|error| panic!("read release/{name}: {error}"));
    let lines = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        lines.windows(2).all(|pair| pair[0] < pair[1]),
        "release/{name} must be strictly sorted and unique"
    );
    lines
}

fn plain_inventory(name: &str) -> BTreeSet<String> {
    inventory_lines(name).into_iter().collect()
}

fn mapped_inventory(name: &str) -> BTreeMap<String, String> {
    inventory_lines(name)
        .into_iter()
        .map(|line| {
            let (source, destination) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("release/{name} line must be source<TAB>destination"));
            assert!(!source.is_empty() && !destination.is_empty());
            (source.to_owned(), destination.to_owned())
        })
        .collect()
}

fn tracked_files(paths: &[&str]) -> BTreeSet<String> {
    let output = Command::new("git")
        .arg("ls-files")
        .args(paths)
        .current_dir(repo())
        .output()
        .expect("list tracked release candidates");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("git paths are UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn relative_rss_imports(source: &str, text: &str) -> Vec<String> {
    let source_path = Path::new(source);
    let module_parent = source_path.parent().expect("RSS parent");
    let rss_root = Path::new("rss");
    let mut imports = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(mut path) = line.strip_prefix("use ") else {
            continue;
        };
        if let Some(index) = path.find("::{") {
            path = &path[..index];
        } else if let Some(index) = path.find(" as ") {
            path = &path[..index];
        } else {
            path = path.trim_end_matches(';');
        }
        let (mut base, relative) = if let Some(relative) = path.strip_prefix("self::") {
            (module_parent.to_path_buf(), relative)
        } else if let Some(relative) = path.strip_prefix("super::") {
            (
                module_parent
                    .parent()
                    .expect("super import remains under rss")
                    .to_path_buf(),
                relative,
            )
        } else {
            continue;
        };
        for component in relative.split("::") {
            if component.is_empty() || component == "self" || component == "super" {
                continue;
            }
            base.push(component);
        }
        base.set_extension("rss");
        if base.starts_with(rss_root) && repo().join(&base).is_file() {
            imports.push(base.to_string_lossy().replace('\\', "/"));
        }
    }
    imports
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex byte"))
        .collect()
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
        if member.isfile():
            row["hex"] = archive.extractfile(member).read().hex()
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

fn write_malformed_archive(path: &Path, names: &[&str]) {
    let program = r#"
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz") as archive:
    for name in sys.argv[2:]:
        info = tarfile.TarInfo(name)
        info.mode = 0o644
        info.mtime = 1700000000
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
"#;
    let output = Command::new("python3")
        .args(["-c", program])
        .arg(path)
        .args(names)
        .output()
        .expect("write malformed tar archive");
    assert!(output.status.success());
}

fn expected_file_bytes(binary_dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut expected = BTreeMap::new();
    for name in ["rustscript-agent", "rustscript-agent-gateway"] {
        expected.insert(
            format!("bin/{name}"),
            fs::read(binary_dir.join(name)).expect("read fake binary"),
        );
    }
    for name in ["README.md", "LICENSE", "CHANGELOG.md"] {
        expected.insert(
            name.to_owned(),
            fs::read(repo().join(name)).expect("read root release file"),
        );
    }
    for source in plain_inventory("rss-production.txt") {
        let relative = source.strip_prefix("rss/").expect("RSS source prefix");
        expected.insert(
            format!("share/rustscript-agent/rss/{relative}"),
            fs::read(repo().join(source)).expect("read production RSS"),
        );
    }
    for inventory in ["schema-production.txt", "example-production.txt"] {
        for (source, destination) in mapped_inventory(inventory) {
            expected.insert(
                destination,
                fs::read(repo().join(source)).expect("read mapped production asset"),
            );
        }
    }
    let mut manifest_paths = expected.keys().cloned().collect::<Vec<_>>();
    manifest_paths.push("MANIFEST.txt".to_owned());
    manifest_paths.sort();
    expected.insert(
        "MANIFEST.txt".to_owned(),
        format!("{}\n", manifest_paths.join("\n")).into_bytes(),
    );
    expected
}

#[test]
fn explicit_release_classification_is_complete_and_import_closed() {
    let rss_production = plain_inventory("rss-production.txt");
    let rss_support = plain_inventory("rss-support.txt");
    assert_eq!(rss_production.len(), 82, "production RSS count changed");
    assert_eq!(
        rss_support,
        BTreeSet::from([
            "rss/auth/config_entry.rss".to_owned(),
            "rss/auth/oauth_flow.rss".to_owned(),
            "rss/auth/store_entry.rss".to_owned(),
            "rss/llm/harness.rss".to_owned(),
            "rss/storage/import-test.rss".to_owned(),
        ])
    );
    assert!(rss_production.is_disjoint(&rss_support));
    let tracked_rss = tracked_files(&["rss"])
        .into_iter()
        .filter(|path| path.ends_with(".rss"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        rss_production
            .union(&rss_support)
            .cloned()
            .collect::<BTreeSet<_>>(),
        tracked_rss,
        "every tracked RSS must be explicitly production or support"
    );

    for source in &rss_production {
        let text = fs::read_to_string(repo().join(source)).expect("read production RSS");
        for imported in relative_rss_imports(source, &text) {
            assert!(
                rss_production.contains(&imported),
                "production RSS {source} imports omitted module {imported}"
            );
        }
    }

    let schemas = mapped_inventory("schema-production.txt");
    assert_eq!(schemas.len(), 10, "production schema count changed");
    assert!(schemas.iter().all(|(source, destination)| {
        source.starts_with("schemas/")
            && source.ends_with(".yaml")
            && destination
                == &format!(
                    "share/rustscript-agent/schemas/{}",
                    source.strip_prefix("schemas/").unwrap()
                )
    }));
    let schema_support = plain_inventory("schema-support.txt");
    assert!(
        schemas
            .keys()
            .all(|source| !schema_support.contains(source))
    );
    assert_eq!(
        schemas
            .keys()
            .cloned()
            .chain(schema_support)
            .collect::<BTreeSet<_>>(),
        tracked_files(&["schemas"]),
        "every tracked schema asset must be explicitly production or support"
    );

    let examples = mapped_inventory("example-production.txt");
    assert_eq!(
        examples,
        BTreeMap::from([
            (
                "docs/examples/auth.yaml".to_owned(),
                "share/rustscript-agent/examples/auth.yaml".to_owned(),
            ),
            (
                "docs/examples/config.yaml".to_owned(),
                "share/rustscript-agent/examples/config.yaml".to_owned(),
            ),
            (
                "examples/http_get.rss".to_owned(),
                "share/rustscript-agent/examples/http_get.rss".to_owned(),
            ),
        ])
    );
    let example_support = plain_inventory("example-support.txt");
    assert!(
        examples
            .keys()
            .all(|source| !example_support.contains(source))
    );
    assert_eq!(
        examples
            .keys()
            .cloned()
            .chain(example_support)
            .collect::<BTreeSet<_>>(),
        tracked_files(&["examples", "docs/examples"]),
        "every tracked example asset must be explicitly production or support"
    );

    let destinations = schemas
        .values()
        .chain(examples.values())
        .collect::<BTreeSet<_>>();
    assert_eq!(destinations.len(), schemas.len() + examples.len());
}

#[test]
fn package_contains_exact_unique_inventory_modes_and_source_bytes() {
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
    assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 1);

    let root = archive_name.strip_suffix(".tar.gz").unwrap();
    let entries = archive_entries(&archive);
    let raw_names = entries
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        raw_names.iter().collect::<BTreeSet<_>>().len(),
        raw_names.len(),
        "raw tar member names must be unique"
    );
    assert!(entries.iter().all(|entry| {
        let name = entry["name"].as_str().expect("archive path is text");
        name == root || name.starts_with(&format!("{root}/"))
    }));

    let expected = expected_file_bytes(&binary_dir);
    let files = entries
        .iter()
        .filter(|entry| entry["kind"] == "file")
        .collect::<Vec<_>>();
    assert_eq!(files.len(), expected.len(), "regular member count");
    let actual_paths = files
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .unwrap()
                .strip_prefix(&format!("{root}/"))
                .unwrap()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_paths, expected.keys().cloned().collect());

    let mut expected_directories = BTreeSet::from([root.to_owned()]);
    for path in expected.keys() {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            expected_directories.insert(format!("{root}/{}", directory.to_string_lossy()));
            parent = directory.parent();
        }
    }
    let actual_directories = entries
        .iter()
        .filter(|entry| entry["kind"] == "dir")
        .map(|entry| {
            entry["name"]
                .as_str()
                .unwrap()
                .trim_end_matches('/')
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_directories, expected_directories);
    assert_eq!(
        entries.len(),
        expected.len() + expected_directories.len(),
        "raw member count"
    );

    for entry in files {
        let raw_name = entry["name"].as_str().unwrap();
        let path = raw_name.strip_prefix(&format!("{root}/")).unwrap();
        let data = decode_hex(entry["hex"].as_str().unwrap());
        assert_eq!(&data, expected.get(path).unwrap(), "wrong bytes for {path}");
        let expected_mode = if path.starts_with("bin/") {
            0o755
        } else {
            0o644
        };
        assert_eq!(entry["mode"].as_u64(), Some(expected_mode));
        assert!(
            !data
                .windows(repo().as_os_str().len())
                .any(|window| { window == repo().to_string_lossy().as_bytes() })
        );
    }
}

#[test]
fn verifier_rejects_duplicate_raw_member_names() {
    let scratch = Scratch::new("duplicate-raw");
    let binary_dir = fake_binaries(&scratch.0);
    let archive = scratch.0.join("duplicate.tar.gz");
    write_malformed_archive(&archive, &["root/file", "root/file"]);
    let output = run_verifier(&archive, "v0.1.0", &binary_dir, "/checkout");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate raw tar member"));
}

#[test]
fn verifier_rejects_normalized_member_aliases_before_mapping() {
    let scratch = Scratch::new("duplicate-normalized");
    let binary_dir = fake_binaries(&scratch.0);
    let archive = scratch.0.join("duplicate-normalized.tar.gz");
    write_malformed_archive(&archive, &["root/file", "root/./file"]);
    let output = run_verifier(&archive, "v0.1.0", &binary_dir, "/checkout");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("duplicate normalized tar member") || error.contains("unsafe tar member")
    );
}

#[test]
fn verifier_rejects_unsafe_normalization_before_extraction() {
    let scratch = Scratch::new("unsafe-normalization");
    let binary_dir = fake_binaries(&scratch.0);
    let archive = scratch.0.join("unsafe.tar.gz");
    write_malformed_archive(&archive, &["root/../escape"]);
    let output = run_verifier(&archive, "v0.1.0", &binary_dir, "/checkout");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe tar member"));
}

#[test]
fn verifier_scans_every_regular_member_for_checkout_path_bytes() {
    let scratch = Scratch::new("path-leak");
    let binary_dir = fake_binaries(&scratch.0);
    fs::write(
        binary_dir.join("rustscript-agent"),
        format!("binary embeds {}", repo().display()),
    )
    .unwrap();
    let output_dir = scratch.0.join("out");
    fs::create_dir(&output_dir).unwrap();
    assert!(
        run_packager("v0.1.0", &binary_dir, &output_dir)
            .status
            .success()
    );
    let archive = output_dir.join("rustscript-agent-v0.1.0-x86_64-unknown-linux-gnu.tar.gz");
    let output = run_verifier(&archive, "v0.1.0", &binary_dir, &repo().to_string_lossy());
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("forbidden byte string"));
}

#[test]
fn repeated_packaging_produces_identical_archive_bytes() {
    let scratch = Scratch::new("deterministic");
    let binary_dir = fake_binaries(&scratch.0);
    let first = scratch.0.join("first");
    let second = scratch.0.join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();

    assert!(run_packager("v0.1.0", &binary_dir, &first).status.success());
    assert!(
        run_packager("v0.1.0", &binary_dir, &second)
            .status
            .success()
    );

    let name = "rustscript-agent-v0.1.0-x86_64-unknown-linux-gnu.tar.gz";
    assert_eq!(
        fs::read(first.join(name)).unwrap(),
        fs::read(second.join(name)).unwrap(),
        "deterministic archives must compare byte-for-byte"
    );
}

#[test]
fn semantic_version_prerelease_classification_ignores_build_metadata_hyphens() {
    for (tag, expected) in [
        ("v1.2.3", "false\n"),
        ("v1.2.3-rc.1", "true\n"),
        ("v1.2.3+build-7", "false\n"),
        ("v1.2.3-rc.1+build-7", "true\n"),
    ] {
        let output = classify_prerelease(tag);
        assert!(
            output.status.success(),
            "classification failed for {tag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected, "{tag}");
    }
}

#[test]
fn tag_must_exactly_match_the_cargo_package_version() {
    let scratch = Scratch::new("tag");
    let binary_dir = fake_binaries(&scratch.0);
    let output_dir = scratch.0.join("out");
    fs::create_dir(&output_dir).unwrap();

    let output = run_packager("v9.9.9", &binary_dir, &output_dir);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not match package version 'v0.1.0'")
    );
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
fn release_workflow_rejects_tag_races_and_limits_credentials_and_platform() {
    let workflow = fs::read_to_string(repo().join(".github/workflows/release.yml"))
        .expect("release workflow must exist");

    assert!(workflow.contains("tags:\n      - 'v*'"));
    assert!(workflow.contains(
        "if: github.event.created == true && github.event.deleted == false && github.event.forced == false"
    ));
    assert!(
        workflow.contains(
            "concurrency:\n  group: release-${{ github.ref }}\n  cancel-in-progress: false"
        )
    );
    assert!(!workflow.contains("pull_request:"));
    assert!(!workflow.contains("branches:"));
    assert!(!workflow.contains("schedule:"));
    assert!(workflow.contains("permissions:\n  contents: write"));
    assert_eq!(workflow.matches("runs-on:").count(), 1);
    assert!(workflow.contains("runs-on: ubuntu-latest"));
    assert!(!workflow.contains("matrix:"));
    for forbidden in ["macos", "windows", "aarch64"] {
        assert!(!workflow.contains(forbidden));
    }

    assert!(workflow.contains("actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"));
    assert!(workflow.contains("persist-credentials: false"));
    assert!(workflow.contains("dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30"));
    assert!(workflow.contains("toolchain: '1.99.1'"));
    assert!(workflow.contains("target: x86_64-unknown-linux-gnu"));
    assert!(workflow.contains("git rev-parse \"${GITHUB_REF}^{commit}\""));
    assert!(workflow.contains("git rev-parse HEAD"));
    assert!(workflow.contains("git show -s --format=%ct \"$RELEASE_COMMIT\""));
    assert!(!workflow.contains("git show -s --format=%ct \"$GITHUB_SHA\""));
    assert!(workflow.contains("--remap-path-prefix=${{ github.workspace }}=."));
    assert!(workflow.contains(
        "cargo build --release --locked --target x86_64-unknown-linux-gnu --bin rustscript-agent --bin rustscript-agent-gateway"
    ));
    assert!(workflow.contains("cargo test --locked --all-features --test release_packaging_tests"));
    assert!(workflow.contains("--verify-archive \"$ASSET\""));
    assert!(workflow.contains("--forbid-byte-string \"$GITHUB_WORKSPACE\""));

    assert_eq!(workflow.matches("GH_TOKEN:").count(), 1);
    let publication = workflow
        .split("- name: Create or update GitHub Release")
        .nth(1)
        .expect("final publication step");
    assert!(publication.contains("GH_TOKEN: ${{ github.token }}"));
    assert!(publication.contains("git ls-remote"));
    assert!(publication.matches("verify_remote_tag").count() >= 5);
    assert!(publication.contains("verify_remote_tag\n            gh release edit"));
    assert!(publication.contains("verify_remote_tag\n            gh release upload"));
    assert!(publication.contains("verify_remote_tag\n            gh release create"));
    assert!(publication.trim_end().ends_with("verify_remote_tag"));
    assert!(publication.contains("--clobber"));
    assert!(publication.contains("--verify-tag"));
    assert!(publication.contains("--prerelease=\"$PRERELEASE\""));
    assert!(publication.contains("--print-prerelease"));
    assert!(!publication.contains("[[ \"$VERSION\" == *-* ]]"));
}

#[test]
fn v0_1_0_release_notes_preserve_distribution_and_platform_boundaries() {
    let notes = fs::read_to_string(repo().join("docs/releases/v0.1.0.md"))
        .expect("v0.1.0 release notes must exist");
    for required in [
        "rustscript-agent v0.1.0",
        "rustscript-agent-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
        "82 production RSS",
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
