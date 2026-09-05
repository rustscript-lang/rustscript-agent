//! Dependency provenance guard for the RustScript VM.
//!
//! This test deliberately uses only `std` so it can also be compiled directly
//! with `rustc --test` when a broken local path dependency prevents Cargo from
//! resolving the workspace:
//!
//! ```bash
//! rustc --test --env CARGO_MANIFEST_DIR=$PWD \
//!     tests/dependency_pin_tests.rs -o /mnt/TEMP/rustscript/dependency-pin-tests/pin-direct
//! ```

use std::path::PathBuf;

const RUSTSCRIPT_GIT: &str = "https://github.com/rustscript-lang/rustscript.git";
const RUSTSCRIPT_REV: &str = "f9ca4143f8ba2f486e270347504c49f5ea846097";

fn manifest() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read Cargo.toml")
}

fn lockfile() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .expect("read Cargo.lock")
}

#[test]
fn pd_vm_uses_the_reviewed_immutable_git_revision() {
    let manifest = manifest();
    let dependency = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("rustscript-vm = {"))
        .expect("Cargo.toml must declare rustscript-vm");

    assert!(
        dependency.contains(&format!("git = \"{RUSTSCRIPT_GIT}\"")),
        "rustscript-vm must use the canonical HTTPS Git remote: {dependency}"
    );
    assert!(
        dependency.contains(&format!("rev = \"{RUSTSCRIPT_REV}\"")),
        "rustscript-vm must pin the reviewed full commit: {dependency}"
    );
    assert!(
        !dependency.contains("path ="),
        "rustscript-vm must not depend on sibling checkout state: {dependency}"
    );
}

#[test]
fn pd_vm_and_pd_host_function_lock_sources_are_canonical_https_at_the_pinned_rev() {
    let lockfile = lockfile();

    // The canonical source line Cargo writes for a git dependency pinned to a
    // full revision. Asserting the exact string simultaneously guards: the
    // canonical HTTPS remote (no `path`/`file` source), the full 40-character
    // revision, and the `#<rev>` checkout suffix.
    let canonical = format!("git+{RUSTSCRIPT_GIT}?rev={RUSTSCRIPT_REV}#{RUSTSCRIPT_REV}");

    for package in ["pd-vm", "pd-host-schema", "pd-host-function"] {
        let block = lockfile
            .split("\n[[package]]")
            .find(|block| block.contains(&format!("\nname = \"{package}\"\n")))
            .unwrap_or_else(|| panic!("Cargo.lock must declare {package}"));
        let source = block
            .lines()
            .find(|line| line.starts_with("source = "))
            .unwrap_or_else(|| panic!("Cargo.lock {package} must declare a source"));
        assert_eq!(
            source.trim(),
            format!("source = \"{canonical}\""),
            "Cargo.lock {package} must use the canonical HTTPS source at the pinned full rev"
        );
    }
}
