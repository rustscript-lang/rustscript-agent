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
const RUSTSCRIPT_REV: &str = "b1d6cffede77f49410bf63525f30b9a46b02dc01";
const STALE_REV: &str = "f9ca4143f8ba2f486e270347504c49f5ea846097";
const ABBREVIATED_REV: &str = "b1d6cff";

fn manifest() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read Cargo.toml")
}

fn lockfile() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .expect("read Cargo.lock")
}

fn rustscript_vm_dependency(manifest: &str) -> &str {
    manifest
        .lines()
        .find(|line| line.trim_start().starts_with("rustscript-vm = {"))
        .expect("Cargo.toml must declare rustscript-vm")
}

fn quoted_rev<'a>(dependency: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key} = \"");
    let start = dependency.find(&needle)? + needle.len();
    let end = start + dependency[start..].find('"')?;
    Some(&dependency[start..end])
}

#[test]
fn pd_vm_uses_the_reviewed_immutable_git_revision() {
    let manifest = manifest();
    let dependency = rustscript_vm_dependency(&manifest);

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
fn pd_vm_pin_is_the_exact_full_sha_and_rejects_stale_or_abbreviated_pins() {
    let manifest = manifest();
    let dependency = rustscript_vm_dependency(&manifest);
    let rev = quoted_rev(dependency, "rev").expect("rustscript-vm must declare rev");

    assert_eq!(
        rev.len(),
        40,
        "rustscript-vm rev must be the full 40-character SHA, not an abbreviation: {rev}"
    );
    assert!(
        rev.chars().all(|ch| ch.is_ascii_hexdigit()),
        "rustscript-vm rev must be hexadecimal: {rev}"
    );
    assert_eq!(
        rev, RUSTSCRIPT_REV,
        "rustscript-vm must pin the frozen full SHA {RUSTSCRIPT_REV}, got {rev}"
    );
    assert_ne!(
        rev, ABBREVIATED_REV,
        "rustscript-vm must not pin the abbreviated SHA {ABBREVIATED_REV}"
    );
    assert_ne!(
        rev, STALE_REV,
        "rustscript-vm must not remain on the stale SHA {STALE_REV}"
    );
    assert!(
        !dependency.contains(&format!("rev = \"{ABBREVIATED_REV}\"")),
        "rustscript-vm must not use an abbreviated rev literal: {dependency}"
    );
    assert!(
        !dependency.contains(STALE_REV),
        "rustscript-vm must not mention the stale pin {STALE_REV}: {dependency}"
    );
}

#[test]
fn pd_host_function_uses_the_same_frozen_full_sha() {
    let manifest = manifest();
    let dependency = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("pd-host-function = {"))
        .expect("Cargo.toml must declare pd-host-function for descriptor macros");

    assert!(
        dependency.contains(&format!("git = \"{RUSTSCRIPT_GIT}\"")),
        "pd-host-function must use the canonical HTTPS Git remote: {dependency}"
    );
    let rev = quoted_rev(dependency, "rev").expect("pd-host-function must declare rev");
    assert_eq!(
        rev, RUSTSCRIPT_REV,
        "pd-host-function must pin the same frozen full SHA as rustscript-vm: {dependency}"
    );
    assert_eq!(rev.len(), 40, "pd-host-function rev must be the full SHA");
    assert!(
        !dependency.contains("path ="),
        "pd-host-function must not depend on sibling checkout state: {dependency}"
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
    let stale = format!("git+{RUSTSCRIPT_GIT}?rev={STALE_REV}#{STALE_REV}");
    // The full SHA has `b1d6cff` as a prefix, so a substring `rev=b1d6cff` is not
    // enough. An abbreviated pin would be `rev=b1d6cff"` or `rev=b1d6cff#`.
    let abbreviated_quoted = format!("rev={ABBREVIATED_REV}\"");
    let abbreviated_fragment = format!("rev={ABBREVIATED_REV}#");

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
        assert!(
            !block.contains(&stale),
            "Cargo.lock {package} must not resolve the stale SHA {STALE_REV}"
        );
        assert!(
            !source.contains(&abbreviated_quoted) && !source.contains(&abbreviated_fragment),
            "Cargo.lock {package} must not resolve an abbreviated SHA: {source}"
        );
    }
}
