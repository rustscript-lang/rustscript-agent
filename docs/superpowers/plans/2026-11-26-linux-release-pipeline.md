# Linux Release Pipeline Implementation Plan

**Goal:** Build and verify a Linux-only GitHub Release pipeline that produces a deterministic, relocatable archive with both binaries and the complete production RSS/YAML inventory.

**Architecture:** A Python standard-library packager owns validation and deterministic archive construction. A cargo integration test exercises the packager and statically checks the workflow/release-note contract; the tag workflow builds real target binaries, packages them, extracts the archive for a second structural check, and publishes idempotently.

**Tech Stack:** Rust 1.99.1 integration tests, Python 3 standard library, GitHub Actions, GitHub CLI.

---

### Task 1: Freeze the packaging and workflow contract in a failing integration test

**Files:**
- Create: `tests/release_packaging_tests.rs`

**Steps:**
1. Add helpers that discover tracked production RSS, schemas, and examples; create fake regular binaries; invoke the wished-for packager CLI; and inspect tar metadata/content.
2. Test exact archive naming/root/layout, all 82 explicitly classified production RSS mappings and the five reviewed support exclusions, every approved schema/example mapping, binary modes, sorted path-only manifest, deterministic repeated bytes, tag mismatch, missing binary, symlink rejection, and forbidden entries.
3. Test focused workflow properties: pushed `v*` tags only, one Linux job, least privilege, Rust/target/build commands, contract test, tagged-commit epoch, fresh extraction validation, versioned notes, create/edit paths, `--verify-tag`, `--clobber`, and conditional prerelease behavior. Test the v0.1.0 notes file and required boundaries.
4. Run `cargo +1.99.1 test --locked --all-features --test release_packaging_tests`; record the expected RED caused by the absent script/workflow/notes.

### Task 2: Implement deterministic packaging

**Files:**
- Create: `scripts/package_linux_release.py`

**Steps:**
1. Parse `Cargo.toml` with `tomllib`; validate the exact `v<package.version>` tag and `SOURCE_DATE_EPOCH`.
2. Validate every explicit source and both binary inputs using `lstat`, rejecting symlinks and nonregular files.
3. Build a sorted in-memory inventory from the reviewed `release/` production classifications with fixed destination paths and modes; generate sorted `MANIFEST.txt` without hashes.
4. Emit deterministic tar and gzip metadata to a temporary file, atomically replace the exact output filename, and ensure no other output is produced.
5. Re-run the focused test and iterate until packaging behavior is GREEN.

### Task 3: Add the Linux release workflow and release notes

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `docs/releases/v0.1.0.md`

**Steps:**
1. Add the tag-creation-only, per-tag-serialized, one-job Linux workflow with full-SHA-pinned checkout/toolchain actions, checkout credential persistence disabled, Rust 1.99.1, explicit GNU target, annotated-tag peeling and `HEAD` equality, locked two-binary build with checkout-prefix remapping, contract test, deterministic package invocation, verifier-before-extraction, and final-step-only GitHub CLI credentials.
2. Make publication idempotent and race-aware: explicitly compute/set title, notes, and SemVer prerelease state; resolve and peel the exact remote tag immediately before each create/edit/upload and after publication; edit and clobber-upload when the release exists; create with `--verify-tag` otherwise.
3. Add the reviewed v0.1.0 body with pinned Core revision, platform boundaries, source/crate distinction, downloadable Linux archive, and current limits.
4. Re-run the focused test until the workflow/notes contract is GREEN.

### Task 4: Align deployment and changelog documentation

**Files:**
- Modify: `docs/deployment.md`
- Modify: `docs/status.md`
- Modify: `CHANGELOG.md`

**Steps:**
1. Document the tag-triggered Linux archive name, relocatable layout, and direct execution paths while preserving the no-crates.io and pinned-Core facts.
2. Replace obsolete no-prebuilt-artifact statements with conditional publication wording that remains true before the tag exists.
3. Run `cargo +1.99.1 test --locked --all-features --test docs_contract_tests` and repair only release-related contract drift.

### Task 5: Verify real packaging and repository quality

**Files:**
- No new production files expected.

**Steps:**
1. Run `cargo +1.99.1 fmt --all -- --check`, focused packaging tests, full docs contract tests, and `git diff --check`.
2. Parse `.github/workflows/release.yml` using an available YAML parser and assert the workflow has one Linux job.
3. Build both real release binaries for `x86_64-unknown-linux-gnu` if feasible, run the packager against them, and inspect the tar inventory programmatically against tracked production counts and forbidden-path rules.
4. Self-review the design, plan, tests, script, workflow, and docs against every stated requirement; inspect `git diff` and repository status.
5. Commit meaningful groups as `fffonion <fffonion@gmail.com>`.
