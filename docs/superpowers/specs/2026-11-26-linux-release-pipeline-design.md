# Linux Release Pipeline Design

**Approved requirement:** A pushed `v*` tag publishes one deterministic Linux x86_64 GNU archive containing both release binaries and every production RSS/YAML runtime asset in a relocatable tree. No other platform or architecture is built.

## Delivery contract

`.github/workflows/release.yml` has one `ubuntu-latest` job, `contents: write`, full-SHA-pinned actions, Rust 1.99.1, and the explicit `x86_64-unknown-linux-gnu` target. It accepts only non-forced tag-creation events, serializes each tag with non-cancelling per-tag concurrency, and checks out without persisted credentials. It peels annotated tags to a commit, requires checkout `HEAD` to equal that commit, and derives the one-line `SOURCE_DATE_EPOCH` from it. The release build remaps the checkout prefix, packages both manifest binaries, verifies and extracts the result, and then creates or updates the GitHub Release. `GH_TOKEN` exists only in the final publication step. That step resolves and peels the exact remote tag immediately before every create, edit, or upload operation and verifies it again after publication, so a run for a deleted or moved tag cannot continue. Existing releases have title/notes refreshed and the asset uploaded with `--clobber`; new releases use `--verify-tag`. A SemVer parser sets the prerelease flag from the prerelease component only, independently of build metadata.

The workflow derives `SOURCE_DATE_EPOCH` from the tagged commit and uses `docs/releases/<version>.md` as release notes. The asset is `rustscript-agent-<tag>-x86_64-unknown-linux-gnu.tar.gz` and the release title is `rustscript-agent <tag>`.

## Packaging contract

`scripts/package_linux_release.py --tag TAG --binary-dir DIR --output-dir DIR` reads the package version from `Cargo.toml` and accepts only `v<package.version>`. It rejects missing, symlinked, or nonregular inputs. The reviewed files under `release/` classify every tracked RSS, schema, and example candidate as production or support, and give explicit archive destinations for approved schemas and examples. Python standard-library tar/gzip APIs create byte-repeatable output with sorted entries, normalized ownership, fixed modes, and `SOURCE_DATE_EPOCH` timestamps. Its verifier rejects duplicate raw names, normalized aliases, unsafe paths, links, and count/inventory drift before extraction; it then compares every regular member byte-for-byte with its selected source or binary, validates the exact manifest, and scans every regular member for the original checkout path.

The archive root equals the archive filename stem. Its relocatable layout is:

- `bin/rustscript-agent` and `bin/rustscript-agent-gateway`, mode 0755;
- all 82 explicitly classified production `rss/**/*.rss` files under `share/rustscript-agent/rss/**`, preserving relative topology and import closure while excluding the five reviewed support/fixture entries;
- the 10 explicitly approved production YAML schemas under `share/rustscript-agent/schemas/**`;
- the explicitly approved `examples/http_get.rss`, `docs/examples/config.yaml`, and `docs/examples/auth.yaml` under `share/rustscript-agent/examples/**`;
- `README.md`, `LICENSE`, `CHANGELOG.md`, and a sorted path-only `MANIFEST.txt` at the root.

Only these explicit source trees/files are eligible. Test fixtures, workflow YAML, credentials, state databases, target intermediates, and checkout paths cannot enter the archive. No checksums are generated.

## Verification strategy

`tests/release_packaging_tests.rs` constructs real archives with fake regular binaries and checks complete production/support classification, RSS import closure, exact production inventory/mapping, every regular member's bytes against its independently selected source, raw and normalized member uniqueness, modes, direct byte reproducibility, exact manifest order/content/counts, duplicate/unsafe archive failures, validation failures, checkout-path absence from every regular member, and workflow/release-note contracts without whole-file snapshots. Existing CI discovers this cargo integration test. The release workflow runs the same contract test before the real remapped build, then invokes the verifier before extracting the produced artifact.

## Documentation boundary

Release notes retain the reviewed v0.1.0 capability and limitation statements, pin RustScript Core revision `11c9ee908a29365bd02573311f56e9308eb7dbe6`, state Unix read/list and Linux mutation/publication boundaries, and distinguish the attached Linux bundle from the absence of crates.io packages or published Core crates. Deployment and changelog documentation describe the downloadable archive and layout without claiming an artifact exists before the tag workflow publishes it.
