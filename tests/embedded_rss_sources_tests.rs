//! Embedded compile-time RSS resource catalog: production gates.
//!
//! Three independent gate families:
//!
//! 1. Real Core VM policy execution: the catalog's `source_policy.rss` bytes
//!    compiles with the production host catalog, runs at a guaranteed-absent
//!    virtual root, and returns the genuine bundled/default, Unicode
//!    legacy-precedence, and invalid-authority decisions.
//! 2. A trusted raw compile qualification: the ACTUAL coding `agent/main.rss`
//!    compiles entirely from embedded overrides at an absent virtual root.
//!    This is a compile-boundary proof, NOT a provider turn or full shared
//!    import-admission safety claim.
//! 3. A source-free child re-exec: the current test executable re-runs the
//!    same compile from an assigned source-free scratch cwd, proving the
//!    catalog has no runtime source-root dependency.
//!
//! The library never reopens a source root, reads an environment variable, or
//! materializes files at runtime; test-only byte binding below reads the
//! tracked tree solely to prove the embedded bytes are the real assets.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::{agent_host_catalog, bundled_rss_sources};
use rustscript_vm::{
    CompileSourceFileOptions, InvocationItem, InvocationPoll, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};

const VIRTUAL_ROOT: &str = "/__task9_embedded_rss_absent_root__";
const FUEL: u64 = 5_000_000;
const MAIN_KEY: &str = "rss/agent/main.rss";
const EXCLUDED_FIXTURES: &[&str] = &[
    "rss/auth/oauth_flow.rss",
    "rss/auth/store_entry.rss",
    "rss/auth/config_entry.rss",
];
const SOURCE_FREE_CHILD_ENV: &str = "TASK9_SOURCE_FREE_CHILD";

fn virtual_path(key: &str) -> String {
    format!("{VIRTUAL_ROOT}/{key}")
}

fn catalog_source(key: &str) -> &'static str {
    bundled_rss_sources()
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, source)| *source)
        .unwrap_or_else(|| panic!("catalog is missing {key}"))
}

fn compile_options() -> CompileSourceFileOptions {
    let catalog = agent_host_catalog();
    let mut options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    for (key, source) in bundled_rss_sources() {
        options.set_module_override_source(virtual_path(key), *source);
    }
    options
}

fn compile_entry(entry_key: &str) -> rustscript_vm::Program {
    let entry_path = virtual_path(entry_key);
    let source = catalog_source(entry_key);
    compile_source_at_path_with_flavor_and_options(
        entry_path,
        source,
        SourceFlavor::RustScript,
        compile_options(),
    )
    .unwrap_or_else(|error| panic!("catalog entry {entry_key} must compile: {error}"))
    .program
}

fn invoke(program: rustscript_vm::Program, context: Value) -> Value {
    let mut vm = Vm::try_new(program).expect("fresh Core VM");
    assert_eq!(vm.run().expect("run RSS root frame"), VmStatus::Halted);
    let callable = vm
        .resolve_exported_callable("run")
        .expect("resolve exported run");
    vm.set_fuel(FUEL);
    let mut invocation = vm
        .start_invocation(callable, vec![context])
        .expect("start invocation");
    loop {
        match invocation.poll_next().expect("poll invocation") {
            InvocationPoll::Pending => std::thread::sleep(Duration::from_millis(1)),
            InvocationPoll::Ready(Some(Ok(InvocationItem::Complete(value)))) => return value,
            InvocationPoll::Ready(Some(Ok(InvocationItem::Event(value)))) => {
                panic!("source policy emitted an unexpected event: {value:?}")
            }
            InvocationPoll::Ready(Some(Err(error))) => {
                panic!("source policy invocation failed: {error:?}")
            }
            InvocationPoll::Ready(None) => panic!("source policy stream ended early"),
        }
    }
}

fn map_field<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected a map, got {value:?}");
    };
    fields
        .iter()
        .find_map(|(k, v)| match k {
            Value::String(name) if name.as_ref() == key => Some(v),
            _ => None,
        })
        .unwrap_or_else(|| panic!("map is missing field {key}: {value:?}"))
}

fn bundled_success() -> Value {
    Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("source"), Value::string("bundled:coding")),
        (
            Value::string("descriptor"),
            Value::map(vec![
                (Value::string("kind"), Value::string("bundled")),
                (Value::string("resource"), Value::string("coding")),
            ]),
        ),
        (Value::string("deprecated_override"), Value::Bool(false)),
    ])
}

fn file_success(source: &str, path: &str, deprecated_override: bool) -> Value {
    Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("source"), Value::string(source)),
        (
            Value::string("descriptor"),
            Value::map(vec![
                (Value::string("kind"), Value::string("file")),
                (Value::string("path"), Value::string(path)),
            ]),
        ),
        (
            Value::string("deprecated_override"),
            Value::Bool(deprecated_override),
        ),
    ])
}

fn failure(code: &str, message: &str) -> Value {
    Value::map(vec![
        (Value::string("ok"), Value::Bool(false)),
        (Value::string("deprecated_override"), Value::Bool(false)),
        (
            Value::string("error"),
            Value::map(vec![
                (Value::string("code"), Value::string(code)),
                (Value::string("message"), Value::string(message)),
            ]),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Gate 1: real Core VM source-policy execution at an absent virtual root.
// ---------------------------------------------------------------------------

#[test]
fn source_policy_default_selects_bundled_coding() {
    let program = compile_entry("rss/agent/source_policy.rss");
    assert_eq!(invoke(program, Value::map(vec![])), bundled_success());
}

#[test]
fn source_policy_configured_unicode_path_beats_legacy() {
    let program = compile_entry("rss/agent/source_policy.rss");
    let path = "/srv/エージェント dir/my agent.rss";
    let context = Value::map(vec![
        (
            Value::string("source"),
            Value::string(format!("file:{path}")),
        ),
        (
            Value::string("legacy_script"),
            Value::string("/legacy/agent.rss"),
        ),
    ]);
    let value = invoke(program, context);
    assert_eq!(value, file_success(&format!("file:{path}"), path, false));
    assert_eq!(
        map_field(map_field(&value, "descriptor"), "path"),
        &Value::string(path)
    );
}

#[test]
fn source_policy_invalid_authority_has_no_fallback() {
    let program = compile_entry("rss/agent/source_policy.rss");
    let context = Value::map(vec![
        (Value::string("source"), Value::Int(12)),
        (
            Value::string("legacy_script"),
            Value::string("/legacy/agent.rss"),
        ),
    ]);
    assert_eq!(
        invoke(program, context),
        failure("invalid_agent_source", "agent source is invalid")
    );
}

// ---------------------------------------------------------------------------
// Inventory structure and test-only byte binding.
// ---------------------------------------------------------------------------

#[test]
fn catalog_keys_are_sorted_unique_rss_paths() {
    let keys: Vec<&str> = bundled_rss_sources().iter().map(|(key, _)| *key).collect();
    assert!(!keys.is_empty(), "catalog must not be empty");
    assert!(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "catalog keys must be strictly sorted and unique"
    );
    for key in &keys {
        assert!(
            key.starts_with("rss/") && key.ends_with(".rss"),
            "key {key} is not an original rss/... asset key"
        );
        assert!(
            !key.contains('\\') && !key.chars().any(char::is_control),
            "key {key} carries a backslash or control character"
        );
    }
    for fixture in EXCLUDED_FIXTURES {
        assert!(
            !keys.contains(fixture),
            "default-corpus fixture {fixture} must be excluded"
        );
    }
    assert!(
        keys.contains(&"rss/storage/import-test.rss"),
        "legacy storage/import-test.rss is inventory and must be included"
    );
}

/// Test-only binding: prove the embedded `include_str!` bytes equal the
/// tracked on-disk assets for the full catalog key set, and that the key set
/// is exactly the tracked tree minus the three exact fixtures. The library
/// never performs this read; it exists so catalog bytes bind to the manifest.
#[test]
fn catalog_bytes_bind_to_tracked_tree() {
    let rss_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss");
    let mut tracked: Vec<String> = Vec::new();
    walk_rss(&rss_root, &rss_root, &mut tracked);
    let mut expected: Vec<String> = tracked
        .into_iter()
        .filter(|key| !EXCLUDED_FIXTURES.contains(&key.as_str()))
        .collect();
    expected.sort();

    let keys: Vec<String> = bundled_rss_sources()
        .iter()
        .map(|(key, _)| (*key).to_owned())
        .collect();
    assert_eq!(
        keys, expected,
        "catalog key set must match the tracked tree"
    );

    for (key, embedded) in bundled_rss_sources() {
        let on_disk = std::fs::read(rss_root.join(key.strip_prefix("rss/").expect("rss/ prefix")))
            .unwrap_or_else(|error| panic!("read {key}: {error}"));
        let on_disk = String::from_utf8(on_disk).unwrap_or_else(|_| panic!("{key} is not UTF-8"));
        assert_eq!(*embedded, on_disk, "embedded bytes diverge from {key}");
    }
}

fn walk_rss(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let meta = std::fs::symlink_metadata(&path).expect("symlink_metadata");
        assert!(
            !meta.file_type().is_symlink(),
            "rss tree must not contain symlinks: {}",
            path.display()
        );
        if meta.is_dir() {
            walk_rss(root, &path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rss") {
            let relative = path.strip_prefix(root).expect("under rss root");
            out.push(format!(
                "rss/{}",
                relative.to_string_lossy().replace('\\', "/")
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Gate 2: trusted raw compile qualification of the coding main entry.
// ---------------------------------------------------------------------------

#[test]
fn coding_main_compiles_from_embedded_overrides_at_absent_root() {
    // The entry is the real production coding agent; it and every transitive
    // relative import resolve exclusively from embedded catalog bytes. The
    // virtual root is a guaranteed-absent absolute path, so any attempt to
    // reopen a repository file fails the compile.
    assert!(
        !PathBuf::from(VIRTUAL_ROOT).exists(),
        "virtual root must be absent"
    );
    let program = compile_entry(MAIN_KEY);
    assert!(
        program
            .exported_callables
            .iter()
            .any(|callable| callable.name == "run"),
        "coding main must export run(context)"
    );
}

/// Child-only variant used by the source-free re-exec test. Ignored in the
/// ordinary suite: it is executed explicitly with `--ignored` by
/// `coding_main_compiles_outside_checkout_from_scratch_cwd`, so it never
/// passes vacuously.
#[test]
#[ignore = "child-only: re-executed by the source-free parent gate"]
fn source_free_child_compiles_coding_main() {
    assert_eq!(
        std::env::var(SOURCE_FREE_CHILD_ENV).as_deref(),
        Ok("1"),
        "child-only test must be launched with {SOURCE_FREE_CHILD_ENV}=1"
    );
    let cwd = std::env::current_dir().expect("child cwd");
    assert!(
        !cwd.starts_with(env!("CARGO_MANIFEST_DIR")),
        "child must run outside the checkout, got {}",
        cwd.display()
    );
    let program = compile_entry(MAIN_KEY);
    assert!(
        program
            .exported_callables
            .iter()
            .any(|callable| callable.name == "run"),
        "source-free child must compile coding main"
    );
}

#[test]
fn coding_main_compiles_outside_checkout_from_scratch_cwd() {
    // Re-run THIS test executable as a child from an assigned source-free
    // scratch directory. The catalog's compile-time absolute include_str!
    // paths still resolve, proving there is no runtime source-root reopening.
    let exe = std::env::current_exe().expect("current test executable");
    let scratch = std::env::temp_dir().join(format!("task9-source-free-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("create scratch cwd");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "source_free_child_compiles_coding_main",
            "--ignored",
            "--nocapture",
        ])
        .env(SOURCE_FREE_CHILD_ENV, "1")
        .current_dir(&scratch)
        .output()
        .expect("spawn source-free child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "source-free child failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "source-free child did not run the single child test:\n{stdout}"
    );
}
