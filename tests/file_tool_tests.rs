use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustscript_agent::config::{
    ARTIFACT_RECONCILE_OVERHEAD_ENTRIES, ArtifactStoreConfig, FileToolConfig, MAX_ARTIFACT_OBJECTS,
};
use rustscript_agent::tools::{
    ArtifactOwner, ArtifactStore, FileTools, NativeToolExecutor, ReadFileRequest,
    SearchFilesRequest, ToolResult,
};
use rustscript_vm::MAX_ENUM_ENTRIES;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn test_temp_root() -> PathBuf {
    std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let parent =
            test_temp_root().join(format!("file-tools-{}-{}", std::process::id(), sequence));
        let root = parent.join("workspace");
        fs::create_dir_all(&root).expect("create task fixture root");
        Self { root, parent }
    }

    fn tools(&self) -> FileTools {
        FileTools::new(FileToolConfig::for_workspace(&self.root))
            .expect("fixture file tools should initialize")
    }

    fn tools_with_config(&self, mut config: FileToolConfig) -> FileTools {
        config.workspace_root = self.root.clone();
        config.artifact_store.root = self.parent.join(format!(
            "artifacts-{}",
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        FileTools::new(config).expect("configured fixture file tools should initialize")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

fn error_code(result: &ToolResult) -> &str {
    result
        .error
        .as_ref()
        .expect("tool result should contain an error")
        .code
        .as_str()
}

fn owner() -> ArtifactOwner {
    ArtifactOwner::new("profile-test", "session-test", "run-test").expect("owner")
}

fn synthetic_artifact_id(index: usize) -> String {
    format!("00000000-0000-4000-8000-{index:012x}")
}

fn seed_artifact_objects(root: &std::path::Path, count: usize) -> Vec<String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_millis() as u64;
    let mut objects = Vec::with_capacity(count);
    let mut ids = Vec::with_capacity(count);
    for index in 0..count {
        let id = synthetic_artifact_id(index);
        fs::write(root.join(&id), b"x").expect("write seeded artifact object");
        objects.push(serde_json::json!({
            "id": id,
            "profile": "profile-test",
            "session": "session-test",
            "run": "run-test",
            "size": 1,
            "created_unix_ms": now_ms,
            "expires_unix_ms": now_ms + 60_000,
        }));
        ids.push(id);
    }
    let manifest = serde_json::json!({
        "version": 1,
        "objects": objects,
    });
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("encode seeded manifest"),
    )
    .expect("write seeded manifest");
    ids
}

fn artifact_config(root: std::path::PathBuf, max_objects: usize) -> ArtifactStoreConfig {
    ArtifactStoreConfig {
        root,
        max_object_bytes: 16,
        max_total_bytes: max_objects.saturating_mul(16).max(16),
        max_objects,
        ttl: Duration::from_secs(60),
    }
}

#[test]
fn file_paths_reject_traversal_absolute_and_nul_without_host_details() {
    let fixture = Fixture::new();
    let tools = fixture.tools();

    for path in [
        "../outside.txt",
        "/tmp/outside.txt",
        "nested/../../outside.txt",
        "bad\0name",
        "",
    ] {
        let result = tools.read_file(ReadFileRequest::new(path));
        assert!(!result.ok, "path {path:?} must be rejected");
        assert_eq!(error_code(&result), "path_denied");
        let message = &result.error.as_ref().unwrap().message;
        assert!(!message.contains(fixture.root.to_string_lossy().as_ref()));
        assert!(!message.contains("outside"));
    }
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_denied_for_reads_writes_and_search() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let outside = fixture
        .root
        .parent()
        .unwrap()
        .join("file-tools-outside-secret");
    fs::write(&outside, "outside-secret\n").expect("write outside fixture");
    symlink(&outside, fixture.root.join("link.txt")).expect("create file symlink");
    fs::create_dir(fixture.root.join("nested")).expect("create nested fixture");
    symlink(
        outside.parent().unwrap(),
        fixture.root.join("nested/outside-dir"),
    )
    .expect("create directory symlink");

    let tools = fixture.tools();
    let read = tools.read_file(ReadFileRequest::new("link.txt"));
    assert!(!read.ok);
    assert_eq!(error_code(&read), "path_denied");

    let write = tools.write_file("link.txt", "replacement\n");
    assert!(!write.ok);
    assert_eq!(error_code(&write), "path_denied");
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside-secret\n");

    let search = tools.search_files(SearchFilesRequest::new("outside-secret"));
    assert!(search.ok, "symlink entries should be skipped by search");
    assert!(!search.content.contains("outside-secret"));
    assert!(!search.content.contains("outside-dir"));
}

#[test]
fn read_file_uses_one_based_line_offset_and_bounded_line_limit() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("lines.txt"), "one\ntwo\nthree\nfour\n")
        .expect("write line fixture");
    let tools = fixture.tools();

    let result = tools.read_file(ReadFileRequest {
        path: "lines.txt".to_string(),
        offset: Some(2),
        limit: Some(2),
    });
    assert!(result.ok);
    assert_eq!(result.content, "two\nthree\n");
    assert_eq!(result.data["offset"], 2);
    assert_eq!(result.data["line_count"], 2);
    assert!(!result.truncated);

    let zero = tools.read_file(ReadFileRequest {
        path: "lines.txt".to_string(),
        offset: Some(0),
        limit: Some(1),
    });
    assert!(!zero.ok);
    assert_eq!(error_code(&zero), "invalid_offset");
    assert!(zero.content.is_empty());

    let overflow = tools.read_file(ReadFileRequest {
        path: "lines.txt".to_string(),
        offset: Some(usize::MAX),
        limit: Some(usize::MAX),
    });
    assert!(
        overflow.ok,
        "offset/limit overflow must fail closed without panicking"
    );
    assert!(overflow.content.is_empty());
    assert_eq!(overflow.data["offset"], usize::MAX as u64);
    assert_eq!(overflow.data["line_count"], 0);
}

#[test]
fn read_file_reports_invalid_utf8_and_binary_as_distinct_typed_errors() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("invalid.txt"), [0xff, 0xfe, b'\n']).expect("write invalid utf8");
    fs::write(fixture.root.join("binary.bin"), [0, 1, 2, 3]).expect("write binary fixture");
    let tools = fixture.tools();

    let invalid = tools.read_file(ReadFileRequest::new("invalid.txt"));
    assert!(!invalid.ok);
    assert_eq!(error_code(&invalid), "invalid_utf8");

    let binary = tools.read_file(ReadFileRequest::new("binary.bin"));
    assert!(!binary.ok);
    assert_eq!(error_code(&binary), "binary_file");
}

#[test]
fn oversized_result_without_owner_is_bounded_output_too_large() {
    let fixture = Fixture::new();
    let payload = "0123456789abcdef\n".repeat(16);
    fs::write(fixture.root.join("large.txt"), &payload).expect("write large fixture");
    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_output_bytes = 32;
    config.max_read_bytes = 1024;
    config.max_search_output_bytes = 32;
    config.artifact_store.max_object_bytes = 1024;
    config.artifact_store.max_total_bytes = 2048;
    let tools = fixture.tools_with_config(config);

    let result = tools.read_file(ReadFileRequest::new("large.txt"));
    assert!(!result.ok);
    assert_eq!(error_code(&result), "output_truncated");
    assert!(result.artifacts.is_empty());
    assert!(result.truncated);
    let encoded = serde_json::to_vec(&result).expect("serialize");
    assert!(
        encoded.len() < 512,
        "fail-closed envelope should stay compact: {}",
        encoded.len()
    );
}

#[test]
fn search_output_budget_is_independent_of_model_visible_output_budget() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.join("hit.txt"),
        "needle one\nneedle two\nneedle three\n",
    )
    .expect("write search fixture");
    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_search_output_bytes = 24;
    config.max_output_bytes = 1024;
    config.max_read_bytes = 1024;
    config.max_search_matches = 100;
    config.artifact_store.max_object_bytes = 1024;
    config.artifact_store.max_total_bytes = 2048;
    let tools = fixture.tools_with_config(config);

    let result = tools.search_files(SearchFilesRequest::new("needle"));
    assert!(result.ok);
    assert!(result.truncated);
    assert!(result.content.len() <= 24);
    assert!(result.artifacts.is_empty());
    assert!(!result.content.contains("needle three"));
}

#[test]
fn search_start_path_rejects_traversal_without_host_details() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("inside.txt"), "needle\n").expect("write inside fixture");
    let tools = fixture.tools();

    for path in [
        "../outside.txt",
        "/tmp/outside.txt",
        "nested/../../outside.txt",
        "bad\0name",
    ] {
        let result = tools.search_files(SearchFilesRequest {
            pattern: "needle".to_string(),
            path: Some(path.to_string()),
            target: None,
            file_glob: None,
            limit: None,
            offset: None,
        });
        assert!(!result.ok, "search start {path:?} must be rejected");
        assert_eq!(error_code(&result), "path_denied");
        let message = &result.error.as_ref().unwrap().message;
        assert!(!message.contains(fixture.root.to_string_lossy().as_ref()));
        assert!(!message.contains("outside"));
        assert!(result.content.is_empty());
    }
}

#[test]
fn patch_reports_binary_and_invalid_utf8_as_distinct_typed_errors() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("invalid.txt"), [0xff, 0xfe, b'\n']).expect("write invalid utf8");
    fs::write(fixture.root.join("binary.bin"), [0, 1, 2, 3]).expect("write binary fixture");
    let tools = fixture.tools();

    let invalid = tools.patch("invalid.txt", "a", "b", false);
    assert!(!invalid.ok);
    assert_eq!(error_code(&invalid), "invalid_utf8");
    assert_eq!(invalid.data["publication"], "not_published");

    let binary = tools.patch("binary.bin", "a", "b", false);
    assert!(!binary.ok);
    assert_eq!(error_code(&binary), "binary_file");
    assert_eq!(binary.data["publication"], "not_published");
}

#[test]
fn oversized_read_output_is_stored_as_bounded_owned_artifact() {
    let fixture = Fixture::new();
    let payload = "0123456789abcdef\n".repeat(256);
    fs::write(fixture.root.join("large.txt"), &payload).expect("write large fixture");
    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_output_bytes = 2048;
    config.max_read_bytes = 8192;
    config.max_search_output_bytes = 32;
    config.artifact_store.max_object_bytes = 8192;
    config.artifact_store.max_total_bytes = 16_384;
    let tools = fixture.tools_with_config(config);
    let tools = tools.with_owner(owner());

    let result = tools.read_file(ReadFileRequest::new("large.txt"));
    assert!(result.ok);
    assert!(result.truncated);
    assert_eq!(result.artifacts.len(), 1);
    assert!(serde_json::to_vec(&result).expect("serialize").len() <= 2048);
    assert!(result.content.contains("artifact"));
    assert!(!result.content.contains("0123456789abcdef"));

    let artifact = tools
        .artifact_store()
        .retrieve(&owner(), &result.artifacts[0])
        .expect("owner should retrieve its artifact");
    assert_eq!(artifact, payload.as_bytes());
}

#[test]
fn search_files_is_deterministic_and_bounds_files_matches_scan_and_output() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("z")).expect("create z directory");
    fs::create_dir(fixture.root.join("a")).expect("create a directory");
    fs::write(fixture.root.join("z/match.rs"), "needle z\nneedle z2\n").expect("write z fixture");
    fs::write(fixture.root.join("a/match.rs"), "needle a\n").expect("write a fixture");
    fs::write(fixture.root.join("root.txt"), "needle root\n").expect("write root fixture");

    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_search_files = 2;
    config.max_search_matches = 2;
    config.max_search_output_bytes = 1024;
    let tools = fixture.tools_with_config(config);

    let result = tools.search_files(SearchFilesRequest::new("needle"));
    assert!(result.ok);
    assert!(result.truncated);
    let lines: Vec<_> = result.content.lines().collect();
    assert!(lines.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(lines.len() <= 2);
}

#[test]
fn write_file_is_atomic_preserves_existing_permissions_and_cleans_failed_temps() {
    let fixture = Fixture::new();
    let path = fixture.root.join("atomic.txt");
    fs::write(&path, "old\n").expect("write old file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("set fixture mode");
    }
    let tools = fixture.tools();

    let result = tools.write_file("atomic.txt", "new\n");
    assert!(result.ok);
    assert_eq!(result.data["publication"], "published");
    assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Exclusive confined temps publish mode 0o600; the destination inode is
        // replaced rather than reopened through a host path to copy bits.
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_write_bytes = 2;
    let bounded = fixture.tools_with_config(config);
    let failed = bounded.write_file("atomic.txt", "too large\n");
    assert!(!failed.ok);
    assert_eq!(error_code(&failed), "write_too_large");
    assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    let residue: Vec<_> = fs::read_dir(&fixture.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rustscript-agent-tmp-"))
        .collect();
    assert!(
        residue.is_empty(),
        "failed writes must remove temporary files"
    );
}

#[test]
fn nested_write_publishes_through_same_directory_leaf() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("nested/dir")).expect("create nested parent");
    let tools = fixture.tools();

    let result = tools.write_file("nested/dir/leaf.txt", "nested-bytes\n");
    assert!(result.ok, "nested write should publish: {:?}", result.error);
    assert_eq!(result.data["publication"], "published");
    assert_eq!(
        fs::read_to_string(fixture.root.join("nested/dir/leaf.txt")).unwrap(),
        "nested-bytes\n"
    );
    let residue: Vec<_> = fs::read_dir(fixture.root.join("nested/dir"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rustscript-agent-tmp-"))
        .collect();
    assert!(residue.is_empty(), "nested write must clean staging files");
}

#[test]
fn nested_patch_publishes_through_same_directory_leaf() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("nested/dir")).expect("create nested parent");
    fs::write(
        fixture.root.join("nested/dir/leaf.txt"),
        "keep\nneedle\nkeep\n",
    )
    .expect("write nested patch fixture");
    let tools = fixture.tools();

    let result = tools.patch("nested/dir/leaf.txt", "needle", "replaced", false);
    assert!(result.ok, "nested patch should publish: {:?}", result.error);
    assert_eq!(result.data["publication"], "published");
    assert_eq!(result.data["replacements"], 1);
    assert_eq!(
        fs::read_to_string(fixture.root.join("nested/dir/leaf.txt")).unwrap(),
        "keep\nreplaced\nkeep\n"
    );
}

#[cfg(unix)]
#[test]
fn nested_symlink_and_swapped_parent_are_denied_without_touching_outside() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let outside_dir = fixture
        .root
        .parent()
        .unwrap()
        .join("file-tools-nested-outside-dir");
    fs::create_dir_all(&outside_dir).expect("create outside directory");
    fs::write(outside_dir.join("secret.txt"), "outside-secret\n").expect("write outside secret");
    fs::create_dir_all(fixture.root.join("nested/real")).expect("create nested real parent");
    fs::write(fixture.root.join("nested/real/leaf.txt"), "inside\n").expect("write nested leaf");
    symlink(&outside_dir, fixture.root.join("nested/swapped"))
        .expect("create nested parent symlink");
    symlink(
        outside_dir.join("secret.txt"),
        fixture.root.join("nested/real/link.txt"),
    )
    .expect("create nested destination symlink");
    let tools = fixture.tools();

    let parent = tools.write_file("nested/swapped/secret.txt", "changed\n");
    assert!(!parent.ok);
    assert_eq!(error_code(&parent), "path_denied");
    assert_eq!(parent.data["publication"], "not_published");

    let destination = tools.write_file("nested/real/link.txt", "changed\n");
    assert!(!destination.ok);
    assert_eq!(error_code(&destination), "path_denied");
    assert_eq!(destination.data["publication"], "not_published");

    let patched = tools.patch("nested/real/link.txt", "outside-secret", "changed", false);
    assert!(!patched.ok);
    assert_eq!(error_code(&patched), "path_denied");
    assert_eq!(patched.data["publication"], "not_published");

    assert_eq!(
        fs::read_to_string(outside_dir.join("secret.txt")).unwrap(),
        "outside-secret\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("nested/real/leaf.txt")).unwrap(),
        "inside\n"
    );
}

#[cfg(unix)]
#[test]
fn parent_and_target_symlink_swaps_fail_closed_without_touching_outside() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let outside_dir = fixture
        .root
        .parent()
        .unwrap()
        .join("file-tools-outside-dir");
    fs::create_dir_all(&outside_dir).expect("create outside directory");
    fs::write(outside_dir.join("target.txt"), "outside\n").expect("write outside target");
    fs::create_dir(fixture.root.join("real")).expect("create real parent");
    symlink(&outside_dir, fixture.root.join("swapped")).expect("create parent symlink");
    symlink(
        outside_dir.join("target.txt"),
        fixture.root.join("target.txt"),
    )
    .expect("create target symlink");
    let tools = fixture.tools();

    let parent_result = tools.write_file("swapped/target.txt", "changed\n");
    assert!(!parent_result.ok);
    assert_eq!(error_code(&parent_result), "path_denied");
    let target_result = tools.write_file("target.txt", "changed\n");
    assert!(!target_result.ok);
    assert_eq!(error_code(&target_result), "path_denied");
    assert_eq!(
        fs::read_to_string(outside_dir.join("target.txt")).unwrap(),
        "outside\n"
    );
}

#[test]
fn patch_requires_unique_match_unless_replace_all_is_explicit() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("patch.txt"), "a\nb\na\n").expect("write patch fixture");
    let tools = fixture.tools();

    let zero = tools.patch("patch.txt", "missing", "x", false);
    assert!(!zero.ok);
    assert_eq!(error_code(&zero), "patch_no_match");

    let multiple = tools.patch("patch.txt", "a", "x", false);
    assert!(!multiple.ok);
    assert_eq!(error_code(&multiple), "patch_multiple_matches");
    assert_eq!(
        fs::read_to_string(fixture.root.join("patch.txt")).unwrap(),
        "a\nb\na\n"
    );

    let all = tools.patch("patch.txt", "a", "x", true);
    assert!(all.ok);
    assert_eq!(all.data["replacements"], 2);
    assert!(all.content.contains("diff"));
    assert_eq!(
        fs::read_to_string(fixture.root.join("patch.txt")).unwrap(),
        "x\nb\nx\n"
    );
}

#[test]
fn patch_rejects_unbounded_growth_before_replacing_file() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("patch.txt"), "needle\n").expect("write patch fixture");
    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_patch_bytes = 16;
    let tools = fixture.tools_with_config(config);

    let result = tools.patch("patch.txt", "needle", &"x".repeat(64), false);
    assert!(!result.ok);
    assert_eq!(error_code(&result), "patch_too_large");
    assert_eq!(
        fs::read_to_string(fixture.root.join("patch.txt")).unwrap(),
        "needle\n"
    );
}

#[test]
fn artifact_store_enforces_opaque_ids_ownership_and_exhaustion() {
    let fixture = Fixture::new();
    let artifact_root = fixture.root.join("artifacts");
    fs::create_dir(&artifact_root).expect("create artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 1,
        ttl: std::time::Duration::from_secs(60),
    };
    let store = ArtifactStore::with_config(config).expect("create artifact store");
    let first_owner = owner();
    let other_owner =
        ArtifactOwner::new("other-profile", "other-session", "other-run").expect("other owner");

    let first = store
        .put(&first_owner, b"artifact-data")
        .expect("store first artifact");
    assert!(!first.id.contains('/'));
    assert!(!first.id.contains(".."));
    assert_eq!(
        store.retrieve(&first_owner, &first.id).unwrap(),
        b"artifact-data"
    );
    assert_eq!(
        store.retrieve(&other_owner, &first.id).unwrap_err().code(),
        "artifact_not_found"
    );

    let exhausted = store.put(&first_owner, b"second");
    assert_eq!(exhausted.unwrap_err().code(), "artifact_store_exhausted");
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.total_bytes(), b"artifact-data".len());
    assert_eq!(
        store.confined_object_len(&first.id).unwrap(),
        b"artifact-data".len() as u64
    );
    assert_retained_matches_confined_disk(&store);
    let oversized = store.put(&first_owner, &[0_u8; 65]);
    assert_eq!(oversized.unwrap_err().code(), "artifact_too_large");
    let residue: Vec<_> = fs::read_dir(store.root_path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rustscript-agent-tmp-"))
        .collect();
    assert!(residue.is_empty());
}

#[test]
fn config_rejects_zero_and_overlarge_file_tool_budgets() {
    let fixture = Fixture::new();
    let base = FileToolConfig::for_workspace(&fixture.root);
    base.validate()
        .expect("default file tool config should validate");

    let mut invalid = base.clone();
    invalid.max_read_bytes = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = base.clone();
    invalid.max_read_lines = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = base.clone();
    invalid.max_search_wall_time = std::time::Duration::ZERO;
    assert!(invalid.validate().is_err());
    let mut invalid = base.clone();
    invalid.artifact_store.max_objects = 0;
    assert!(invalid.validate().is_err());
    let mut accepted = base.clone();
    accepted.artifact_store.max_objects = MAX_ARTIFACT_OBJECTS;
    accepted
        .validate()
        .expect("payload ceiling reconciled to core enum max must validate");
    let mut rejected = base.clone();
    rejected.artifact_store.max_objects = MAX_ARTIFACT_OBJECTS + 1;
    assert!(rejected.validate().is_err());
    assert_eq!(
        MAX_ARTIFACT_OBJECTS,
        MAX_ENUM_ENTRIES - ARTIFACT_RECONCILE_OVERHEAD_ENTRIES,
        "public max_objects ceiling must be core enum max minus reconcile overhead"
    );
    let mut invalid = base.clone();
    invalid.artifact_store.ttl = std::time::Duration::ZERO;
    assert!(invalid.validate().is_err());
    let mut invalid = base;
    invalid.max_output_bytes = invalid.artifact_store.max_object_bytes + 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn every_tool_result_serializes_the_common_bounded_envelope() {
    let fixture = Fixture::new();
    let tools = fixture.tools();
    let result = tools.write_file("result.txt", "ok\n");
    let wire = serde_json::to_value(result).expect("tool result should serialize");
    for key in ["ok", "content", "data", "error", "truncated", "artifacts"] {
        assert!(wire.get(key).is_some(), "missing common result field {key}");
    }
}

#[test]
fn search_files_bounds_depth_scan_bytes_and_wall_time() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("nested/deep")).expect("create nested dirs");
    fs::write(fixture.root.join("root.txt"), "needle root\n").expect("write root fixture");
    fs::write(
        fixture.root.join("nested/deep/hidden.txt"),
        "needle hidden\n",
    )
    .expect("write deep fixture");
    fs::write(fixture.root.join("large.txt"), "needle ".repeat(1024)).expect("write large fixture");

    let mut depth_config = FileToolConfig::for_workspace(&fixture.root);
    depth_config.max_search_depth = 1;
    let depth_tools = fixture.tools_with_config(depth_config);
    let depth = depth_tools.search_files(SearchFilesRequest::new("needle"));
    assert!(depth.ok);
    assert!(depth.content.contains("root.txt"));
    assert!(!depth.content.contains("hidden"));

    let mut scan_config = FileToolConfig::for_workspace(&fixture.root);
    scan_config.max_search_scanned_bytes = 8;
    let scan_tools = fixture.tools_with_config(scan_config);
    let scan = scan_tools.search_files(SearchFilesRequest::new("needle"));
    assert!(scan.ok);
    assert!(scan.truncated);

    let mut time_config = FileToolConfig::for_workspace(&fixture.root);
    time_config.max_search_wall_time = std::time::Duration::from_nanos(1);
    let time_tools = fixture.tools_with_config(time_config);
    let timed = time_tools.search_files(SearchFilesRequest::new("needle"));
    assert!(timed.ok);
    assert!(timed.truncated);
}

#[test]
fn patch_applies_a_unique_match_and_denied_writes_stay_unpublished() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("unique.txt"), "keep\nneedle\nkeep\n")
        .expect("write unique fixture");
    let tools = fixture.tools();

    let unique = tools.patch("unique.txt", "needle", "replaced", false);
    assert!(unique.ok);
    assert_eq!(unique.data["replacements"], 1);
    assert_eq!(unique.data["publication"], "published");
    assert_eq!(
        fs::read_to_string(fixture.root.join("unique.txt")).unwrap(),
        "keep\nreplaced\nkeep\n"
    );

    let denied = tools.write_file("../escape.txt", "nope\n");
    assert!(!denied.ok);
    assert_eq!(error_code(&denied), "path_denied");
    assert_eq!(denied.data["publication"], "not_published");
}

#[test]
fn artifact_store_expires_objects_through_cleanup() {
    let fixture = Fixture::new();
    let artifact_root = fixture.root.join("artifacts-ttl");
    fs::create_dir(&artifact_root).expect("create ttl artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 4,
        ttl: Duration::from_secs(60),
    };
    let store = ArtifactStore::with_config(config).expect("create ttl artifact store");
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    store.set_now(start);
    let handle = store
        .put(&owner(), b"expire-me")
        .expect("store expiring artifact");
    store.set_now(start + Duration::from_secs(60));
    let removed = store.cleanup().expect("cleanup expired artifacts");
    assert!(removed >= 1);
    assert_eq!(store.object_count(), 0);
    assert_eq!(store.total_bytes(), 0);
    assert_eq!(
        store.confined_object_len(&handle.id).unwrap_err().code(),
        "artifact_not_found"
    );
    assert_eq!(
        store.retrieve(&owner(), &handle.id).unwrap_err().code(),
        "artifact_not_found"
    );
}

fn assert_retained_matches_confined_disk(store: &ArtifactStore) {
    let mut names = store
        .confined_object_names()
        .expect("artifact store should enumerate through the confined root");
    names.sort();
    assert_eq!(
        names.len(),
        store.object_count(),
        "retained count must match confined disk objects {names:?}"
    );
    let mut bytes = 0_usize;
    for name in &names {
        bytes += usize::try_from(store.confined_object_len(name).expect("confined metadata"))
            .expect("object size should fit usize");
    }
    assert_eq!(store.total_bytes(), bytes);
}

#[test]
fn artifact_ttl_cleanup_unlinks_files_and_reclaims_count_bytes_per_owner() {
    let fixture = Fixture::new();
    let artifact_root = fixture.root.join("artifacts-reclaim");
    fs::create_dir(&artifact_root).expect("create reclaim artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 256,
        max_objects: 8,
        ttl: Duration::from_secs(60),
    };
    let store = ArtifactStore::with_config(config).expect("create reclaim artifact store");
    let first_owner = owner();
    let other_owner =
        ArtifactOwner::new("other-profile", "other-session", "other-run").expect("other owner");
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
    store.set_now(start);

    let first = store
        .put(&first_owner, b"owner-a")
        .expect("store first owner artifact");
    let second = store
        .put(&other_owner, b"owner-bb")
        .expect("store second owner artifact");
    assert_eq!(store.object_count(), 2);
    assert_eq!(store.total_bytes(), b"owner-a".len() + b"owner-bb".len());
    assert_eq!(
        store.retrieve(&other_owner, &first.id).unwrap_err().code(),
        "artifact_not_found"
    );
    assert_eq!(store.retrieve(&first_owner, &first.id).unwrap(), b"owner-a");
    assert_eq!(
        store.retrieve(&other_owner, &second.id).unwrap(),
        b"owner-bb"
    );
    assert_eq!(
        store.confined_object_len(&first.id).unwrap(),
        b"owner-a".len() as u64
    );
    assert_eq!(
        store.confined_object_len(&second.id).unwrap(),
        b"owner-bb".len() as u64
    );
    assert_retained_matches_confined_disk(&store);

    store.set_now(start + Duration::from_secs(60));
    let removed = store.cleanup().expect("ttl cleanup should unlink objects");
    assert_eq!(removed, 2);
    assert_eq!(store.object_count(), 0);
    assert_eq!(store.total_bytes(), 0);
    assert!(
        store
            .confined_object_names()
            .expect("confined enumeration after ttl")
            .is_empty()
    );
    assert_eq!(
        store.retrieve(&first_owner, &first.id).unwrap_err().code(),
        "artifact_not_found"
    );
    assert_eq!(
        store.retrieve(&other_owner, &second.id).unwrap_err().code(),
        "artifact_not_found"
    );
    assert_eq!(
        store.confined_object_len(&first.id).unwrap_err().code(),
        "artifact_not_found"
    );
    assert_eq!(
        store.confined_object_len(&second.id).unwrap_err().code(),
        "artifact_not_found"
    );
    assert_retained_matches_confined_disk(&store);
}

#[test]
fn concurrent_put_and_cleanup_keep_count_bytes_aligned_with_disk() {
    let fixture = Fixture::new();
    let artifact_root = fixture.root.join("artifacts-race");
    fs::create_dir(&artifact_root).expect("create race artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 32,
        max_total_bytes: 96,
        max_objects: 3,
        ttl: Duration::from_secs(60),
    };
    let store = std::sync::Arc::new(ArtifactStore::with_config(config).expect("create race store"));
    let owners = [
        ArtifactOwner::new("p0", "s0", "r0").expect("owner 0"),
        ArtifactOwner::new("p1", "s1", "r1").expect("owner 1"),
        ArtifactOwner::new("p2", "s2", "r2").expect("owner 2"),
        ArtifactOwner::new("p3", "s3", "r3").expect("owner 3"),
    ];

    std::thread::scope(|scope| {
        for owner in &owners {
            let store = std::sync::Arc::clone(&store);
            let owner = owner.clone();
            scope.spawn(move || {
                for round in 0..8 {
                    let payload = [round as u8; 8];
                    let _ = store.put(&owner, &payload);
                    let _ = store.cleanup();
                }
            });
        }
        let cleaner = std::sync::Arc::clone(&store);
        scope.spawn(move || {
            for _ in 0..16 {
                let _ = cleaner.cleanup();
            }
        });
    });

    let _ = store.cleanup();
    assert_retained_matches_confined_disk(&store);
    assert!(store.object_count() <= 3);
    assert!(store.total_bytes() <= 96);
}

#[test]
fn coding_executors_run_through_native_tool_executor_contracts() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("exec.txt"), "alpha\nbeta\n").expect("write executor fixture");
    let tools = fixture.tools();

    let read = tools.execute(
        &NativeToolExecutor::ReadFile,
        &serde_json::json!({"path": "exec.txt", "offset": 2, "limit": 1}),
    );
    assert!(read.ok);
    assert_eq!(read.content, "beta\n");

    let search = tools.execute(
        &NativeToolExecutor::SearchFiles,
        &serde_json::json!({"pattern": "alpha", "target": "content"}),
    );
    assert!(search.ok);
    assert!(search.content.contains("exec.txt"));

    let write = tools.execute(
        &NativeToolExecutor::WriteFile,
        &serde_json::json!({"path": "exec.txt", "content": "gamma\n"}),
    );
    assert!(write.ok);
    assert_eq!(
        fs::read_to_string(fixture.root.join("exec.txt")).unwrap(),
        "gamma\n"
    );

    let patch = tools.execute(
        &NativeToolExecutor::Patch,
        &serde_json::json!({
            "path": "exec.txt",
            "old_string": "gamma",
            "new_string": "delta",
            "replace_all": false
        }),
    );
    assert!(patch.ok);
    assert_eq!(
        fs::read_to_string(fixture.root.join("exec.txt")).unwrap(),
        "delta\n"
    );

    let terminal = tools.execute(
        &NativeToolExecutor::Terminal,
        &serde_json::json!({"argv": ["true"]}),
    );
    assert!(!terminal.ok);
    assert_eq!(error_code(&terminal), "unsupported_executor");

    let process = tools.execute(
        &NativeToolExecutor::Process,
        &serde_json::json!({"action": "poll"}),
    );
    assert!(!process.ok);
    assert_eq!(error_code(&process), "unsupported_executor");
    assert!(process.content.is_empty());
}

fn assert_valid_utf8_preview(preview: &str, max_bytes: usize) {
    assert!(
        preview.len() <= max_bytes,
        "preview is {} bytes, budget {max_bytes}",
        preview.len()
    );
    assert!(
        preview.is_char_boundary(preview.len()),
        "preview must end on a UTF-8 boundary"
    );
    assert!(
        std::str::from_utf8(preview.as_bytes()).is_ok(),
        "preview must remain valid UTF-8"
    );
}

#[test]
fn patch_preview_truncates_multibyte_path_and_content_on_char_boundaries() {
    let fixture = Fixture::new();
    let path = "café/🦀.txt";
    fs::create_dir_all(fixture.root.join("café")).expect("create multibyte parent");
    fs::write(fixture.root.join(path), "keep\n旧文字行\nkeep\n").expect("write multibyte fixture");

    let header = format!("diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n");
    let changed = "-旧文字行\n+新文字行\n";
    let full = format!("{header}{changed}");
    let marker = "…";

    let budgets = [
        1usize,
        2,
        header.len().saturating_sub(1),
        header.len(),
        header.len() + 1,
        header.len() + "旧".len() + 1,
        header.len() + changed.len() / 2,
        full.len().saturating_sub(1),
        full.len(),
        full.len() + marker.len(),
        16,
        24,
        32,
        40,
        48,
        64,
    ];
    for max_bytes in budgets {
        if max_bytes == 0 {
            continue;
        }
        let mut config = FileToolConfig::for_workspace(&fixture.root);
        config.max_patch_preview_bytes = max_bytes;
        let tools = fixture.tools_with_config(config);
        fs::write(fixture.root.join(path), "keep\n旧文字行\nkeep\n")
            .expect("reset multibyte fixture");
        let result = tools.patch(path, "旧文字行", "新文字行", false);
        assert!(
            result.ok,
            "preview budget {max_bytes} should still publish: {:?}",
            result.error
        );
        assert_valid_utf8_preview(&result.content, max_bytes);
        if result.content.len() < full.len() && max_bytes >= marker.len() {
            assert!(
                result.content.ends_with(marker)
                    || result.content.len() + marker.len() > max_bytes
                    || result.content == full,
                "truncated preview should reserve marker bytes at budget {max_bytes}: {:?}",
                result.content
            );
        }
        if result.content.contains(marker) {
            assert!(
                result.content.len() <= max_bytes,
                "marker must fit inside the byte budget"
            );
        }
    }
}

#[test]
fn search_stops_immediately_on_file_cap_without_walking_sibling_trees() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("a")).expect("create a directory");
    fs::create_dir(fixture.root.join("z")).expect("create z directory");
    for index in 0..32 {
        fs::write(
            fixture.root.join(format!("a/f{index:02}.txt")),
            "needle-a\n",
        )
        .expect("write a fixture");
    }
    fs::write(fixture.root.join("z/unique-z.txt"), "needle-z\n").expect("write z fixture");

    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_search_files = 4;
    config.max_search_matches = 100;
    config.max_search_output_bytes = 1024;
    let tools = fixture.tools_with_config(config);

    let started = Instant::now();
    let result = tools.search_files(SearchFilesRequest::new("needle"));
    let elapsed = started.elapsed();
    assert!(result.ok);
    assert!(result.truncated);
    assert!(
        elapsed < Duration::from_millis(500),
        "search must stop at the file cap instead of walking remaining siblings ({elapsed:?})"
    );
    let files_visited = result.data["files_visited"].as_u64().unwrap();
    let dirs_visited = result.data["dirs_visited"].as_u64().unwrap();
    assert!(
        files_visited <= 4,
        "files_visited={files_visited} must not exceed max_search_files"
    );
    assert!(
        dirs_visited <= 2,
        "dirs_visited={dirs_visited} must not continue into sibling trees after the cap"
    );
    assert!(!result.content.contains("unique-z"));
}

#[test]
fn search_huge_fanout_enumerates_with_config_budget_and_hard_elapsed_bound() {
    let fixture = Fixture::new();
    for index in 0..256 {
        fs::write(
            fixture.root.join(format!("fanout-{index:03}.txt")),
            "needle\n",
        )
        .expect("write fanout fixture");
    }
    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_search_files = 8;
    config.max_search_matches = 8;
    config.max_search_output_bytes = 2048;
    let tools = fixture.tools_with_config(config);

    let started = Instant::now();
    let result = tools.search_files(SearchFilesRequest::new("needle"));
    let elapsed = started.elapsed();
    assert!(result.ok);
    assert!(result.truncated);
    assert!(
        elapsed < Duration::from_millis(750),
        "huge-fanout search must stop from the enumerate budget ({elapsed:?})"
    );
    let files_visited = result.data["files_visited"].as_u64().unwrap();
    assert!(
        files_visited <= 8,
        "files_visited={files_visited} must not scan the whole fanout"
    );
}

#[test]
fn artifact_root_is_outside_workspace_and_invisible_to_read_and_search() {
    let fixture = Fixture::new();
    let payload = "secret-artifact-payload-xyz\n".repeat(200);
    fs::write(fixture.root.join("large.txt"), &payload).expect("write large fixture");
    let config = FileToolConfig::for_workspace(&fixture.root);
    assert!(
        !config.artifact_store.root.starts_with(&fixture.root),
        "default artifact root must not live inside the workspace"
    );
    assert!(
        !fixture.root.starts_with(&config.artifact_store.root),
        "workspace must not live inside the artifact root"
    );
    config
        .validate()
        .expect("default workspace config must validate");

    let mut nested = FileToolConfig::for_workspace(&fixture.root);
    nested.artifact_store.root = fixture.root.join("inside-artifacts");
    assert!(
        nested.validate().is_err(),
        "artifact root inside the workspace must fail closed"
    );

    let mut config = FileToolConfig::for_workspace(&fixture.root);
    config.max_output_bytes = 2048;
    config.max_read_bytes = 8192;
    config.max_search_output_bytes = 32;
    config.artifact_store.max_object_bytes = 8192;
    config.artifact_store.max_total_bytes = 16_384;
    let tools = fixture.tools_with_config(config).with_owner(owner());
    let stored = tools.read_file(ReadFileRequest::new("large.txt"));
    assert!(stored.ok);
    assert_eq!(stored.artifacts.len(), 1);
    let artifact_id = &stored.artifacts[0];

    let read = tools.read_file(ReadFileRequest::new(artifact_id));
    assert!(!read.ok);
    assert_eq!(error_code(&read), "not_found");
    assert!(!read.content.contains("secret-artifact-payload-xyz"));

    let search = tools.search_files(SearchFilesRequest::new("secret-artifact-payload-xyz"));
    assert!(search.ok);
    assert!(!search.content.contains("secret-artifact-payload-xyz"));
    assert!(!search.content.contains(artifact_id));
}

#[test]
fn default_file_tool_budgets_are_coherent_and_finalize_does_not_surprise() {
    let fixture = Fixture::new();
    let config = FileToolConfig::for_workspace(&fixture.root);
    config
        .validate()
        .expect("default file tool config must validate");
    assert!(config.max_search_output_bytes <= config.max_output_bytes);
    assert!(config.max_output_bytes <= config.artifact_store.max_object_bytes);
    assert!(config.max_read_bytes <= config.artifact_store.max_object_bytes);
    assert!(config.max_search_output_bytes <= config.artifact_store.max_object_bytes);

    fs::write(fixture.root.join("ok.txt"), "hello\n").expect("write small fixture");
    let tools = fixture.tools();
    let read = tools.read_file(ReadFileRequest::new("ok.txt"));
    assert!(read.ok, "valid defaults must not reject a small read");
    assert!(!read.truncated);
    assert!(read.artifacts.is_empty());

    let mut invalid = FileToolConfig::for_workspace(&fixture.root);
    invalid.max_search_output_bytes = invalid.max_output_bytes + 1;
    assert!(invalid.validate().is_err());
    let mut invalid = FileToolConfig::for_workspace(&fixture.root);
    invalid.max_read_bytes = invalid.artifact_store.max_object_bytes + 1;
    assert!(invalid.validate().is_err());
}

#[cfg(unix)]
#[test]
fn artifact_cleanup_uses_retained_dirfd_after_root_path_swap() {
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-retained");
    fs::create_dir(&artifact_root).expect("create artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root.clone(),
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 4,
        ttl: Duration::from_secs(60),
    };
    let store = ArtifactStore::with_config(config).expect("create artifact store");
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000);
    store.set_now(start);
    let handle = store
        .put(&owner(), b"retain-me")
        .expect("store retained artifact");
    let aside = fixture.parent.join("artifacts-aside");
    fs::rename(&artifact_root, &aside).expect("swap artifact root aside");
    fs::create_dir(&artifact_root).expect("replacement artifact root");
    fs::write(artifact_root.join("decoy"), b"decoy").expect("write decoy");
    store.set_now(start + Duration::from_secs(60));
    let removed = store.cleanup().expect("cleanup through retained dirfd");
    assert_eq!(removed, 1);
    assert!(!aside.join(&handle.id).exists());
    assert!(artifact_root.join("decoy").exists());
}

#[cfg(unix)]
#[test]
fn artifact_store_rejects_symlink_root() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let real = fixture.parent.join("artifacts-real");
    let link = fixture.parent.join("artifacts-link");
    fs::create_dir(&real).expect("create real artifact root");
    symlink(&real, &link).expect("symlink artifact root");
    let config = ArtifactStoreConfig {
        root: link,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 4,
        ttl: Duration::from_secs(60),
    };
    let error = match ArtifactStore::with_config(config) {
        Ok(_) => panic!("symlink root must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "invalid_config");
}

#[test]
fn artifact_store_reopens_from_durable_index_and_reclaims_orphans() {
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-durable");
    fs::create_dir(&artifact_root).expect("create durable artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root.clone(),
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 2,
        ttl: Duration::from_secs(60),
    };
    let id;
    {
        let store = ArtifactStore::with_config(config.clone()).expect("create first store");
        let handle = store
            .put(&owner(), b"durable-bytes")
            .expect("store durable artifact");
        id = handle.id.clone();
        assert_eq!(store.object_count(), 1);
        assert_eq!(store.total_bytes(), b"durable-bytes".len());
        fs::write(artifact_root.join("orphan-not-uuid"), b"orphan").ok();
    }

    let store = ArtifactStore::with_config(config.clone()).expect("reopen artifact store");
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.total_bytes(), b"durable-bytes".len());
    assert_eq!(store.retrieve(&owner(), &id).unwrap(), b"durable-bytes");
    assert_retained_matches_confined_disk(&store);
    let names = store
        .confined_object_names()
        .expect("reopened store should list confined objects");
    assert_eq!(names, vec![id.clone()]);
}

#[test]
fn artifact_store_reopen_expires_stale_objects_and_accounts_disk() {
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-restart-expire");
    fs::create_dir(&artifact_root).expect("create restart artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 2,
        ttl: Duration::from_secs(10),
    };
    let id;
    {
        let store = ArtifactStore::with_config(config.clone()).expect("create expiring store");
        let past = SystemTime::now()
            .checked_sub(Duration::from_secs(30))
            .expect("system clock should allow a past timestamp");
        store.set_now(past);
        id = store
            .put(&owner(), b"stale")
            .expect("store stale artifact")
            .id;
    }

    let store = ArtifactStore::with_config(config).expect("reopen after expiry window");
    assert_eq!(store.object_count(), 0);
    assert_eq!(store.total_bytes(), 0);
    assert_eq!(
        store.retrieve(&owner(), &id).unwrap_err().code(),
        "artifact_not_found"
    );
}

#[test]
fn artifact_store_corrupt_index_fails_closed() {
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-corrupt");
    fs::create_dir(&artifact_root).expect("create corrupt artifact root");
    fs::write(artifact_root.join("manifest.json"), b"{not-json").expect("write corrupt index");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 2,
        ttl: Duration::from_secs(60),
    };
    let error = match ArtifactStore::with_config(config) {
        Ok(_) => panic!("corrupt index must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "invalid_config");
}

#[test]
fn artifact_store_missing_index_with_objects_fails_closed() {
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-missing-index");
    fs::create_dir(&artifact_root).expect("create missing-index root");
    fs::write(
        artifact_root.join("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        b"orphan-object",
    )
    .expect("write orphan object");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 2,
        ttl: Duration::from_secs(60),
    };
    let error = match ArtifactStore::with_config(config) {
        Ok(_) => panic!("objects without an index must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "invalid_config");
}

#[test]
fn artifact_store_second_writer_is_denied() {
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-lease");
    fs::create_dir(&artifact_root).expect("create lease artifact root");
    let config = ArtifactStoreConfig {
        root: artifact_root,
        max_object_bytes: 64,
        max_total_bytes: 96,
        max_objects: 2,
        ttl: Duration::from_secs(60),
    };
    let first = ArtifactStore::with_config(config.clone()).expect("first writer");
    let second = match ArtifactStore::with_config(config) {
        Ok(_) => panic!("second writer must be denied"),
        Err(error) => error,
    };
    assert_eq!(second.code(), "artifact_store_busy");
    drop(first);
}

#[test]
fn artifact_store_reopens_at_configured_capacity_above_default_enum_budget() {
    const OBJECTS: usize = 4097;
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-over-default-enum");
    fs::create_dir(&artifact_root).expect("create over-default artifact root");
    let ids = seed_artifact_objects(&artifact_root, OBJECTS);
    let config = artifact_config(artifact_root, OBJECTS);
    let store = ArtifactStore::with_config(config).expect("valid store at max_objects must reopen");
    assert_eq!(store.object_count(), OBJECTS);
    assert_eq!(store.total_bytes(), OBJECTS);
    assert_eq!(
        store
            .retrieve(&owner(), ids.last().expect("seeded id"))
            .unwrap(),
        b"x"
    );
    assert_retained_matches_confined_disk(&store);
}

#[test]
fn artifact_store_reopen_reclaims_one_extra_unindexed_object_above_capacity() {
    const OBJECTS: usize = 4097;
    let fixture = Fixture::new();
    let artifact_root = fixture.parent.join("artifacts-one-extra");
    fs::create_dir(&artifact_root).expect("create one-extra artifact root");
    let ids = seed_artifact_objects(&artifact_root, OBJECTS);
    let extra = synthetic_artifact_id(OBJECTS);
    fs::write(artifact_root.join(&extra), b"y").expect("write extra unindexed object");
    let config = artifact_config(artifact_root.clone(), OBJECTS);
    let store = ArtifactStore::with_config(config)
        .expect("one extra unindexed object must reopen and reclaim or fail closed without silent truncation");
    assert_eq!(store.object_count(), OBJECTS);
    assert_eq!(store.total_bytes(), OBJECTS);
    assert!(
        !artifact_root.join(&extra).exists(),
        "extra unindexed object must be reclaimed"
    );
    assert_eq!(
        store
            .retrieve(&owner(), ids.last().expect("seeded id"))
            .unwrap(),
        b"x"
    );
    assert_retained_matches_confined_disk(&store);
}

#[test]
fn tests_use_slot_temp_roots_not_host_fixed_paths() {
    let fixture = Fixture::new();
    let rendered = fixture.root.to_string_lossy();
    if let Some(test_tmpdir) = std::env::var_os("TEST_TMPDIR") {
        assert!(
            fixture.root.starts_with(PathBuf::from(test_tmpdir)),
            "fixture must stay under TEST_TMPDIR: {rendered}"
        );
    } else {
        assert!(
            fixture.root.starts_with(std::env::temp_dir()),
            "fixture must use std::env::temp_dir when TEST_TMPDIR is unset: {rendered}"
        );
    }
}
