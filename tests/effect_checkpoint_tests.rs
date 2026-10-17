//! Checkpoint and branch restore for the Native filesystem effect API.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use rustscript_agent::effects::{
    CheckpointRecord, CheckpointRequest, EffectCancellation, EffectDeadline, EffectErrorKind,
    EffectStore, ImportWorkspace, JournalKind, OpenViewRequest, PublicCheckpointRef,
    PublishRequest, ResourceQuota, RestoreRequest, WorkspaceHandle, parse_checkpoint_yaml,
    pre_conversion_yaml_error,
};

fn scratch(test: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = PathBuf::from(
        std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("RUSTSCRIPT_AGENT_TEST_TMP"),
    )
    .join(format!("effect-checkpoint-{test}-{}-{n}", process::id()));
    fs::create_dir_all(&root).expect("scratch");
    root
}

fn generous() -> ResourceQuota {
    ResourceQuota::new(128, 1024 * 1024, 8).expect("quota")
}

fn far_deadline() -> EffectDeadline {
    EffectDeadline::at(Instant::now() + Duration::from_secs(30))
}

fn expired_deadline() -> EffectDeadline {
    EffectDeadline::at(Instant::now() - Duration::from_millis(1))
}

fn import_ok(store: &EffectStore, source: &Path) -> WorkspaceHandle {
    store
        .import_workspace(ImportWorkspace {
            source: source.to_path_buf(),
            quota: generous(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("import")
}

fn publish_edit(
    handle: &WorkspaceHandle,
    edit: impl FnOnce(&rustscript_agent::effects::WritableView),
) {
    let view = handle
        .open_view(OpenViewRequest {
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("open");
    edit(&view);
    handle
        .publish(
            view,
            PublishRequest {
                expected_head: handle.head(),
                expected_epoch: handle.epoch(),
                cancellation: EffectCancellation::new(),
                deadline: far_deadline(),
            },
        )
        .expect("publish");
}

#[test]
fn active_writer_rejects_checkpoint_immediately() {
    let root = scratch("busy");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let head = handle.head();
    let view = handle
        .open_view(OpenViewRequest {
            expected_head: head.clone(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let started = Instant::now();
    let err = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect_err("busy");
    assert_eq!(err.kind(), EffectErrorKind::CheckpointBusy);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(handle.head(), head);
    view.write_file("a.txt", b"still-open").unwrap();
    handle.discard(view).unwrap();
    let record = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("quiescent checkpoint");
    assert_eq!(record.active_writers(), 0);
    assert!(record.external_effects_not_reverted().is_empty());
    assert_eq!(record.immutable_root(), &head);
}

#[test]
fn expired_deadline_rejects_checkpoint_without_waiting() {
    let root = scratch("deadline");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let started = Instant::now();
    let err = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: expired_deadline(),
        })
        .expect_err("deadline");
    assert_eq!(err.kind(), EffectErrorKind::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        fs::read_dir(store.root().join("checkpoints"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn restore_replays_deleted_and_renamed_files_on_new_branch() {
    let root = scratch("restore");
    let seed = root.join("seed");
    fs::create_dir_all(seed.join("keep")).unwrap();
    fs::write(seed.join("a.txt"), b"one").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    publish_edit(&handle, |view| {
        view.delete("a.txt").unwrap();
        view.write_file("b.txt", b"two").unwrap();
        view.write_file("c.txt", b"c").unwrap();
        view.rename("c.txt", "d.txt").unwrap();
    });
    let record = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let checkpoint_head = record.immutable_root().clone();
    publish_edit(&handle, |view| {
        view.write_file("b.txt", b"changed").unwrap();
        view.write_file("e.txt", b"extra").unwrap();
    });
    let mutated = handle.head();
    assert_ne!(mutated, checkpoint_head);
    let old_epoch = handle.epoch();
    let old_branch = handle.branch_id().clone();
    let journal_before = handle.journal();
    let restored = handle
        .restore(RestoreRequest {
            checkpoint_id: record.checkpoint_id().clone(),
            expected_head: mutated.clone(),
            expected_epoch: old_epoch,
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    assert_ne!(restored.handle.branch_id(), &old_branch);
    assert!(restored.handle.epoch().get() > old_epoch.get());
    assert_eq!(restored.head, checkpoint_head);
    assert!(restored.external_effects_not_reverted.is_empty());
    assert_eq!(restored.handle.read_committed("b.txt").unwrap(), b"two");
    assert_eq!(restored.handle.read_committed("d.txt").unwrap(), b"c");
    assert!(restored.handle.read_committed("a.txt").is_err());
    assert!(restored.handle.read_committed("e.txt").is_err());
    assert!(restored.handle.read_committed("c.txt").is_err());
    assert!(
        restored
            .handle
            .immutable_path(&restored.head)
            .unwrap()
            .join("keep")
            .is_dir()
    );
    assert_eq!(handle.read_committed("e.txt").unwrap(), b"extra");
    assert_eq!(handle.head(), mutated);
    let err = handle
        .open_view(OpenViewRequest {
            expected_head: mutated,
            expected_epoch: old_epoch,
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect_err("old epoch");
    assert_eq!(err.kind(), EffectErrorKind::StaleEpoch);
    let journal_after = handle.journal();
    assert!(journal_after.len() > journal_before.len());
    assert_eq!(&journal_after[..journal_before.len()], &journal_before[..]);
    assert_eq!(journal_after.last().unwrap().kind, JournalKind::Restored);
    assert!(
        journal_after
            .iter()
            .any(|entry| entry.kind == JournalKind::Imported)
    );
    assert!(
        journal_after
            .iter()
            .any(|entry| entry.kind == JournalKind::Published)
    );
    assert!(
        journal_after
            .iter()
            .any(|entry| entry.kind == JournalKind::Checkpoint)
    );
    assert!(restored.handle.lineage().contains(&old_branch));
}

#[test]
fn restore_with_active_writer_is_rejected() {
    let root = scratch("restore-busy");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let record = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let view = handle
        .open_view(OpenViewRequest {
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let started = Instant::now();
    let err = handle
        .restore(RestoreRequest {
            checkpoint_id: record.checkpoint_id().clone(),
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect_err("writer");
    assert_eq!(err.kind(), EffectErrorKind::Busy);
    assert!(started.elapsed() < Duration::from_secs(1));
    handle.discard(view).unwrap();
}

#[test]
fn revoked_checkpoint_file_remains_but_restore_fails() {
    let root = scratch("revoke");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let record = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let path = handle.checkpoint_path(record.checkpoint_id()).unwrap();
    let yaml = fs::read_to_string(&path).unwrap();
    assert!(yaml.contains("rustscript.checkpoint/v1"));
    store.revoke(&handle).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), yaml);
    let err = handle
        .restore(RestoreRequest {
            checkpoint_id: record.checkpoint_id().clone(),
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect_err("revoked");
    assert_eq!(err.kind(), EffectErrorKind::Revoked);
    let refs = PublicCheckpointRef {
        workspace_id: handle.workspace_id().clone(),
        checkpoint_id: record.checkpoint_id().clone(),
    };
    assert_eq!(
        store.restore_from_public_ids(&refs).unwrap_err().kind(),
        EffectErrorKind::AuthorityRequired
    );
}

#[test]
fn other_owner_cannot_restore() {
    let root = scratch("owner-restore");
    let seed_a = root.join("a");
    let seed_b = root.join("b");
    fs::create_dir_all(&seed_a).unwrap();
    fs::create_dir_all(&seed_b).unwrap();
    fs::write(seed_a.join("a.txt"), b"A").unwrap();
    fs::write(seed_b.join("b.txt"), b"B").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let owner_a = import_ok(&store, &seed_a);
    let owner_b = import_ok(&store, &seed_b);
    let record = owner_b
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let head_a = owner_a.head();
    let err = owner_a
        .restore(RestoreRequest {
            checkpoint_id: record.checkpoint_id().clone(),
            expected_head: head_a.clone(),
            expected_epoch: owner_a.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect_err("foreign checkpoint");
    assert_eq!(err.kind(), EffectErrorKind::NotFound);
    assert_eq!(owner_a.head(), head_a);
    assert_eq!(owner_b.read_committed("b.txt").unwrap(), b"B");
}

#[test]
fn checkpoint_yaml_matches_schema_and_rejects_unsafe_input() {
    let root = scratch("schema");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let record = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    let yaml = record.to_yaml();
    let parsed = parse_checkpoint_yaml(&yaml).unwrap();
    assert_eq!(parsed, record);
    let schema_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/v1/checkpoint.schema.yaml");
    let schema_text = fs::read_to_string(&schema_path).unwrap();
    let schema_yaml: serde_yaml::Value = serde_yaml::from_str(&schema_text).unwrap();
    let schema_json = serde_json::to_value(schema_yaml).unwrap();
    jsonschema::meta::validate(&schema_json).expect("schema is draft 2020-12");
    let validator = jsonschema::draft202012::options()
        .build(&schema_json)
        .expect("validator");
    let instance = record.to_json_value();
    validator
        .validate(&instance)
        .expect("instance matches schema");
    let mut extra = instance.clone();
    extra
        .as_object_mut()
        .unwrap()
        .insert("token".to_string(), serde_json::json!("secret"));
    assert!(validator.validate(&extra).is_err());
    let mut snapped = instance.clone();
    snapped["plugin_state"]["availability"] = serde_json::json!("snapshotted");
    assert!(validator.validate(&snapped).is_err());
    assert_eq!(
        parse_checkpoint_yaml("format: &a rustscript.checkpoint/v1\ncopy: *a\n")
            .unwrap_err()
            .kind(),
        EffectErrorKind::SchemaRejected
    );
    assert_eq!(
        parse_checkpoint_yaml("format: !!str rustscript.checkpoint/v1\n")
            .unwrap_err()
            .kind(),
        EffectErrorKind::SchemaRejected
    );
    assert_eq!(
        parse_checkpoint_yaml(
            "format: rustscript.checkpoint/v1\nformat: rustscript.checkpoint/v2\n"
        )
        .unwrap_err()
        .kind(),
        EffectErrorKind::SchemaRejected
    );
    let mut unknown = yaml.clone();
    unknown.push_str("token: secret\n");
    assert_eq!(
        parse_checkpoint_yaml(&unknown).unwrap_err().kind(),
        EffectErrorKind::SchemaRejected
    );
    assert_eq!(
        parse_checkpoint_yaml(&format!(
            "{yaml}\nplugin_state:\n  availability: snapshotted\n"
        ))
        .unwrap_err()
        .kind(),
        EffectErrorKind::SchemaRejected
    );
    let huge = "a: ".to_string() + &"x".repeat(70_000);
    assert_eq!(
        parse_checkpoint_yaml(&huge).unwrap_err().kind(),
        EffectErrorKind::SchemaRejected
    );
}

fn complete_checkpoint_yaml() -> String {
    let root = scratch("scanner-base");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &source);
    handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("quiescent checkpoint")
        .to_yaml()
}

fn duplicate_mapping_line(yaml: &str, key: &str) -> String {
    let needle = format!("{key}:");
    let mut out = String::new();
    let mut duplicated = false;
    for line in yaml.split_inclusive('\n') {
        out.push_str(line);
        if !duplicated && line.trim_start().starts_with(&needle) {
            out.push_str(line);
            duplicated = true;
        }
    }
    assert!(duplicated, "complete checkpoint yaml missing key {key}");
    out
}

fn assert_scanner_rejects_duplicate(yaml: &str) {
    let scan = pre_conversion_yaml_error(yaml);
    assert!(
        matches!(
            scan.as_ref(),
            Err(error)
                if error.kind() == EffectErrorKind::SchemaRejected
                    && error.to_string().contains("duplicate yaml key before conversion")
        ),
        "pre-conversion scanner must reject at its own boundary, got {scan:?}"
    );
    let parsed = parse_checkpoint_yaml(yaml);
    assert!(
        matches!(
            parsed.as_ref(),
            Err(error) if error.to_string().contains("duplicate yaml key before conversion")
        ),
        "production parse must surface the scanner rejection before conversion, got {parsed:?}"
    );
}

#[test]
fn duplicate_owner_id_rejected_before_conversion() {
    let yaml = duplicate_mapping_line(&complete_checkpoint_yaml(), "owner_id");
    assert_scanner_rejects_duplicate(&yaml);
}

#[test]
fn duplicate_immutable_root_rejected_before_conversion() {
    let yaml = duplicate_mapping_line(&complete_checkpoint_yaml(), "immutable_root");
    assert_scanner_rejects_duplicate(&yaml);
}

#[test]
fn duplicate_epoch_rejected_before_conversion() {
    let yaml = duplicate_mapping_line(&complete_checkpoint_yaml(), "epoch");
    assert_scanner_rejects_duplicate(&yaml);
}

#[test]
fn duplicate_nested_availability_rejected_before_conversion() {
    let yaml = duplicate_mapping_line(&complete_checkpoint_yaml(), "availability");
    assert_scanner_rejects_duplicate(&yaml);
}

const LINEAGE_BOUND: usize = 64;

fn document_lineage(record: &CheckpointRecord) -> Vec<String> {
    record.to_json_value()["lineage"]
        .as_array()
        .expect("checkpoint lineage")
        .iter()
        .map(|item| item.as_str().expect("branch id").to_string())
        .collect()
}

fn lineage_text(handle: &WorkspaceHandle) -> Vec<String> {
    handle
        .lineage()
        .iter()
        .map(|branch| branch.as_str().to_string())
        .collect()
}

fn restore_recorded(
    handle: &WorkspaceHandle,
    checkpoint: &rustscript_agent::effects::CheckpointId,
) -> Result<rustscript_agent::effects::RestoredBranch, rustscript_agent::effects::EffectError> {
    handle.restore(RestoreRequest {
        checkpoint_id: checkpoint.clone(),
        expected_head: handle.head(),
        expected_epoch: handle.epoch(),
        cancellation: EffectCancellation::new(),
        deadline: far_deadline(),
    })
}

fn roundtrip_lineage(handle: &WorkspaceHandle, record: &CheckpointRecord) -> Vec<String> {
    let path = handle.checkpoint_path(record.checkpoint_id()).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    let parsed = parse_checkpoint_yaml(&text).expect("parser accepts checkpoint producer output");
    let from_file = document_lineage(&parsed);
    assert_eq!(from_file, document_lineage(record));
    assert_eq!(from_file, lineage_text(handle));
    from_file
}

fn store_files(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    let mut files = Vec::new();
    fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, Option<Vec<u8>>)>) {
        let mut entries = fs::read_dir(dir)
            .expect("store entry")
            .map(|entry| entry.expect("store dir"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .expect("store prefix")
                .to_string_lossy()
                .replace('\\', "/");
            let kind = entry.file_type().expect("file type");
            if kind.is_dir() {
                files.push((rel, None));
                walk(root, &path, files);
            } else if kind.is_file() {
                files.push((rel, Some(fs::read(&path).expect("store file"))));
            } else {
                panic!("store snapshot saw a non-file at {rel}");
            }
        }
    }
    walk(root, root, &mut files);
    files
}

#[test]
fn lineage_bound_restore_is_rejected() {
    let root = scratch("lineage-bound");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let mut handle = import_ok(&store, &seed);
    let import_branch = handle.branch_id().clone();
    let recorded = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    assert_eq!(handle.lineage().len(), 1);
    while handle.lineage().len() < LINEAGE_BOUND {
        handle = restore_recorded(&handle, recorded.checkpoint_id())
            .expect("restore inside the lineage bound")
            .handle;
    }
    let lineage = handle.lineage();
    assert_eq!(lineage.len(), LINEAGE_BOUND);
    assert_eq!(lineage.first(), Some(&import_branch));
    assert_eq!(lineage.last(), Some(handle.branch_id()));
    assert_eq!(lineage.iter().collect::<HashSet<_>>().len(), LINEAGE_BOUND);
    let bound = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("checkpoint at the lineage bound");
    let bound_lineage = roundtrip_lineage(&handle, &bound);
    assert_eq!(bound_lineage.len(), LINEAGE_BOUND);
    assert_eq!(
        bound_lineage.first().map(String::as_str),
        Some(import_branch.as_str())
    );
    assert_eq!(
        bound_lineage.last().map(String::as_str),
        Some(handle.branch_id().as_str())
    );

    let held = handle
        .open_view(OpenViewRequest {
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .unwrap();
    held.write_file("held.txt", b"held").unwrap();
    let busy = restore_recorded(&handle, recorded.checkpoint_id()).expect_err("live writer");
    assert_eq!(busy.kind(), EffectErrorKind::Busy);
    assert_eq!(held.read_file("held.txt").unwrap(), b"held");
    held.write_file("held.txt", b"still-owner").unwrap();
    let still_busy = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect_err("writer lease remains on the original branch");
    assert_eq!(still_busy.kind(), EffectErrorKind::CheckpointBusy);
    handle.discard(held).unwrap();

    let head = handle.head();
    let epoch = handle.epoch();
    let branch = handle.branch_id().clone();
    let journal = handle.journal();
    let lineage_before = handle.lineage();
    let files_before = store_files(store.root());
    let rejected = restore_recorded(&handle, recorded.checkpoint_id())
        .expect_err("restore past the lineage bound");
    assert_eq!(rejected.kind(), EffectErrorKind::SchemaRejected);
    let shown = rejected.to_string();
    assert!(
        !shown.contains('/') && !shown.contains('\\'),
        "lineage rejection leaked a path: {shown}"
    );
    assert_eq!(shown, "SchemaRejected: lineage cannot grow past 64");
    assert_eq!(handle.branch_id(), &branch);
    assert_eq!(handle.head(), head);
    assert_eq!(handle.epoch(), epoch);
    assert_eq!(handle.lineage(), lineage_before);
    assert_eq!(handle.journal(), journal);
    assert_eq!(store_files(store.root()), files_before);
    assert_eq!(handle.read_committed("a.txt").unwrap(), b"a");

    let resumed = handle
        .open_view(OpenViewRequest {
            expected_head: head.clone(),
            expected_epoch: epoch,
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("original branch epoch and writer lease stay usable");
    resumed.write_file("probe.txt", b"probe").unwrap();
    assert_eq!(resumed.read_file("probe.txt").unwrap(), b"probe");
    handle.discard(resumed).unwrap();
    publish_edit(&handle, |view| {
        view.write_file("after.txt", b"after").unwrap();
    });
    assert_eq!(handle.read_committed("after.txt").unwrap(), b"after");
    assert_eq!(handle.lineage().len(), LINEAGE_BOUND);
    let after = handle
        .checkpoint(CheckpointRequest {
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("legal checkpoint after the rejected restore");
    let after_lineage = roundtrip_lineage(&handle, &after);
    assert_eq!(after_lineage, lineage_text(&handle));
    assert_eq!(after_lineage.len(), LINEAGE_BOUND);
}
