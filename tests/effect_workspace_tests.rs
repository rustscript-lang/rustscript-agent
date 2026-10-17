//! Native workspace views, immutable roots, and publish conflicts.
//!
//! These tests drive the filesystem effect API directly. They do not claim
//! plugin, OCI, or control-plane integration.

use std::{
    ffi::CString,
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::effects::{
    CheckpointRecord, CheckpointRequest, EffectCancellation, EffectDeadline, EffectError,
    EffectErrorKind, EffectFailure, EffectStore, ImportWorkspace, OpenViewRequest,
    PublicWorkspaceRef, PublishRequest, ResourceQuota, RestoreRequest, RestoredBranch,
    WorkspaceHandle, WorkspaceId, WritableView,
};

fn scratch(test: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = assigned_temp().join(format!("effect-workspace-{test}-{}-{n}", process::id()));
    fs::create_dir_all(&root).expect("scratch");
    root
}

fn assigned_temp() -> PathBuf {
    PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("RUSTSCRIPT_AGENT_TEST_TMP"))
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

fn import_req(
    source: &Path,
    quota: ResourceQuota,
    cancellation: EffectCancellation,
) -> ImportWorkspace {
    ImportWorkspace {
        source: source.to_path_buf(),
        quota,
        cancellation,
        deadline: far_deadline(),
    }
}

fn import_ok(store: &EffectStore, source: &Path) -> WorkspaceHandle {
    store
        .import_workspace(import_req(source, generous(), EffectCancellation::new()))
        .expect("import")
}

fn open_ok(handle: &WorkspaceHandle) -> WritableView {
    handle
        .open_view(OpenViewRequest {
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("open view")
}

fn publish_ok(handle: &WorkspaceHandle, view: WritableView) {
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

fn kind(err: EffectError) -> EffectErrorKind {
    err.kind()
}

fn dev_ino(path: &Path) -> (u64, u64) {
    let meta = fs::symlink_metadata(path).expect("metadata");
    (meta.dev(), meta.ino())
}

#[test]
fn write_view_does_not_change_seed() {
    let root = scratch("seed");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"seed-bytes").unwrap();
    let before = fs::read(seed.join("a.txt")).unwrap();
    let before_meta = fs::symlink_metadata(seed.join("a.txt")).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let view = open_ok(&handle);
    view.write_file("a.txt", b"view-bytes").unwrap();
    view.write_file("new.txt", b"created").unwrap();
    assert_eq!(fs::read(seed.join("a.txt")).unwrap(), before);
    assert!(!seed.join("new.txt").exists());
    let after_meta = fs::symlink_metadata(seed.join("a.txt")).unwrap();
    assert_eq!(before_meta.mode(), after_meta.mode());
    assert_eq!(
        dev_ino(&seed.join("a.txt")),
        (after_meta.dev(), after_meta.ino())
    );
    assert_eq!(handle.read_committed("a.txt").unwrap(), b"seed-bytes");
}

#[test]
fn file_tool_and_terminal_root_see_the_same_bytes() {
    let root = scratch("same-view");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"base").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let view = open_ok(&handle);
    view.write_file("from-tool.txt", b"tool").unwrap();
    assert_eq!(
        fs::read(view.work_root().join("from-tool.txt")).unwrap(),
        b"tool"
    );
    fs::write(view.work_root().join("from-terminal.txt"), b"terminal").unwrap();
    assert_eq!(view.read_file("from-terminal.txt").unwrap(), b"terminal");
    assert_eq!(view.read_file("from-tool.txt").unwrap(), b"tool");
    assert_ne!(view.private_temp(), view.work_root());
    fs::write(view.private_temp().join("scratch"), b"tmp").unwrap();
    assert!(view.read_file("scratch").is_err());
}

#[test]
fn discarded_view_keeps_parent_head() {
    let root = scratch("discard");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"head").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let head = handle.head();
    let epoch = handle.epoch();
    let view = open_ok(&handle);
    let view_root = view.work_root().to_path_buf();
    view.write_file("a.txt", b"dirty").unwrap();
    handle.discard(view).unwrap();
    assert_eq!(handle.head(), head);
    assert_eq!(handle.epoch(), epoch);
    assert!(!view_root.exists());
    assert_eq!(handle.read_committed("a.txt").unwrap(), b"head");
    assert_eq!(fs::read(seed.join("a.txt")).unwrap(), b"head");
}

#[test]
fn rejected_publish_keeps_parent_head() {
    let root = scratch("reject-publish");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"head").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let head = handle.head();
    let view = open_ok(&handle);
    view.write_file("a.txt", b"dirty").unwrap();
    std::os::unix::fs::symlink("a.txt", view.work_root().join("link")).unwrap();
    let EffectFailure { error, recovered } = handle
        .publish(
            view,
            PublishRequest {
                expected_head: head.clone(),
                expected_epoch: handle.epoch(),
                cancellation: EffectCancellation::new(),
                deadline: far_deadline(),
            },
        )
        .expect_err("symlink publish");
    assert_eq!(error.kind(), EffectErrorKind::UnsupportedEntry);
    assert_eq!(handle.head(), head);
    assert_eq!(handle.read_committed("a.txt").unwrap(), b"head");
    assert_eq!(
        fs::read(recovered.work_root().join("a.txt")).unwrap(),
        b"dirty"
    );
    let retained = recovered.work_root().to_path_buf();
    handle.discard(recovered).unwrap();
    assert!(!retained.exists());
    assert_eq!(handle.head(), head);
}

#[test]
fn writable_view_does_not_share_inode_with_snapshot() {
    let root = scratch("inode");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"same").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let immutable = handle.immutable_path(&handle.head()).unwrap().join("a.txt");
    let view = open_ok(&handle);
    let view_file = view.work_root().join("a.txt");
    let seed_id = dev_ino(&seed.join("a.txt"));
    let tree_id = dev_ino(&immutable);
    let view_id = dev_ino(&view_file);
    assert_ne!(seed_id, tree_id);
    assert_ne!(view_id, tree_id);
    assert_ne!(view_id, seed_id);
    assert_eq!(fs::symlink_metadata(&immutable).unwrap().nlink(), 1);
    assert_eq!(fs::symlink_metadata(&view_file).unwrap().nlink(), 1);
    view.write_file("a.txt", b"changed").unwrap();
    assert_eq!(fs::read(&immutable).unwrap(), b"same");
    assert_eq!(fs::read(seed.join("a.txt")).unwrap(), b"same");
    fs::OpenOptions::new()
        .write(true)
        .open(&immutable)
        .expect_err("sealed file");
    fs::write(immutable.parent().unwrap().join("extra.txt"), b"no").expect_err("sealed dir");
    let recorded_view = view_id;
    publish_ok(&handle, view);
    let published = handle.immutable_path(&handle.head()).unwrap().join("a.txt");
    assert_ne!(dev_ino(&published), recorded_view);
    assert_ne!(dev_ino(&published), seed_id);
    assert_eq!(fs::symlink_metadata(&published).unwrap().nlink(), 1);
    assert_eq!(fs::read(&published).unwrap(), b"changed");
}

#[test]
fn import_rejects_external_symlink() {
    let root = scratch("symlink");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("inside.txt"), b"in").unwrap();
    std::os::unix::fs::symlink(seed.join("inside.txt"), seed.join("rel")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", seed.join("out")).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let err = store
        .import_workspace(import_req(&seed, generous(), EffectCancellation::new()))
        .expect_err("symlink");
    assert_eq!(err.kind(), EffectErrorKind::UnsupportedEntry);
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(fs::read(seed.join("inside.txt")).unwrap(), b"in");
}

#[test]
fn import_rejects_device_path() {
    let root = scratch("device");
    let store = EffectStore::create(root.join("store")).unwrap();
    let err = store
        .import_workspace(import_req(
            Path::new("/dev/null"),
            generous(),
            EffectCancellation::new(),
        ))
        .expect_err("device");
    assert_eq!(err.kind(), EffectErrorKind::UnsupportedEntry);
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn import_rejects_fifo_and_socket() {
    let root = scratch("fifo");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let fifo = seed.join("pipe");
    let rc = unsafe {
        libc::mkfifo(
            CString::new(fifo.as_os_str().as_bytes()).unwrap().as_ptr(),
            0o644,
        )
    };
    assert_eq!(rc, 0, "mkfifo {}", std::io::Error::last_os_error());
    let store = EffectStore::create(root.join("store")).unwrap();
    let err = store
        .import_workspace(import_req(&seed, generous(), EffectCancellation::new()))
        .expect_err("fifo");
    assert_eq!(err.kind(), EffectErrorKind::UnsupportedEntry);

    // sun_path is 108 bytes, so the socket has to live in a short assigned-temp directory.
    let sock_seed = assigned_temp()
        .join(format!("s{}", process::id()))
        .join("s");
    let _ = fs::remove_dir_all(sock_seed.parent().unwrap());
    fs::create_dir_all(&sock_seed).unwrap();
    let _listener = UnixListener::bind(sock_seed.join("k")).unwrap();
    let err = store
        .import_workspace(import_req(
            &sock_seed,
            generous(),
            EffectCancellation::new(),
        ))
        .expect_err("socket");
    assert_eq!(err.kind(), EffectErrorKind::UnsupportedEntry);
    drop(_listener);
    let _ = fs::remove_dir_all(sock_seed.parent().unwrap());
}

#[test]
fn import_rejects_external_hardlink() {
    let root = scratch("hardlink");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"linked").unwrap();
    fs::hard_link(seed.join("a.txt"), root.join("outside.txt")).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let err = store
        .import_workspace(import_req(&seed, generous(), EffectCancellation::new()))
        .expect_err("external hardlink");
    assert_eq!(err.kind(), EffectErrorKind::UnsupportedEntry);
    assert_eq!(fs::read(root.join("outside.txt")).unwrap(), b"linked");
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn internal_hardlink_copies_do_not_share_inodes() {
    let root = scratch("internal-link");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"linked").unwrap();
    fs::hard_link(seed.join("a.txt"), seed.join("b.txt")).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let tree = handle.immutable_path(&handle.head()).unwrap();
    let a = dev_ino(&tree.join("a.txt"));
    let b = dev_ino(&tree.join("b.txt"));
    assert_ne!(a, b);
    assert_ne!(a, dev_ino(&seed.join("a.txt")));
    assert_ne!(b, dev_ino(&seed.join("b.txt")));
    assert_eq!(fs::read(tree.join("a.txt")).unwrap(), b"linked");
    assert_eq!(fs::read(tree.join("b.txt")).unwrap(), b"linked");
    assert_eq!(fs::symlink_metadata(tree.join("a.txt")).unwrap().nlink(), 1);
}

#[test]
fn quota_excess_does_not_publish() {
    let root = scratch("quota");
    let seed = root.join("seed");
    fs::create_dir_all(seed.join("nested")).unwrap();
    fs::write(seed.join("a.txt"), b"1234").unwrap();
    fs::write(seed.join("b.txt"), b"zzzz").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let err = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(1, 1024, 8).unwrap(),
            EffectCancellation::new(),
        ))
        .expect_err("entries");
    assert_eq!(err.kind(), EffectErrorKind::QuotaExceeded);
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );

    fs::remove_dir_all(&seed).unwrap();
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"1234").unwrap();
    let err = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(8, 3, 8).unwrap(),
            EffectCancellation::new(),
        ))
        .expect_err("bytes");
    assert_eq!(err.kind(), EffectErrorKind::QuotaExceeded);

    fs::remove_dir_all(&seed).unwrap();
    fs::create_dir_all(seed.join("nested")).unwrap();
    fs::write(seed.join("nested/a.txt"), b"x").unwrap();
    let err = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(8, 1024, 1).unwrap(),
            EffectCancellation::new(),
        ))
        .expect_err("depth");
    assert_eq!(err.kind(), EffectErrorKind::QuotaExceeded);

    fs::remove_dir_all(&seed).unwrap();
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"ok").unwrap();
    let handle = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(4, 4, 4).unwrap(),
            EffectCancellation::new(),
        ))
        .unwrap();
    let head = handle.head();
    let view = open_ok(&handle);
    let err = view.write_file("b.txt", b"0123456789").unwrap_err();
    assert_eq!(kind(err), EffectErrorKind::QuotaExceeded);
    fs::write(view.work_root().join("terminal-extra.txt"), b"yyyy").unwrap();
    let EffectFailure { error, recovered } = handle
        .publish(
            view,
            PublishRequest {
                expected_head: head.clone(),
                expected_epoch: handle.epoch(),
                cancellation: EffectCancellation::new(),
                deadline: far_deadline(),
            },
        )
        .expect_err("terminal quota");
    assert_eq!(error.kind(), EffectErrorKind::QuotaExceeded);
    assert_eq!(handle.head(), head);
    handle.discard(recovered).unwrap();
}

#[test]
fn cancellation_discards_partial_import() {
    let root = scratch("cancel");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"one").unwrap();
    fs::write(seed.join("b.txt"), b"two").unwrap();
    fs::write(seed.join("c.txt"), b"three").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let cancellation = EffectCancellation::new();
    cancellation.cancel_at_check(2);
    let started = Instant::now();
    let err = store
        .import_workspace(import_req(&seed, generous(), cancellation))
        .expect_err("cancel");
    assert_eq!(err.kind(), EffectErrorKind::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(fs::read(seed.join("a.txt")).unwrap(), b"one");

    let pre = EffectCancellation::new();
    pre.cancel();
    let err = store
        .import_workspace(import_req(&seed, generous(), pre))
        .expect_err("pre-cancel");
    assert_eq!(err.kind(), EffectErrorKind::Cancelled);
}

#[test]
fn expired_deadline_is_not_extended() {
    let root = scratch("deadline");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"one").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let started = Instant::now();
    let err = store
        .import_workspace(ImportWorkspace {
            source: seed.clone(),
            quota: generous(),
            cancellation: EffectCancellation::new(),
            deadline: expired_deadline(),
        })
        .expect_err("deadline");
    assert_eq!(err.kind(), EffectErrorKind::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(
        ResourceQuota::new(0, 10, 1).unwrap_err().kind(),
        EffectErrorKind::InvalidConfiguration
    );
    assert_eq!(
        ResourceQuota::new(1_000_001, 10, 1).unwrap_err().kind(),
        EffectErrorKind::InvalidConfiguration
    );
}

#[test]
fn concurrent_publish_conflicts_on_parent_head() {
    let root = scratch("cas");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("base.txt"), b"base").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let expected = handle.head();
    let epoch = handle.epoch();
    let left = open_ok(&handle);
    let right = open_ok(&handle);
    left.write_file("left.txt", b"L").unwrap();
    right.write_file("right.txt", b"R").unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let spawn = |handle: WorkspaceHandle,
                 view: WritableView,
                 marker: &'static str,
                 expected_head: rustscript_agent::effects::TreeId| {
        let barrier = Arc::clone(&barrier);
        thread::spawn(
            #[allow(clippy::result_large_err)]
            move || {
                barrier.wait();
                handle
                    .publish(
                        view,
                        PublishRequest {
                            expected_head,
                            expected_epoch: epoch,
                            cancellation: EffectCancellation::new(),
                            deadline: far_deadline(),
                        },
                    )
                    .map(|publication| (marker, publication.head))
            },
        )
    };
    let first = spawn(handle.clone(), left, "left", expected.clone());
    let second = spawn(handle.clone(), right, "right", expected);
    let results = [first.join().unwrap(), second.join().unwrap()];
    let mut winner = None;
    let mut loser = None;
    for result in results {
        match result {
            Ok(publication) => winner = Some(publication),
            Err(failure) => loser = Some(failure),
        }
    }
    let winner = winner.expect("one publish wins");
    let EffectFailure { error, recovered } = loser.expect("one publish conflicts");
    assert_eq!(handle.head(), winner.1);
    assert_eq!(error.kind(), EffectErrorKind::Conflict);
    let loser_name = if winner.0 == "left" {
        "right.txt"
    } else {
        "left.txt"
    };
    let loser_bytes: &[u8] = if winner.0 == "left" { b"R" } else { b"L" };
    assert_eq!(recovered.read_file(loser_name).unwrap(), loser_bytes);
    assert!(handle.read_committed(loser_name).is_err());
    let winner_name = if winner.0 == "left" {
        "left.txt"
    } else {
        "right.txt"
    };
    assert_eq!(
        handle.read_committed(winner_name).unwrap(),
        if winner.0 == "left" {
            &b"L"[..]
        } else {
            &b"R"[..]
        }
    );
    handle.discard(recovered).unwrap();
    assert_eq!(handle.head(), winner.1);
}

#[test]
fn public_ids_do_not_authorize() {
    let root = scratch("ids");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"secret-not-really").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let refs = handle.public_ref();
    let err = store.open_view_from_public_ids(&refs).unwrap_err();
    assert_eq!(err.kind(), EffectErrorKind::AuthorityRequired);
    let forged = PublicWorkspaceRef {
        workspace_id: WorkspaceId::parse_public("ws-00000000000000000000000000000000").unwrap(),
        branch_id: refs.branch_id.clone(),
        head: refs.head.clone(),
        epoch: refs.epoch,
    };
    assert_eq!(
        store.open_view_from_public_ids(&forged).unwrap_err().kind(),
        EffectErrorKind::AuthorityRequired
    );
    assert_eq!(
        handle.read_committed("a.txt").unwrap(),
        b"secret-not-really"
    );
}

#[test]
fn other_owner_cannot_publish() {
    let root = scratch("owners");
    let seed_a = root.join("a");
    let seed_b = root.join("b");
    fs::create_dir_all(&seed_a).unwrap();
    fs::create_dir_all(&seed_b).unwrap();
    fs::write(seed_a.join("a.txt"), b"A").unwrap();
    fs::write(seed_b.join("b.txt"), b"B").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let owner_a = import_ok(&store, &seed_a);
    let owner_b = import_ok(&store, &seed_b);
    let head_b = owner_b.head();
    let view_b = open_ok(&owner_b);
    view_b.write_file("b.txt", b"stolen").unwrap();
    let EffectFailure { error, recovered } = owner_a
        .publish(
            view_b,
            PublishRequest {
                expected_head: head_b.clone(),
                expected_epoch: owner_b.epoch(),
                cancellation: EffectCancellation::new(),
                deadline: far_deadline(),
            },
        )
        .expect_err("cross owner");
    assert_eq!(error.kind(), EffectErrorKind::OwnerMismatch);
    assert_eq!(owner_b.head(), head_b);
    assert_eq!(owner_b.read_committed("b.txt").unwrap(), b"B");
    owner_b.discard(recovered).unwrap();
    let own_view = open_ok(&owner_a);
    own_view.write_file("a.txt", b"AA").unwrap();
    publish_ok(&owner_a, own_view);
    assert_eq!(owner_a.read_committed("a.txt").unwrap(), b"AA");
    assert_eq!(owner_b.read_committed("b.txt").unwrap(), b"B");
}

#[test]
fn private_temp_is_not_in_snapshot() {
    let root = scratch("temp");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let first = open_ok(&handle);
    let second = open_ok(&handle);
    assert_ne!(first.private_temp(), second.private_temp());
    fs::write(first.private_temp().join("only-first"), b"1").unwrap();
    assert!(!second.private_temp().join("only-first").exists());
    first.write_file("a.txt", b"published").unwrap();
    let temp = first.private_temp().to_path_buf();
    publish_ok(&handle, first);
    let tree = handle.immutable_path(&handle.head()).unwrap();
    assert!(!tree.join("only-first").exists());
    assert!(!tree.join("tmp").exists());
    assert_eq!(fs::read(tree.join("a.txt")).unwrap(), b"published");
    let _ = temp;
    handle.discard(second).unwrap();
}

#[test]
fn source_change_during_import_is_rejected() {
    let root = scratch("race");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let first = seed.join("a.txt");
    fs::write(&first, b"before").unwrap();
    fs::write(seed.join("b.txt"), b"stable").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let cancellation = EffectCancellation::new();
    let mutated = first.clone();
    cancellation.set_before_check_hook(move |n| {
        if n == 3 {
            fs::write(&mutated, b"during").unwrap();
        }
    });
    let err = store
        .import_workspace(import_req(&seed, generous(), cancellation))
        .expect_err("inconsistent");
    assert_eq!(err.kind(), EffectErrorKind::InconsistentSource);
    assert!(
        fs::read_dir(store.root().join("trees"))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(fs::read(&first).unwrap(), b"during");
}

#[test]
fn setuid_bit_is_stripped_and_empty_dir_remains() {
    let root = scratch("mode");
    let seed = root.join("seed");
    fs::create_dir_all(seed.join("empty")).unwrap();
    let exe = seed.join("run.sh");
    fs::write(&exe, b"#!/bin/sh\n").unwrap();
    let mut perms = fs::metadata(&exe).unwrap().permissions();
    perms.set_mode(0o4755);
    fs::set_permissions(&exe, perms).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let tree = handle.immutable_path(&handle.head()).unwrap();
    assert!(tree.join("empty").is_dir());
    let mode = fs::symlink_metadata(tree.join("run.sh")).unwrap().mode();
    assert_eq!(mode & 0o4000, 0);
    assert_eq!(mode & 0o2000, 0);
    assert_ne!(mode & 0o111, 0);
    let view = open_ok(&handle);
    let view_mode = fs::symlink_metadata(view.work_root().join("run.sh"))
        .unwrap()
        .mode();
    assert_eq!(view_mode & 0o4000, 0);
    assert_ne!(view_mode & 0o111, 0);
    view.create_dir("added").unwrap();
    view.set_executable("run.sh", false).unwrap();
    assert_eq!(
        fs::symlink_metadata(view.work_root().join("run.sh"))
            .unwrap()
            .mode()
            & 0o111,
        0
    );
    publish_ok(&handle, view);
    assert!(
        handle
            .immutable_path(&handle.head())
            .unwrap()
            .join("added")
            .is_dir()
    );
}

#[test]
fn relative_escape_is_rejected() {
    let root = scratch("escape");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let outside = root.join("outside.txt");
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let view = open_ok(&handle);
    for bad in [
        "../outside.txt",
        "/tmp/x",
        "a/../../outside.txt",
        "a\\b",
        "a\0b",
        "",
    ] {
        let err = view.write_file(bad, b"no").unwrap_err();
        assert_eq!(kind(err), EffectErrorKind::RejectedPath, "{bad}");
    }
    assert!(!outside.exists());
    handle.discard(view).unwrap();
}

fn checkpoint_now(handle: &WorkspaceHandle) -> Result<CheckpointRecord, EffectError> {
    handle.checkpoint(CheckpointRequest {
        cancellation: EffectCancellation::new(),
        deadline: far_deadline(),
    })
}

fn restore_now(handle: &WorkspaceHandle, record: &CheckpointRecord) -> RestoredBranch {
    handle
        .restore(RestoreRequest {
            checkpoint_id: record.checkpoint_id().clone(),
            expected_head: handle.head(),
            expected_epoch: handle.epoch(),
            cancellation: EffectCancellation::new(),
            deadline: far_deadline(),
        })
        .expect("restore")
}

#[test]
fn writer_lease_stale_handle_discard_after_restore_is_rejected() {
    let root = scratch("stale-discard");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let old = import_ok(&store, &seed);
    let record = checkpoint_now(&old).expect("quiescent checkpoint");
    let restored = restore_now(&old, &record);
    assert_ne!(restored.handle.branch_id(), old.branch_id());
    let view = open_ok(&restored.handle);
    let sibling = open_ok(&restored.handle);
    view.write_file("a.txt", b"live").unwrap();
    let EffectFailure { error, recovered } = old
        .discard(view)
        .expect_err("stale handle must not discard the restored view");
    assert_eq!(error.kind(), EffectErrorKind::Conflict);
    assert_eq!(
        recovered
            .read_file("a.txt")
            .expect("returned view stays readable"),
        b"live"
    );
    recovered
        .write_file("note.txt", b"continued")
        .expect("legitimate owner can continue");
    let started = Instant::now();
    let busy = checkpoint_now(&restored.handle).expect_err("held views keep the writer");
    assert_eq!(busy.kind(), EffectErrorKind::CheckpointBusy);
    assert!(started.elapsed() < Duration::from_secs(1));
    restored.handle.discard(recovered).unwrap();
    let still = checkpoint_now(&restored.handle).expect_err("sibling writer remains");
    assert_eq!(still.kind(), EffectErrorKind::CheckpointBusy);
    drop(sibling);
    let after = checkpoint_now(&restored.handle).expect("originating writers released once");
    let again = restore_now(&restored.handle, &after);
    assert_eq!(again.handle.read_committed("a.txt").unwrap(), b"a");
    assert_eq!(
        store
            .open_view_from_public_ids(&again.handle.public_ref())
            .unwrap_err()
            .kind(),
        EffectErrorKind::AuthorityRequired
    );
}

#[test]
fn writer_lease_wrong_owner_discard_does_not_leave_branch_busy() {
    let root = scratch("wrong-owner-discard");
    let seed_a = root.join("a");
    let seed_b = root.join("b");
    fs::create_dir_all(&seed_a).unwrap();
    fs::create_dir_all(&seed_b).unwrap();
    fs::write(seed_a.join("a.txt"), b"A").unwrap();
    fs::write(seed_b.join("b.txt"), b"B").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let owner_a = import_ok(&store, &seed_a);
    let owner_b = import_ok(&store, &seed_b);
    let view = open_ok(&owner_b);
    let sibling = open_ok(&owner_b);
    view.write_file("b.txt", b"kept").unwrap();
    let EffectFailure { error, recovered } = owner_a
        .discard(view)
        .expect_err("wrong owner must not discard");
    assert_eq!(error.kind(), EffectErrorKind::OwnerMismatch);
    assert_eq!(
        recovered
            .read_file("b.txt")
            .expect("returned view stays readable"),
        b"kept"
    );
    recovered
        .write_file("b.txt", b"still-owner")
        .expect("legitimate owner can continue");
    let started = Instant::now();
    let busy = checkpoint_now(&owner_b).expect_err("returned view still holds the writer");
    assert_eq!(busy.kind(), EffectErrorKind::CheckpointBusy);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(recovered);
    let still = checkpoint_now(&owner_b).expect_err("sibling writer remains after one drop");
    assert_eq!(still.kind(), EffectErrorKind::CheckpointBusy);
    owner_b.discard(sibling).unwrap();
    let record = checkpoint_now(&owner_b).expect("cleanup after exactly one release each");
    let restored = restore_now(&owner_b, &record);
    assert_eq!(restored.handle.read_committed("b.txt").unwrap(), b"B");
    assert_eq!(
        store
            .open_view_from_public_ids(&owner_b.public_ref())
            .unwrap_err()
            .kind(),
        EffectErrorKind::AuthorityRequired
    );
}

#[test]
fn writer_lease_same_branch_discard_and_drop_release_once() {
    let root = scratch("release-once");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    fs::write(seed.join("a.txt"), b"a").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let first = open_ok(&handle);
    let second = open_ok(&handle);
    handle.discard(first).unwrap();
    let started = Instant::now();
    let busy = checkpoint_now(&handle).expect_err("second view still holds the writer");
    assert_eq!(busy.kind(), EffectErrorKind::CheckpointBusy);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(second);
    checkpoint_now(&handle).expect("drop released the remaining writer once");
    let record = checkpoint_now(&handle).expect("a second checkpoint is not blocked");
    let restored = restore_now(&handle, &record);
    assert_eq!(restored.handle.read_committed("a.txt").unwrap(), b"a");
}

fn dir_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    names
}

struct ControlCase {
    label: &'static str,
    byte: u8,
    control_dir: bool,
    legal_parent: bool,
    bytes: &'static [u8],
}

fn control_layout(case: &ControlCase) -> (Vec<String>, String) {
    let marked = format!("bad{}name", char::from(case.byte));
    if case.control_dir {
        (vec![marked], "child.txt".to_string())
    } else if case.legal_parent {
        (vec!["ok".to_string()], format!("{marked}.txt"))
    } else {
        (Vec::new(), format!("{marked}.txt"))
    }
}

fn join_rel(dirs: &[String], file: &str) -> String {
    let mut parts = dirs.to_vec();
    parts.push(file.to_string());
    parts.join("/")
}

fn write_rel(seed: &Path, dirs: &[String], file: &str, bytes: &[u8]) -> PathBuf {
    let mut path = seed.to_path_buf();
    for dir in dirs {
        path.push(dir);
        fs::create_dir_all(&path).unwrap();
    }
    path.push(file);
    fs::write(&path, bytes).unwrap();
    path
}

// Import must reject a component validate_relative already rejects.
// This is a path-policy boundary, not a symlink, hardlink, or traversal check.
#[test]
fn import_rejects_control_byte_components() {
    let cases = [
        ControlCase {
            label: "newline-file",
            byte: 0x0a,
            control_dir: false,
            legal_parent: false,
            bytes: b"newline-bytes",
        },
        ControlCase {
            label: "tab-file",
            byte: 0x09,
            control_dir: false,
            legal_parent: false,
            bytes: b"tab-bytes",
        },
        ControlCase {
            label: "cr-file",
            byte: 0x0d,
            control_dir: false,
            legal_parent: false,
            bytes: b"cr-bytes",
        },
        ControlCase {
            label: "us-file",
            byte: 0x1f,
            control_dir: false,
            legal_parent: false,
            bytes: b"us-bytes",
        },
        ControlCase {
            label: "newline-dir",
            byte: 0x0a,
            control_dir: true,
            legal_parent: false,
            bytes: b"nested-bytes",
        },
        ControlCase {
            label: "tab-nested-file",
            byte: 0x09,
            control_dir: false,
            legal_parent: true,
            bytes: b"nested-tab",
        },
    ];
    let mut accepted = Vec::new();
    for case in cases {
        assert!(case.byte < 0x20, "{}", case.label);
        let (dirs, file) = control_layout(&case);
        let rel = join_rel(&dirs, &file);
        assert!(
            rel.bytes().any(|byte| byte < 0x20),
            "{} must contain a control byte",
            case.label
        );
        let root = scratch(&format!("ctrl-{}", case.label));
        let legal = root.join("legal");
        fs::create_dir_all(&legal).unwrap();
        fs::write(legal.join("keep.txt"), b"kept").unwrap();
        let store = EffectStore::create(root.join("store")).unwrap();
        let handle = import_ok(&store, &legal);
        let head = handle.head();
        let epoch = handle.epoch();
        let branch = handle.branch_id().clone();
        let view = open_ok(&handle);
        view.write_file("note.txt", b"live").unwrap();
        let trees_before = dir_names(&store.root().join("trees"));
        let staging_before = dir_names(&store.root().join("staging"));
        let views_before = dir_names(&store.root().join("views"));
        let seed = root.join("seed");
        fs::create_dir_all(&seed).unwrap();
        let seed_file = write_rel(&seed, &dirs, &file, case.bytes);
        let parent = seed_file.parent().unwrap().to_path_buf();
        let parent_before = dir_names(&parent);
        let seed_root_before = dir_names(&seed);
        let imported =
            store.import_workspace(import_req(&seed, generous(), EffectCancellation::new()));
        assert_eq!(fs::read(&seed_file).unwrap(), case.bytes, "{}", case.label);
        assert_eq!(dir_names(&parent), parent_before, "{}", case.label);
        assert_eq!(dir_names(&seed), seed_root_before, "{}", case.label);
        assert_eq!(handle.head(), head, "{}", case.label);
        assert_eq!(handle.epoch(), epoch, "{}", case.label);
        assert_eq!(handle.branch_id(), &branch, "{}", case.label);
        assert_eq!(handle.read_committed("keep.txt").unwrap(), b"kept");
        assert_eq!(view.read_file("note.txt").unwrap(), b"live");
        view.write_file("after.txt", b"after").unwrap();
        assert_eq!(view.read_file("after.txt").unwrap(), b"after");
        assert_eq!(handle.journal().len(), 1, "{}", case.label);
        match imported {
            Err(err) => {
                assert_eq!(err.kind(), EffectErrorKind::RejectedPath, "{}", case.label);
                assert_eq!(
                    dir_names(&store.root().join("trees")),
                    trees_before,
                    "{}",
                    case.label
                );
                assert_eq!(
                    dir_names(&store.root().join("staging")),
                    staging_before,
                    "{}",
                    case.label
                );
                assert_eq!(
                    dir_names(&store.root().join("views")),
                    views_before,
                    "{}",
                    case.label
                );
            }
            Ok(bad) => {
                let read_kind = bad
                    .read_committed(&rel)
                    .map(|bytes| format!("ok-{}", bytes.len()))
                    .unwrap_or_else(|err| format!("{:?}", err.kind()));
                let bad_view = open_ok(&bad);
                let write_kind = bad_view
                    .write_file(&rel, b"no")
                    .map(|_| "ok".to_string())
                    .unwrap_or_else(|err| format!("{:?}", err.kind()));
                let delete_kind = bad_view
                    .delete(&rel)
                    .map(|_| "ok".to_string())
                    .unwrap_or_else(|err| format!("{:?}", err.kind()));
                let mut copied = bad.immutable_path(&bad.head()).expect("imported tree");
                for dir in &dirs {
                    copied.push(dir);
                }
                copied.push(&file);
                let copied_ok = fs::read(&copied).ok().as_deref() == Some(case.bytes);
                let tree_created = dir_names(&store.root().join("trees")) != trees_before;
                accepted.push(format!(
                    "{}: import accepted; read={} write={} delete={} copied={} tree_created={}",
                    case.label, read_kind, write_kind, delete_kind, copied_ok, tree_created
                ));
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "import accepted entries the relative API cannot address: {accepted:?}"
    );
}

#[test]
fn legal_utf8_names_round_trip_through_publish() {
    let root = scratch("legal-utf8");
    let seed = root.join("seed");
    let dir = "目录";
    let nested = "文件.txt";
    let created = "新建.txt";
    let del = format!("del{}.txt", char::from(0x7f));
    let pad = format!("pad{}.txt", char::from(0x80));
    assert_eq!(dir.as_bytes(), &[0xe7, 0x9b, 0xae, 0xe5, 0xbd, 0x95]);
    assert_eq!(
        nested.as_bytes(),
        &[0xe6, 0x96, 0x87, 0xe4, 0xbb, 0xb6, b'.', b't', b'x', b't']
    );
    assert!(del.as_bytes().contains(&0x7f));
    assert!(pad.chars().any(|ch| ch == char::from(0x80)));
    for name in [
        &del,
        &pad,
        &dir.to_string(),
        &nested.to_string(),
        &created.to_string(),
    ] {
        assert!(
            name.bytes().all(|byte| byte >= 0x20),
            "{name:?} is a legal component"
        );
    }
    fs::create_dir_all(seed.join(dir)).unwrap();
    fs::write(seed.join("plain.txt"), b"plain").unwrap();
    fs::write(seed.join(&del), b"del-bytes").unwrap();
    fs::write(seed.join(&pad), b"pad-bytes").unwrap();
    fs::write(seed.join(dir).join(nested), b"cjk-bytes").unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let nested_rel = format!("{dir}/{nested}");
    assert_eq!(handle.read_committed("plain.txt").unwrap(), b"plain");
    assert_eq!(handle.read_committed(&del).unwrap(), b"del-bytes");
    assert_eq!(handle.read_committed(&pad).unwrap(), b"pad-bytes");
    assert_eq!(handle.read_committed(&nested_rel).unwrap(), b"cjk-bytes");
    let tree = handle.immutable_path(&handle.head()).unwrap();
    assert_eq!(fs::read(tree.join(&del)).unwrap(), b"del-bytes");
    assert_eq!(fs::read(tree.join(dir).join(nested)).unwrap(), b"cjk-bytes");
    let view = open_ok(&handle);
    assert_eq!(view.read_file("plain.txt").unwrap(), b"plain");
    assert_eq!(view.read_file(&del).unwrap(), b"del-bytes");
    assert_eq!(view.read_file(&pad).unwrap(), b"pad-bytes");
    assert_eq!(view.read_file(&nested_rel).unwrap(), b"cjk-bytes");
    assert_eq!(view.list(dir).unwrap(), vec![nested.to_string()]);
    view.write_file("plain.txt", b"updated").unwrap();
    view.write_file(created, b"created").unwrap();
    view.delete(&del).unwrap();
    let rejected = view.write_file(&format!("no{}pe.txt", char::from(0x0a)), b"x");
    assert_eq!(rejected.unwrap_err().kind(), EffectErrorKind::RejectedPath);
    assert!(
        !view
            .list("")
            .unwrap()
            .iter()
            .any(|name| name.bytes().any(|byte| byte < 0x20))
    );
    publish_ok(&handle, view);
    assert_eq!(handle.read_committed("plain.txt").unwrap(), b"updated");
    assert_eq!(handle.read_committed(created).unwrap(), b"created");
    assert_eq!(handle.read_committed(&pad).unwrap(), b"pad-bytes");
    assert_eq!(handle.read_committed(&nested_rel).unwrap(), b"cjk-bytes");
    assert_eq!(
        handle.read_committed(&del).unwrap_err().kind(),
        EffectErrorKind::NotFound
    );
    assert_eq!(fs::read(seed.join("plain.txt")).unwrap(), b"plain");
    assert_eq!(fs::read(seed.join(&del)).unwrap(), b"del-bytes");
    assert_eq!(fs::read(seed.join(dir).join(nested)).unwrap(), b"cjk-bytes");
}

#[cfg(feature = "workspace-io-fault")]
fn assert_simulated_io(err: &EffectError, errno_name: &str) {
    assert_eq!(err.kind(), EffectErrorKind::Io);
    let text = err.to_string();
    assert!(
        text.contains("simulated I/O error"),
        "fault must be labeled simulated, not a hardware or disk-full event: {text}"
    );
    assert!(
        text.contains("not a hardware failure or disk-full event"),
        "{text}"
    );
    assert!(text.contains(errno_name), "{text}");
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_new_file_partial_write_keeps_path_absent_and_quota() {
    let root = scratch("io-new-partial");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(4, 32, 4).unwrap(),
            EffectCancellation::new(),
        ))
        .unwrap();
    let view = open_ok(&handle);
    assert_eq!(view.accounted_usage(), (0, 0));
    view.arm_simulated_io_fault(rustscript_agent::effects::SimulatedIoFault::PartialWrite {
        errno: rustscript_agent::effects::SimulatedIoFault::EIO,
    })
    .unwrap();
    let err = view.write_file("new.txt", b"0123456789abcdef").unwrap_err();
    assert_simulated_io(&err, "EIO");
    let leaked = fs::read(view.work_root().join("new.txt")).ok();
    assert!(
        leaked.is_none(),
        "partial new file leaked into the view: {leaked:?}"
    );
    assert_eq!(view.accounted_usage(), (0, 0));
    view.write_file("new.txt", b"0123456789abcdef").unwrap();
    assert_eq!(view.read_file("new.txt").unwrap(), b"0123456789abcdef");
    assert_eq!(view.accounted_usage(), (1, 16));
    let again = view.write_file("other.txt", b"0123456789abcdef0");
    assert_eq!(again.unwrap_err().kind(), EffectErrorKind::QuotaExceeded);
    assert_eq!(view.accounted_usage(), (1, 16));
}

#[cfg(feature = "workspace-io-fault")]
fn private_file_residue(view: &WritableView) -> Vec<String> {
    let view_dir = view.work_root().parent().expect("view dir");
    let mut found = Vec::new();
    for entry in fs::read_dir(view_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "work" || name == "tmp" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            for child in fs::read_dir(&path).unwrap() {
                let child = child.unwrap();
                found.push(format!("{name}/{}", child.file_name().to_string_lossy()));
            }
        } else {
            found.push(name);
        }
    }
    found.sort();
    found
}

#[cfg(feature = "workspace-io-fault")]
fn mode_bits(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o777
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_overwrite_partial_write_keeps_bytes_mode_and_quota() {
    let root = scratch("io-overwrite-partial");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let original = b"0123456789abcdef0123456789abcdef01234567";
    assert_eq!(original.len(), 40);
    let source = seed.join("a.txt");
    fs::write(&source, original).unwrap();
    let mut perms = fs::metadata(&source).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&source, perms).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(4, 40, 4).unwrap(),
            EffectCancellation::new(),
        ))
        .unwrap();
    let view = open_ok(&handle);
    let dest = view.work_root().join("a.txt");
    assert_eq!(fs::read(&dest).unwrap(), original);
    assert_eq!(mode_bits(&dest), 0o755);
    assert_eq!(view.accounted_usage(), (1, 40));
    view.arm_simulated_io_fault(rustscript_agent::effects::SimulatedIoFault::PartialWrite {
        errno: rustscript_agent::effects::SimulatedIoFault::ENOSPC,
    })
    .unwrap();
    let replacement = b"abcdefghijklmnopqrstuvwxyz0123456789ABCD";
    assert_eq!(replacement.len(), 40);
    let err = view.write_file("a.txt", replacement).unwrap_err();
    assert_simulated_io(&err, "ENOSPC");
    assert_eq!(fs::read(&dest).unwrap(), original);
    assert_eq!(mode_bits(&dest), 0o755);
    assert_eq!(view.accounted_usage(), (1, 40));
    assert!(private_file_residue(&view).is_empty());
    view.write_file("a.txt", replacement).unwrap();
    assert_eq!(view.read_file("a.txt").unwrap(), replacement);
    assert_eq!(mode_bits(&dest), 0o755);
    assert_eq!(view.accounted_usage(), (1, 40));
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_new_file_fsync_keeps_path_absent_and_usage() {
    let root = scratch("io-new-fsync");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = store
        .import_workspace(import_req(
            &seed,
            ResourceQuota::new(4, 32, 4).unwrap(),
            EffectCancellation::new(),
        ))
        .unwrap();
    let view = open_ok(&handle);
    view.arm_simulated_io_fault(rustscript_agent::effects::SimulatedIoFault::FileFsync {
        errno: rustscript_agent::effects::SimulatedIoFault::EIO,
    })
    .unwrap();
    let err = view.write_file("new.txt", b"0123456789abcdef").unwrap_err();
    assert_simulated_io(&err, "EIO");
    let leaked = fs::read(view.work_root().join("new.txt")).ok();
    assert!(
        leaked.is_none(),
        "fsync failure published a new file: {leaked:?}"
    );
    assert_eq!(view.accounted_usage(), (0, 0));
    assert!(private_file_residue(&view).is_empty());
    view.write_file("new.txt", b"0123456789abcdef").unwrap();
    assert_eq!(view.accounted_usage(), (1, 16));
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_overwrite_fsync_keeps_bytes_mode_and_usage() {
    let root = scratch("io-overwrite-fsync");
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let original = b"kept-bytes";
    fs::write(seed.join("a.txt"), original).unwrap();
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let view = open_ok(&handle);
    view.set_executable("a.txt", true).unwrap();
    let dest = view.work_root().join("a.txt");
    let mode = mode_bits(&dest);
    assert_ne!(mode & 0o111, 0);
    let usage = view.accounted_usage();
    view.arm_simulated_io_fault(rustscript_agent::effects::SimulatedIoFault::FileFsync {
        errno: rustscript_agent::effects::SimulatedIoFault::ENOSPC,
    })
    .unwrap();
    let err = view.write_file("a.txt", b"replaced").unwrap_err();
    assert_simulated_io(&err, "ENOSPC");
    assert_eq!(fs::read(&dest).unwrap(), original);
    assert_eq!(mode_bits(&dest), mode);
    assert_eq!(view.accounted_usage(), usage);
    assert!(private_file_residue(&view).is_empty());
    view.write_file("a.txt", b"replaced").unwrap();
    assert_eq!(view.read_file("a.txt").unwrap(), b"replaced");
    assert_eq!(mode_bits(&dest), mode);
}

#[cfg(feature = "workspace-io-fault")]
fn nested_seed(root: &Path) -> PathBuf {
    let seed = root.join("seed");
    fs::create_dir_all(seed.join("sub")).unwrap();
    fs::write(seed.join("sub").join("a.txt"), b"kept").unwrap();
    seed
}

#[cfg(feature = "workspace-io-fault")]
fn publish_request(handle: &WorkspaceHandle) -> PublishRequest {
    PublishRequest {
        expected_head: handle.head(),
        expected_epoch: handle.epoch(),
        cancellation: EffectCancellation::new(),
        deadline: far_deadline(),
    }
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_import_post_rename_chmod_removes_unregistered_tree() {
    let root = scratch("io-import-chmod");
    let seed = nested_seed(&root);
    let store = EffectStore::create(root.join("store")).unwrap();
    store
        .arm_simulated_io_fault(
            rustscript_agent::effects::SimulatedIoFault::PostRenameChmod {
                errno: rustscript_agent::effects::SimulatedIoFault::EIO,
            },
        )
        .unwrap();
    let err = store
        .import_workspace(import_req(&seed, generous(), EffectCancellation::new()))
        .unwrap_err();
    assert_simulated_io(&err, "EIO");
    let leaked = dir_names(&store.root().join("trees"));
    assert!(
        leaked.is_empty(),
        "post-rename import failure left an unregistered tree: {leaked:?}; error={err}"
    );
    assert!(dir_names(&store.root().join("staging")).is_empty());
    assert!(dir_names(&store.root().join("views")).is_empty());
    let handle = import_ok(&store, &seed);
    assert_eq!(handle.read_committed("sub/a.txt").unwrap(), b"kept");
    assert!(dir_names(&store.root().join("staging")).is_empty());
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_import_post_rename_fsync_removes_unregistered_tree() {
    let root = scratch("io-import-fsync");
    let seed = nested_seed(&root);
    let store = EffectStore::create(root.join("store")).unwrap();
    store
        .arm_simulated_io_fault(
            rustscript_agent::effects::SimulatedIoFault::PostRenameDirFsync {
                errno: rustscript_agent::effects::SimulatedIoFault::ENOSPC,
            },
        )
        .unwrap();
    let err = store
        .import_workspace(import_req(&seed, generous(), EffectCancellation::new()))
        .unwrap_err();
    assert_simulated_io(&err, "ENOSPC");
    let leaked = dir_names(&store.root().join("trees"));
    assert!(
        leaked.is_empty(),
        "post-rename import fsync failure left an unregistered tree: {leaked:?}; error={err}"
    );
    assert!(dir_names(&store.root().join("staging")).is_empty());
    import_ok(&store, &seed);
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_import_cleanup_retains_unregistered_tree_evidence() {
    let root = scratch("io-import-cleanup");
    let seed = nested_seed(&root);
    let store = EffectStore::create(root.join("store")).unwrap();
    store
        .arm_simulated_io_fault(
            rustscript_agent::effects::SimulatedIoFault::PostRenameChmod {
                errno: rustscript_agent::effects::SimulatedIoFault::EIO,
            },
        )
        .unwrap();
    store
        .arm_simulated_io_fault(rustscript_agent::effects::SimulatedIoFault::OwnedCleanup {
            errno: rustscript_agent::effects::SimulatedIoFault::ENOSPC,
        })
        .unwrap();
    let err = store
        .import_workspace(import_req(&seed, generous(), EffectCancellation::new()))
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("simulated I/O error"),
        "primary fault must stay simulated: {text}"
    );
    assert!(
        text.contains("owned tree cleanup failed"),
        "cleanup failure must stay explicit, not be reported as a clean failure: {text}"
    );
    assert!(
        text.contains("ENOSPC"),
        "cleanup fault must be labeled simulated ENOSPC, not a disk-full event: {text}"
    );
    let leaked = dir_names(&store.root().join("trees"));
    assert_eq!(
        leaked.len(),
        1,
        "failed cleanup must retain the unregistered tree as evidence, not pretend it is gone: {leaked:?}"
    );
    assert!(dir_names(&store.root().join("staging")).is_empty());
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_publish_post_rename_chmod_keeps_head_writer_and_removes_new_tree() {
    let root = scratch("io-publish-chmod");
    let seed = nested_seed(&root);
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let head = handle.head();
    let epoch = handle.epoch();
    let journal = handle.journal();
    let trees = dir_names(&store.root().join("trees"));
    let committed = store.root().join("trees").join(head.as_str());
    let committed_mode = mode_bits(&committed);
    let view = open_ok(&handle);
    view.write_file("sub/a.txt", b"next").unwrap();
    let view_mode = mode_bits(&view.work_root().join("sub").join("a.txt"));
    view.arm_simulated_io_fault(
        rustscript_agent::effects::SimulatedIoFault::PostRenameChmod {
            errno: rustscript_agent::effects::SimulatedIoFault::EIO,
        },
    )
    .unwrap();
    let EffectFailure { error, recovered } = handle
        .publish(view, publish_request(&handle))
        .expect_err("chmod after rename must fail");
    assert_simulated_io(&error, "EIO");
    assert_eq!(handle.head(), head);
    assert_eq!(handle.epoch(), epoch);
    assert_eq!(handle.journal(), journal);
    assert_eq!(
        dir_names(&store.root().join("trees")),
        trees,
        "post-rename publish failure left an unregistered tree; error={error}"
    );
    assert!(dir_names(&store.root().join("staging")).is_empty());
    assert_eq!(mode_bits(&committed), committed_mode);
    assert_eq!(handle.read_committed("sub/a.txt").unwrap(), b"kept");
    assert_eq!(
        recovered.read_file("sub/a.txt").unwrap(),
        b"next",
        "failed publish must return the original writer view"
    );
    assert_eq!(
        mode_bits(&recovered.work_root().join("sub").join("a.txt")),
        view_mode
    );
    assert_eq!(
        checkpoint_now(&handle).unwrap_err().kind(),
        EffectErrorKind::CheckpointBusy
    );
    assert!(private_file_residue(&recovered).is_empty());
    handle
        .publish(recovered, publish_request(&handle))
        .expect("same view retries after the one-shot fault");
    assert_ne!(handle.head(), head);
    assert_eq!(handle.epoch(), epoch);
    assert_eq!(handle.read_committed("sub/a.txt").unwrap(), b"next");
    assert!(dir_names(&store.root().join("staging")).is_empty());
    checkpoint_now(&handle).expect("successful publish released the writer");
}

#[cfg(feature = "workspace-io-fault")]
#[test]
fn failed_publish_post_rename_fsync_drop_discards_view_without_new_tree() {
    let root = scratch("io-publish-fsync");
    let seed = nested_seed(&root);
    let store = EffectStore::create(root.join("store")).unwrap();
    let handle = import_ok(&store, &seed);
    let head = handle.head();
    let epoch = handle.epoch();
    let journal = handle.journal();
    let trees = dir_names(&store.root().join("trees"));
    let view = open_ok(&handle);
    let view_dir = view.work_root().parent().unwrap().to_path_buf();
    view.arm_simulated_io_fault(
        rustscript_agent::effects::SimulatedIoFault::PostRenameDirFsync {
            errno: rustscript_agent::effects::SimulatedIoFault::ENOSPC,
        },
    )
    .unwrap();
    let EffectFailure { error, recovered } = handle
        .publish(view, publish_request(&handle))
        .expect_err("dir fsync after rename must fail");
    assert_simulated_io(&error, "ENOSPC");
    assert_eq!(handle.head(), head);
    assert_eq!(handle.epoch(), epoch);
    assert_eq!(handle.journal(), journal);
    assert_eq!(
        dir_names(&store.root().join("trees")),
        trees,
        "post-rename publish fsync failure left an unregistered tree; error={error}"
    );
    assert!(dir_names(&store.root().join("staging")).is_empty());
    assert!(
        view_dir.exists(),
        "writer view must survive the failed publish"
    );
    drop(recovered);
    assert!(!view_dir.exists(), "drop must remove the view directory");
    assert_eq!(handle.head(), head);
    assert_eq!(handle.journal(), journal);
    checkpoint_now(&handle).expect("drop released the writer");
    let again = open_ok(&handle);
    handle.discard(again).unwrap();
    assert_eq!(handle.head(), head);
    assert_eq!(handle.epoch(), epoch);
    assert!(dir_names(&store.root().join("views")).is_empty());
}
