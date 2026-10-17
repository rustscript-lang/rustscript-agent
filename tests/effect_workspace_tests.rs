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
