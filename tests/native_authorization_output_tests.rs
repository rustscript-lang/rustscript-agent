//! Real Linux pipe/PTY integration tests for bounded native authorization output
//! and the leading queue worker, plus one real AA restricted-RSS enqueue path.
//!
//! Every descriptor here is a private local pipe, PTY or loopback socket. No
//! operator credential, provider endpoint, network call or state store is used.
#![cfg(target_os = "linux")]

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier, mpsc::Receiver, mpsc::SyncSender, mpsc::sync_channel},
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::{
    RunCancellation,
    auth::{
        authorization_output::{
            NativeAuthorizationInstructionOutput, NativeAuthorizationInstructionWorker,
            native_authorization_io_context,
        },
        host::{
            AuthHost, PublicAuthorizationInstruction, RunOAuthCancel, SystemOAuthClock,
            auth_host_catalog, authorization_instruction_channel,
        },
        native_https::NativeHttpsTransport,
        oauth::{BrowserOpener, OAuthError, OAuthHost, OAuthIoContext},
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostApiCatalog, HostFunctionRegistry, SourceFlavor, Value, Vm,
    VmStatus, compile_source_at_path_with_flavor_and_options,
};
use url::Url;

// ---------------------------------------------------------------- primitives

fn pipe(nonblocking: bool) -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors has space for the two pipe descriptors.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: pipe2 returned two newly owned descriptors.
    let (read_fd, write_fd) = unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    };
    if nonblocking {
        for fd in [read_fd.as_raw_fd(), write_fd.as_raw_fd()] {
            // SAFETY: fcntl reads and updates flags on a valid owned descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
    }
    (read_fd, write_fd)
}

fn pty() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: openpty fills both out-parameters with newly owned descriptors.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    // SAFETY: openpty returned two newly owned descriptors.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

fn status_flags(fd: RawFd) -> libc::c_int {
    // SAFETY: fcntl reads status flags from a valid descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0);
    flags
}

fn context_for(deadline: Instant) -> OAuthIoContext {
    let cancellation = RunCancellation::with_deadline(deadline);
    native_authorization_io_context(&cancellation).expect("bounded exact-deadline context")
}

/// Set a descriptor nonblocking and drain every currently available byte.
fn drain_nonblocking(fd: RawFd) -> Vec<u8> {
    // SAFETY: fcntl reads and updates flags on a valid descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        // SAFETY: buffer is a valid writable buffer of its own length.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count > 0 {
            bytes.extend_from_slice(&buffer[..count as usize]);
            continue;
        }
        break;
    }
    bytes
}

/// Fill a nonblocking pipe writer until it reports EAGAIN.
fn fill_pipe(fd: RawFd) {
    let block = [b'x'; 4096];
    loop {
        // SAFETY: block is a valid buffer and fd is a valid pipe writer.
        let written = unsafe { libc::write(fd, block.as_ptr().cast(), block.len()) };
        if written > 0 {
            continue;
        }
        assert_eq!(written, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        return;
    }
}

fn open_fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("read process descriptors")
        .count()
}

/// Whether an observed Linux thread id is still live in this process.
fn thread_alive(tid: i64) -> bool {
    Path::new(&format!("/proc/self/task/{tid}")).exists()
}

fn public_instruction() -> PublicAuthorizationInstruction {
    PublicAuthorizationInstruction {
        authorization_url:
            "https://auth.example.test/oauth/authorize?response_type=code&client_id=public-client-id&state=public-state&code_challenge=public-challenge&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback"
                .to_owned(),
        redirect_uri: "http://127.0.0.1:49152/callback".to_owned(),
    }
}

const EXPECTED_RECORD: &[u8] = b"Open https://auth.example.test/oauth/authorize?response_type=code&client_id=public-client-id&state=public-state&code_challenge=public-challenge&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback\nRedirect: http://127.0.0.1:49152/callback\n";

// --------------------------------------------------------- direct sink tests

#[test]
fn real_pipe_record_roundtrips_and_preserves_shared_original_status_flags() {
    let (read_fd, write_fd) = pipe(false);
    // A duplicate shares the writer's open file description, so any status-flag
    // mutation on the original is observable here.
    // SAFETY: dup returns a newly owned descriptor for a valid descriptor.
    let duplicate = unsafe { libc::dup(write_fd.as_raw_fd()) };
    assert!(duplicate >= 0);
    // SAFETY: dup returned a newly owned descriptor.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let shared_flags = status_flags(duplicate.as_raw_fd());
    assert_eq!(shared_flags & libc::O_NONBLOCK, 0);

    let output = NativeAuthorizationInstructionOutput::from_fd(write_fd)
        .expect("admitted real pipe descriptor");
    assert_eq!(output.target_label(), "pipe");
    output
        .emit(
            &public_instruction(),
            &context_for(Instant::now() + Duration::from_secs(2)),
        )
        .expect("pipe record delivered");
    // The shared original description kept its flags.
    assert_eq!(status_flags(duplicate.as_raw_fd()), shared_flags);
    drop(duplicate);
    drop(output);

    let bytes = drain_nonblocking(read_fd.as_raw_fd());
    assert_eq!(bytes, EXPECTED_RECORD);
}

#[test]
fn real_pty_record_written_under_a_tty_class() {
    let (master, slave) = pty();
    let output = NativeAuthorizationInstructionOutput::from_fd(slave)
        .expect("admitted real PTY slave descriptor");
    assert_eq!(output.target_label(), "tty");
    output
        .emit(
            &public_instruction(),
            &context_for(Instant::now() + Duration::from_secs(2)),
        )
        .expect("pty record delivered");
    // SAFETY: fcntl switches the master read side to nonblocking for draining.
    let flags = status_flags(master.as_raw_fd());
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let bytes = drain_nonblocking(master.as_raw_fd());
    assert!(String::from_utf8_lossy(&bytes).starts_with("Open https://"));
    assert!(String::from_utf8_lossy(&bytes).contains("Redirect: http://127.0.0.1:49152/callback"));
}

#[test]
fn oversize_control_and_secret_instructions_produce_no_output() {
    let cases = [
        {
            let mut bad = public_instruction();
            bad.authorization_url =
                "https://auth.example.test/oauth/authorize?client_secret=leaked".to_owned();
            bad
        },
        {
            let mut bad = public_instruction();
            bad.authorization_url =
                "https://user:password@auth.example.test/oauth/authorize".to_owned();
            bad
        },
        {
            let mut bad = public_instruction();
            bad.authorization_url = "https://auth.example.test/\r\nHeader: x".to_owned();
            bad
        },
        {
            let mut bad = public_instruction();
            bad.authorization_url = format!(
                "https://auth.example.test/oauth/authorize?x={}",
                "a".repeat(8192)
            );
            bad
        },
        {
            let mut bad = public_instruction();
            bad.redirect_uri = "http://example.test/not-loopback/callback".to_owned();
            bad
        },
    ];
    for bad in cases {
        let (read_fd, write_fd) = pipe(false);
        let output = NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("pipe");
        let result = output.emit(&bad, &context_for(Instant::now() + Duration::from_secs(2)));
        assert!(
            matches!(result, Err(OAuthError::Transport { .. })),
            "{result:?}"
        );
        drop(output);
        assert!(
            drain_nonblocking(read_fd.as_raw_fd()).is_empty(),
            "rejected instruction wrote output"
        );
    }
}

#[test]
fn unsupported_regular_file_and_socket_owned_fds_fail_closed() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let file = fs::File::open(&manifest).expect("readable regular manifest file");
    let owned: OwnedFd = file.into();
    assert!(NativeAuthorizationInstructionOutput::from_fd(owned).is_err());

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let peer = TcpStream::connect(listener.local_addr().expect("listener addr"))
        .expect("loopback connect");
    let (server, _) = listener.accept().expect("accept loopback");
    let owned_peer: OwnedFd = peer.into();
    let owned_server: OwnedFd = server.into();
    assert!(NativeAuthorizationInstructionOutput::from_fd(owned_peer).is_err());
    assert!(NativeAuthorizationInstructionOutput::from_fd(owned_server).is_err());
}

#[test]
fn blocked_full_pipe_deadline_within_budget_leaves_no_partial_record() {
    let (read_fd, write_fd) = pipe(true);
    fill_pipe(write_fd.as_raw_fd());
    let output = NativeAuthorizationInstructionOutput::from_fd(write_fd)
        .expect("admitted full pipe descriptor");
    let started = Instant::now();
    let result = output.emit(
        &public_instruction(),
        &context_for(Instant::now() + Duration::from_millis(750)),
    );
    assert!(
        matches!(result, Err(OAuthError::DeadlineExceeded)),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // The reader holds only the filler: no partial record survived.
    let bytes = drain_nonblocking(read_fd.as_raw_fd());
    assert!(!bytes.is_empty());
    assert!(bytes.iter().all(|byte| *byte == b'x'));
}

#[test]
fn peer_close_is_sanitized_failure_without_process_signal() {
    let (read_fd, write_fd) = pipe(false);
    let output =
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor");
    drop(read_fd);
    let result = output.emit(
        &public_instruction(),
        &context_for(Instant::now() + Duration::from_secs(1)),
    );
    assert!(
        matches!(result, Err(OAuthError::Transport { .. })),
        "{result:?}"
    );
    // Reaching here proves SIGPIPE did not terminate the process.
    assert_eq!(std::process::id(), std::process::id());
}

fn current_thread_mask() -> libc::sigset_t {
    // SAFETY: pthread_sigmask accepts a null `set` to query the current thread mask.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) },
        0
    );
    mask
}

fn sigpipe_is_pending() -> bool {
    // SAFETY: sigpending writes to valid stack storage.
    let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigpending(&mut pending) }, 0);
    // SAFETY: pending is a valid signal set.
    unsafe { libc::sigismember(&pending, libc::SIGPIPE) == 1 }
}

fn assert_thread_mask_matches(expected: &libc::sigset_t) {
    let actual = current_thread_mask();
    for signal in 1..=64 {
        // SAFETY: both values are valid Linux signal sets and signal is in range.
        let expected_member = unsafe { libc::sigismember(expected, signal) };
        // SAFETY: both values are valid Linux signal sets and signal is in range.
        let actual_member = unsafe { libc::sigismember(&actual, signal) };
        assert_eq!(actual_member, expected_member, "signal mask bit {signal}");
    }
}

fn install_default_sigpipe() -> libc::sigaction {
    // SAFETY: sigaction structures are initialized before use and SIGPIPE is valid.
    unsafe {
        let mut previous: libc::sigaction = std::mem::zeroed();
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(libc::sigaction(libc::SIGPIPE, &action, &mut previous), 0);
        previous
    }
}

fn restore_sigpipe_state(previous_action: &libc::sigaction, previous_mask: &libc::sigset_t) {
    // SAFETY: the saved action/mask are exact values returned by libc.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut set), 0);
        assert_eq!(libc::sigaddset(&mut set, libc::SIGPIPE), 0);
        if sigpipe_is_pending() {
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(
                libc::sigtimedwait(&set, std::ptr::null_mut(), &timeout),
                libc::SIGPIPE
            );
        }
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, previous_mask, std::ptr::null_mut()),
            0
        );
        assert_eq!(
            libc::sigaction(libc::SIGPIPE, previous_action, std::ptr::null_mut()),
            0
        );
    }
}

fn run_isolated_sigpipe_child(test_name: &str, mode: &str) -> std::process::Output {
    Command::new(std::env::current_exe().expect("native test binary path"))
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("RUSTSCRIPT_NATIVE_SIGPIPE_CHILD", mode)
        .output()
        .expect("spawn isolated native SIGPIPE child")
}

#[test]
fn native_emit_preserves_preexisting_sigpipe_under_default_disposition() {
    let child = run_isolated_sigpipe_child("isolated_sigpipe_pending_child", "pending");
    assert!(
        child.status.success(),
        "isolated pending-signal proof failed: status={:?}, stdout={}, stderr={}",
        child.status,
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn native_emit_peerclose_survives_default_sigpipe_only_in_isolated_child() {
    let child = run_isolated_sigpipe_child("isolated_sigpipe_unblocked_child", "unblocked");
    assert!(
        child.status.success(),
        "isolated peer-close proof failed: status={:?}, stdout={}, stderr={}",
        child.status,
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn isolated_sigpipe_pending_child() {
    if std::env::var("RUSTSCRIPT_NATIVE_SIGPIPE_CHILD").as_deref() != Ok("pending") {
        return;
    }
    let previous_action = install_default_sigpipe();
    let previous_mask = current_thread_mask();
    // Deliberately make SIGPIPE part of the caller's original blocked mask.
    // SAFETY: set is a valid SIGPIPE-only set.
    let mut sigpipe: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigemptyset(&mut sigpipe) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut sigpipe, libc::SIGPIPE) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &sigpipe, std::ptr::null_mut()) },
        0
    );
    let caller_mask = current_thread_mask();
    assert!(!sigpipe_is_pending());

    // Generate a genuine thread-pending SIGPIPE from a native pipe write.
    let (trigger_reader, trigger_writer) = pipe(false);
    drop(trigger_reader);
    let byte = b"x";
    // SAFETY: byte is readable and trigger_writer is a real pipe descriptor.
    assert_eq!(
        unsafe { libc::write(trigger_writer.as_raw_fd(), byte.as_ptr().cast(), 1) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPIPE)
    );
    assert!(
        sigpipe_is_pending(),
        "the setup EPIPE must really queue SIGPIPE"
    );

    // A distinct healthy native pipe must not consume the caller's pending bit.
    let (healthy_reader, healthy_writer) = pipe(false);
    let output = NativeAuthorizationInstructionOutput::from_fd(healthy_writer)
        .expect("healthy pipe admitted");
    output
        .emit(
            &public_instruction(),
            &context_for(Instant::now() + Duration::from_secs(2)),
        )
        .expect("healthy native emit");
    assert!(sigpipe_is_pending(), "healthy emit drained caller SIGPIPE");
    assert_thread_mask_matches(&caller_mask);
    assert_eq!(
        drain_nonblocking(healthy_reader.as_raw_fd()),
        EXPECTED_RECORD
    );
    drop(output);

    // A second actual EPIPE coalesces with, but must not drain, the old pending bit.
    let (closed_reader, closed_writer) = pipe(false);
    let closed_output = NativeAuthorizationInstructionOutput::from_fd(closed_writer)
        .expect("closed-peer pipe admitted before peer close");
    drop(closed_reader);
    let result = closed_output.emit(
        &public_instruction(),
        &context_for(Instant::now() + Duration::from_secs(2)),
    );
    assert!(
        matches!(result, Err(OAuthError::Transport { .. })),
        "{result:?}"
    );
    assert!(
        sigpipe_is_pending(),
        "EPIPE emit drained the preexisting SIGPIPE"
    );
    assert_thread_mask_matches(&caller_mask);
    drop(closed_output);

    // With no prior pending bit, a caller-blocked mask still owns a new EPIPE.
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `sigpipe` is the valid SIGPIPE-only set prepared above.
    assert_eq!(
        unsafe { libc::sigtimedwait(&sigpipe, std::ptr::null_mut(), &timeout) },
        libc::SIGPIPE
    );
    assert!(!sigpipe_is_pending());
    let (blocked_reader, blocked_writer) = pipe(false);
    let blocked_output = NativeAuthorizationInstructionOutput::from_fd(blocked_writer)
        .expect("blocked-mask peer-close pipe admitted");
    drop(blocked_reader);
    let blocked_result = blocked_output.emit(
        &public_instruction(),
        &context_for(Instant::now() + Duration::from_secs(2)),
    );
    assert!(
        matches!(blocked_result, Err(OAuthError::Transport { .. })),
        "{blocked_result:?}"
    );
    assert!(
        sigpipe_is_pending(),
        "caller-blocked mask must retain the new EPIPE SIGPIPE"
    );
    assert_thread_mask_matches(&caller_mask);
    drop(blocked_output);
    restore_sigpipe_state(&previous_action, &previous_mask);
}

#[test]
fn isolated_sigpipe_unblocked_child() {
    if std::env::var("RUSTSCRIPT_NATIVE_SIGPIPE_CHILD").as_deref() != Ok("unblocked") {
        return;
    }
    let previous_action = install_default_sigpipe();
    let previous_mask = current_thread_mask();
    let mut caller_mask = previous_mask;
    // SAFETY: caller_mask is a valid signal set.
    assert_eq!(
        unsafe { libc::sigdelset(&mut caller_mask, libc::SIGPIPE) },
        0
    );
    // SAFETY: caller_mask is the exact test caller mask required for this proof.
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &caller_mask, std::ptr::null_mut()) },
        0
    );
    assert!(
        !sigpipe_is_pending(),
        "isolated child starts without pending SIGPIPE"
    );

    let (reader, writer) = pipe(false);
    let output = NativeAuthorizationInstructionOutput::from_fd(writer)
        .expect("peer-close pipe admitted before close");
    drop(reader);
    let result = output.emit(
        &public_instruction(),
        &context_for(Instant::now() + Duration::from_secs(2)),
    );
    assert!(
        matches!(result, Err(OAuthError::Transport { .. })),
        "{result:?}"
    );
    assert!(
        !sigpipe_is_pending(),
        "own EPIPE remained pending for unblocked caller"
    );
    assert_thread_mask_matches(&caller_mask);
    drop(output);
    restore_sigpipe_state(&previous_action, &previous_mask);
}

#[test]
fn concurrent_callers_serialize_records_and_keep_shared_flags() {
    let (read_fd, write_fd) = pipe(true);
    // SAFETY: dup returns a newly owned descriptor sharing the description.
    let duplicate = unsafe { libc::dup(write_fd.as_raw_fd()) };
    assert!(duplicate >= 0);
    // SAFETY: dup returned a newly owned descriptor.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let shared_flags = status_flags(duplicate.as_raw_fd());
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor"),
    );
    // Drain concurrently so writers are never permanently blocked.
    let drainer = {
        let read_raw = read_fd.as_raw_fd();
        // SAFETY: switching the read side to nonblocking for draining.
        let flags = status_flags(read_raw);
        assert_eq!(
            unsafe { libc::fcntl(read_raw, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        thread::spawn(move || {
            let mut collected = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let mut buffer = [0u8; 8192];
                // SAFETY: buffer is a valid writable buffer of its own length.
                let count =
                    unsafe { libc::read(read_raw, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count > 0 {
                    collected.extend_from_slice(&buffer[..count as usize]);
                }
                thread::sleep(Duration::from_millis(2));
            }
            collected
        })
    };

    let callers = 4;
    let barrier = Arc::new(Barrier::new(callers));
    let mut handles = Vec::new();
    for _ in 0..callers {
        let output = Arc::clone(&output);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            output.emit(
                &public_instruction(),
                &context_for(Instant::now() + Duration::from_secs(3)),
            )
        }));
    }
    for handle in handles {
        handle
            .join()
            .expect("caller joined")
            .expect("emit succeeded");
    }
    // The shared original description kept its flags under concurrency.
    assert_eq!(status_flags(duplicate.as_raw_fd()), shared_flags);
    drop(output);
    drop(duplicate);

    let bytes = drainer.join().expect("drainer joined");
    let text = String::from_utf8_lossy(&bytes);
    // Each record is intact and never interleaved with another.
    assert_eq!(text.matches("Open https://").count(), callers);
    assert_eq!(
        text.matches("Redirect: http://127.0.0.1:49152/callback\n")
            .count(),
        callers
    );
    for line in text.lines() {
        assert!(line.starts_with("Open https://") || line.starts_with("Redirect: "));
    }
}

// ------------------------------------------------------- worker lifecycle

/// A bounded public-authorization queue with the accepted capacity of four.
fn queue() -> (
    SyncSender<PublicAuthorizationInstruction>,
    Receiver<PublicAuthorizationInstruction>,
) {
    sync_channel(4)
}

#[test]
fn worker_aborted_pending_output_is_not_reported_delivered() {
    let (read_fd, write_fd) = pipe(true);
    fill_pipe(write_fd.as_raw_fd());
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted full pipe"),
    );
    let (sender, receiver) = queue();
    // A generous budget keeps the worker alive while the abort comes from the
    // supplied child cancellation on a pending, permanently-blocked record.
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let context = native_authorization_io_context(&cancellation).expect("bounded context");
    let worker = NativeAuthorizationInstructionWorker::start(
        Arc::clone(&output),
        receiver,
        cancellation.clone(),
    )
    .expect("worker on full pipe");
    let tid = wait_for_thread_id(&worker);
    sender
        .try_send(public_instruction())
        .expect("queue the instruction");
    // Bounded engagement wait: the worker observes its stop and dequeues within
    // one 10 ms poll slice, then blocks on the full pipe. This is far inside the
    // 10 s budget and never hides a timing failure.
    thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    cancellation.request(rustscript_agent::CancellationReason::Requested);
    // A pending aborted record must surface as an error, never as delivered.
    let result = worker.finish();
    assert!(matches!(result, Err(OAuthError::Cancelled)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!thread_alive(tid), "worker thread was joined, not detached");
    // The exact supplied cancellation still governs the accepted context.
    assert!(context.check().is_err());
    // The reader never received a partial record.
    let bytes = drain_nonblocking(read_fd.as_raw_fd());
    assert!(!bytes.is_empty());
    assert!(bytes.iter().all(|byte| *byte == b'x'));
}

#[test]
fn worker_idle_stop_is_ok_and_leaves_no_detached_thread_or_fd() {
    let fds_before = open_fd_count();
    let (read_fd, write_fd) = pipe(false);
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor"),
    );
    let (_sender, receiver) = queue();
    let deadline = Instant::now() + Duration::from_secs(30);
    let cancellation = RunCancellation::with_deadline(deadline);
    // The worker owns the sink (and its reopened descriptor) and releases it on
    // a joined orderly stop.
    let worker = NativeAuthorizationInstructionWorker::start(output, receiver, cancellation)
        .expect("finite-deadline worker");
    assert_eq!(worker.deadline(), deadline);
    assert!(worker.is_running());
    // Observe the exact worker thread while it is running.
    let tid = wait_for_thread_id(&worker);
    assert!(thread_alive(tid), "worker thread is live");
    // Nothing was queued: this is an idle orderly stop.
    assert!(worker.finish().is_ok());
    assert!(!thread_alive(tid), "worker thread was joined, not detached");
    drop(read_fd);
    assert_eq!(open_fd_count(), fds_before, "no descriptor leaked");
}

fn wait_for_thread_id(worker: &NativeAuthorizationInstructionWorker) -> i64 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(tid) = worker.thread_id() {
            return tid;
        }
        assert!(
            Instant::now() < deadline,
            "worker never reported its thread id"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn worker_delivers_queue_record_to_real_pipe_and_preserves_exact_deadline() {
    let (read_fd, write_fd) = pipe(false);
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor"),
    );
    let (sender, receiver) = queue();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancellation = RunCancellation::with_deadline(deadline);
    let worker =
        NativeAuthorizationInstructionWorker::start(Arc::clone(&output), receiver, cancellation)
            .expect("worker");
    // The worker observes the exact supplied child deadline, not a new budget.
    assert_eq!(worker.deadline(), deadline);
    sender
        .try_send(public_instruction())
        .expect("enqueue authorization instruction");

    let wait_until = Instant::now() + Duration::from_secs(3);
    let bytes = loop {
        let bytes = drain_nonblocking(read_fd.as_raw_fd());
        if !bytes.is_empty() {
            break bytes;
        }
        assert!(Instant::now() < wait_until, "record was never delivered");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(bytes, EXPECTED_RECORD);
    assert!(worker.finish().is_ok());
}

#[test]
fn worker_requires_finite_child_deadline() {
    let (read_fd, write_fd) = pipe(false);
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor"),
    );
    let (_sender, receiver) = queue();
    let no_deadline = RunCancellation::new();
    assert!(
        NativeAuthorizationInstructionWorker::start(Arc::clone(&output), receiver, no_deadline)
            .is_err()
    );
    drop(read_fd);
}

#[test]
fn worker_stops_promptly_on_supplied_child_cancellation() {
    let (read_fd, write_fd) = pipe(false);
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor"),
    );
    let (_sender, receiver) = queue();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let worker = NativeAuthorizationInstructionWorker::start(
        Arc::clone(&output),
        receiver,
        cancellation.clone(),
    )
    .expect("worker on supplied child cancellation");
    let tid = wait_for_thread_id(&worker);
    let started = Instant::now();
    cancellation.request(rustscript_agent::CancellationReason::Requested);
    assert!(worker.finish().is_ok(), "cancellation is an orderly stop");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!thread_alive(tid), "worker thread was joined, not detached");
    drop(read_fd);
}

// ------------------------------------------- real AA restricted-RSS enqueue

struct TestHome(PathBuf);

impl TestHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned private test temp"),
        );
        let path = root.join(format!("native-authz-output-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create isolated fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy synthetic configured provider policy");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("write empty synthetic credential store");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("restrict fixture home");
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                .expect("restrict fixture file");
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoopBrowser;

impl BrowserOpener for NoopBrowser {
    fn open(&self, _authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()
    }
}

fn native_oauth(cancellation: &RunCancellation) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NoopBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ))
}

fn authorization_contract_source() -> (PathBuf, String) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let mut source = fs::read_to_string(&path).expect("read real callback RSS contract");
    source.push_str(
        r#"

pub fn emit_instruction(
    callback_handle: resource<oauth.callback>
) -> AuthorizationInstructionResultEnvelope {
    oauth::emit_authorization_instruction_result(&callback_handle)
}
"#,
    );
    (path, source)
}

fn compile_contract(path: &Path, source: &str) -> (Vm, Arc<HostApiCatalog>) {
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real RSS against restricted catalog");
    (Vm::new_shared(Arc::new(compiled.program)), catalog)
}

fn restricted_vm(auth: &AuthHost, path: &Path, source: &str) -> Vm {
    let (mut vm, catalog) = compile_contract(path, source);
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth module descriptors");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind actual restricted auth catalog");
    assert!(matches!(
        vm.run().expect("execute RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS record");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing typed RSS field {name}"))
}

fn string_field(value: &Value, name: &str) -> String {
    let Value::String(value) = field(value, name) else {
        panic!("expected string field {name}");
    };
    value.to_string()
}

fn intent() -> Value {
    Value::map(vec![
        (
            Value::string("credential_id"),
            Value::string("fixture-codex"),
        ),
        (Value::string("path"), Value::string("/codex/device")),
        (
            Value::string("flow"),
            Value::string("authorization_code_pkce"),
        ),
        (Value::string("callback_mode"), Value::string("browser")),
        (
            Value::string("scopes"),
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        (
            Value::string("public_query"),
            Value::array(vec![
                Value::map(vec![
                    (Value::string("name"), Value::string("client_id")),
                    (Value::string("value"), Value::string("public-client-id")),
                ]),
                Value::map(vec![
                    (Value::string("name"), Value::string("response_type")),
                    (Value::string("value"), Value::string("code")),
                ]),
            ]),
        ),
    ])
}

fn callback_address(redirect_uri: &str) -> SocketAddr {
    let redirect = Url::parse(redirect_uri).expect("native redirect URI");
    SocketAddr::new(
        Ipv4Addr::LOCALHOST.into(),
        redirect.port().expect("ephemeral callback port"),
    )
}

fn assert_port_released(begun: &Value) {
    let address = callback_address(&string_field(begun, "redirect_uri"));
    drop(TcpListener::bind(address).expect("native callback listener released"));
}

#[test]
fn real_aa_restricted_rss_enqueue_reaches_native_pipe_through_worker() {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    // Real bounded AA queue plus a private pipe sink behind the worker.
    let (read_fd, write_fd) = pipe(false);
    let output = Arc::new(
        NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("admitted pipe descriptor"),
    );
    let (sender, receiver) = authorization_instruction_channel();
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation))
        .with_authorization_instruction_sender(sender);
    let worker = NativeAuthorizationInstructionWorker::start(
        Arc::clone(&output),
        receiver,
        cancellation.clone(),
    )
    .expect("authorization output worker");

    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&auth, &path, &source);
    let bound = auth.bind_vm(&mut vm).expect("bind actual owner");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("real RSS begin");
    let begun = vm
        .invoke_callable(begin, &[field(&bound, "host_home"), intent()])
        .expect("native PKCE begin through real RSS");
    let callback = field(&begun, "callback_handle");
    let emit = vm
        .resolve_exported_callable("emit_instruction")
        .expect("typed RSS instruction emitter");
    let ack = vm
        .invoke_callable(emit, std::slice::from_ref(&callback))
        .expect("typed sanitized acknowledgement");
    assert_eq!(field(&ack, "ok"), Value::Bool(true));
    assert_eq!(field(&ack, "value"), Value::Bool(true));

    // The worker must deliver the actual AA-enqueued URL to the real pipe.
    let expected_url = string_field(&begun, "authorization_url");
    let expected_redirect = string_field(&begun, "redirect_uri");
    let wait_until = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    while Instant::now() < wait_until {
        bytes = drain_nonblocking(read_fd.as_raw_fd());
        if !bytes.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let text = String::from_utf8(bytes).expect("native record is UTF-8");
    assert!(
        text.contains(&expected_url),
        "delivered URL mismatch: {text}"
    );
    assert!(
        text.contains(&expected_redirect),
        "delivered redirect mismatch: {text}"
    );
    assert!(text.contains("state="));
    assert!(text.contains("code_challenge="));

    // Sanitized acknowledgement must never leak the URL into RSS debug output.
    assert!(!format!("{ack:?}").contains(&expected_url));

    assert!(worker.finish().is_ok());
    // The flow is still live while bound; releasing it frees the callback port.
    drop(vm);
    assert_port_released(&begun);
}
