//! Native device-instruction output adapters.

#[cfg(unix)]
use std::os::fd::OwnedFd;

#[cfg(unix)]
use std::{
    os::fd::{AsRawFd, FromRawFd},
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::Duration,
};

use crate::auth::host::{DeviceInstructionSink, PublicDeviceInstruction};
use crate::auth::oauth::{OAuthError, OAuthIoContext};

const MAX_VERIFICATION_URL_BYTES: usize = 2048;
const MAX_USER_CODE_BYTES: usize = 128;
const MAX_RENDERED_INSTRUCTION_BYTES: usize = 4096;
const SECRET_QUERY_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "device_code",
    "device_id",
    "device_auth_id",
    "authorization_code",
    "code_verifier",
    "code",
    "state",
];

/// A bounded Unix descriptor sink for public device-login instructions.
pub struct NativeDeviceInstructionOutput {
    #[cfg(unix)]
    fd: OwnedFd,
    #[cfg(unix)]
    close_on_exec_ready: bool,
}

impl NativeDeviceInstructionOutput {
    /// Take ownership of an explicitly selected native output descriptor.
    #[cfg(unix)]
    pub fn from_fd(fd: OwnedFd) -> Self {
        let close_on_exec_ready = ensure_close_on_exec(fd.as_raw_fd());
        Self {
            fd,
            close_on_exec_ready,
        }
    }

    /// Duplicate stderr as a close-on-exec descriptor.
    #[cfg(unix)]
    pub fn stderr() -> Result<Self, OAuthError> {
        // SAFETY: F_DUPFD_CLOEXEC duplicates the process-owned stderr descriptor.
        let fd = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(output_failure());
        }
        // SAFETY: fcntl returned a newly owned descriptor.
        Ok(Self::from_fd(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Platforms without a bounded native writer fail closed.
    #[cfg(not(unix))]
    pub fn stderr() -> Result<Self, OAuthError> {
        Err(output_failure())
    }
}

#[cfg(unix)]
impl DeviceInstructionSink for NativeDeviceInstructionOutput {
    fn emit(
        &self,
        instruction: &PublicDeviceInstruction,
        context: &OAuthIoContext,
    ) -> Result<(), OAuthError> {
        context.check()?;
        if !self.close_on_exec_ready || !valid_instruction(instruction) {
            return Err(output_failure());
        }
        let rendered = format!(
            "Open {}\nCode: {}\nExpires in {} seconds\n",
            instruction.verification_url, instruction.user_code, instruction.expires_in_seconds
        );
        let bytes = rendered.as_bytes();
        if bytes.len() > MAX_RENDERED_INSTRUCTION_BYTES {
            return Err(output_failure());
        }

        let _serialization = acquire_flag_lock(context)?;
        context.check()?;
        let fd = self.fd.as_raw_fd();
        let mut flags = NonblockingFlags::enable(fd)?;
        context.check()?;
        write_all_bounded(fd, bytes, context)?;
        context.check()?;
        flags.restore()?;
        context.check()?;
        Ok(())
    }
}

#[cfg(not(unix))]
impl DeviceInstructionSink for NativeDeviceInstructionOutput {
    fn emit(
        &self,
        _instruction: &PublicDeviceInstruction,
        context: &OAuthIoContext,
    ) -> Result<(), OAuthError> {
        context.check()?;
        Err(output_failure())
    }
}

/// Share the exact admission bounds and URL checks used by the host parser.
pub(crate) fn valid_public_instruction(url: &str, user_code: &str, expires: u64) -> bool {
    if url.is_empty()
        || url.len() > MAX_VERIFICATION_URL_BYTES
        || url.chars().any(char::is_control)
        || user_code.is_empty()
        || user_code.len() > MAX_USER_CODE_BYTES
        || user_code.chars().any(char::is_control)
        || expires == 0
    {
        return false;
    }

    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.host().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
        && !parsed.query_pairs().any(|(name, _)| {
            SECRET_QUERY_KEYS
                .iter()
                .any(|secret| name.eq_ignore_ascii_case(secret))
        })
}

fn valid_instruction(instruction: &PublicDeviceInstruction) -> bool {
    valid_public_instruction(
        &instruction.verification_url,
        &instruction.user_code,
        instruction.expires_in_seconds,
    )
}

#[cfg(unix)]
static FLAG_MUTATION_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
const POLL_SLICE: Duration = Duration::from_millis(50);

#[cfg(unix)]
fn acquire_flag_lock(context: &OAuthIoContext) -> Result<MutexGuard<'static, ()>, OAuthError> {
    loop {
        context.check()?;
        match FLAG_MUTATION_LOCK.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                let remaining = context.remaining()?;
                thread::sleep(remaining.min(POLL_SLICE));
            }
        }
    }
}

#[cfg(unix)]
struct NonblockingFlags {
    fd: libc::c_int,
    original: libc::c_int,
    restore_on_drop: bool,
}

#[cfg(unix)]
impl NonblockingFlags {
    fn enable(fd: libc::c_int) -> Result<Self, OAuthError> {
        let original = get_status_flags(fd)?;
        set_status_flags(fd, original | libc::O_NONBLOCK)?;
        Ok(Self {
            fd,
            original,
            restore_on_drop: true,
        })
    }

    fn restore(&mut self) -> Result<(), OAuthError> {
        set_status_flags(self.fd, self.original)?;
        self.restore_on_drop = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for NonblockingFlags {
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = set_status_flags(self.fd, self.original);
            self.restore_on_drop = false;
        }
    }
}

#[cfg(unix)]
fn ensure_close_on_exec(fd: libc::c_int) -> bool {
    for _ in 0..16 {
        // SAFETY: fcntl reads descriptor flags from the owned output descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            if flags & libc::FD_CLOEXEC != 0 {
                return true;
            }
            // SAFETY: fcntl sets FD_CLOEXEC on this owned descriptor.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0 {
                return true;
            }
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
    false
}

#[cfg(unix)]
fn get_status_flags(fd: libc::c_int) -> Result<libc::c_int, OAuthError> {
    for _ in 0..16 {
        // SAFETY: fcntl reads status flags from the owned output descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            return Ok(flags);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    Err(output_failure())
}

#[cfg(unix)]
fn set_status_flags(fd: libc::c_int, flags: libc::c_int) -> Result<(), OAuthError> {
    for _ in 0..16 {
        // SAFETY: fcntl changes only status flags on the owned output descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } == 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    Err(output_failure())
}

#[cfg(unix)]
fn write_all_bounded(
    fd: libc::c_int,
    bytes: &[u8],
    context: &OAuthIoContext,
) -> Result<(), OAuthError> {
    let mut written = 0;
    wait_writable(fd, context)?;
    while written < bytes.len() {
        context.check()?;
        // SAFETY: the remaining slice is readable for the supplied byte count.
        let count =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if count > 0 {
            written += count as usize;
            continue;
        }
        if count == 0 {
            return Err(output_failure());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(errno) if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK => {
                wait_writable(fd, context)?;
            }
            _ => return Err(output_failure()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn wait_writable(fd: libc::c_int, context: &OAuthIoContext) -> Result<(), OAuthError> {
    loop {
        context.check()?;
        let remaining = context.remaining()?;
        let timeout_ms = remaining.as_millis().clamp(1, POLL_SLICE.as_millis()) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: descriptor is a valid pollfd and the timeout is finite.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready > 0 {
            if descriptor.revents & (libc::POLLNVAL | libc::POLLERR | libc::POLLHUP) != 0 {
                return Err(output_failure());
            }
            if descriptor.revents & libc::POLLOUT != 0 {
                return Ok(());
            }
            continue;
        }
        if ready == 0 {
            context.check()?;
            continue;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            context.check()?;
            continue;
        }
        return Err(output_failure());
    }
}

fn output_failure() -> OAuthError {
    OAuthError::Transport {
        message: "native device instruction output failed".to_owned(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::auth::{host::SystemOAuthClock, oauth::OAuthCancel};
    use std::{
        fs::File,
        io::Read,
        os::fd::{AsRawFd, FromRawFd},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct TestCancel(AtomicBool);

    impl OAuthCancel for TestCancel {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    fn context(duration: Duration, cancel: Arc<dyn OAuthCancel>) -> OAuthIoContext {
        OAuthIoContext::new(
            Instant::now() + duration,
            Arc::new(SystemOAuthClock),
            cancel,
        )
    }

    fn instruction() -> PublicDeviceInstruction {
        PublicDeviceInstruction {
            verification_url: "https://auth.example.test/codex/device".to_owned(),
            user_code: "PUBLIC-CODE-7QK".to_owned(),
            expires_in_seconds: 900,
        }
    }

    fn pipe(nonblocking: bool) -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has space for the two pipe descriptors.
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        // SAFETY: pipe returned two newly owned descriptors.
        let (read_fd, write_fd) = unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        };
        for fd in [read_fd.as_raw_fd(), write_fd.as_raw_fd()] {
            // SAFETY: fcntl reads and updates flags on a valid owned pipe descriptor.
            let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(descriptor_flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) },
                0
            );
            if nonblocking {
                // SAFETY: fcntl reads and updates flags on a valid owned pipe descriptor.
                let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                assert!(status_flags >= 0);
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK) },
                    0
                );
            }
        }
        (read_fd, write_fd)
    }

    fn flags(fd: std::os::fd::RawFd) -> i32 {
        // SAFETY: fcntl reads status flags from a valid descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0);
        flags
    }

    fn fill_pipe(fd: std::os::fd::RawFd) {
        let bytes = [b'x'; 4096];
        loop {
            // SAFETY: bytes is a valid buffer and fd is a nonblocking pipe writer.
            let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
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

    #[test]
    fn writes_real_pipe_bytes_and_restores_original_status_flags() {
        let (read_fd, write_fd) = pipe(false);
        let raw_fd = write_fd.as_raw_fd();
        let original_flags = flags(raw_fd);
        let output = NativeDeviceInstructionOutput::from_fd(write_fd);
        output
            .emit(
                &instruction(),
                &context(Duration::from_secs(1), Arc::new(TestCancel::default())),
            )
            .expect("real pipe output completes");
        assert_eq!(flags(raw_fd), original_flags);
        drop(output);
        let mut reader = File::from(read_fd);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read pipe bytes");
        assert_eq!(
            bytes,
            b"Open https://auth.example.test/codex/device\nCode: PUBLIC-CODE-7QK\nExpires in 900 seconds\n"
        );
    }

    #[test]
    fn full_pipe_wait_observes_cancellation_and_restores_original_flags() {
        let (read_fd, write_fd) = pipe(true);
        let raw_fd = write_fd.as_raw_fd();
        fill_pipe(raw_fd);
        let original_flags = flags(raw_fd);
        let cancel = Arc::new(TestCancel::default());
        let signal = Arc::clone(&cancel);
        let signal_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            signal.0.store(true, Ordering::Release);
        });
        let output = NativeDeviceInstructionOutput::from_fd(write_fd);
        let result = output.emit(&instruction(), &context(Duration::from_secs(1), cancel));
        signal_thread.join().expect("cancel signal thread");
        assert_eq!(result, Err(OAuthError::Cancelled));
        assert_eq!(flags(raw_fd), original_flags);
        drop(output);
        drop(read_fd);
    }

    #[test]
    fn full_pipe_wait_stops_at_deadline_and_restores_original_status_flags() {
        let (read_fd, write_fd) = pipe(true);
        let raw_fd = write_fd.as_raw_fd();
        fill_pipe(raw_fd);
        let original_flags = flags(raw_fd);
        let output = NativeDeviceInstructionOutput::from_fd(write_fd);
        let started = Instant::now();
        let result = output.emit(
            &instruction(),
            &context(Duration::from_millis(40), Arc::new(TestCancel::default())),
        );
        assert_eq!(result, Err(OAuthError::DeadlineExceeded));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(flags(raw_fd), original_flags);
        drop(output);
        drop(read_fd);
    }

    const STDERR_CHILD_ENV: &str = "RUSTSCRIPT_TEST_DEVICE_OUTPUT_STDERR_CHILD";
    const STDERR_CHILD_TIMEOUT: Duration = Duration::from_secs(5);
    const STDERR_CHILD_OUTPUT_LIMIT: usize = 16 * 1024;

    // Like the native_callback exact-name resource fixture, but with synchronous
    // nonblocking drains so even an inherited writer cannot leave a reader task.
    struct StderrTestChild(std::process::Child);

    impl Drop for StderrTestChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    fn nonblocking_child_pipe(reader: &impl AsRawFd) {
        let fd = reader.as_raw_fd();
        // SAFETY: the child pipe is owned and remains live for both flag calls.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0, "read child pipe status flags");
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "set child pipe nonblocking"
        );
    }

    fn drain_child_pipe(reader: &mut impl Read, captured: &mut Vec<u8>) -> bool {
        let mut buffer = [0_u8; 2048];
        // Bound each turn as well as capture size, preserving the wait deadline
        // even if a failing child continuously produces output.
        for _ in 0..8 {
            match reader.read(&mut buffer) {
                Ok(0) => return true,
                Ok(read) => {
                    assert!(
                        read <= STDERR_CHILD_OUTPUT_LIMIT.saturating_sub(captured.len()),
                        "isolated stderr test exceeded its output bound"
                    );
                    captured.extend_from_slice(&buffer[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return false,
                Err(_) => panic!("failed to drain isolated stderr test pipe"),
            }
        }
        false
    }

    fn run_stderr_test_child(test_name: &str, expect_close_failure: bool) -> bool {
        if let Some(marker) = std::env::var_os(STDERR_CHILD_ENV) {
            let marker = marker.to_str().expect("stderr child marker encoding");
            let (parent, selected) = marker.split_once('|').expect("stderr child marker shape");
            let parent = parent.parse::<u32>().expect("stderr child parent id");
            // SAFETY: getppid has no pointer arguments or side effects.
            assert_eq!(parent, unsafe { libc::getppid() as u32 });
            assert_ne!(parent, std::process::id());
            assert_eq!(selected, test_name);
            assert!(
                std::env::args()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|pair| pair[0] == "--exact" && pair[1] == test_name)
            );
            return false;
        }

        let mut command = std::process::Command::new(
            std::env::current_exe().expect("current stderr test executable"),
        );
        command
            .args(["--exact", test_name, "--nocapture"])
            .current_dir(std::env::current_dir().expect("stderr test working directory"))
            .env_clear()
            .env(
                STDERR_CHILD_ENV,
                format!("{}|{test_name}", std::process::id()),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for alias in [
            "TMPDIR",
            "TMP",
            "TEMP",
            "TEST_TMPDIR",
            "RUSTSCRIPT_AGENT_TEST_TMP",
            "RUSTSCRIPT_AGENT_TEST_TMPDIR",
        ] {
            if let Some(value) = std::env::var_os(alias) {
                command.env(alias, value);
            }
        }
        let mut child = StderrTestChild(command.spawn().expect("spawn isolated stderr test"));
        let mut stdout = child.0.stdout.take().expect("isolated stderr test stdout");
        let mut stderr = child.0.stderr.take().expect("isolated stderr test stderr");
        nonblocking_child_pipe(&stdout);
        nonblocking_child_pipe(&stderr);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let deadline = Instant::now() + STDERR_CHILD_TIMEOUT;
        let status = loop {
            drain_child_pipe(&mut stdout, &mut out);
            drain_child_pipe(&mut stderr, &mut err);
            match child.0.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(None) => panic!("isolated stderr test exceeded its wait bound"),
                Err(_) => panic!("failed to observe isolated stderr test status"),
            }
        };
        let drain_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let stdout_eof = drain_child_pipe(&mut stdout, &mut out);
            let stderr_eof = drain_child_pipe(&mut stderr, &mut err);
            if stdout_eof && stderr_eof {
                break;
            }
            assert!(
                Instant::now() < drain_deadline,
                "stderr child drain timed out"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let out = String::from_utf8_lossy(&out);
        let err = String::from_utf8_lossy(&err);
        assert_eq!(
            out.lines().filter(|line| *line == "running 1 test").count(),
            1
        );
        let outcome = if expect_close_failure { "FAILED" } else { "ok" };
        assert_eq!(
            out.lines()
                .filter(|line| *line == format!("test {test_name} ... {outcome}"))
                .count(),
            1,
            "exact stderr child executed its selected case"
        );
        if expect_close_failure {
            assert!(status.code().is_some() && !status.success());
            assert!(out.contains("test result: FAILED. 0 passed; 1 failed; 0 ignored;"));
            assert!(err.contains("retained-stderr-owner-established"));
            assert!(err.contains("assertion `left == right` failed"));
            assert!(err.contains("left: 1") && err.contains("right: -1"));
        } else {
            assert!(status.success(), "isolated stderr test failed: {status}");
            assert!(out.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        }
        // Record the actual status without reflecting arbitrary child diagnostics.
        eprintln!(
            "device-output-child test={test_name} status={status} expected_close_failure={expect_close_failure}"
        );
        true
    }

    fn assert_stderr_owner_closes(retain_owner: bool) {
        let output = NativeDeviceInstructionOutput::stderr().expect("duplicate stderr");
        let raw_fd = output.fd.as_raw_fd();
        // SAFETY: fcntl reads flags from the output's owned descriptor.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        if retain_owner {
            eprintln!("retained-stderr-owner-established");
            // A genuine negative: retain this exact OwnedFd until child exit.
            std::mem::forget(output);
        } else {
            drop(output);
        }
        // SAFETY: this exact child runs no other fixture that can reuse raw_fd.
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn stderr_duplicate_is_close_on_exec_and_closes_with_its_owner() {
        if run_stderr_test_child(
            concat!(
                "auth::device_output::tests::",
                "stderr_duplicate_is_close_on_exec_and_closes_with_its_owner"
            ),
            false,
        ) {
            return;
        }
        assert_stderr_owner_closes(false);
    }

    #[test]
    fn retained_stderr_owner_negative_control_keeps_close_assertion_strict() {
        if run_stderr_test_child(
            concat!(
                "auth::device_output::tests::",
                "retained_stderr_owner_negative_control_keeps_close_assertion_strict"
            ),
            true,
        ) {
            return;
        }
        assert_stderr_owner_closes(true);
    }

    #[test]
    fn stderr_fd_integer_reuse_does_not_identify_the_dropped_owner() {
        if run_stderr_test_child(
            concat!(
                "auth::device_output::tests::",
                "stderr_fd_integer_reuse_does_not_identify_the_dropped_owner"
            ),
            false,
        ) {
            return;
        }
        let output = NativeDeviceInstructionOutput::stderr().expect("duplicate stderr");
        let raw_fd = output.fd.as_raw_fd();
        drop(output);
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        // Diagnostic control only: deliberately reuse the now-free integer. This
        // does not claim to reconstruct the reported parallel interleaving.
        let reused = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, raw_fd) };
        assert!(reused >= 0);
        // SAFETY: fcntl returned a fresh descriptor, with exactly one local owner.
        let reused = unsafe { OwnedFd::from_raw_fd(reused) };
        assert_eq!(reused.as_raw_fd(), raw_fd);
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, 1);
        drop(reused);
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }
}
