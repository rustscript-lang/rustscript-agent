use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::NativeLoopbackCallbacks;
use super::manual_input::NativeManualCallbackInput;
use crate::auth::oauth::{
    CallbackMode, CallbackWaiter, OAuthCancel, OAuthError, OAuthIoContext, PreparedCallbackSession,
    RawCallbackInput,
};

/// Trusted per-host inputs for concrete native callback dispatch.
pub(crate) struct NativeCallbackInputs {
    browser: NativeLoopbackCallbacks,
    manual_input: Mutex<Option<Arc<NativeManualCallbackInput>>>,
}

impl NativeCallbackInputs {
    pub(crate) fn new(manual_input: Option<OwnedFd>) -> Result<Self, OAuthError> {
        let manual_input = manual_input
            .map(NativeManualCallbackInput::new)
            .transpose()?
            .map(Arc::new);
        Ok(Self {
            browser: NativeLoopbackCallbacks,
            manual_input: Mutex::new(manual_input),
        })
    }

    fn lock_manual_input(&self) -> MutexGuard<'_, Option<Arc<NativeManualCallbackInput>>> {
        self.manual_input
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl CallbackWaiter for NativeCallbackInputs {
    fn prepare(
        &self,
        mode: CallbackMode,
        context: &OAuthIoContext,
    ) -> Result<Option<Arc<dyn PreparedCallbackSession>>, OAuthError> {
        context.check()?;
        if mode == CallbackMode::Browser {
            return self.browser.prepare(mode, context);
        }

        let input = self
            .lock_manual_input()
            .take()
            .ok_or_else(|| transport("native manual callback input is unavailable"))?;
        context.check()?;
        let redirect = self
            .browser
            .prepare(CallbackMode::Browser, context)?
            .ok_or_else(|| transport("native redirect resource is unavailable"))?;
        context.check()?;
        Ok(Some(Arc::new(ManualPreparedSession {
            redirect,
            input: Mutex::new(Some(input)),
            cancelled: Arc::new(AtomicBool::new(false)),
            claimed: AtomicBool::new(false),
        })))
    }

    fn wait_one(&self, _context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        Err(transport(
            "native callback requires a prepared flow session",
        ))
    }
}

struct ManualPreparedSession {
    redirect: Arc<dyn PreparedCallbackSession>,
    input: Mutex<Option<Arc<NativeManualCallbackInput>>>,
    cancelled: Arc<AtomicBool>,
    claimed: AtomicBool,
}

impl ManualPreparedSession {
    fn lock_input(&self) -> MutexGuard<'_, Option<Arc<NativeManualCallbackInput>>> {
        self.input.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn revoke(&self) {
        if self.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let input = self.lock_input().take();
        drop(input);
        self.redirect.revoke();
    }
}

struct SessionOAuthCancel(Arc<AtomicBool>);

impl OAuthCancel for SessionOAuthCancel {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct RevokeManualSessionOnDrop<'a>(&'a ManualPreparedSession);

impl Drop for RevokeManualSessionOnDrop<'_> {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

impl PreparedCallbackSession for ManualPreparedSession {
    fn redirect_uri(&self) -> &str {
        self.redirect.redirect_uri()
    }

    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            self.revoke();
            return Err(transport(
                "native manual callback session was already consumed",
            ));
        }
        let _revoke = RevokeManualSessionOnDrop(self);
        context.check()?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(transport("native manual callback session was revoked"));
        }
        let input = self
            .lock_input()
            .take()
            .ok_or_else(|| transport("native manual callback input is unavailable"))?;
        let context = context
            .with_additional_cancel(Arc::new(SessionOAuthCancel(Arc::clone(&self.cancelled))));
        input.wait_one(&context)
    }

    fn revoke(&self) {
        ManualPreparedSession::revoke(self);
    }
}

impl Drop for ManualPreparedSession {
    fn drop(&mut self) {
        self.revoke();
    }
}

fn transport(message: &'static str) -> OAuthError {
    OAuthError::Transport {
        message: message.to_string(),
    }
}

#[cfg(test)]
pub(in crate::auth::native_callback) mod tests {
    use std::{
        ffi::c_char,
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        path::PathBuf,
        process::{Command, Stdio},
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use super::NativeCallbackInputs;
    use crate::auth::oauth::{
        CallbackMode, CallbackWaiter, OAuthCancel, OAuthClock, OAuthIoContext, RawCallbackInput,
    };
    use url::Url;

    const CODE: &str = "COMPOSITE_PRIVATE_CODE_MARKER";

    struct TestClock {
        now: Instant,
        panic: AtomicBool,
        now_calls: std::sync::atomic::AtomicUsize,
        deadline_on_call: Option<usize>,
    }

    impl OAuthClock for TestClock {
        fn now(&self) -> Instant {
            assert!(
                !self.panic.load(Ordering::Acquire),
                "clock panic requested by test"
            );
            let call = self.now_calls.fetch_add(1, Ordering::AcqRel) + 1;
            if self.deadline_on_call == Some(call) {
                self.now + Duration::from_secs(3)
            } else {
                self.now
            }
        }

        fn unix_ms(&self) -> u64 {
            1
        }
    }

    #[derive(Default)]
    struct TestCancel(AtomicBool);

    impl OAuthCancel for TestCancel {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    fn context() -> (OAuthIoContext, Arc<TestClock>, Arc<TestCancel>) {
        let now = Instant::now();
        let clock = Arc::new(TestClock {
            now,
            panic: AtomicBool::new(false),
            now_calls: std::sync::atomic::AtomicUsize::new(0),
            deadline_on_call: None,
        });
        let cancel = Arc::new(TestCancel::default());
        let clock_trait: Arc<dyn OAuthClock> = clock.clone();
        let cancel_trait: Arc<dyn OAuthCancel> = cancel.clone();
        (
            OAuthIoContext::new(now + Duration::from_secs(3), clock_trait, cancel_trait),
            clock,
            cancel,
        )
    }

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn pty_pair() -> (OwnedFd, OwnedFd) {
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
        assert!(master >= 0);
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        assert_eq!(unsafe { libc::grantpt(master.as_raw_fd()) }, 0);
        assert_eq!(unsafe { libc::unlockpt(master.as_raw_fd()) }, 0);
        let mut name = [0 as c_char; 128];
        assert_eq!(
            unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) },
            0
        );
        let slave = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        assert!(slave >= 0);
        (master, unsafe { OwnedFd::from_raw_fd(slave) })
    }

    fn duplicate(fd: i32) -> OwnedFd {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        assert!(duplicate >= 0);
        unsafe { OwnedFd::from_raw_fd(duplicate) }
    }

    fn termios(fd: i32) -> libc::termios {
        let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
        assert_eq!(unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) }, 0);
        unsafe { value.assume_init() }
    }

    fn assert_termios_restored(actual: &libc::termios, expected: &libc::termios) {
        assert_eq!(actual.c_iflag, expected.c_iflag);
        assert_eq!(actual.c_oflag, expected.c_oflag);
        assert_eq!(actual.c_cflag, expected.c_cflag);
        assert_eq!(actual.c_lflag, expected.c_lflag);
        assert_eq!(actual.c_line, expected.c_line);
        assert_eq!(actual.c_cc, expected.c_cc);
        assert_eq!(unsafe { libc::cfgetispeed(actual) }, unsafe {
            libc::cfgetispeed(expected)
        });
        assert_eq!(unsafe { libc::cfgetospeed(actual) }, unsafe {
            libc::cfgetospeed(expected)
        });
    }

    fn expiring_context_on_check(check: usize) -> OAuthIoContext {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3);
        let clock = Arc::new(TestClock {
            now,
            panic: AtomicBool::new(false),
            now_calls: std::sync::atomic::AtomicUsize::new(0),
            deadline_on_call: Some(check),
        });
        let cancel = Arc::new(TestCancel::default());
        let clock_trait: Arc<dyn OAuthClock> = clock;
        let cancel_trait: Arc<dyn OAuthCancel> = cancel;
        OAuthIoContext::new(deadline, clock_trait, cancel_trait)
    }

    fn socket_targets() -> Vec<PathBuf> {
        let mut sockets = std::fs::read_dir("/proc/self/fd")
            .expect("inspect this process's owned sockets")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .filter(|target| target.to_string_lossy().starts_with("socket:["))
            .collect::<Vec<_>>();
        sockets.sort();
        sockets
    }

    fn port(uri: &str) -> u16 {
        Url::parse(uri)
            .expect("prepared redirect URI")
            .port()
            .expect("ephemeral port")
    }

    fn assert_port_released(uri: &str) {
        drop(
            std::net::TcpListener::bind(("127.0.0.1", port(uri)))
                .expect("owned redirect listener was revoked"),
        );
    }

    fn assert_fd_closed(fd: i32) {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    const RESOURCE_CHILD_ENV: &str = "RUSTSCRIPT_TEST_NATIVE_CALLBACK_COMPOSITE_CHILD";
    const RESOURCE_CHILD_TIMEOUT: Duration = Duration::from_secs(5);
    const RESOURCE_CHILD_OUTPUT_LIMIT: usize = 16 * 1024;

    #[derive(Clone, Copy)]
    pub(in crate::auth::native_callback) enum ExpectedChildResult {
        Pass,
        AssertionFailure(&'static str),
    }

    struct ChildResult {
        status: std::process::ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        timed_out: bool,
        output_truncated: bool,
    }

    fn capture_child_output(mut reader: impl Read) -> (Vec<u8>, bool) {
        let mut captured = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 2048];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let remaining = RESOURCE_CHILD_OUTPUT_LIMIT.saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..read.min(remaining)]);
                    truncated |= read > remaining;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        (captured, truncated)
    }

    pub(in crate::auth::native_callback) fn run_resource_test_child(
        test_name: &str,
        expected: ExpectedChildResult,
    ) -> bool {
        if let Some(marker) = std::env::var_os(RESOURCE_CHILD_ENV) {
            let marker = marker.to_string_lossy();
            let (parent, selected_test) = marker
                .split_once('|')
                .expect("resource-observation child marker shape");
            let parent = parent
                .parse::<u32>()
                .expect("resource-observation parent process id");
            let args = std::env::args().collect::<Vec<_>>();
            assert_eq!(parent, unsafe { libc::getppid() as u32 });
            assert_ne!(parent, std::process::id());
            assert!(
                args.windows(2)
                    .any(|pair| { pair[0] == "--exact" && pair[1] == test_name })
            );
            assert_eq!(selected_test, test_name);
            return false;
        }

        let executable = std::env::current_exe().expect("current test executable");
        let marker = format!("{}|{test_name}", std::process::id());
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .current_dir(std::env::current_dir().expect("test working directory"))
            .env_clear()
            .env(RESOURCE_CHILD_ENV, marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated native callback resource test");
        let stdout = child.stdout.take().expect("isolated child stdout");
        let stderr = child.stderr.take().expect("isolated child stderr");
        let stdout_reader = thread::spawn(move || capture_child_output(stdout));
        let stderr_reader = thread::spawn(move || capture_child_output(stderr));
        let deadline = Instant::now() + RESOURCE_CHILD_TIMEOUT;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().expect("reap timed-out resource-test child");
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("failed to observe isolated resource-test child status");
                }
            }
        };
        let (stdout, stdout_truncated) =
            stdout_reader.join().expect("capture isolated child stdout");
        let (stderr, stderr_truncated) =
            stderr_reader.join().expect("capture isolated child stderr");
        let result = ChildResult {
            status,
            stdout,
            stderr,
            timed_out,
            output_truncated: stdout_truncated || stderr_truncated,
        };
        assert!(
            child_result_is_valid(test_name, expected, &result),
            "isolated native callback child did not meet its expected result: {}",
            sanitized_child_result(test_name, &result)
        );
        true
    }

    fn child_result_is_valid(
        test_name: &str,
        expected: ExpectedChildResult,
        result: &ChildResult,
    ) -> bool {
        if result.timed_out || result.output_truncated {
            return false;
        }
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let lines = stdout.lines().chain(stderr.lines()).collect::<Vec<_>>();
        let run_once = lines
            .iter()
            .filter(|line| **line == "running 1 test")
            .count()
            == 1;
        let passed = format!("test {test_name} ... ok");
        let failed = format!("test {test_name} ... FAILED");
        match expected {
            ExpectedChildResult::Pass => {
                result.status.success()
                    && run_once
                    && lines.iter().filter(|line| **line == passed).count() == 1
                    && lines.iter().any(|line| {
                        line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
                    })
            }
            ExpectedChildResult::AssertionFailure(witness) => {
                result.status.code() == Some(101)
                    && run_once
                    && lines.iter().filter(|line| **line == failed).count() == 1
                    && lines.iter().any(|line| {
                        line.starts_with("test result: FAILED. 0 passed; 1 failed; 0 ignored;")
                    })
                    && stderr.contains(witness)
                    && stderr.contains("assertion `left == right` failed")
                    && stderr.contains("left: 1")
                    && stderr.contains("right: -1")
            }
        }
    }

    fn sanitized_child_result(test_name: &str, result: &ChildResult) -> String {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let mut safe_lines = Vec::new();
        for line in stdout.lines().chain(stderr.lines()) {
            if line == "running 1 test"
                || line == "running 0 tests"
                || line == format!("test {test_name} ... ok")
                || line == format!("test {test_name} ... FAILED")
                || line.starts_with("test result:")
            {
                safe_lines.push(line.to_string());
            }
        }
        if stderr.contains("panicked at ") {
            safe_lines.push("stderr: panic observed (details suppressed)".to_string());
        }
        if stderr.contains("assertion `left == right` failed") {
            safe_lines.push("stderr: assertion `left == right` failed".to_string());
        }
        for witness in ["numeric-fd-reuse-established", "leaked-open-fd-established"] {
            if stderr.contains(witness) {
                safe_lines.push(format!("stderr: {witness}"));
            }
        }
        if stderr.contains("left: 1") && stderr.contains("right: -1") {
            safe_lines
                .push("stderr: observed numeric descriptor result 1 versus EBADF -1".to_string());
        }
        format!(
            "exit={:?}, timed_out={}, output_truncated={}, stdout_bytes={}, stderr_bytes={}, sanitized=[{}]",
            result.status.code(),
            result.timed_out,
            result.output_truncated,
            result.stdout.len(),
            result.stderr.len(),
            safe_lines.join(" | ")
        )
    }

    #[test]
    fn deadline_after_redirect_allocation_releases_reserved_fd_and_socket() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::deadline_after_redirect_allocation_releases_reserved_fd_and_socket"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let sockets_before = socket_targets();
        let context = expiring_context_on_check(4);
        let failure = match inputs.prepare(CallbackMode::Manual, &context) {
            Err(failure) => failure,
            Ok(_) => panic!("late deadline must reject prepared resources"),
        };
        assert_eq!(failure.code(), "deadline_exceeded");
        assert_fd_closed(raw_fd);
        assert_eq!(socket_targets(), sockets_before);
    }

    #[test]
    fn browser_prepare_does_not_consume_manual_fd_and_manual_reserves_it_once() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::browser_prepare_does_not_consume_manual_fd_and_manual_reserves_it_once"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let (context, _, _) = context();
        let browser = inputs
            .prepare(CallbackMode::Browser, &context)
            .expect("browser preparation")
            .expect("browser session");
        let manual = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("manual session");
        assert_ne!(browser.redirect_uri(), manual.redirect_uri());
        assert!(inputs.prepare(CallbackMode::None, &context).is_err());
        assert!(inputs.wait_one(&context).is_err());
        assert!(
            inputs
                .inject(RawCallbackInput::ManualUrl("unused".to_string()))
                .is_err()
        );
        let browser_uri = browser.redirect_uri().to_string();
        let manual_uri = manual.redirect_uri().to_string();
        browser.revoke();
        manual.revoke();
        assert_port_released(&browser_uri);
        assert_port_released(&manual_uri);
    }

    #[test]
    fn manual_and_none_modes_forward_exact_host_url_once() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::manual_and_none_modes_forward_exact_host_url_once"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        for mode in [CallbackMode::Manual, CallbackMode::None] {
            let (reader, writer) = pipe_pair();
            let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
            let (context, _, _) = context();
            let session = inputs
                .prepare(mode, &context)
                .expect("manual/none preparation")
                .expect("prepared session");
            let redirect = session.redirect_uri().to_string();
            let callback = format!("{redirect}?code={CODE}&state=generated-state");
            let mut writer = File::from(writer);
            writer
                .write_all(format!("{callback}\n").as_bytes())
                .expect("write test callback URL");
            drop(writer);
            let result = session.wait_one(&context).expect("read exact manual URL");
            assert!(matches!(result, RawCallbackInput::ManualUrl(value) if value == callback));
            assert!(session.wait_one(&context).is_err());
            assert_port_released(&redirect);
        }
    }

    #[test]
    fn concurrent_manual_preparation_reserves_the_single_fd_once() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::concurrent_manual_preparation_reserves_the_single_fd_once"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let inputs = Arc::new(NativeCallbackInputs::new(Some(reader)).expect("own manual input"));
        let (context, _, _) = context();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for mode in [CallbackMode::Manual, CallbackMode::None] {
            let inputs = Arc::clone(&inputs);
            let context = context.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                inputs.prepare(mode, &context)
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let session = results
            .into_iter()
            .find_map(|result| match result {
                Ok(Some(session)) => Some(session),
                Ok(None) | Err(_) => None,
            })
            .expect("one flow reserved the reader");
        let redirect = session.redirect_uri().to_string();
        session.revoke();
        assert_port_released(&redirect);
    }

    #[test]
    fn revoking_pending_manual_read_cancels_wait_and_releases_owned_resources() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::revoking_pending_manual_read_cancels_wait_and_releases_owned_resources"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let (context, _, _) = context();
        let session = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("prepared session");
        let redirect = session.redirect_uri().to_string();
        let waiter_session = Arc::clone(&session);
        let (started_tx, started_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            started_tx.send(()).expect("signal pending wait");
            waiter_session.wait_one(&context)
        });
        started_rx.recv().expect("wait worker started");
        thread::sleep(Duration::from_millis(60));
        session.revoke();
        assert!(worker.join().expect("wait worker joined").is_err());
        assert_fd_closed(fd);
        assert_port_released(&redirect);
    }

    #[test]
    fn host_cancellation_during_pending_manual_read_closes_input_and_redirect() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::host_cancellation_during_pending_manual_read_closes_input_and_redirect"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let now = Instant::now();
        let clock = Arc::new(TestClock {
            now,
            panic: AtomicBool::new(false),
            now_calls: std::sync::atomic::AtomicUsize::new(0),
            deadline_on_call: None,
        });
        let cancel = Arc::new(TestCancel::default());
        let context = OAuthIoContext::new(now + Duration::from_secs(3), clock, cancel.clone());
        let session = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("prepared session");
        let redirect = session.redirect_uri().to_string();
        let waiter = Arc::clone(&session);
        let wait_context = context.clone();
        let worker = thread::spawn(move || waiter.wait_one(&wait_context));
        thread::sleep(Duration::from_millis(60));
        cancel.0.store(true, Ordering::Release);
        assert!(matches!(
            worker.join().expect("wait worker joined"),
            Err(crate::auth::oauth::OAuthError::Cancelled)
        ));
        assert_fd_closed(fd);
        assert_port_released(&redirect);
    }

    #[test]
    fn deadline_during_pending_manual_read_closes_input_and_redirect() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::deadline_during_pending_manual_read_closes_input_and_redirect"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let context = expiring_context_on_check(12);
        let session = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("prepared session");
        let redirect = session.redirect_uri().to_string();
        let failure = session
            .wait_one(&context)
            .expect_err("deadline applies while the descriptor is pending");
        assert_eq!(failure.code(), "deadline_exceeded");
        assert_fd_closed(fd);
        assert_port_released(&redirect);
    }

    #[test]
    fn revoking_before_wait_closes_idle_fd_and_redirect_listener() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::revoking_before_wait_closes_idle_fd_and_redirect_listener"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let (context, _, _) = context();
        let session = inputs
            .prepare(CallbackMode::None, &context)
            .expect("none preparation")
            .expect("prepared session");
        let redirect = session.redirect_uri().to_string();
        session.revoke();
        assert_fd_closed(fd);
        assert_port_released(&redirect);
        assert!(session.wait_one(&context).is_err());
    }

    #[test]
    fn panic_during_manual_wait_still_revokes_fd_and_redirect_listener() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::panic_during_manual_wait_still_revokes_fd_and_redirect_listener"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own manual input");
        let (context, clock, _) = context();
        let session = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("prepared session");
        let redirect = session.redirect_uri().to_string();
        clock.panic.store(true, Ordering::Release);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = session.wait_one(&context);
        }));
        assert!(result.is_err());
        assert_fd_closed(fd);
        assert_port_released(&redirect);
    }

    #[test]
    fn pty_manual_read_suppresses_echo_and_restores_flags_and_termios() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::pty_manual_read_suppresses_echo_and_restores_flags_and_termios"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (master, slave) = pty_pair();
        let input_fd = slave.as_raw_fd();
        let observer = duplicate(input_fd);
        let original_flags = unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) };
        assert!(original_flags >= 0);
        let mut original_termios = termios(observer.as_raw_fd());
        original_termios.c_lflag |= libc::ECHO | libc::ECHONL;
        assert_eq!(
            unsafe { libc::tcsetattr(observer.as_raw_fd(), libc::TCSANOW, &original_termios) },
            0
        );
        let original_termios = termios(observer.as_raw_fd());
        let inputs = NativeCallbackInputs::new(Some(slave)).expect("own PTY input");
        let (context, _, _) = context();
        let session = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("prepared session");
        let redirect = session.redirect_uri().to_string();
        let callback = format!("{redirect}?code={CODE}&state=pty-state");
        let expected_callback = callback.clone();
        let _master_guard = duplicate(master.as_raw_fd());
        let mut master = File::from(master);
        let observer_thread = duplicate(observer.as_raw_fd());
        let echo_result = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let current = termios(observer_thread.as_raw_fd());
                if current.c_lflag & (libc::ECHO | libc::ECHONL) == 0 {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "manual wait did not suppress PTY echo"
                );
                thread::sleep(Duration::from_millis(1));
            }
            master
                .write_all(format!("{callback}\n").as_bytes())
                .expect("write callback through PTY master");
            let mut descriptor = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut descriptor, 1, 100) }
        });
        let result = session
            .wait_one(&context)
            .expect("read the callback line from the PTY slave");
        assert!(matches!(result, RawCallbackInput::ManualUrl(value) if value == expected_callback));
        assert_eq!(echo_result.join().expect("PTY observer"), 0);
        assert_eq!(
            unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
        assert_termios_restored(&termios(observer.as_raw_fd()), &original_termios);
        assert_fd_closed(input_fd);
        assert_port_released(&redirect);
    }

    #[test]
    fn numeric_fd_reuse_is_a_deterministic_native_close_red_case() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::numeric_fd_reuse_is_a_deterministic_native_close_red_case"
            ),
            ExpectedChildResult::AssertionFailure("numeric-fd-reuse-established"),
        ) {
            return;
        }
        let (reader, writer) = pipe_pair();
        let input_fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own native manual input");
        let (context, _, _) = context();
        let session = inputs
            .prepare(CallbackMode::Manual, &context)
            .expect("manual preparation")
            .expect("prepared session");
        let mut writer = File::from(writer);
        writer
            .write_all(b"callback-test-value\n")
            .expect("write bounded test input");
        drop(writer);
        let result = session
            .wait_one(&context)
            .expect("native input reader closes after one callback");
        assert!(matches!(
            result,
            RawCallbackInput::ManualUrl(value) if value == "callback-test-value"
        ));
        drop(session);
        drop(inputs);

        // Prove the native owner already closed the original descriptor before
        // forcing an unrelated descriptor to reuse the exact integer.
        assert_fd_closed(input_fd);
        let replacement =
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert_eq!(replacement, input_fd, "force exact descriptor-number reuse");
        let _replacement = unsafe { OwnedFd::from_raw_fd(replacement) };
        eprintln!("numeric-fd-reuse-established");
        assert_fd_closed(input_fd);
    }

    #[test]
    fn leaked_open_fd_negative_control_keeps_closed_assertion_strict() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::composite::tests",
                "::leaked_open_fd_negative_control_keeps_closed_assertion_strict"
            ),
            ExpectedChildResult::AssertionFailure("leaked-open-fd-established"),
        ) {
            return;
        }
        let (reader, _writer) = pipe_pair();
        let input_fd = reader.as_raw_fd();
        let inputs = NativeCallbackInputs::new(Some(reader)).expect("own native manual input");

        // Test-only leaked-owner mutant: the still-open fd exists only in this
        // expected-failure child and is reclaimed when that process exits.
        std::mem::forget(inputs);
        assert!(unsafe { libc::fcntl(input_fd, libc::F_GETFD) } >= 0);
        eprintln!("leaked-open-fd-established");
        assert_fd_closed(input_fd);
    }
}
