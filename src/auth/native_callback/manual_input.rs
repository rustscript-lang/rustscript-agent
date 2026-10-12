//! Bounded private descriptor input for a manually supplied callback URL.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::auth::oauth::{CallbackWaiter, OAuthError, OAuthIoContext, RawCallbackInput};

const MAX_INPUT_BYTES: usize = 8192;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// One-shot reader over a dedicated, trusted input descriptor.
///
/// The descriptor must not be shared with concurrent readers. Temporarily
/// changing `O_NONBLOCK` affects every duplicate of its open-file description;
/// the original status flags are restored before the owned descriptor closes.
/// Raw input remains in one bounded zeroizing buffer. Success transfers one
/// host-side `String` through the existing redacted `ManualUrl` variant; this
/// cannot erase copies retained by the caller, kernel, or receiving component.
pub struct NativeManualCallbackInput {
    input: Mutex<Option<OwnedFd>>,
}

impl NativeManualCallbackInput {
    /// Takes ownership of one private callback-input descriptor.
    pub fn new(input: OwnedFd) -> Result<Self, OAuthError> {
        ensure_cloexec(input.as_raw_fd())?;
        Ok(Self {
            input: Mutex::new(Some(input)),
        })
    }
}

impl CallbackWaiter for NativeManualCallbackInput {
    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        let descriptor = {
            let mut input = self.input.lock().unwrap_or_else(PoisonError::into_inner);
            input.take()
        }
        .ok_or_else(|| transport("manual callback input was already consumed"))?;

        context.check()?;
        let mut descriptor = InputDescriptor::new(descriptor)?;
        context.check()?;
        let result = read_callback_url(descriptor.as_raw_fd(), context);
        let restored = descriptor.restore();
        match result {
            Ok(mut url) => {
                restored?;
                context.check()?;
                let url = std::mem::take(&mut *url);
                Ok(RawCallbackInput::ManualUrl(url))
            }
            Err(error) => {
                let _ = restored;
                Err(error)
            }
        }
    }
}

struct InputDescriptor {
    fd: OwnedFd,
    original_flags: libc::c_int,
    original_termios: Option<libc::termios>,
    flags_restored: bool,
}

impl InputDescriptor {
    fn new(fd: OwnedFd) -> Result<Self, OAuthError> {
        let original_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if original_flags < 0 {
            return Err(transport("manual callback input setup failed"));
        }
        let mut descriptor = Self {
            fd,
            original_flags,
            original_termios: None,
            flags_restored: false,
        };
        if unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFL,
                original_flags | libc::O_NONBLOCK,
            )
        } < 0
        {
            return Err(transport("manual callback input setup failed"));
        }

        let mut current = std::mem::MaybeUninit::<libc::termios>::uninit();
        let result = unsafe { libc::tcgetattr(descriptor.as_raw_fd(), current.as_mut_ptr()) };
        if result == 0 {
            let original = unsafe { current.assume_init() };
            descriptor.original_termios = Some(original);
            let mut private = original;
            private.c_lflag &= !(libc::ECHO | libc::ECHONL);
            if unsafe { libc::tcsetattr(descriptor.as_raw_fd(), libc::TCSANOW, &private) } < 0 {
                return Err(transport("manual callback terminal setup failed"));
            }
        } else if io::Error::last_os_error().raw_os_error() != Some(libc::ENOTTY) {
            return Err(transport("manual callback terminal setup failed"));
        }
        Ok(descriptor)
    }

    fn as_raw_fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }

    fn restore(&mut self) -> Result<(), OAuthError> {
        let mut restored = true;
        if let Some(original) = self.original_termios.as_ref()
            && unsafe { libc::tcsetattr(self.as_raw_fd(), libc::TCSANOW, original) } < 0
        {
            restored = false;
        } else if self.original_termios.is_some() {
            self.original_termios = None;
        }
        if unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, self.original_flags) } < 0 {
            restored = false;
        } else {
            self.flags_restored = true;
        }
        if restored {
            Ok(())
        } else {
            Err(transport("manual callback input restoration failed"))
        }
    }
}

impl Drop for InputDescriptor {
    fn drop(&mut self) {
        if self.original_termios.is_some() || !self.flags_restored {
            let _ = self.restore();
        }
    }
}

fn ensure_cloexec(fd: libc::c_int) -> Result<(), OAuthError> {
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(transport("manual callback input setup failed"));
    }
    if descriptor_flags & libc::FD_CLOEXEC == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(transport("manual callback input setup failed"));
    }
    Ok(())
}

fn read_callback_url(
    fd: libc::c_int,
    context: &OAuthIoContext,
) -> Result<Zeroizing<String>, OAuthError> {
    // One zeroizing buffer serves as both the current read area and aggregate,
    // keeping all raw bytes within the single 8192-byte input budget.
    let mut bytes = Zeroizing::new([0_u8; MAX_INPUT_BYTES]);
    let mut length = 0;
    loop {
        context.check()?;
        if length == MAX_INPUT_BYTES {
            let events = poll_readable(fd, context)?;
            if at_eof_after_limit(fd, events) {
                return finish_line(&bytes[..length], false);
            }
            return Err(invalid("manual callback input exceeds limit"));
        }

        let events = poll_readable(fd, context)?;
        if events & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(transport("manual callback input poll failed"));
        }
        context.check()?;
        let read = unsafe {
            libc::read(
                fd,
                bytes[length..].as_mut_ptr().cast(),
                MAX_INPUT_BYTES - length,
            )
        };
        let read_error = (read < 0).then(|| io::Error::last_os_error().raw_os_error());
        context.check()?;
        if read > 0 {
            length += read as usize;
            if let Some(delimiter) = bytes[..length].iter().position(|byte| *byte == b'\n') {
                if delimiter + 1 != length {
                    return Err(invalid("manual callback input contains trailing bytes"));
                }
                return finish_line(&bytes[..length], true);
            }
        } else if read == 0
            || (read_error.flatten() == Some(libc::EIO) && events & libc::POLLHUP != 0)
        {
            return finish_line(&bytes[..length], false);
        } else if matches!(read_error.flatten(), Some(code) if code == libc::EINTR || code == libc::EAGAIN || code == libc::EWOULDBLOCK)
        {
            continue;
        } else {
            return Err(transport("manual callback input read failed"));
        }
    }
}

fn poll_readable(fd: libc::c_int, context: &OAuthIoContext) -> Result<libc::c_short, OAuthError> {
    loop {
        context.check()?;
        let remaining = context.remaining()?;
        let timeout = remaining.min(POLL_INTERVAL);
        let timeout = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::ppoll(&mut descriptor, 1, &timeout, std::ptr::null()) };
        let poll_error = (result < 0).then(|| io::Error::last_os_error().raw_os_error());
        context.check()?;
        if result < 0 {
            if poll_error.flatten() == Some(libc::EINTR) {
                continue;
            }
            return Err(transport("manual callback input poll failed"));
        }
        if result == 0 {
            continue;
        }
        return Ok(descriptor.revents);
    }
}

fn at_eof_after_limit(fd: libc::c_int, events: libc::c_short) -> bool {
    if regular_file_at_eof(fd) {
        return true;
    }
    if events & libc::POLLHUP == 0 {
        return false;
    }
    match queued_bytes(fd) {
        Some(0) => true,
        Some(_) => false,
        None => events & libc::POLLIN == 0,
    }
}

fn regular_file_at_eof(fd: libc::c_int) -> bool {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
        return false;
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return false;
    }
    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    offset >= 0 && offset >= metadata.st_size
}

fn queued_bytes(fd: libc::c_int) -> Option<libc::c_int> {
    let mut available: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut available) } < 0 {
        None
    } else {
        Some(available)
    }
}

fn finish_line(bytes: &[u8], terminated: bool) -> Result<Zeroizing<String>, OAuthError> {
    let mut end = bytes.len();
    if terminated {
        if end == 0 || bytes[end - 1] != b'\n' {
            return Err(invalid("manual callback input line is malformed"));
        }
        end -= 1;
        if end > 0 && bytes[end - 1] == b'\r' {
            end -= 1;
        }
    }
    if end == 0 {
        return Err(invalid("manual callback input line is empty"));
    }
    let line = std::str::from_utf8(&bytes[..end])
        .map_err(|_| invalid("manual callback input is not UTF-8"))?;
    if line.chars().any(char::is_control) {
        return Err(invalid("manual callback input contains controls"));
    }
    Ok(Zeroizing::new(line.to_owned()))
}

fn invalid(reason: &'static str) -> OAuthError {
    OAuthError::InvalidIntent {
        reason: reason.to_owned(),
    }
}

fn transport(message: &'static str) -> OAuthError {
    OAuthError::Transport {
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::native_callback::composite::tests::{
        ExpectedChildResult, run_resource_test_child,
    };
    use crate::auth::oauth::{OAuthCancel, OAuthClock};
    use std::ffi::c_char;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    struct TestClock;

    impl OAuthClock for TestClock {
        fn now(&self) -> Instant {
            Instant::now()
        }

        fn unix_ms(&self) -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        }
    }

    #[derive(Default)]
    struct TestCancel(AtomicBool);

    impl OAuthCancel for TestCancel {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    struct PanicSecondClock(AtomicUsize);

    impl OAuthClock for PanicSecondClock {
        fn now(&self) -> Instant {
            if self.0.fetch_add(1, Ordering::AcqRel) == 1 {
                panic!("test deadline clock panic");
            }
            Instant::now()
        }

        fn unix_ms(&self) -> u64 {
            0
        }
    }

    fn context(timeout: Duration, cancel: Arc<TestCancel>) -> OAuthIoContext {
        OAuthIoContext::new(Instant::now() + timeout, Arc::new(TestClock), cancel)
    }

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(result, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn socket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
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

    fn get_termios(fd: i32) -> libc::termios {
        let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
        assert_eq!(unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) }, 0);
        unsafe { value.assume_init() }
    }

    fn assert_termios_equal(left: &libc::termios, right: &libc::termios) {
        assert_eq!(left.c_iflag, right.c_iflag);
        assert_eq!(left.c_oflag, right.c_oflag);
        assert_eq!(left.c_cflag, right.c_cflag);
        assert_eq!(left.c_lflag, right.c_lflag);
        assert_eq!(left.c_line, right.c_line);
        assert_eq!(left.c_cc, right.c_cc);
        assert_eq!(unsafe { libc::cfgetispeed(left) }, unsafe {
            libc::cfgetispeed(right)
        });
        assert_eq!(unsafe { libc::cfgetospeed(left) }, unsafe {
            libc::cfgetospeed(right)
        });
    }

    fn duplicate(fd: i32) -> OwnedFd {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        assert!(duplicate >= 0);
        unsafe { OwnedFd::from_raw_fd(duplicate) }
    }

    fn error_for(input: &[u8]) -> (OAuthError, i32) {
        let (reader, writer) = pipe_pair();
        let raw = reader.as_raw_fd();
        let waiter = NativeManualCallbackInput::new(reader).expect("input owner");
        let mut writer = File::from(writer);
        writer.write_all(input).expect("write fixture input");
        drop(writer);
        let error = waiter
            .wait_one(&context(
                Duration::from_secs(2),
                Arc::new(TestCancel::default()),
            ))
            .expect_err("invalid line must be rejected");
        (error, raw)
    }

    fn wait_for_nonblocking(observer: i32, original: i32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let flags = unsafe { libc::fcntl(observer, libc::F_GETFL) };
            if flags == original | libc::O_NONBLOCK {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "input did not become nonblocking"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn accepts_lf_crlf_and_nonempty_eof_lines() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::accepts_lf_crlf_and_nonempty_eof_lines"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        for (bytes, expected) in [
            (&b"callback-url\n"[..], "callback-url"),
            (&b"callback-url\r\n"[..], "callback-url"),
            (&b"callback-url"[..], "callback-url"),
        ] {
            let (reader, writer) = pipe_pair();
            let waiter = NativeManualCallbackInput::new(reader).expect("input owner");
            let mut writer = File::from(writer);
            writer.write_all(bytes).expect("write input");
            drop(writer);
            let result = waiter
                .wait_one(&context(
                    Duration::from_secs(2),
                    Arc::new(TestCancel::default()),
                ))
                .expect("one bounded line");
            assert!(matches!(&result, RawCallbackInput::ManualUrl(value) if value == expected));
            assert!(!format!("{result:?}").contains(expected));
        }
    }

    #[test]
    fn fragmented_socket_input_is_read_as_one_crlf_line() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::fragmented_socket_input_is_read_as_one_crlf_line"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, writer) = socket_pair();
        let waiter = NativeManualCallbackInput::new(reader).expect("input owner");
        let mut writer = File::from(writer);
        writer.write_all(b"callback-").expect("first fragment");
        let input = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            writer.write_all(b"url\r\n").expect("second fragment");
            unsafe { libc::shutdown(writer.as_raw_fd(), libc::SHUT_WR) };
        });
        let result = waiter
            .wait_one(&context(
                Duration::from_secs(2),
                Arc::new(TestCancel::default()),
            ))
            .expect("fragmented socket line");
        input.join().expect("socket writer");
        assert!(matches!(result, RawCallbackInput::ManualUrl(value) if value == "callback-url"));
    }

    #[test]
    fn rejects_empty_invalid_utf8_controls_and_trailing_bytes_without_reflection() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::rejects_empty_invalid_utf8_controls_and_trailing_bytes_without_reflection"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let payloads: &[&[u8]] = &[
            b"\n",
            b"",
            b"\xff\n",
            b"prefix\0suffix\n",
            b"prefix\x7fsuffix\n",
            b"prefix\xc2\x85suffix\n",
            b"line\nsecond-line",
        ];
        for payload in payloads {
            let (error, raw_fd) = error_for(payload);
            assert_eq!(error.code(), "invalid_intent");
            assert!(!error.to_string().contains("prefix"));
            assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        }
    }

    #[test]
    fn enforces_the_8192_byte_limit_including_a_delimiter() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::enforces_the_8192_byte_limit_including_a_delimiter"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let mut exact_limit = vec![b'a'; MAX_INPUT_BYTES - 1];
        exact_limit.push(b'\n');
        let (reader, writer) = pipe_pair();
        let waiter = NativeManualCallbackInput::new(reader).expect("input owner");
        let mut writer = File::from(writer);
        writer.write_all(&exact_limit).expect("write exact limit");
        drop(writer);
        let result = waiter
            .wait_one(&context(
                Duration::from_secs(2),
                Arc::new(TestCancel::default()),
            ))
            .expect("exact bounded line");
        assert!(
            matches!(result, RawCallbackInput::ManualUrl(value) if value.len() == MAX_INPUT_BYTES - 1)
        );

        let oversized = vec![b'Q'; MAX_INPUT_BYTES + 1];
        let (error, _) = error_for(&oversized);
        assert_eq!(error.code(), "invalid_intent");
        assert!(!error.to_string().contains('Q'));
    }

    #[test]
    fn owned_descriptor_is_cloexec_one_shot_and_restores_shared_status_flags() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::owned_descriptor_is_cloexec_one_shot_and_restores_shared_status_flags"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let observer = duplicate(raw_fd);
        let original_flags = unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) };
        assert!(original_flags >= 0);
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_SETFD, 0) }, 0);
        let waiter = Arc::new(NativeManualCallbackInput::new(reader).expect("input owner"));
        let cloexec = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert_ne!(cloexec & libc::FD_CLOEXEC, 0);
        let waiting = Arc::clone(&waiter);
        let cancel = Arc::new(TestCancel::default());
        let wait_context = context(Duration::from_secs(2), Arc::clone(&cancel));
        let thread = thread::spawn(move || waiting.wait_one(&wait_context));

        wait_for_nonblocking(observer.as_raw_fd(), original_flags);
        let replay = waiter
            .wait_one(&context(Duration::from_secs(2), Arc::clone(&cancel)))
            .expect_err("second wait must fail closed");
        assert!(!replay.to_string().contains("callback-url"));
        cancel.0.store(true, Ordering::Release);
        assert!(matches!(
            thread.join().expect("first wait"),
            Err(OAuthError::Cancelled)
        ));
        drop(writer);
        assert_eq!(
            unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
    }

    #[test]
    fn cancellation_and_deadline_terminate_without_input_and_close_the_fd() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::cancellation_and_deadline_terminate_without_input_and_close_the_fd"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let waiter = NativeManualCallbackInput::new(reader).expect("input owner");
        let cancel = Arc::new(TestCancel::default());
        let cancelled = context(Duration::from_secs(2), Arc::clone(&cancel));
        let waiting = thread::spawn(move || waiter.wait_one(&cancelled));
        thread::sleep(Duration::from_millis(30));
        cancel.0.store(true, Ordering::Release);
        assert!(matches!(
            waiting.join().expect("cancel wait"),
            Err(OAuthError::Cancelled)
        ));
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        drop(writer);

        let (reader, writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let waiter = NativeManualCallbackInput::new(reader).expect("input owner");
        let deadline = context(Duration::from_millis(35), Arc::new(TestCancel::default()));
        assert!(matches!(
            waiter.wait_one(&deadline),
            Err(OAuthError::DeadlineExceeded)
        ));
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        drop(writer);
    }

    #[test]
    fn poisoned_owner_lock_still_consumes_the_descriptor() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::poisoned_owner_lock_still_consumes_the_descriptor"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (reader, writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let waiter = Arc::new(NativeManualCallbackInput::new(reader).expect("input owner"));
        let poisoner = Arc::clone(&waiter);
        let _ = thread::spawn(move || {
            let _guard = poisoner.input.lock().expect("fresh owner lock");
            panic!("poison fixture");
        })
        .join();
        let mut writer = File::from(writer);
        writer
            .write_all(b"poisoned-owner\n")
            .expect("write fixture");
        drop(writer);
        let result = waiter
            .wait_one(&context(
                Duration::from_secs(2),
                Arc::new(TestCancel::default()),
            ))
            .expect("poison recovery preserves owned resource handling");
        assert!(matches!(result, RawCallbackInput::ManualUrl(value) if value == "poisoned-owner"));
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
    }

    #[test]
    fn cancellation_restores_tty_echo_and_flags_without_echoing_input() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::cancellation_restores_tty_echo_and_flags_without_echoing_input"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (master, slave) = pty_pair();
        let raw_fd = slave.as_raw_fd();
        let observer = duplicate(raw_fd);
        let original_flags = unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) };
        let mut original_termios = get_termios(observer.as_raw_fd());
        original_termios.c_lflag |= libc::ECHO | libc::ECHONL;
        assert_eq!(
            unsafe { libc::tcsetattr(observer.as_raw_fd(), libc::TCSANOW, &original_termios) },
            0
        );
        let original_termios = get_termios(observer.as_raw_fd());
        let waiter = Arc::new(NativeManualCallbackInput::new(slave).expect("input owner"));
        let cancel = Arc::new(TestCancel::default());
        let waiting = Arc::clone(&waiter);
        let wait_cancel = Arc::clone(&cancel);
        let thread =
            thread::spawn(move || waiting.wait_one(&context(Duration::from_secs(2), wait_cancel)));
        wait_for_nonblocking(observer.as_raw_fd(), original_flags);
        let hidden = get_termios(observer.as_raw_fd());
        assert_eq!(hidden.c_lflag & (libc::ECHO | libc::ECHONL), 0);
        cancel.0.store(true, Ordering::Release);
        assert!(matches!(
            thread.join().expect("tty cancel"),
            Err(OAuthError::Cancelled)
        ));
        assert_eq!(
            unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_termios_equal(&original_termios, &get_termios(observer.as_raw_fd()));
        drop(master);
    }

    #[test]
    fn restores_tty_state_during_unwind_after_io_setup() {
        if run_resource_test_child(
            concat!(
                "auth::native_callback::manual_input::tests",
                "::restores_tty_state_during_unwind_after_io_setup"
            ),
            ExpectedChildResult::Pass,
        ) {
            return;
        }
        let (master, slave) = pty_pair();
        let raw_fd = slave.as_raw_fd();
        let observer = duplicate(raw_fd);
        let original_flags = unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) };
        let mut original_termios = get_termios(observer.as_raw_fd());
        original_termios.c_lflag |= libc::ECHO | libc::ECHONL;
        assert_eq!(
            unsafe { libc::tcsetattr(observer.as_raw_fd(), libc::TCSANOW, &original_termios) },
            0
        );
        let original_termios = get_termios(observer.as_raw_fd());
        let waiter = NativeManualCallbackInput::new(slave).expect("input owner");
        let context = OAuthIoContext::new(
            Instant::now() + Duration::from_secs(2),
            Arc::new(PanicSecondClock(AtomicUsize::new(0))),
            Arc::new(TestCancel::default()),
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = waiter.wait_one(&context);
        }));
        assert!(result.is_err());
        assert_eq!(
            unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_termios_equal(&original_termios, &get_termios(observer.as_raw_fd()));
        drop(master);
    }
}
