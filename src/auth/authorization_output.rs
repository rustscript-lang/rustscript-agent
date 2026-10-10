//! Linux bounded native authorization-instruction output and queue worker.
//!
//! This module is the minimum OS-level mechanism between the accepted AA
//! bounded `PublicAuthorizationInstruction` queue and a native output sink. It
//! makes no business decision: it does not choose a provider, mode, retry,
//! fallback, polling policy, token-save decision or login outcome, and it never
//! accepts a raw guest string or descriptor.
//!
//! ## Descriptor discipline
//!
//! A native caller hands over one explicitly owned descriptor (or selects
//! stderr, which is duplicated first). Construction classifies the target and
//! reopens it through `/proc/self/fd/<n>` with `O_WRONLY|O_NONBLOCK|O_CLOEXEC`,
//! producing a *separate* open file description. The original descriptor's
//! `F_GETFL` status flags and `F_GETFD` descriptor flags are only ever read,
//! never changed. Only FIFOs/pipes and real ttys/PTYs are accepted; regular
//! files, sockets and any other target fail closed. Construction failure closes
//! every acquired descriptor, because each one is owned by an RAII wrapper.
//!
//! ## Write discipline
//!
//! Writes are nonblocking on the independent description, bounded by an
//! [`OAuthIoContext`] check before and after every wait and write, with finite
//! poll slices. For FIFO targets the rendered record is bounded by the actual
//! `_PC_PIPE_BUF`, one `write` is issued per attempt, and a full pipe is retried
//! with the whole record so a record is delivered all-or-none and no partial
//! record survives cancellation or deadline. For tty targets a partial write is
//! possible; the record is finished when the context allows and an honest
//! failure is reported otherwise, without any pipe-atomicity claim. Writes from
//! one sink are serialized under a cancellable lock; no cross-sink or
//! cross-process atomicity is claimed.
//!
//! ## Peer close
//!
//! `SIGPIPE` is blocked with a *thread-local* mask around each write. The
//! caller's original mask and pending state are preserved; only an EPIPE from
//! this sink's own write may be drained, and only when SIGPIPE was previously
//! unblocked and not already pending. No process-global disposition or handler
//! is mutated, so a peer close becomes an ordinary sanitized write failure.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::auth::host::{PublicAuthorizationInstruction, RunOAuthCancel, SystemOAuthClock};
use crate::auth::oauth::{OAuthCancel, OAuthError, OAuthIoContext};
use crate::runtime::RunCancellation;

/// Maximum rendered public record: one bounded native line pair.
const MAX_RENDERED_BYTES: usize = 4096;
/// Finite poll slice; every wait is also bounded by the caller's remaining time.
const POLL_SLICE: Duration = Duration::from_millis(10);

/// Query keys that never belong in a public authorization URL. `state` and
/// `code_challenge` are public authorization fields and are deliberately absent.
const SECRET_QUERY_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "device_code",
    "device_id",
    "device_auth_id",
    "authorization_code",
    "code",
    "code_verifier",
    "api_key",
    "token",
    "secret",
];

/// The admitted native target class of an output descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetKind {
    /// A pipe or FIFO: a record up to `PIPE_BUF` may be written atomically.
    Pipe,
    /// A tty or PTY: partial writes are possible and are not atomic.
    Tty,
}

impl TargetKind {
    fn label(self) -> &'static str {
        match self {
            Self::Pipe => "pipe",
            Self::Tty => "tty",
        }
    }
}

fn transport_failure() -> OAuthError {
    OAuthError::Transport {
        message: "native authorization output failed".to_owned(),
    }
}

/// Build a bounded native I/O context from the exact supplied child deadline.
///
/// The context uses the caller's deadline as-is with the production system
/// clock and the supplied cancellation view. It creates no new timeout budget
/// and does not arm or disarm any runtime watcher; a missing, overflowing or
/// already-elapsed deadline fails closed.
pub fn native_authorization_io_context(
    cancellation: &RunCancellation,
) -> Result<OAuthIoContext, OAuthError> {
    let deadline = cancellation
        .deadline_instant()
        .ok_or_else(transport_failure)?;
    if cancellation.has_deadline_overflow() || deadline <= Instant::now() {
        return Err(transport_failure());
    }
    Ok(OAuthIoContext::new(
        deadline,
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ))
}

/// A bounded native sink for public authorization instructions.
///
/// The sink owns an independent nonblocking close-on-exec description of an
/// admitted pipe/FIFO or tty/PTY. It never mutates the original descriptor it
/// was built from.
pub struct NativeAuthorizationInstructionOutput {
    fd: OwnedFd,
    kind: TargetKind,
    pipe_buf: usize,
    serialization: Mutex<()>,
}

impl std::fmt::Debug for NativeAuthorizationInstructionOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthorizationInstructionOutput")
            .field("kind", &self.kind.label())
            .field("fd", &"<redacted>")
            .finish()
    }
}

impl NativeAuthorizationInstructionOutput {
    /// Take ownership of one explicitly selected native descriptor.
    ///
    /// The descriptor is classified and reopened into a separate description;
    /// the original's flags are preserved. Unsupported target types fail closed
    /// and every acquired descriptor is dropped.
    pub fn from_fd(fd: OwnedFd) -> Result<Self, OAuthError> {
        let original = fd.as_raw_fd();
        let (kind, dev, ino) = classify_target(original)?;
        let reopened = reopen_independent(original)?;
        let (reopened_kind, reopened_dev, reopened_ino) = classify_target(reopened.as_raw_fd())?;
        if reopened_kind != kind || reopened_dev != dev || reopened_ino != ino {
            // The reopened description is not the same object we classified.
            return Err(transport_failure());
        }
        let pipe_buf = if kind == TargetKind::Pipe {
            pipe_buffer_size(reopened.as_raw_fd())?
        } else {
            MAX_RENDERED_BYTES
        };
        if pipe_buf == 0 {
            return Err(transport_failure());
        }
        drop(fd);
        Ok(Self {
            fd: reopened,
            kind,
            pipe_buf,
            serialization: Mutex::new(()),
        })
    }

    /// Duplicate stderr as a close-on-exec descriptor and reopen it.
    ///
    /// The process stderr descriptor keeps its own flags; only the duplicate is
    /// classified and reopened. A redirected regular-file stderr fails closed.
    pub fn stderr() -> Result<Self, OAuthError> {
        // SAFETY: F_DUPFD_CLOEXEC duplicates the process-owned stderr descriptor.
        let duplicated = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(transport_failure());
        }
        // SAFETY: fcntl returned a newly owned descriptor.
        let duplicated = unsafe { OwnedFd::from_raw_fd(duplicated) };
        Self::from_fd(duplicated)
    }

    /// The admitted native target class, e.g. `"pipe"` or `"tty"`.
    pub fn target_label(&self) -> &'static str {
        self.kind.label()
    }

    /// Render and write one bounded public authorization record.
    ///
    /// A rejected or oversize instruction produces no output at all. The
    /// context is checked before and after every wait and write.
    pub fn emit(
        &self,
        instruction: &PublicAuthorizationInstruction,
        context: &OAuthIoContext,
    ) -> Result<(), OAuthError> {
        context.check()?;
        let record = render_record(instruction)?;
        if record.len() > self.pipe_buf {
            // Downstream oversize must fail safely, never truncate or claim delivery.
            return Err(transport_failure());
        }
        let _serialization = self.acquire(context)?;
        context.check()?;
        self.write_record(&record, context)
    }

    fn acquire(&self, context: &OAuthIoContext) -> Result<MutexGuard<'_, ()>, OAuthError> {
        loop {
            context.check()?;
            match self.serialization.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {
                    let remaining = context.remaining()?;
                    thread::sleep(remaining.min(POLL_SLICE));
                }
            }
        }
    }

    fn write_record(&self, record: &[u8], context: &OAuthIoContext) -> Result<(), OAuthError> {
        let fd = self.fd.as_raw_fd();
        let mut sigpipe = SigpipeGuard::block()?;
        match self.kind {
            TargetKind::Pipe => write_pipe_atomic(fd, record, context, &mut sigpipe),
            TargetKind::Tty => write_tty_bounded(fd, record, context, &mut sigpipe),
        }
    }
}

/// Render the bounded native public record from public authorization fields.
///
/// Only a native [`PublicAuthorizationInstruction`] is accepted. Authorization
/// `state` and `code_challenge` are permitted public authorization fields
/// carried by the URL; credential-secret query keys, userinfo, control
/// characters and non-HTTPS authorities are rejected.
fn render_record(instruction: &PublicAuthorizationInstruction) -> Result<Vec<u8>, OAuthError> {
    if !valid_authorization_url(&instruction.authorization_url)
        || !valid_redirect_uri(&instruction.redirect_uri)
    {
        return Err(transport_failure());
    }
    let record = format!(
        "Open {}\nRedirect: {}\n",
        instruction.authorization_url, instruction.redirect_uri
    );
    if record.len() > MAX_RENDERED_BYTES {
        return Err(transport_failure());
    }
    Ok(record.into_bytes())
}

fn valid_authorization_url(url: &str) -> bool {
    if url.is_empty() || url.len() > MAX_RENDERED_BYTES || url.chars().any(char::is_control) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    if parsed.query().is_some_and(|query| query.ends_with('&')) {
        return false;
    }
    !parsed.query_pairs().any(|(name, _)| {
        SECRET_QUERY_KEYS
            .iter()
            .any(|secret| name.eq_ignore_ascii_case(secret))
    })
}

fn valid_redirect_uri(uri: &str) -> bool {
    if uri.is_empty() || uri.len() > 2048 || uri.chars().any(char::is_control) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return false;
    }
    match parsed.scheme() {
        "https" => parsed.host().is_some(),
        "http" => {
            let loopback = parsed.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
            loopback && parsed.port().is_some()
        }
        _ => false,
    }
}

/// Classify an admitted target by type, returning `(kind, dev, ino)`.
///
/// The descriptor's own flags are only read here.
fn classify_target(fd: RawFd) -> Result<(TargetKind, u64, u64), OAuthError> {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `status` is a valid out-parameter for fstat on this descriptor.
    if unsafe { libc::fstat(fd, &mut status) } != 0 {
        return Err(transport_failure());
    }
    let file_type = (status.st_mode as libc::mode_t) & libc::S_IFMT;
    let kind = match file_type {
        libc::S_IFIFO => TargetKind::Pipe,
        libc::S_IFCHR => {
            // A character device is admitted only when it is a real terminal.
            // SAFETY: isatty only inspects the descriptor.
            if unsafe { libc::isatty(fd) } == 1 {
                TargetKind::Tty
            } else {
                return Err(transport_failure());
            }
        }
        _ => return Err(transport_failure()),
    };
    Ok((kind, status.st_dev as u64, status.st_ino as u64))
}

/// Reopen a descriptor through `/proc/self/fd` as an independent description.
fn reopen_independent(fd: RawFd) -> Result<OwnedFd, OAuthError> {
    let Ok(path) = std::ffi::CString::new(format!("/proc/self/fd/{fd}")) else {
        return Err(transport_failure());
    };
    // SAFETY: `path` is a valid NUL-terminated string; the returned descriptor
    // is newly owned on success.
    let reopened = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if reopened < 0 {
        return Err(transport_failure());
    }
    // SAFETY: open returned a newly owned descriptor.
    let reopened = unsafe { OwnedFd::from_raw_fd(reopened) };
    if !independent_flags_ready(reopened.as_raw_fd()) {
        return Err(transport_failure());
    }
    Ok(reopened)
}

/// Confirm the reopened description is nonblocking and close-on-exec.
fn independent_flags_ready(fd: RawFd) -> bool {
    // SAFETY: fcntl reads status flags from the reopened descriptor.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status < 0 || status & libc::O_NONBLOCK == 0 {
        return false;
    }
    // SAFETY: fcntl reads descriptor flags from the reopened descriptor.
    let descriptor = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    descriptor >= 0 && descriptor & libc::FD_CLOEXEC != 0
}

/// The actual `PIPE_BUF` of the reopened descriptor.
fn pipe_buffer_size(fd: RawFd) -> Result<usize, OAuthError> {
    // SAFETY: fpathconf only reads a bound from the descriptor.
    let value = unsafe { libc::fpathconf(fd, libc::_PC_PIPE_BUF) };
    if value <= 0 {
        return Err(transport_failure());
    }
    Ok(value as usize)
}

/// Write a whole record to a pipe in one atomic, non-partial step.
fn write_pipe_atomic(
    fd: RawFd,
    record: &[u8],
    context: &OAuthIoContext,
    sigpipe: &mut SigpipeGuard,
) -> Result<(), OAuthError> {
    loop {
        context.check()?;
        // SAFETY: `record` is readable for its length and the descriptor is a
        // nonblocking pipe writer.
        let written = unsafe { libc::write(fd, record.as_ptr().cast(), record.len()) };
        let write_error = if written < 0 {
            // Preserve errno before context or signal helpers can overwrite it.
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPIPE) {
                sigpipe.record_epipe();
            }
            Some(error)
        } else {
            None
        };
        // A successful final write is still subject to this same context.
        context.check()?;
        if written == record.len() as isize {
            return Ok(());
        }
        if written == 0 {
            return Err(transport_failure());
        }
        if written > 0 {
            // A record within PIPE_BUF must not be split; treat this as failure.
            return Err(transport_failure());
        }
        match write_error.and_then(|error| error.raw_os_error()) {
            Some(libc::EINTR) => continue,
            Some(errno) if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK => {
                wait_writable(fd, context)?;
            }
            // Peer close (EPIPE) or any other error is a sanitized failure.
            _ => return Err(transport_failure()),
        }
    }
}

/// Write a whole record to a tty, finishing bounded progress when possible.
fn write_tty_bounded(
    fd: RawFd,
    record: &[u8],
    context: &OAuthIoContext,
    sigpipe: &mut SigpipeGuard,
) -> Result<(), OAuthError> {
    let mut written = 0;
    while written < record.len() {
        context.check()?;
        // SAFETY: the remaining slice is readable for the supplied byte count
        // and the descriptor is a nonblocking tty writer.
        let count = unsafe {
            libc::write(
                fd,
                record[written..].as_ptr().cast(),
                record.len() - written,
            )
        };
        let write_error = if count < 0 {
            // Preserve errno before context or signal helpers can overwrite it.
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPIPE) {
                sigpipe.record_epipe();
            }
            Some(error)
        } else {
            None
        };
        // Positive progress may already be visible; report cancellation honestly.
        context.check()?;
        if count > 0 {
            written += count as usize;
            continue;
        }
        if count == 0 {
            return Err(transport_failure());
        }
        match write_error.and_then(|error| error.raw_os_error()) {
            Some(libc::EINTR) => continue,
            Some(errno) if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK => {
                wait_writable(fd, context)?;
            }
            _ => return Err(transport_failure()),
        }
    }
    context.check()?;
    Ok(())
}

/// Wait for writability in finite slices, honoring the context each time.
fn wait_writable(fd: RawFd, context: &OAuthIoContext) -> Result<(), OAuthError> {
    loop {
        context.check()?;
        let remaining = context.remaining()?;
        let timeout_ms = remaining.as_millis().clamp(1, POLL_SLICE.as_millis()) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `descriptor` is a valid single pollfd with a finite timeout.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready > 0 {
            if descriptor.revents & libc::POLLOUT != 0 {
                return Ok(());
            }
            // POLLERR / POLLHUP / POLLNVAL: the peer is gone or unusable.
            return Err(transport_failure());
        }
        if ready == 0 {
            context.check()?;
            continue;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            context.check()?;
            continue;
        }
        return Err(transport_failure());
    }
}

/// A thread-local `SIGPIPE` block that only drains this sink's unmasked EPIPE.
struct SigpipeGuard {
    set: libc::sigset_t,
    previous: libc::sigset_t,
    previously_blocked: bool,
    pending_before_write: bool,
    wrote_epipe: bool,
}

impl SigpipeGuard {
    fn block() -> Result<Self, OAuthError> {
        // SAFETY: all sigset operations use valid zeroed stack storage.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut previous: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut set) != 0 || libc::sigaddset(&mut set, libc::SIGPIPE) != 0 {
                return Err(transport_failure());
            }
            // Only this thread's mask changes; no process-global state is touched.
            if libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous) != 0 {
                return Err(transport_failure());
            }

            let mut pending: libc::sigset_t = std::mem::zeroed();
            if libc::sigpending(&mut pending) != 0 {
                let _ = libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                return Err(transport_failure());
            }
            let pending_member = libc::sigismember(&pending, libc::SIGPIPE);
            let blocked_member = libc::sigismember(&previous, libc::SIGPIPE);
            if pending_member < 0 || blocked_member < 0 {
                let _ = libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                return Err(transport_failure());
            }
            Ok(Self {
                set,
                previous,
                previously_blocked: blocked_member == 1,
                pending_before_write: pending_member == 1,
                wrote_epipe: false,
            })
        }
    }

    fn record_epipe(&mut self) {
        self.wrote_epipe = true;
    }
}

impl Drop for SigpipeGuard {
    fn drop(&mut self) {
        // SAFETY: `set`/`previous` were produced by the calls in `block`.
        unsafe {
            if self.wrote_epipe && !self.previously_blocked && !self.pending_before_write {
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                // Drain at most the one standard signal generated by our EPIPE.
                let _ = libc::sigtimedwait(&self.set, std::ptr::null_mut(), &timeout);
            }
            let _ = libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

/// Private worker stop flag, combined with the supplied child cancellation.
struct WorkerStop {
    stopped: AtomicBool,
}

impl WorkerStop {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
        }
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}

impl OAuthCancel for WorkerStop {
    fn is_cancelled(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// A bounded queue worker consuming public authorization instructions.
///
/// The worker owns exactly one thread. It requires the *same* invocation child
/// [`RunCancellation`] supplied by the caller with a finite deadline; it builds
/// its context from that exact deadline with [`SystemOAuthClock`] and
/// [`RunOAuthCancel`], then combines the private worker stop through
/// `with_additional_cancel`, preserving the deadline and clock. It creates no
/// new timeout budget and never arms or disarms a runtime watcher.
///
/// The consumer only uses bounded `try_recv` plus finite poll slices, captures
/// the first output error, and never performs an unbounded receive, write, lock
/// or thread join. `finish`/`Drop` stop and join the thread on every terminal
/// path; a pending or aborted record is never reported as delivered. An idle
/// orderly stop is distinct from a queued/pending output error.
pub struct NativeAuthorizationInstructionWorker {
    stop: Arc<WorkerStop>,
    drain_requested: Arc<AtomicBool>,
    error: Arc<Mutex<Option<OAuthError>>>,
    handle: Option<JoinHandle<()>>,
    original_context: OAuthIoContext,
    /// Exact Linux thread id observed by the worker while running; `-1` before
    /// it runs, cleared by the worker on exit. Used to prove the thread was
    /// joined rather than detached.
    thread_id: Arc<AtomicI64>,
}

impl std::fmt::Debug for NativeAuthorizationInstructionWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthorizationInstructionWorker")
            .field("context", &"<redacted>")
            .field("joined", &self.handle.is_none())
            .finish()
    }
}

impl NativeAuthorizationInstructionWorker {
    /// Start one owned worker on the supplied bounded queue.
    ///
    /// Fails closed unless the supplied child cancellation carries a finite,
    /// still-future deadline. The supplied cancellation is observed exactly as
    /// given; no timeout is created or extended here.
    pub fn start(
        output: Arc<NativeAuthorizationInstructionOutput>,
        receiver: Receiver<PublicAuthorizationInstruction>,
        cancellation: RunCancellation,
    ) -> Result<Self, OAuthError> {
        let context = native_authorization_io_context(&cancellation)?;
        let stop = Arc::new(WorkerStop::new());
        let drain_requested = Arc::new(AtomicBool::new(false));
        let combined = context.with_additional_cancel(Arc::clone(&stop) as Arc<dyn OAuthCancel>);
        let error = Arc::new(Mutex::new(None));
        let thread_id = Arc::new(AtomicI64::new(-1));
        let worker_error = Arc::clone(&error);
        let worker_stop = Arc::clone(&stop);
        let worker_drain_requested = Arc::clone(&drain_requested);
        let worker_thread_id = Arc::clone(&thread_id);
        let worker_context = combined.clone();
        let handle = thread::Builder::new()
            .name("authzoutworker".to_owned())
            .spawn(move || {
                run_worker(
                    output,
                    receiver,
                    worker_context,
                    worker_stop,
                    worker_drain_requested,
                    worker_error,
                    worker_thread_id,
                );
            })
            .map_err(|_| transport_failure())?;
        Ok(Self {
            stop,
            drain_requested,
            error,
            handle: Some(handle),
            original_context: context,
            thread_id,
        })
    }

    /// The exact deadline this worker observes (from the supplied child).
    pub fn deadline(&self) -> Instant {
        self.original_context.deadline()
    }

    /// The first captured output error, if any.
    pub fn error(&self) -> Option<OAuthError> {
        self.error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Whether the worker still owns its thread.
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }

    /// The exact observed worker thread id, if the worker is currently running.
    ///
    /// Returns `None` once the worker has exited or been joined.
    pub fn thread_id(&self) -> Option<i64> {
        // SAFETY: SYS_gettid reads the calling thread's id.
        let self_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i64;
        match self.thread_id.load(Ordering::Acquire) {
            -1 => None,
            tid if tid == self_tid => None,
            tid => Some(tid),
        }
    }

    /// Stop and join the worker, returning the first captured output error.
    ///
    /// An idle orderly stop returns `Ok(())`. A join failure is a sanitized
    /// failure; a pending record is never reported as delivered.
    pub fn finish(mut self) -> Result<(), OAuthError> {
        self.join();
        match self.error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Drain every queued record under the original child context, then join.
    ///
    /// Unlike `finish`, this does not cancel the worker before consuming the
    /// queue. A write or context failure is returned and a pending record is
    /// never reported as delivered.
    pub fn finish_draining(mut self) -> Result<(), OAuthError> {
        self.drain_requested.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take()
            && handle.join().is_err()
        {
            record_error(&self.error, transport_failure());
        }
        if let Err(failure) = self.original_context.remaining() {
            record_error(&self.error, failure);
        }
        self.stop.stop();
        match self.error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn join(&mut self) {
        self.stop.stop();
        if let Some(handle) = self.handle.take()
            && handle.join().is_err()
        {
            record_error(&self.error, transport_failure());
        }
    }
}

impl Drop for NativeAuthorizationInstructionWorker {
    fn drop(&mut self) {
        self.join();
    }
}

fn run_worker(
    output: Arc<NativeAuthorizationInstructionOutput>,
    receiver: Receiver<PublicAuthorizationInstruction>,
    context: OAuthIoContext,
    stop: Arc<WorkerStop>,
    drain_requested: Arc<AtomicBool>,
    error: Arc<Mutex<Option<OAuthError>>>,
    thread_id: Arc<AtomicI64>,
) {
    // SAFETY: SYS_gettid reads this worker thread's id.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i64;
    thread_id.store(tid, Ordering::Release);
    loop {
        if stop.is_cancelled() {
            break;
        }
        match receiver.try_recv() {
            Ok(instruction) => {
                if let Err(failure) = output.emit(&instruction, &context) {
                    record_error(&error, failure);
                    break;
                }
            }
            Err(TryRecvError::Empty) => {
                if drain_requested.load(Ordering::Acquire) {
                    break;
                }
                // Idle: bounded slice, honoring the exact supplied context.
                match context.remaining() {
                    Ok(remaining) => thread::sleep(remaining.min(POLL_SLICE)),
                    Err(failure) => {
                        if drain_requested.load(Ordering::Acquire) {
                            record_error(&error, failure);
                        }
                        break;
                    }
                }
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }
    // Clear the observed id so a joined worker is distinguishable from a live one.
    thread_id.store(-1, Ordering::Release);
}

fn record_error(slot: &Mutex<Option<OAuthError>>, failure: OAuthError) {
    let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(failure);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instruction() -> PublicAuthorizationInstruction {
        PublicAuthorizationInstruction {
            authorization_url:
                "https://auth.example.test/oauth/authorize?response_type=code&client_id=public-client&state=public-state&code_challenge=public-challenge"
                    .to_owned(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_owned(),
        }
    }

    fn context_for(deadline: Instant) -> OAuthIoContext {
        OAuthIoContext::new(
            deadline,
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(RunCancellation::with_deadline(
                deadline,
            ))),
        )
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has space for the two pipe descriptors.
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: pipe2 returned two newly owned descriptors.
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn pipe_nonblocking() -> (OwnedFd, OwnedFd) {
        let (read_fd, write_fd) = pipe();
        // SAFETY: fcntl makes the writer nonblocking so a full pipe returns EAGAIN.
        let flags = unsafe { libc::fcntl(write_fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    write_fd.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            },
            0
        );
        (read_fd, write_fd)
    }

    fn fill_pipe(fd: RawFd) {
        let block = [b'x'; 4096];
        loop {
            // SAFETY: block is a valid buffer and fd is a nonblocking pipe writer.
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

    /// Drain a read descriptor after switching it to nonblocking.
    fn drain(fd: RawFd) -> Vec<u8> {
        // SAFETY: fcntl reads and updates status flags on a valid descriptor.
        let original = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(original >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, original | libc::O_NONBLOCK) },
            0
        );
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
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

    #[test]
    fn pipe_record_roundtrips_and_preserves_original_flags() {
        let (read_fd, write_fd) = pipe();
        // Capture the original writer flags before construction.
        let original_writer = status_flags(write_fd.as_raw_fd());
        let reader_flags = status_flags(read_fd.as_raw_fd());
        let output = NativeAuthorizationInstructionOutput::from_fd(write_fd)
            .expect("admitted pipe descriptor");
        assert_eq!(output.target_label(), "pipe");
        output
            .emit(
                &instruction(),
                &context_for(Instant::now() + Duration::from_secs(1)),
            )
            .expect("pipe record delivered");
        // The independent reader was never touched by the sink.
        assert_eq!(status_flags(read_fd.as_raw_fd()), reader_flags);
        assert_eq!(original_writer & libc::O_NONBLOCK, 0);
        let bytes = drain(read_fd.as_raw_fd());
        assert_eq!(
            bytes,
            b"Open https://auth.example.test/oauth/authorize?response_type=code&client_id=public-client&state=public-state&code_challenge=public-challenge\nRedirect: http://127.0.0.1:49152/callback\n"
        );
        assert_eq!(output.target_label(), "pipe");
    }

    /// A real pipe-readability cancellation view; no counter or injected phase.
    struct PipeReadableCancel {
        reader: OwnedFd,
    }

    impl OAuthCancel for PipeReadableCancel {
        fn is_cancelled(&self) -> bool {
            let mut available: libc::c_int = 0;
            // SAFETY: FIONREAD reads the byte count into valid storage; reader is owned.
            (unsafe { libc::ioctl(self.reader.as_raw_fd(), libc::FIONREAD, &mut available) } == 0)
                && available > 0
        }
    }

    #[test]
    fn successful_pipe_write_observes_os_readable_additional_cancellation() {
        let (reader, writer) = pipe();
        let reader_fd = reader.as_raw_fd();
        let output = NativeAuthorizationInstructionOutput::from_fd(writer)
            .expect("admitted pipe descriptor");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let base_context = native_authorization_io_context(&cancellation)
            .expect("exact finite child-deadline context");
        let readable = Arc::new(PipeReadableCancel { reader });
        assert!(!readable.is_cancelled(), "the real pipe begins empty");
        let cancel_view: Arc<dyn OAuthCancel> = readable.clone();
        let context = base_context.with_additional_cancel(cancel_view);
        assert!(context.check().is_ok(), "empty pipe is not cancelled");

        let result = output.emit(&instruction(), &context);
        assert!(matches!(result, Err(OAuthError::Cancelled)), "{result:?}");
        assert!(
            readable.is_cancelled(),
            "the native write must make the actual OS pipe readable"
        );
        // Cancellation wins after visible bytes; it must not pretend they were absent.
        assert_eq!(
            drain(reader_fd),
            b"Open https://auth.example.test/oauth/authorize?response_type=code&client_id=public-client&state=public-state&code_challenge=public-challenge\nRedirect: http://127.0.0.1:49152/callback\n"
        );
    }

    #[test]
    fn worker_is_not_detached_and_idle_orderly_stop_is_ok() {
        let (read_fd, write_fd) = pipe();
        let output = Arc::new(
            NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("pipe descriptor"),
        );
        let (_sender, receiver) = crate::auth::host::authorization_instruction_channel();
        let deadline = Instant::now() + Duration::from_secs(3);
        let cancellation = RunCancellation::with_deadline(deadline);
        let worker =
            NativeAuthorizationInstructionWorker::start(output, receiver, cancellation.clone())
                .expect("finite-deadline worker");
        assert_eq!(worker.deadline(), deadline);
        assert!(worker.is_running());
        // The worker observes its own exact thread id while running.
        let observed = wait_for_thread_id(&worker);
        // SAFETY: SYS_gettid reads the test thread's id.
        let self_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i64;
        assert_ne!(observed, self_tid, "worker id is a distinct thread");
        // No instruction was queued: this is an idle orderly stop.
        assert!(worker.finish().is_ok());
        // A joined worker's thread is gone.
        assert!(!std::path::Path::new(&format!("/proc/self/task/{observed}")).exists());
        assert_eq!(status_flags(read_fd.as_raw_fd()) & libc::O_NONBLOCK, 0);
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
    fn worker_requires_finite_deadline() {
        let (read_fd, write_fd) = pipe();
        let output = Arc::new(
            NativeAuthorizationInstructionOutput::from_fd(write_fd).expect("pipe descriptor"),
        );
        let (_sender, receiver) = crate::auth::host::authorization_instruction_channel();
        let no_deadline = RunCancellation::new();
        assert!(
            NativeAuthorizationInstructionWorker::start(Arc::clone(&output), receiver, no_deadline)
                .is_err()
        );
        drop(read_fd);
        drop(output);
    }

    #[test]
    fn unsupported_regular_and_socket_targets_fail_closed() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let file = std::fs::File::open(&manifest).expect("readable regular manifest file");
        let owned: OwnedFd = file.into();
        assert!(NativeAuthorizationInstructionOutput::from_fd(owned).is_err());

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let stream = std::net::TcpStream::connect(listener.local_addr().expect("addr"))
            .expect("loopback connect");
        let (server, _) = listener.accept().expect("accept");
        let owned_stream: OwnedFd = stream.into();
        let owned_server: OwnedFd = server.into();
        assert!(NativeAuthorizationInstructionOutput::from_fd(owned_stream).is_err());
        assert!(NativeAuthorizationInstructionOutput::from_fd(owned_server).is_err());
    }

    #[test]
    fn credential_secret_fields_are_rejected_without_output() {
        let mut bad = instruction();
        bad.authorization_url =
            "https://auth.example.test/oauth/authorize?client_secret=leaked".to_owned();
        assert!(render_record(&bad).is_err());

        let mut userinfo = instruction();
        userinfo.authorization_url =
            "https://user:pass@auth.example.test/oauth/authorize".to_owned();
        assert!(render_record(&userinfo).is_err());

        let mut control = instruction();
        control.authorization_url = "https://auth.example.test/\n".to_owned();
        assert!(render_record(&control).is_err());

        let mut plain_http_authority = instruction();
        plain_http_authority.authorization_url =
            "http://auth.example.test/oauth/authorize".to_owned();
        assert!(render_record(&plain_http_authority).is_err());

        // The public fields required by the PKCE flow are permitted.
        let record = render_record(&instruction()).expect("public record");
        let text = String::from_utf8_lossy(&record);
        assert!(text.contains("state=public-state"));
        assert!(text.contains("code_challenge=public-challenge"));
    }

    #[test]
    fn debug_is_redacted_for_instruction() {
        assert_eq!(
            format!("{:?}", instruction()),
            "PublicAuthorizationInstruction { authorization_url: \"<redacted>\", redirect_uri: \"<redacted>\" }"
        );
    }

    #[test]
    fn tty_record_is_written_without_pipe_atomicity_claim() {
        let (master, slave) = pty();
        let output = NativeAuthorizationInstructionOutput::from_fd(slave)
            .expect("admitted pty slave descriptor");
        assert_eq!(output.target_label(), "tty");
        output
            .emit(
                &instruction(),
                &context_for(Instant::now() + Duration::from_secs(1)),
            )
            .expect("pty record delivered");
        let bytes = drain(master.as_raw_fd());
        assert!(String::from_utf8_lossy(&bytes).starts_with("Open https://"));
    }

    #[test]
    fn peer_close_becomes_sanitized_failure_without_process_signal() {
        let (read_fd, write_fd) = pipe();
        let output = NativeAuthorizationInstructionOutput::from_fd(write_fd)
            .expect("admitted pipe descriptor");
        // Close the only reader: the next write raises EPIPE/SIGPIPE.
        drop(read_fd);
        let result = output.emit(
            &instruction(),
            &context_for(Instant::now() + Duration::from_secs(1)),
        );
        assert!(matches!(result, Err(OAuthError::Transport { .. })));
        // Reaching this point proves the process was not killed by SIGPIPE.
        assert_eq!(std::process::id(), std::process::id());
    }

    #[test]
    fn deadline_cancellation_leaves_no_partial_pipe_record() {
        let (read_fd, write_fd) = pipe_nonblocking();
        // Fill the pipe through the shared nonblocking description so the sink's
        // independent reopened description also observes a full pipe.
        fill_pipe(write_fd.as_raw_fd());
        let output = NativeAuthorizationInstructionOutput::from_fd(write_fd)
            .expect("admitted full pipe descriptor");
        let started = Instant::now();
        let result = output.emit(
            &instruction(),
            &context_for(Instant::now() + Duration::from_millis(40)),
        );
        assert!(matches!(result, Err(OAuthError::DeadlineExceeded)));
        assert!(started.elapsed() < Duration::from_secs(1));
        // The reader holds only the filler; no partial record was appended.
        let bytes = drain(read_fd.as_raw_fd());
        assert!(!bytes.is_empty());
        assert!(bytes.iter().all(|byte| *byte == b'x'));
    }
}
