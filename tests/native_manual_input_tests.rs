#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_char;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustscript_agent::auth::native_callback::manual_input::NativeManualCallbackInput;
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, BoundedPublicOAuthIntent, BrowserOpener, CallbackMode, CallbackOutcome,
    OAuthCancel, OAuthClock, OAuthError, OAuthFlowKind, OAuthHost, OAuthIoContext,
    PreparedHttpsRequest, RawHttpsResponse, TrustedEndpoint, TrustedTransportPolicy,
};
use url::Url;

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

#[derive(Default)]
struct UnusedTransport(AtomicUsize);

impl BoundedHttpsTransport for UnusedTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        _context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Err(OAuthError::Transport {
            message: "unexpected transport use".to_owned(),
        })
    }
}

struct UnusedBrowser;

impl BrowserOpener for UnusedBrowser {
    fn open(&self, _url: &str, _context: &OAuthIoContext) -> Result<(), OAuthError> {
        Err(OAuthError::Transport {
            message: "unexpected browser use".to_owned(),
        })
    }
}

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(result, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn duplicate(fd: i32) -> OwnedFd {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    assert!(duplicate >= 0);
    unsafe { OwnedFd::from_raw_fd(duplicate) }
}

fn policy() -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: 1,
        run_id: "manual-input-fixture".to_owned(),
        deadline: Instant::now() + Duration::from_secs(10),
        endpoints: vec![TrustedEndpoint {
            authority: "login.example.invalid".to_owned(),
            path_prefix: "/oauth".to_owned(),
        }],
        allowed_header_names: BTreeSet::new(),
        transport_identity: None,
    }
}

fn intent() -> BoundedPublicOAuthIntent {
    BoundedPublicOAuthIntent {
        flow: OAuthFlowKind::AuthorizationCodePkce,
        callback_mode: CallbackMode::Manual,
        path: "/oauth/authorize".to_owned(),
        scopes: Vec::new(),
        public_query: BTreeMap::new(),
        credential_id: "manual-input-fixture".to_owned(),
    }
}

fn host(input: OwnedFd, cancel: Arc<TestCancel>) -> (OAuthHost, Arc<UnusedTransport>) {
    let transport = Arc::new(UnusedTransport::default());
    let host = OAuthHost::new(
        transport.clone(),
        Arc::new(NativeManualCallbackInput::new(input).expect("owned input descriptor")),
        Arc::new(UnusedBrowser),
        Arc::new(TestClock),
        cancel,
    );
    (host, transport)
}

fn callback_url(authorization_url: &str, redirect_uri: &str, state: &str) -> String {
    let authorization = Url::parse(authorization_url).expect("authorization URL");
    assert_eq!(authorization.scheme(), "https");
    let mut callback = Url::parse(redirect_uri).expect("redirect URI");
    callback.query_pairs_mut().append_pair("state", state);
    callback
        .query_pairs_mut()
        .append_pair("code", "opaque-code-fixture");
    callback.to_string()
}

fn state_from(authorization_url: &str) -> String {
    Url::parse(authorization_url)
        .expect("authorization URL")
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("actual generated state")
}

#[test]
fn real_pipe_manual_callback_uses_pkce_state_and_consumes_input_once() {
    let (read_end, write_end) = pipe_pair();
    let raw_fd = read_end.as_raw_fd();
    let observer = duplicate(raw_fd);
    let original_flags = unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) };
    assert!(original_flags >= 0);
    let fd_flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    assert!(fd_flags >= 0);

    let (host, transport) = host(read_end, Arc::new(TestCancel::default()));
    let policy = policy();
    let begun = host
        .pkce_begin(&policy, intent())
        .expect("existing PKCE begin");
    let state = state_from(&begun.authorization_url);
    let pasted = callback_url(&begun.authorization_url, &begun.redirect_uri, &state);
    let replay_handle = begun.callback_handle.clone();
    let callback_handle = begun.callback_handle;
    let callback_host = Arc::new(host);
    let waiting_host = Arc::clone(&callback_host);
    let waiting = thread::spawn(move || waiting_host.callback_wait(&callback_handle));

    let mut writer = std::fs::File::from(write_end);
    let pasted_bytes = pasted.as_bytes();
    for fragment in [
        &pasted_bytes[..pasted_bytes.len() / 2],
        &pasted_bytes[pasted_bytes.len() / 2..],
    ] {
        writer.write_all(fragment).expect("write callback fragment");
        thread::sleep(Duration::from_millis(10));
    }
    writer.write_all(b"\n").expect("write LF delimiter");
    drop(writer);

    let result = waiting
        .join()
        .expect("callback wait thread")
        .expect("callback accepted");
    assert_eq!(result.outcome, CallbackOutcome::Success);
    assert!(result.code_handle.is_some());
    let debug = format!("{result:?}");
    assert!(!debug.contains(&state));
    assert!(!debug.contains("opaque-code-fixture"));
    assert_eq!(transport.0.load(Ordering::Acquire), 0);
    assert_eq!(
        unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
        original_flags
    );
    assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);

    let replay = callback_host
        .callback_wait(&replay_handle)
        .expect_err("callback handle is one-shot");
    assert_eq!(replay.code(), "handle_replayed");
}

#[test]
fn real_pipe_rejects_pkce_state_mismatch_without_minting_code_handle() {
    let (read_end, write_end) = pipe_pair();
    let (host, transport) = host(read_end, Arc::new(TestCancel::default()));
    let policy = policy();
    let begun = host
        .pkce_begin(&policy, intent())
        .expect("existing PKCE begin");
    let wrong_state = format!("{}-wrong", state_from(&begun.authorization_url));
    let pasted = callback_url(&begun.authorization_url, &begun.redirect_uri, &wrong_state);
    let callback_handle = begun.callback_handle;
    let callback_host = Arc::new(host);
    let waiting = thread::spawn(move || callback_host.callback_wait(&callback_handle));
    let mut writer = std::fs::File::from(write_end);
    writer
        .write_all(format!("{pasted}\r\n").as_bytes())
        .expect("write CRLF callback");
    drop(writer);

    let error = waiting
        .join()
        .expect("callback wait thread")
        .expect_err("wrong state must fail");
    assert_eq!(error.code(), "state_mismatch");
    assert!(!error.to_string().contains("opaque-code-fixture"));
    assert_eq!(transport.0.load(Ordering::Acquire), 0);
}

#[test]
fn pty_manual_callback_disables_echo_and_restores_termios() {
    let (master, slave) = open_pty();
    let raw_slave = slave.as_raw_fd();
    let observer = duplicate(raw_slave);
    let original_flags = unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) };
    assert!(original_flags >= 0);
    let original_termios = get_termios(observer.as_raw_fd());

    let cancel = Arc::new(TestCancel::default());
    let (host, transport) = host(slave, cancel);
    let policy = policy();
    let begun = host
        .pkce_begin(&policy, intent())
        .expect("existing PKCE begin");
    let state = state_from(&begun.authorization_url);
    let pasted = callback_url(&begun.authorization_url, &begun.redirect_uri, &state);
    let callback_handle = begun.callback_handle;
    let callback_host = Arc::new(host);
    let waiting = thread::spawn(move || callback_host.callback_wait(&callback_handle));

    wait_for_flag(observer.as_raw_fd(), original_flags | libc::O_NONBLOCK);
    let no_echo_termios = get_termios(observer.as_raw_fd());
    assert_eq!(no_echo_termios.c_lflag & (libc::ECHO | libc::ECHONL), 0);

    let mut input = std::fs::File::from(master);
    input
        .write_all(format!("{pasted}\n").as_bytes())
        .expect("write PTY callback");
    let result = waiting
        .join()
        .expect("callback wait thread")
        .expect("callback accepted");
    assert_eq!(result.outcome, CallbackOutcome::Success);
    assert!(result.code_handle.is_some());
    assert_eq!(transport.0.load(Ordering::Acquire), 0);
    assert_eq!(
        unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
        original_flags
    );
    assert_eq!(unsafe { libc::fcntl(raw_slave, libc::F_GETFD) }, -1);
    assert_termios_equal(&original_termios, &get_termios(observer.as_raw_fd()));

    let mut pollfd = libc::pollfd {
        fd: input.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut pollfd, 1, 50) },
        0,
        "PTY echoed callback input"
    );
}

fn wait_for_flag(fd: i32, expected: i32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "input descriptor did not enter nonblocking mode"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn open_pty() -> (OwnedFd, OwnedFd) {
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
