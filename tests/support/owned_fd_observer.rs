//! Test-only exclusive FD namespace and strict owned-completion checkpoints.
use std::{
    any::Any,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const FD_OBSERVER_CHILD_MARKER: &str = "RUSTSCRIPT_PKCE_OWNED_FD_OBSERVER_CHILD";
const FD_OBSERVER_CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const FD_OBSERVER_CHILD_OUTPUT_LIMIT: usize = 64 * 1024;

struct OwnedTestChild(Option<Child>);

impl OwnedTestChild {
    fn wait_before(
        &mut self,
        deadline: Instant,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        loop {
            let child = self.0.as_mut().expect("owned child is still present");
            let observed = match child.try_wait() {
                Ok(observed) => observed,
                Err(error) => {
                    self.kill_and_wait();
                    return Err(error);
                }
            };
            if let Some(status) = observed {
                self.0.take();
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                self.kill_and_wait();
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for OwnedTestChild {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

struct BoundedChildOutput {
    bytes: Vec<u8>,
    discarded: usize,
}

fn capture_child_output(mut reader: impl Read) -> std::io::Result<BoundedChildOutput> {
    let mut output = BoundedChildOutput {
        bytes: Vec::with_capacity(FD_OBSERVER_CHILD_OUTPUT_LIMIT),
        discarded: 0,
    };
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(read) => {
                let keep = read.min(FD_OBSERVER_CHILD_OUTPUT_LIMIT - output.bytes.len());
                output.bytes.extend_from_slice(&buffer[..keep]);
                output.discarded += read - keep;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn fd_observer_child_is_current_test(test_name: &str) -> bool {
    let Ok(marker) = std::env::var(FD_OBSERVER_CHILD_MARKER) else {
        return false;
    };
    let mut parts = marker.splitn(3, ':');
    let (Some(marked_test), Some(parent_pid), Some(nonce)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if marked_test != test_name
        || parent_pid.parse::<libc::pid_t>().ok() != Some(unsafe { libc::getppid() })
        || uuid::Uuid::parse_str(nonce).is_err()
    {
        return false;
    }
    std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|args| args[0] == "--exact" && args[1] == test_name)
}

pub fn spawn_fd_observer_child_unless_child(test_name: &str) -> bool {
    if fd_observer_child_is_current_test(test_name) {
        return false;
    }

    let deadline = Instant::now() + FD_OBSERVER_CHILD_TIMEOUT;
    let nonce = uuid::Uuid::new_v4();
    let marker = format!("{test_name}:{}:{nonce}", std::process::id());
    let mut child = OwnedTestChild(Some(
        Command::new(std::env::current_exe().expect("native test executable path"))
            .args(["--exact", test_name, "--nocapture"])
            .env_clear()
            .envs(
                [
                    "PATH",
                    "HOME",
                    "RUSTC",
                    "RUSTUP_HOME",
                    "RUSTUP_TOOLCHAIN",
                    "CARGO_HOME",
                    "LD_LIBRARY_PATH",
                    "TMPDIR",
                    "TEMP",
                    "TMP",
                    "TEST_TMPDIR",
                    "RUSTSCRIPT_AGENT_TEST_TMP",
                    "RUSTSCRIPT_AGENT_TEST_TMPDIR",
                ]
                .into_iter()
                .filter_map(|key| std::env::var_os(key).map(|value| (key, value))),
            )
            .env(FD_OBSERVER_CHILD_MARKER, marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated FD-observer child"),
    ));
    let stdout = child
        .0
        .as_mut()
        .expect("owned child is still present")
        .stdout
        .take()
        .expect("child stdout is piped");
    let stderr = child
        .0
        .as_mut()
        .expect("owned child is still present")
        .stderr
        .take()
        .expect("child stderr is piped");
    let stdout_reader = thread::spawn(move || capture_child_output(stdout));
    let stderr_reader = thread::spawn(move || capture_child_output(stderr));

    let status = child.wait_before(deadline);
    let stdout = stdout_reader
        .join()
        .expect("child stdout reader joined")
        .expect("read child stdout");
    let stderr = stderr_reader
        .join()
        .expect("child stderr reader joined")
        .expect("read child stderr");
    let stdout_text = String::from_utf8_lossy(&stdout.bytes);
    let stderr_text = String::from_utf8_lossy(&stderr.bytes);
    let output = format!("{stdout_text}\n{stderr_text}");
    let truncated = stdout.discarded + stderr.discarded;
    let ran_exactly_one_named_test = output
        .lines()
        .filter(|line| line.trim() == "running 1 test")
        .count()
        == 1
        && output
            .lines()
            .filter(|line| line.trim() == format!("test {test_name} ... ok"))
            .count()
            == 1
        && output.lines().any(|line| {
            line.trim()
                .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
        });
    let status = status.expect("child wait completed without an I/O error");
    assert!(
        matches!(status, Some(ref exit) if exit.success())
            && ran_exactly_one_named_test
            && truncated == 0,
        "isolated FD-observer child {test_name} did not pass its one exact test: status={status:?}, ran_exactly_one_named_test={ran_exactly_one_named_test}, truncated_output_bytes={truncated}, stdout={stdout_text}, stderr={stderr_text}"
    );
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
    kind: libc::mode_t,
}

pub fn input_identity(fd: i32) -> InputIdentity {
    let mut state = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(
        unsafe { libc::fstat(fd, state.as_mut_ptr()) },
        0,
        "owned input metadata available"
    );
    let state = unsafe { state.assume_init() };
    InputIdentity {
        device: state.st_dev,
        inode: state.st_ino,
        kind: state.st_mode & libc::S_IFMT,
    }
}

#[must_use = "the captured close predicate must be asserted after fixture cleanup"]
pub struct ClosedObservation(Result<(), Box<dyn Any + Send>>);
impl ClosedObservation {
    pub fn assert(self) {
        if let Err(payload) = self.0 {
            std::panic::resume_unwind(payload);
        }
    }
}

// Run the unchanged immediate F_GETFD/EBADF predicate once, before later file
// IO or socket rebind. Preserve its panic until the fixture has joined/cleaned up.
pub fn observe_closed(fd: i32, original: InputIdentity, predicate: fn(i32)) -> ClosedObservation {
    let observed = std::panic::catch_unwind(|| predicate(fd));
    if observed.is_err() {
        let mut state = std::mem::MaybeUninit::<libc::stat>::uninit();
        let metadata_rc = unsafe { libc::fstat(fd, state.as_mut_ptr()) };
        if metadata_rc == 0 {
            let state = unsafe { state.assume_init() };
            let current = InputIdentity {
                device: state.st_dev,
                inode: state.st_ino,
                kind: state.st_mode & libc::S_IFMT,
            };
            eprintln!(
                "FD checkpoint {fd}: original={original:?}, current={current:?}, same_object={}",
                original == current
            );
        } else {
            eprintln!(
                "FD checkpoint {fd}: metadata unavailable after failed predicate; original={original:?}"
            );
        }
    }
    ClosedObservation(observed)
}

pub fn retained_and_reused_control(predicate: fn(i32)) {
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let number = reader.as_raw_fd();
    let original = input_identity(number);
    let retained = observe_closed(number, original, predicate);
    drop(reader);
    predicate(number);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| retained.assert())).is_err(),
        "later cleanup must not erase the retained-owner failure"
    );
    let replacement = File::open("/dev/null").expect("open distinct descriptor");
    assert_eq!(
        replacement.as_raw_fd(),
        number,
        "exclusive namespace reuses lowest free descriptor"
    );
    assert_ne!(
        input_identity(number),
        original,
        "reused integer refers to a different OS object"
    );
    let reused = observe_closed(number, original, predicate);
    drop(replacement);
    predicate(number);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reused.assert())).is_err(),
        "different identity and later cleanup must not weaken EBADF"
    );
    drop(writer);
}
