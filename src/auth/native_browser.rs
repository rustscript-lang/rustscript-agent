//! Trusted native Linux launcher for OAuth authorization URLs.
//!
//! The caller supplies one trusted absolute executable and an explicit,
//! bounded set of approved desktop variables. No launcher discovery occurs.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::auth::oauth::{BrowserOpener, OAuthError, OAuthIoContext};

const APPROVED_ENVIRONMENT: &[&str] = &[
    "HOME",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_CURRENT_DESKTOP",
    "DESKTOP_SESSION",
    "LANG",
    "LC_ALL",
];
const MAX_ENV_ENTRIES: usize = 10;
const MAX_ENV_VALUE_BYTES: usize = 4096;
const MAX_ENV_TOTAL_BYTES: usize = 16_384;
const MAX_AUTHORIZATION_URL_BYTES: usize = 32_768;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const FIXED_PATH: &str = "/usr/bin:/bin";
const CLOSE_RANGE_CLOEXEC: libc::c_uint = libc::CLOSE_RANGE_CLOEXEC;

/// A launcher selected by trusted native code; guest input cannot configure it.
pub struct NativeBrowserOpener {
    executable: PathBuf,
    desktop_environment: BTreeMap<String, String>,
}

impl fmt::Debug for NativeBrowserOpener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeBrowserOpener")
            .field("executable", &"[redacted]")
            .field(
                "desktop_environment_entries",
                &self.desktop_environment.len(),
            )
            .finish()
    }
}

impl NativeBrowserOpener {
    /// Construct from an absolute trusted launcher and explicit desktop environment.
    pub fn new(
        executable: PathBuf,
        desktop_environment: BTreeMap<String, String>,
    ) -> Result<Self, OAuthError> {
        if !executable.is_absolute() || desktop_environment.len() > MAX_ENV_ENTRIES {
            return Err(invalid("native browser configuration is invalid"));
        }
        let mut aggregate_bytes = 0_usize;
        for (key, value) in &desktop_environment {
            if !APPROVED_ENVIRONMENT.contains(&key.as_str())
                || value.len() > MAX_ENV_VALUE_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(invalid("native browser configuration is invalid"));
            }
            aggregate_bytes = aggregate_bytes
                .saturating_add(key.len())
                .saturating_add(value.len());
            if aggregate_bytes > MAX_ENV_TOTAL_BYTES {
                return Err(invalid("native browser configuration is invalid"));
            }
        }
        Ok(Self {
            executable,
            desktop_environment,
        })
    }

    fn validate_executable(&self, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        let metadata = fs::metadata(&self.executable)
            .map_err(|_| transport("native browser launcher is unavailable"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(transport("native browser launcher is unavailable"));
        }
        context.check()
    }

    fn spawn(&self, authorization_url: &str) -> Result<OwnedLauncher, OAuthError> {
        let mut command = Command::new(&self.executable);
        command
            .arg(authorization_url)
            .env_clear()
            .env("PATH", FIXED_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        for (key, value) in &self.desktop_environment {
            command.env(key, value);
        }
        // SAFETY: the child-side closure invokes only async-signal-safe
        // close_range and returns errno. Failure aborts spawn; no fallback exists.
        unsafe {
            command.pre_exec(|| {
                let result =
                    libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC);
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
            .spawn()
            .map(OwnedLauncher::new)
            .map_err(|_| transport("native browser launcher could not be started"))
    }
}

impl BrowserOpener for NativeBrowserOpener {
    /// A zero launcher exit acknowledges the URL argument only.
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        validate_authorization_url(authorization_url)?;
        context.check()?;
        self.validate_executable(context)?;
        context.check()?;

        let mut launcher = self.spawn(authorization_url)?;
        context.check()?;
        loop {
            context.check()?;
            let observed = launcher
                .observe()
                .map_err(|_| transport("native browser launcher ownership was lost"))?;
            context.check()?;
            if let Some(exit) = observed {
                if exit.success() {
                    launcher
                        .reap_direct()
                        .map_err(|_| transport("native browser launcher could not be reaped"))?;
                    return Ok(());
                }
                launcher.terminate_and_reap();
                return Err(transport(
                    "native browser launcher did not acknowledge the URL",
                ));
            }
            let pause = context.remaining()?.min(POLL_INTERVAL);
            thread::sleep(pause);
            context.check()?;
        }
    }
}

fn validate_authorization_url(value: &str) -> Result<(), OAuthError> {
    if value.len() > MAX_AUTHORIZATION_URL_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid("authorization URL is invalid"));
    }
    let parsed = url::Url::parse(value).map_err(|_| invalid("authorization URL is invalid"))?;
    let authority = value
        .find("://")
        .map(|index| &value[index + 3..])
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .unwrap_or_default();
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || authority.contains('@')
    {
        return Err(invalid("authorization URL is invalid"));
    }
    Ok(())
}

struct ExitObservation {
    code: libc::c_int,
    status: libc::c_int,
}

impl ExitObservation {
    fn success(&self) -> bool {
        self.code == libc::CLD_EXITED && self.status == 0
    }
}

/// Keeps the direct child unreaped while its PID anchors process-group signals.
struct OwnedLauncher {
    child: Option<Child>,
    pid: libc::pid_t,
}

impl OwnedLauncher {
    fn new(child: Child) -> Self {
        let pid = child.id() as libc::pid_t;
        Self {
            child: Some(child),
            pid,
        }
    }

    /// Observe without reaping so the child PID remains an identity anchor.
    fn observe(&mut self) -> io::Result<Option<ExitObservation>> {
        if self.child.is_none() {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
        loop {
            let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut information,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                let observed_pid = unsafe { information.si_pid() };
                if observed_pid == 0 {
                    return Ok(None);
                }
                if observed_pid == self.pid {
                    return Ok(Some(ExitObservation {
                        code: information.si_code,
                        status: unsafe { information.si_status() },
                    }));
                }
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                // A numeric PID is no longer a safe signal target.
                self.child.take();
            }
            return Err(error);
        }
    }

    fn reap_direct(&mut self) -> io::Result<()> {
        if self.child.is_none() {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
        loop {
            let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut information,
                    libc::WEXITED,
                )
            };
            if result == 0 {
                let observed_pid = unsafe { information.si_pid() };
                // Successful waitid reaped the target; invalidate its numeric identity first.
                self.child.take();
                return if observed_pid == self.pid {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(libc::ECHILD))
                };
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                // Lost ownership forbids future numeric signals.
                self.child.take();
            }
            return Err(error);
        }
    }

    fn terminate_and_reap(&mut self) {
        if self.child.is_none() || self.observe().is_err() {
            return;
        }
        // Successful WNOWAIT observation and unreaped Child retain the identity.
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
            libc::kill(self.pid, libc::SIGKILL);
        }
        let _ = self.reap_direct();
    }
}

impl Drop for OwnedLauncher {
    fn drop(&mut self) {
        self.terminate_and_reap();
    }
}

fn invalid(reason: &'static str) -> OAuthError {
    OAuthError::InvalidIntent {
        reason: reason.to_string(),
    }
}

fn transport(message: &'static str) -> OAuthError {
    OAuthError::Transport {
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::{NativeBrowserOpener, OwnedLauncher};
    use crate::auth::oauth::{BrowserOpener, OAuthCancel, OAuthClock, OAuthIoContext};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let root = PathBuf::from(
                std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
                    .expect("RUSTSCRIPT_AGENT_TEST_TMP assigned by gate"),
            );
            fs::create_dir_all(&root).expect("create assigned test temp");
            let path = root.join(format!(
                "native-browser-unit-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create fixture directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn helper(&self, name: &str, body: &str) -> PathBuf {
            let source = self.path(&format!("{name}.rs"));
            let executable = self.path(name);
            let program = format!(
                "const REPORT: &str = {:?};\n{}",
                self.path("report").to_string_lossy(),
                body
            );
            fs::write(&source, program).expect("write helper source");
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
            let output = Command::new(rustc)
                .arg("--edition=2024")
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .expect("compile owned helper");
            assert!(
                output.status.success(),
                "helper compile failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            executable
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct RealClock;

    impl OAuthClock for RealClock {
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

    struct NeverCancel;

    impl OAuthCancel for NeverCancel {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    fn context() -> OAuthIoContext {
        OAuthIoContext::new(
            Instant::now() + Duration::from_secs(5),
            Arc::new(RealClock),
            Arc::new(NeverCancel),
        )
    }

    #[test]
    fn launcher_preserves_the_original_single_url_argument_without_shell_parsing() {
        let scratch = Scratch::new();
        let executable = scratch.helper(
            "argv-helper",
            r#"fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(args.len(), 1);
    std::fs::write(REPORT, format!("{}\n{}", args.len(), args[0].to_string_lossy()))
        .expect("write argv report");
}"#,
        );
        let opener = NativeBrowserOpener::new(executable, BTreeMap::new()).expect("opener");
        let original = "https://auth.example.test/authorize?x=$(marker);left|right&y=%3B";
        opener
            .open(original, &context())
            .expect("owned launcher exit");
        assert_eq!(
            fs::read_to_string(scratch.path("report")).expect("helper argv report"),
            format!("1\n{original}")
        );
    }

    #[test]
    fn invalid_urls_fail_before_any_helper_effect_and_keep_errors_redacted() {
        let scratch = Scratch::new();
        let executable = scratch.helper(
            "never-launched-helper",
            r#"fn main() { std::fs::write(REPORT, "launched").expect("write marker"); }"#,
        );
        let opener = NativeBrowserOpener::new(executable, BTreeMap::new()).expect("opener");
        let oversized = format!("https://auth.example.test/{}", "a".repeat(32_769));
        for url in [
            "http://auth.example.test/authorize",
            "https://user:pass@auth.example.test/authorize",
            "https://@auth.example.test/authorize",
            "https://auth.example.test/authorize\nheader: injected",
            oversized.as_str(),
        ] {
            let error = opener
                .open(url, &context())
                .expect_err("invalid URL rejected");
            assert_eq!(error.code(), "invalid_intent");
            assert!(!format!("{error:?}").contains(url));
        }
        assert!(!scratch.path("report").exists());
    }

    #[test]
    fn trusted_configuration_is_bounded_and_debug_errors_do_not_disclose_values() {
        let scratch = Scratch::new();
        let path = scratch.path("private-launcher-path");
        let marker = "PRIVATE_DESKTOP_ENV_MARKER";
        let opener = NativeBrowserOpener::new(
            path.clone(),
            BTreeMap::from([("HOME".into(), marker.into())]),
        )
        .expect("absolute path and approved environment");
        let debug = format!("{opener:?}");
        assert!(!debug.contains(&path.to_string_lossy().to_string()));
        assert!(!debug.contains(marker));
        let all_approved = [
            "HOME",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_CURRENT_DESKTOP",
            "DESKTOP_SESSION",
            "LANG",
            "LC_ALL",
        ]
        .into_iter()
        .map(|key| (key.to_owned(), String::new()))
        .collect();
        assert!(NativeBrowserOpener::new(path.clone(), all_approved).is_ok());

        let error = NativeBrowserOpener::new(PathBuf::from("relative-launcher"), BTreeMap::new())
            .expect_err("relative path denied");
        assert!(!format!("{error:?}").contains("relative-launcher"));

        let per_value = NativeBrowserOpener::new(
            path.clone(),
            BTreeMap::from([("HOME".into(), "x".repeat(4097))]),
        );
        assert!(per_value.is_err());
        let aggregate = BTreeMap::from([
            ("HOME".into(), "x".repeat(4090)),
            ("DISPLAY".into(), "y".repeat(4090)),
            ("WAYLAND_DISPLAY".into(), "z".repeat(4090)),
            ("XAUTHORITY".into(), "q".repeat(4090)),
        ]);
        assert!(NativeBrowserOpener::new(path.clone(), aggregate).is_err());
        for value in ["bad\nvalue", "bad\0value", "bad\u{0085}value"] {
            let result = NativeBrowserOpener::new(
                path.clone(),
                BTreeMap::from([("HOME".into(), value.into())]),
            );
            assert!(result.is_err());
        }
        let error = NativeBrowserOpener::new(
            scratch.path("another-private-path"),
            BTreeMap::from([("BROWSER".into(), marker.into())]),
        )
        .expect_err("unapproved environment key");
        assert!(!format!("{error:?}").contains(marker));
    }

    #[test]
    fn failed_exec_does_not_run_an_invalid_executable_or_leak_a_child() {
        let scratch = Scratch::new();
        let executable = scratch.path("invalid-elf-launcher");
        let bytes = b"\\x7fELF truncated fixture";
        fs::write(&executable, bytes).expect("write invalid executable fixture");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("mark fixture executable");
        let opener = NativeBrowserOpener::new(executable.clone(), BTreeMap::new()).expect("opener");
        let error = opener
            .open("https://auth.example.test/authorize", &context())
            .expect_err("exec format failure is a transport fact");
        assert_eq!(error.code(), "transport_error");
        assert!(!format!("{error:?}").contains(&executable.to_string_lossy().to_string()));
        assert_eq!(
            fs::read(executable).expect("fixture remains unchanged"),
            bytes
        );
    }

    #[test]
    fn unwind_drop_kills_and_reaps_the_owned_launcher() {
        let scratch = Scratch::new();
        let executable = scratch.helper(
            "unwind-helper",
            r#"fn main() { std::thread::sleep(std::time::Duration::from_secs(10)); }"#,
        );
        let mut command = Command::new(executable);
        command
            .arg("https://auth.example.test/authorize")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().expect("spawn child before unwind");
        let pid = child.id() as libc::pid_t;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _launcher = OwnedLauncher::new(child);
            panic!("fixture unwind");
        }));
        assert!(result.is_err());
        let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn repeated_cleanup_reaps_only_the_unreaped_owned_child() {
        let scratch = Scratch::new();
        let executable = scratch.helper(
            "long-helper",
            r#"fn main() { std::thread::sleep(std::time::Duration::from_secs(10)); }"#,
        );
        let mut command = Command::new(executable);
        command
            .arg("https://auth.example.test/authorize")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().expect("spawn owned test child");
        let pid = child.id() as libc::pid_t;
        let mut launcher = OwnedLauncher::new(child);
        launcher.terminate_and_reap();
        launcher.terminate_and_reap();
        assert!(launcher.child.is_none());
        let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
