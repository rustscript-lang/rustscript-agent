use std::env;
use std::fmt::{self, Write as FmtWrite};
use std::future::Future;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::host::{
    AuthHost, ConfigPathHost, DeviceInstructionSender, NativeDeviceInstructionOutput,
    RunOAuthCancel, SystemOAuthClock,
};
use rustscript_agent::auth::native_https::NativeHttpsTransport;
use rustscript_agent::auth::oauth::{
    BrowserOpener, CallbackWaiter, OAuthError, OAuthHost, OAuthIoContext, RawCallbackInput,
};
use rustscript_agent::cli::{
    CliInvocation, CliOutput, cli_usage, execute_auth_cli, execute_config_path_cli, parse_cli_args,
    resolve_cli_paths,
};
use rustscript_agent::runtime::{AuthEntryRunner, RunCancellation};
use rustscript_agent::{
    AgentConfig, AgentRunner, CancellationReason, RunDeliveryError, RunError, RunEventSink,
};
use rustscript_vm::{InvocationError, Value};

const INVOCATION_BUDGET: Duration = Duration::from_secs(900);
const MAX_RUN_OUTPUT_BYTES: usize = 256 * 1024;
const AUTH_ENTRY_PATH: &str = "rss/auth/commands.rss";
const AUTH_SOURCES: &[(&str, &str)] = &[
    (AUTH_ENTRY_PATH, include_str!("../../rss/auth/commands.rss")),
    (
        "rss/config/selection.rss",
        include_str!("../../rss/config/selection.rss"),
    ),
    (
        "rss/auth/login.rss",
        include_str!("../../rss/auth/login.rss"),
    ),
    (
        "rss/auth/codex_device.rss",
        include_str!("../../rss/auth/codex_device.rss"),
    ),
    (
        "rss/auth/types.rss",
        include_str!("../../rss/auth/types.rss"),
    ),
];
const PATH_ENTRY_PATH: &str = "rss/config/path.rss";
const PATH_SOURCES: &[(&str, &str)] =
    &[(PATH_ENTRY_PATH, include_str!("../../rss/config/path.rss"))];

#[tokio::main]
async fn main() -> ExitCode {
    let invocation = match parse_cli_args(env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        Err(error) => {
            return emit_output(CliOutput {
                exit_code: 2,
                stdout: String::new(),
                stderr: format!("{}\n{}\n", error.code(), cli_usage()),
            });
        }
    };

    match invocation {
        CliInvocation::Help => emit_output(CliOutput {
            exit_code: 0,
            stdout: format!("{}\n", cli_usage()),
            stderr: String::new(),
        }),
        invocation => run_with_owned_signal(invocation).await,
    }
}

async fn run_with_owned_signal(invocation: CliInvocation) -> ExitCode {
    let output = run_with_owned_signal_driver(invocation, install_sigint_watcher).await;
    emit_output(output)
}

async fn run_with_owned_signal_driver<I, InstallFuture>(
    invocation: CliInvocation,
    install_watcher: I,
) -> CliOutput
where
    I: FnOnce(RunCancellation) -> InstallFuture,
    InstallFuture: Future<Output = Result<tokio::task::JoinHandle<()>, ()>> + Send,
{
    let cancellation = RunCancellation::with_timeout(INVOCATION_BUDGET);
    let watcher = match install_watcher(cancellation.clone()).await {
        Ok(watcher) => watcher,
        Err(()) => return code_output("cli_signal_unavailable", 1),
    };

    let worker_cancellation = cancellation;
    let result =
        tokio::task::spawn_blocking(move || execute_invocation(invocation, worker_cancellation))
            .await;

    watcher.abort();
    let _ = watcher.await;

    match result {
        Ok(output) => output,
        Err(_) => code_output("agent_run_failed", 1),
    }
}

async fn install_ctrl_c_watcher<F>(
    cancellation: RunCancellation,
    ctrl_c: F,
) -> Result<tokio::task::JoinHandle<()>, ()>
where
    F: Future<Output = io::Result<()>> + Send + 'static,
{
    let mut ctrl_c = Box::pin(ctrl_c);
    let first_poll =
        std::future::poll_fn(|cx| std::task::Poll::Ready(ctrl_c.as_mut().poll(cx))).await;

    match first_poll {
        std::task::Poll::Pending => Ok(tokio::spawn(async move {
            if ctrl_c.await.is_ok() {
                cancellation.request(CancellationReason::Requested);
            }
        })),
        std::task::Poll::Ready(Err(_)) => Err(()),
        std::task::Poll::Ready(Ok(())) => {
            cancellation.request(CancellationReason::Requested);
            Ok(tokio::spawn(async {}))
        }
    }
}

async fn install_sigint_watcher(
    cancellation: RunCancellation,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    install_ctrl_c_watcher(cancellation, tokio::signal::ctrl_c()).await
}

fn execute_invocation(invocation: CliInvocation, cancellation: RunCancellation) -> CliOutput {
    match invocation {
        CliInvocation::Help => CliOutput {
            exit_code: 0,
            stdout: format!("{}\n", cli_usage()),
            stderr: String::new(),
        },
        CliInvocation::Run {
            script,
            allowed_hosts,
        } => execute_legacy_run(script, allowed_hosts, &cancellation),
        CliInvocation::Auth(input) => execute_auth(input, &cancellation),
        CliInvocation::ConfigPath(input) => execute_config_path(input, &cancellation),
    }
}

struct UnavailableCallbackWaiter;

impl CallbackWaiter for UnavailableCallbackWaiter {
    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        context.check()?;
        Err(OAuthError::Transport {
            message: "callback unavailable in this CLI".to_owned(),
        })
    }
}

struct UnavailableBrowserOpener;

impl BrowserOpener for UnavailableBrowserOpener {
    fn open(&self, _url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        Err(OAuthError::Transport {
            message: "browser unavailable in this CLI".to_owned(),
        })
    }
}

fn execute_auth(
    input: rustscript_agent::runtime::AuthCommandInput,
    cancellation: &RunCancellation,
) -> CliOutput {
    let paths = match resolve_cli_paths() {
        Ok(paths) => paths,
        Err(error) => return code_output(error.code(), 1),
    };
    let runner = match AuthEntryRunner::from_bundle(AUTH_ENTRY_PATH, AUTH_SOURCES) {
        Ok(runner) => runner,
        Err(_) => return code_output("agent_compile_failed", 1),
    };
    let configured_login = input.operation == "auth.login";
    execute_auth_cli(&runner, input, cancellation, move |child| {
        if configured_login {
            let host = AuthHost::new_for_login(paths.home, child.clone())?;
            let oauth = Arc::new(OAuthHost::new(
                Arc::new(NativeHttpsTransport::new()),
                Arc::new(UnavailableCallbackWaiter),
                Arc::new(UnavailableBrowserOpener),
                Arc::new(SystemOAuthClock),
                Arc::new(RunOAuthCancel::new(child.clone())),
            ));
            let host = host.with_oauth_host(oauth);
            Ok(match NativeDeviceInstructionOutput::stderr() {
                Ok(output) => host.with_device_instruction_sender(
                    DeviceInstructionSender::from_sink(Arc::new(output)),
                ),
                Err(_) => host,
            })
        } else {
            AuthHost::new_for_commands(paths.home, child)
        }
    })
}

fn execute_config_path(
    input: rustscript_agent::runtime::AuthCommandInput,
    cancellation: &RunCancellation,
) -> CliOutput {
    let paths = match resolve_cli_paths() {
        Ok(paths) => paths,
        Err(error) => return code_output(error.code(), 1),
    };
    let runner = match AuthEntryRunner::from_bundle(PATH_ENTRY_PATH, PATH_SOURCES) {
        Ok(runner) => runner,
        Err(_) => return code_output("agent_compile_failed", 1),
    };
    execute_config_path_cli(&runner, input, cancellation, move |child| {
        ConfigPathHost::new(paths.home, child)
    })
}

fn execute_legacy_run(
    script: PathBuf,
    allowed_hosts: Vec<String>,
    cancellation: &RunCancellation,
) -> CliOutput {
    let runner = match AgentRunner::from_file(
        script,
        AgentConfig::for_hosts(allowed_hosts.iter().map(String::as_str)),
    ) {
        Ok(runner) => runner,
        Err(_) => return code_output("agent_compile_failed", 1),
    };
    let mut sink = DiscardEvents;
    match runner.run_with_context_and_events(Value::Null, &mut sink, cancellation) {
        Ok(value) => run_success_output(&value),
        Err(error) => run_failure_output(error, cancellation),
    }
}

fn run_failure_output(error: RunError, cancellation: &RunCancellation) -> CliOutput {
    if let Some(reason) = cancellation.requested() {
        return cancellation_output(reason);
    }
    match error {
        RunError::Invocation(InvocationError::Cancelled(reason)) => cancellation_output(reason),
        RunError::Invocation(InvocationError::DeadlineReached { .. }) => {
            cancellation_output(CancellationReason::Deadline)
        }
        _ => code_output("agent_run_failed", 1),
    }
}

fn cancellation_output(reason: CancellationReason) -> CliOutput {
    let exit_code = if reason == CancellationReason::Deadline {
        124
    } else {
        130
    };
    code_output("agent_cancelled", exit_code)
}

fn run_success_output(value: &Value) -> CliOutput {
    let mut output = BoundedString::new(MAX_RUN_OUTPUT_BYTES - 1);
    if write!(&mut output, "{value:?}").is_err() {
        return code_output("cli_output_closed", 1);
    }
    output.value.push('\n');
    CliOutput {
        exit_code: 0,
        stdout: output.value,
        stderr: String::new(),
    }
}

struct BoundedString {
    value: String,
    limit: usize,
}

impl BoundedString {
    fn new(limit: usize) -> Self {
        Self {
            value: String::new(),
            limit,
        }
    }
}

impl fmt::Write for BoundedString {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.value.len().saturating_add(value.len()) > self.limit {
            return Err(fmt::Error);
        }
        self.value.push_str(value);
        Ok(())
    }
}

struct DiscardEvents;

impl RunEventSink for DiscardEvents {
    fn deliver(&mut self, _value: Value) -> Result<(), RunDeliveryError> {
        Ok(())
    }
}

fn code_output(code: &str, exit_code: u8) -> CliOutput {
    CliOutput {
        exit_code,
        stdout: String::new(),
        stderr: format!("{code}\n"),
    }
}

fn emit_output(output: CliOutput) -> ExitCode {
    let mut stdout = io::stdout().lock();
    if stdout
        .write_all(output.stdout.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        drop(stdout);
        return emit_static_error("cli_output_closed");
    }
    drop(stdout);

    let mut stderr = io::stderr().lock();
    if stderr
        .write_all(output.stderr.as_bytes())
        .and_then(|()| stderr.flush())
        .is_err()
    {
        return ExitCode::from(1);
    }
    ExitCode::from(output.exit_code)
}

fn emit_static_error(code: &str) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = stderr
        .write_all(format!("{code}\n").as_bytes())
        .and_then(|()| stderr.flush());
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};

    struct GuestScript(PathBuf);

    impl GuestScript {
        fn successful() -> (Self, CliInvocation) {
            Self::with_source("pub fn run(input: string?) -> string { \"real-driver-success\"; }")
        }

        fn looping() -> (Self, CliInvocation) {
            Self::with_source("pub fn run(input: string?) -> int { while true { 1; } 0; }")
        }

        fn with_source(source: &str) -> (Self, CliInvocation) {
            let temp = PathBuf::from(
                env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 TEMP"),
            );
            let root = temp.join(format!("cli-signal-driver-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).expect("create isolated RSS root");
            let path = root.join("main.rss");
            fs::write(&path, source).expect("write isolated RSS guest");
            let invocation = CliInvocation::Run {
                script: path.clone(),
                allowed_hosts: vec!["fixture.invalid".to_owned()],
            };
            (Self(path), invocation)
        }
    }

    impl Drop for GuestScript {
        fn drop(&mut self) {
            if let Some(root) = self.0.parent() {
                let _ = fs::remove_dir_all(root);
            }
        }
    }

    struct PendingCtrlC(Arc<AtomicUsize>);

    impl Future for PendingCtrlC {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().0.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    struct ReadyCtrlC(Arc<AtomicUsize>);

    impl Future for ReadyCtrlC {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            let previous = self.get_mut().0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(previous, 0, "completed ctrl_c future was polled again");
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_ctrl_c_future_runs_the_real_guest_and_keeps_its_watcher_owned() {
        let (_script, invocation) = GuestScript::successful();
        let polls = Arc::new(AtomicUsize::new(0));
        let future_polls = Arc::clone(&polls);
        let output = run_with_owned_signal_driver(invocation, move |cancellation| {
            install_ctrl_c_watcher(cancellation, PendingCtrlC(future_polls))
        })
        .await;

        assert_eq!(output.exit_code, 0, "real guest output: {output:?}");
        assert!(output.stdout.contains("real-driver-success"));
        assert!(polls.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ctrl_c_registration_error_prevents_the_real_guest_driver() {
        let (_script, invocation) = GuestScript::successful();
        let output = run_with_owned_signal_driver(invocation, |cancellation| {
            install_ctrl_c_watcher(
                cancellation,
                std::future::ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "synthetic registration failure",
                ))),
            )
        })
        .await;

        assert_eq!(output, code_output("cli_signal_unavailable", 1));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn already_ready_ctrl_c_requests_cancellation_without_repolling_future() {
        let (_script, invocation) = GuestScript::looping();
        let polls = Arc::new(AtomicUsize::new(0));
        let future_polls = Arc::clone(&polls);
        let output = run_with_owned_signal_driver(invocation, move |cancellation| {
            install_ctrl_c_watcher(cancellation, ReadyCtrlC(future_polls))
        })
        .await;

        assert_eq!(output, code_output("agent_cancelled", 130));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}
