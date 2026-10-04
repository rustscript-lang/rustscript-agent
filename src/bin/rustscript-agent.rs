use std::env;
use std::fmt::{self, Write as FmtWrite};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use rustscript_agent::auth::host::AuthHost;
use rustscript_agent::cli::{
    CliInvocation, CliOutput, cli_usage, execute_auth_cli, parse_cli_args, resolve_cli_paths,
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
];

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
    let cancellation = RunCancellation::with_timeout(INVOCATION_BUDGET);
    let watcher = match install_sigint_watcher(cancellation.clone()).await {
        Ok(watcher) => watcher,
        Err(()) => {
            return emit_output(code_output("cli_signal_unavailable", 1));
        }
    };

    let worker_cancellation = cancellation;
    let result =
        tokio::task::spawn_blocking(move || execute_invocation(invocation, worker_cancellation))
            .await;

    watcher.abort();
    let _ = watcher.await;

    match result {
        Ok(output) => emit_output(output),
        Err(_) => emit_output(code_output("agent_run_failed", 1)),
    }
}

async fn install_sigint_watcher(
    cancellation: RunCancellation,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|_| ())?;
        Ok(tokio::spawn(async move {
            if signal.recv().await.is_some() {
                cancellation.request(CancellationReason::Requested);
            }
        }))
    }
    #[cfg(not(unix))]
    {
        let watcher = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancellation.request(CancellationReason::Requested);
            }
        });
        tokio::task::yield_now().await;
        Ok(watcher)
    }
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
    execute_auth_cli(&runner, input, cancellation, move |child| {
        AuthHost::new_for_commands(paths.home, child)
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
