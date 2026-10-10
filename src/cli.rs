use std::error::Error;
use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use rustscript_vm::Value;

use crate::AgentPaths;
use crate::auth::host::{AuthHost, ConfigPathHost};
use crate::runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner, RunCancellation};

const MAX_STATUS_BYTES: usize = 256 * 1024;
const MAX_ERROR_BYTES: usize = 2048;

#[derive(Debug, PartialEq, Eq)]
pub enum CliInvocation {
    Help,
    Run {
        script: PathBuf,
        allowed_hosts: Vec<String>,
    },
    Auth(AuthCommandInput),
    ConfigPath(AuthCommandInput),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    InvalidArguments,
    InvalidHome,
    OutputInvalid,
    OutputTooLarge,
}

impl CliError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "cli_arguments_invalid",
            Self::InvalidHome => "cli_home_invalid",
            Self::OutputInvalid => "cli_output_invalid",
            Self::OutputTooLarge => "cli_output_too_large",
        }
    }
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for CliError {}

#[derive(Debug, PartialEq, Eq)]
pub struct CliOutput {
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

pub fn resolve_cli_paths() -> Result<AgentPaths, CliError> {
    AgentPaths::resolve().map_err(|_| CliError::InvalidHome)
}

pub fn execute_auth_cli<F>(
    runner: &AuthEntryRunner,
    input: AuthCommandInput,
    cancellation: &RunCancellation,
    build_host: F,
) -> CliOutput
where
    F: FnOnce(RunCancellation) -> Result<AuthHost, String>,
{
    cli_result_output(runner.run_with_host_factory(input, cancellation, build_host))
}

pub fn execute_config_path_cli<F>(
    runner: &AuthEntryRunner,
    input: AuthCommandInput,
    cancellation: &RunCancellation,
    build_host: F,
) -> CliOutput
where
    F: FnOnce(RunCancellation) -> Result<ConfigPathHost, String>,
{
    cli_result_output(runner.run_with_path_host_factory(input, cancellation, build_host))
}

fn cli_result_output(result: Result<Value, AuthEntryError>) -> CliOutput {
    match result {
        Ok(value) => render_result(&value).unwrap_or_else(output_error),
        Err(error) => {
            let exit_code = match &error {
                AuthEntryError::Cancelled(crate::CancellationReason::Deadline) => 124,
                AuthEntryError::Cancelled(_) => 130,
                _ => 1,
            };
            CliOutput {
                exit_code,
                stdout: String::new(),
                stderr: format!("{}\n", error.code()),
            }
        }
    }
}

fn render_result(value: &Value) -> Result<CliOutput, CliError> {
    let Some(Value::Bool(ok)) = value_field(value, "ok") else {
        return Err(CliError::OutputInvalid);
    };
    let Some(Value::String(status)) = value_field(value, "status") else {
        return Err(CliError::OutputInvalid);
    };
    let error = match value_field(value, "error") {
        Some(Value::String(error)) if !error.is_empty() => Some(error.to_string()),
        Some(Value::String(_)) | Some(Value::Null) | None if !ok => {
            Some("command_failed".to_owned())
        }
        Some(Value::String(_)) | Some(Value::Null) | None => None,
        _ => return Err(CliError::OutputInvalid),
    };

    if status.len() > MAX_STATUS_BYTES || unsafe_report_control(status) {
        return Err(if status.len() > MAX_STATUS_BYTES {
            CliError::OutputTooLarge
        } else {
            CliError::OutputInvalid
        });
    }
    let mut stdout = status.to_string();
    if !stdout.is_empty() && !stdout.ends_with('\n') {
        stdout.push('\n');
    }
    if stdout.len() > MAX_STATUS_BYTES {
        return Err(CliError::OutputTooLarge);
    }

    let mut stderr = String::new();
    if let Some(error) = error {
        if error.len() > MAX_ERROR_BYTES {
            return Err(CliError::OutputTooLarge);
        }
        if error.chars().any(char::is_control) {
            return Err(CliError::OutputInvalid);
        }
        stderr.push_str(&error);
        stderr.push('\n');
        if stderr.len() > MAX_ERROR_BYTES {
            return Err(CliError::OutputTooLarge);
        }
    }

    Ok(CliOutput {
        exit_code: if *ok { 0 } else { 1 },
        stdout,
        stderr,
    })
}

fn output_error(error: CliError) -> CliOutput {
    CliOutput {
        exit_code: 1,
        stdout: String::new(),
        stderr: format!("{}\n", error.code()),
    }
}

fn value_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(fields) = value else {
        return None;
    };
    fields.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn unsafe_report_control(value: &str) -> bool {
    value.chars().any(|character| {
        (character <= '\u{001f}' && character != '\n' && character != '\t')
            || character == '\u{007f}'
    })
}

pub fn cli_usage() -> &'static str {
    "Usage:\n  rustscript-agent --script PATH --allow-host HOST [--allow-host HOST ...]\n  rustscript-agent run --script PATH --allow-host HOST [--allow-host HOST ...]\n  rustscript-agent auth login PROVIDER\n  rustscript-agent auth status [PROVIDER]\n  rustscript-agent auth logout ID\n  rustscript-agent config path\n  rustscript-agent config check"
}

pub fn parse_cli_args(args: impl IntoIterator<Item = OsString>) -> Result<CliInvocation, CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.is_empty() {
        return Err(CliError::InvalidArguments);
    }

    match args[0].to_str() {
        Some("run") => parse_run(&args[1..]),
        Some("auth") => parse_auth(&args[1..]),
        Some("config") => parse_config(&args[1..]),
        _ => parse_run(&args),
    }
}

fn parse_run(args: &[OsString]) -> Result<CliInvocation, CliError> {
    let mut script = None;
    let mut allowed_hosts = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--help" | "-h") => return Ok(CliInvocation::Help),
            Some("--script") => {
                let value = args.get(index + 1).ok_or(CliError::InvalidArguments)?;
                if value.is_empty() {
                    return Err(CliError::InvalidArguments);
                }
                script = Some(PathBuf::from(value));
                index += 2;
            }
            Some("--allow-host") => {
                let value = args.get(index + 1).ok_or(CliError::InvalidArguments)?;
                let host = value.to_str().ok_or(CliError::InvalidArguments)?;
                if host.is_empty() {
                    return Err(CliError::InvalidArguments);
                }
                allowed_hosts.push(host.to_owned());
                index += 2;
            }
            _ => return Err(CliError::InvalidArguments),
        }
    }
    let script = script
        .filter(|path: &PathBuf| !path.as_os_str().is_empty())
        .ok_or(CliError::InvalidArguments)?;
    if allowed_hosts.is_empty() {
        return Err(CliError::InvalidArguments);
    }
    Ok(CliInvocation::Run {
        script,
        allowed_hosts,
    })
}

fn parse_auth(args: &[OsString]) -> Result<CliInvocation, CliError> {
    let operation = args.first().and_then(|value| value.to_str());
    let input = match operation {
        Some("login") if args.len() == 2 => AuthCommandInput {
            operation: "auth.login".to_owned(),
            provider: Some(required_selector(&args[1])?),
            credential_id: None,
        },
        Some("status") if args.len() == 1 || args.len() == 2 => AuthCommandInput {
            operation: "auth.status".to_owned(),
            provider: args.get(1).map(required_selector).transpose()?,
            credential_id: None,
        },
        Some("logout") if args.len() == 2 => AuthCommandInput {
            operation: "auth.logout".to_owned(),
            provider: None,
            credential_id: Some(required_selector(&args[1])?),
        },
        _ => return Err(CliError::InvalidArguments),
    };
    Ok(CliInvocation::Auth(input))
}

fn parse_config(args: &[OsString]) -> Result<CliInvocation, CliError> {
    match args {
        [command] if command.to_str() == Some("path") => {
            Ok(CliInvocation::ConfigPath(AuthCommandInput {
                operation: "config.path".to_owned(),
                provider: None,
                credential_id: None,
            }))
        }
        [command] if command.to_str() == Some("check") => {
            Ok(CliInvocation::Auth(AuthCommandInput {
                operation: "config.check".to_owned(),
                provider: None,
                credential_id: None,
            }))
        }
        _ => Err(CliError::InvalidArguments),
    }
}

fn required_selector(value: &OsString) -> Result<String, CliError> {
    let selector = value.to_str().ok_or(CliError::InvalidArguments)?;
    if !valid_selector(selector) {
        return Err(CliError::InvalidArguments);
    }
    Ok(selector.to_owned())
}

fn valid_selector(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control)
}
