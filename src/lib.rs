use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use rustscript_vm::{HostFunctionRegistry, HttpConfig, Program, Value, Vm, VmStatus};

pub type Result<T> = std::result::Result<T, AgentError>;

#[derive(Debug)]
pub enum AgentError {
    Io(std::io::Error),
    Compile(String),
    Vm(rustscript_vm::VmError),
    EmptyResult,
}

impl Display for AgentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Compile(error) => write!(formatter, "RustScript compile error: {error}"),
            Self::Vm(error) => write!(formatter, "RustScript VM error: {error}"),
            Self::EmptyResult => formatter.write_str("agent script halted without a result"),
        }
    }
}

impl Error for AgentError {}

impl From<std::io::Error> for AgentError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustscript_vm::VmError> for AgentError {
    fn from(error: rustscript_vm::VmError) -> Self {
        Self::Vm(error)
    }
}

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub http: HttpConfig,
}

impl AgentConfig {
    pub fn new(http: HttpConfig) -> Self {
        Self { http }
    }

    pub fn for_hosts<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut http = HttpConfig::default();
        http.allowed_hosts = hosts
            .into_iter()
            .map(|host| host.as_ref().to_ascii_lowercase())
            .collect();
        Self { http }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self::new(HttpConfig::default())
    }
}

#[derive(Clone, Debug)]
pub struct AgentRunner {
    program: Program,
    config: AgentConfig,
}

impl AgentRunner {
    pub fn from_source(source: &str, config: AgentConfig) -> Result<Self> {
        let program = rustscript_vm::compile_source(source)
            .map_err(|error| AgentError::Compile(error.to_string()))?
            .program;
        Ok(Self { program, config })
    }

    pub fn from_file(path: impl AsRef<Path>, config: AgentConfig) -> Result<Self> {
        let source = std::fs::read_to_string(path)?;
        Self::from_source(&source, config)
    }

    pub fn run(&self) -> Result<Value> {
        let mut vm = Vm::new(self.program.clone());
        vm.configure_http(self.config.http.clone());
        HostFunctionRegistry::new().bind_vm_cached(&mut vm)?;

        loop {
            match vm.run()? {
                VmStatus::Halted => {
                    return vm.stack().last().cloned().ok_or(AgentError::EmptyResult);
                }
                VmStatus::Yielded => continue,
                VmStatus::Waiting(_) => {
                    vm.wait_for_host_op_blocking()?;
                }
            }
        }
    }
}
