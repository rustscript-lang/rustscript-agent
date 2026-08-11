use std::env;
use std::process::ExitCode;

use rustscript_agent::{AgentConfig, AgentRunner};

fn usage() -> &'static str {
    "Usage: rustscript-agent --script PATH --allow-host HOST [--allow-host HOST ...]"
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut script = None;
    let mut hosts = Vec::new();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--script" => script = args.next(),
            "--allow-host" => match args.next() {
                Some(host) => hosts.push(host),
                None => {
                    eprintln!("--allow-host requires a value\n{}", usage());
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!("{}", usage());
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("unknown argument: {unknown}\n{}", usage());
                return ExitCode::from(2);
            }
        }
    }

    let Some(script) = script else {
        eprintln!("--script is required\n{}", usage());
        return ExitCode::from(2);
    };
    if hosts.is_empty() {
        eprintln!("at least one --allow-host is required\n{}", usage());
        return ExitCode::from(2);
    }

    let result: std::result::Result<rustscript_vm::Value, Box<dyn std::error::Error>> =
        match AgentRunner::from_file(script, AgentConfig::for_hosts(hosts)) {
            Ok(runner) => runner
                .run_with_context(rustscript_vm::Value::Null)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error>),
            Err(error) => Err(Box::new(error)),
        };
    match result {
        Ok(value) => {
            println!("{value:?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
