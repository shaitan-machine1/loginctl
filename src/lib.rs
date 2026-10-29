pub mod admin;
pub mod cli;
pub mod config;
pub mod output;
pub mod pam;

use anyhow::Result;
use cli::{Args, Command, PamCommand};

pub fn run(args: Args) -> Result<String> {
    match args.command {
        Command::Seat { command } => admin::seat(command, args.timeout_seconds),
        Command::Session { command } => admin::session(command, args.timeout_seconds),
        Command::Scope { command } => {
            admin::scope(command, &args.cgroup_root, args.timeout_seconds)
        }
        Command::Acl { command } => admin::acl(command, args.timeout_seconds),
        Command::Pam { command } => {
            let config = config::Config::load()?;
            match command {
                PamCommand::Status => Ok(pam::status(&config.pam_file)?.render()),
                PamCommand::Activate => pam::activate(&config.pam_file),
                PamCommand::Deactivate => pam::deactivate(&config.pam_file),
            }
        }
    }
}
