use clap::Parser;
use loginctl::cli::Args;
use std::process::ExitCode;

fn main() -> ExitCode {
    match loginctl::run(Args::parse()) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("loginctl: {}", loginctl::output::failure(&error));
            ExitCode::FAILURE
        }
    }
}
