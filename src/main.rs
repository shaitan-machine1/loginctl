use clap::Parser;
use loginctl::cli::Args;
use std::process::ExitCode;

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("loginctl: create async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(loginctl::run(Args::parse())) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("loginctl: {error:#}");
            ExitCode::FAILURE
        }
    }
}
