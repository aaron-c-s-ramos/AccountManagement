//! Entry point for the `lusrmgr` Local User and Group Management binary.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = account_management::cli::run_cli(&args);
    ExitCode::from(code.clamp(0, 255) as u8)
}
