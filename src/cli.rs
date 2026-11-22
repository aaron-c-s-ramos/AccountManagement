//! Command-line inspection interface and GUI launcher for `lusrmgr`.

use crate::model::normalize_server_name;
use crate::winapi::{is_process_elevated, local_computer_name, AccountBackend, WindowsBackend};

/// Current application version string.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parses CLI arguments, runs read-only inspection commands, or launches the desktop GUI.
pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        hide_standalone_windows_console();
        return match crate::gui::run_gui() {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("GUI error: {err}");
                1
            }
        };
    }

    let mut mode: Option<&str> = None;
    let mut server_arg: Option<String> = None;
    let mut json_output = false;

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => {
                print_help();
                return 0;
            }
            "-V" | "--version" => {
                println!("lusrmgr {APP_VERSION}");
                return 0;
            }
            "--gui" => {
                mode = Some("gui");
            }
            "--list-users" => {
                mode = Some("users");
            }
            "--list-groups" => {
                mode = Some("groups");
            }
            "--list-builtin" => {
                mode = Some("builtin");
            }
            "--check-admin" => {
                mode = Some("admin");
            }
            "--json" => {
                json_output = true;
            }
            "--server" => {
                if idx + 1 >= args.len() {
                    eprintln!("Error: --server requires a hostname or IP address.");
                    return 2;
                }
                idx += 1;
                server_arg = Some(args[idx].clone());
            }
            unknown => {
                eprintln!("Unknown option: {unknown}");
                eprintln!("Run 'lusrmgr --help' for usage information.");
                return 2;
            }
        }
        idx += 1;
    }

    let local = local_computer_name();
    let normalized_server = server_arg
        .as_deref()
        .and_then(|s| normalize_server_name(s, &local));
    let backend = WindowsBackend;

    match mode {
        None | Some("gui") => {
            hide_standalone_windows_console();
            match crate::gui::run_gui() {
                Ok(()) => 0,
                Err(err) => {
                    eprintln!("GUI error: {err}");
                    1
                }
            }
        }
        Some("admin") => {
            let elevated = is_process_elevated();
            if json_output {
                println!(
                    "{{\"computer\":\"{}\",\"elevated\":{}}}",
                    local.replace('"', "\\\""),
                    elevated
                );
            } else {
                println!(
                    "Computer: {local}\nElevated Administrator: {}",
                    if elevated { "Yes" } else { "No" }
                );
            }
            0
        }
        Some("users") => match backend.list_users(normalized_server.as_deref()) {
            Ok(users) => {
                if json_output {
                    match serde_json::to_string_pretty(&users) {
                        Ok(text) => println!("{text}"),
                        Err(err) => {
                            eprintln!("JSON error: {err}");
                            return 1;
                        }
                    }
                } else {
                    println!(
                        "{:<22} {:<16} {:<24} Description",
                        "Name", "Status", "Full Name"
                    );
                    println!("{}", "-".repeat(80));
                    for user in &users {
                        println!(
                            "{:<22} {:<16} {:<24} {}",
                            user.name,
                            user.status_label(),
                            user.full_name,
                            user.comment
                        );
                    }
                    println!("\nTotal users: {}", users.len());
                }
                0
            }
            Err(err) => {
                eprintln!("Error: {err}");
                1
            }
        },
        Some("groups") => match backend.list_groups(normalized_server.as_deref()) {
            Ok(groups) => {
                if json_output {
                    match serde_json::to_string_pretty(&groups) {
                        Ok(text) => println!("{text}"),
                        Err(err) => {
                            eprintln!("JSON error: {err}");
                            return 1;
                        }
                    }
                } else {
                    println!("{:<32} Description", "Group Name");
                    println!("{}", "-".repeat(80));
                    for group in &groups {
                        println!("{:<32} {}", group.name, group.comment);
                    }
                    println!("\nTotal groups: {}", groups.len());
                }
                0
            }
            Err(err) => {
                eprintln!("Error: {err}");
                1
            }
        },
        Some("builtin") => match backend.list_builtin_principals(normalized_server.as_deref()) {
            Ok(principals) => {
                if json_output {
                    match serde_json::to_string_pretty(&principals) {
                        Ok(text) => println!("{text}"),
                        Err(err) => {
                            eprintln!("JSON error: {err}");
                            return 1;
                        }
                    }
                } else {
                    println!("{:<36} {:<24} SID", "Name", "Domain");
                    println!("{}", "-".repeat(88));
                    for item in &principals {
                        println!("{:<36} {:<24} {}", item.name, item.domain, item.sid);
                    }
                    println!("\nTotal built-in security principals: {}", principals.len());
                }
                0
            }
            Err(err) => {
                eprintln!("Error: {err}");
                1
            }
        },
        Some(_) => 2,
    }
}

/// Prints CLI usage documentation to stdout.
fn print_help() {
    println!(
        "Local User and Group Management (lusrmgr) {APP_VERSION}

Usage:
  lusrmgr [OPTIONS]

Options:
  --gui               Launch the desktop graphical interface (default when no options are given)
  --list-users        List local user accounts with enabled/disabled status
  --list-groups       List local security groups
  --list-builtin      List built-in well-known security principals and SIDs
  --check-admin       Show local computer name and whether the process is elevated
  --server <HOST>     Target a remote Windows computer for read-only inspection
  --json              Emit machine-readable JSON output for inspection commands
  -V, --version       Print version information
  -h, --help          Print this help message"
    );
}

/// Detaches a standalone console window when launched by double-click in Explorer.
#[cfg(windows)]
fn hide_standalone_windows_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};

    let mut pids = [0u32; 4];
    // SAFETY: Buffer pointer and length are valid for GetConsoleProcessList.
    let count = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    if count == 1 {
        // SAFETY: Only this process owns the console window, so detaching hides it cleanly.
        unsafe {
            FreeConsole();
        }
    }
}

/// No-op on non-Windows platforms.
#[cfg(not(windows))]
fn hide_standalone_windows_console() {}
