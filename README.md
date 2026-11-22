# Local User and Group Management (`lusrmgr`)

Local User and Group Management (`lusrmgr`) is a native Rust desktop application and command-line inspection tool for Windows local user accounts, local security groups, and built-in well-known security principals. It provides a standalone alternative to the built-in Windows `lusrmgr.msc` snap-in on all Windows editions, including Windows Home editions where `lusrmgr.msc` is unavailable.

Version `2.0.0` replaces the legacy `.NET Framework` Visual Basic implementation with a compiled Rust codebase powered directly by Win32 `NetAPI32`, `Advapi32` LSA, `MPR` WNet, and an `eframe`/`egui` desktop interface.

## Features

- Manage local user accounts: create, edit properties, enable or disable accounts, unlock locked accounts, reset passwords, rename, and delete.
- Display a high-contrast red circular disabled-state badge on disabled user accounts across the main Users table, Group Members lists, and Global Search results.
- Edit advanced user properties: account flags, expiration dates, profile paths, logon scripts, home folder mappings, local group memberships, and interactive 7x24 weekly logon hours.
- Manage local security groups: create, edit descriptions, add or remove local users, domain accounts, and built-in security principals, rename, and delete.
- Inspect built-in well-known Windows security principals resolved through LSA with numeric SID sorting and clipboard copy actions.
- Connect to remote Windows computers over `WNet` IPC$ sessions with optional explicit credentials.
- Filter active tables instantly with Quick Filter or search across one or all connected computers with Global Search.
- Switch between clean Dark Mode and Light Mode with `1.5x` scaled typography and persistent preferences.
- Run read-only account, group, and built-in principal inspections from the command line with human-readable tables or `--json` output.

## System Requirements

- Windows 10 or Windows 11 (x64). No `.NET Framework` runtime is necessary.
- Standard users can inspect local accounts and principals in read-only mode.
- Administrative elevation (or remote administrative credentials) is necessary to create, modify, rename, or delete accounts and groups.

## Usage

### Desktop Interface

Run `lusrmgr.exe` without arguments (or pass `--gui`) to open the graphical interface:

```powershell
lusrmgr.exe
```

Use the left **Computers** sidebar to switch between **Users**, **Groups**, and **Built-in Security Principals**, or click **Connect Remote...** to administer another Windows machine on the network. Press `F5` to refresh account lists and `Ctrl+F` to open **Global Search**.

### Command-Line Inspection

`lusrmgr` supports safe read-only command-line queries for scripting and audits:

```powershell
# Print version information
lusrmgr.exe --version

# Check local computer name and elevation state
lusrmgr.exe --check-admin

# List local user accounts with Active / Disabled / Locked status
lusrmgr.exe --list-users

# List local security groups in JSON format
lusrmgr.exe --list-groups --json

# List built-in well-known security principals on a remote machine
lusrmgr.exe --list-builtin --server SERVER01
```

## Build and Test

Install the Rust toolchain (edition 2021 or newer), then run:

```powershell
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The compiled executable is written to `target\release\lusrmgr.exe`.

## Attribution

This repository is a Rust port and continuation of [akruhler/AccountManagement](https://github.com/akruhler/AccountManagement) (originally created by `akruhler` / `proviq/lusrmgr`).

## License

Licensed under the GNU General Public License v3.0 (`GPL-3.0-only`). Refer to [LICENSE](LICENSE) for the complete license text.
