//! Windows WNet IPC$ session management for remote computer administration.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::WNet::{
    WNetAddConnection2W, WNetCancelConnection2W, NETRESOURCEW, RESOURCETYPE_ANY,
};

use crate::error::AccountError;
use crate::winapi::to_wide;

/// Formats a hostname into an IPC$ administrative UNC target (`\\HOST\IPC$`).
fn ipc_share_path(host: &str) -> Result<String, AccountError> {
    let clean = host.trim().trim_start_matches('\\');
    if clean.is_empty() {
        return Err(AccountError::Validation(
            "Remote computer name cannot be empty.".to_string(),
        ));
    }
    Ok(format!("\\\\{clean}\\IPC$"))
}

/// Establishes a WNet IPC$ connection to a remote Windows machine.
pub fn connect_remote(
    host: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), AccountError> {
    let target = ipc_share_path(host)?;
    let mut target_w = to_wide(&target);

    let user_w = username.filter(|u| !u.trim().is_empty()).map(to_wide);
    let pass_w = if user_w.is_some() {
        Some(to_wide(password.unwrap_or_default()))
    } else {
        password.filter(|p| !p.is_empty()).map(to_wide)
    };

    let resource = NETRESOURCEW {
        dwScope: 0,
        dwType: RESOURCETYPE_ANY,
        dwDisplayType: 0,
        dwUsage: 0,
        lpLocalName: null_mut(),
        lpRemoteName: target_w.as_mut_ptr(),
        lpComment: null_mut(),
        lpProvider: null_mut(),
    };

    let user_ptr = user_w.as_ref().map_or(null(), |v| v.as_ptr());
    let pass_ptr = pass_w.as_ref().map_or(null(), |v| v.as_ptr());

    // SAFETY: Resource struct and wide string buffers remain alive across WNetAddConnection2W.
    let status = unsafe { WNetAddConnection2W(&resource, pass_ptr, user_ptr, 0) };
    if status != NO_ERROR {
        return Err(AccountError::win32("WNetAddConnection2W", status));
    }
    Ok(())
}

/// Closes an active WNet IPC$ connection to a remote Windows machine.
pub fn disconnect_remote(host: &str) -> Result<(), AccountError> {
    let target = ipc_share_path(host)?;
    let target_w = to_wide(&target);

    // SAFETY: Target string buffer stays alive across WNetCancelConnection2W.
    let status = unsafe { WNetCancelConnection2W(target_w.as_ptr(), 0, 1) };
    // ERROR_NOT_CONNECTED (2250) means no explicit IPC$ session was active.
    if status != NO_ERROR && status != 2250 {
        return Err(AccountError::win32("WNetCancelConnection2W", status));
    }
    Ok(())
}
