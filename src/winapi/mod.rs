//! Windows NetAPI32, LSA, and WNet account management backend.

#[cfg(windows)]
pub mod lsa;
#[cfg(windows)]
pub mod netapi;
#[cfg(windows)]
pub mod wnet;

use chrono::Local;

use crate::error::AccountError;
use crate::model::{
    BuiltInPrincipal, GroupAccount, GroupMember, NewUserRequest, UserAccount, UserUpdateRequest,
};

/// Defines local and remote Windows account management operations.
pub trait AccountBackend {
    /// Lists all local user accounts on the target machine.
    fn list_users(&self, server: Option<&str>) -> Result<Vec<UserAccount>, AccountError>;

    /// Loads full level-4 properties for one user account.
    fn get_user(&self, server: Option<&str>, name: &str) -> Result<UserAccount, AccountError>;

    /// Creates a new local user account and adds it to any requested initial groups.
    fn create_user(&self, server: Option<&str>, req: &NewUserRequest) -> Result<(), AccountError>;

    /// Updates properties, flags, profile paths, and logon hours for a user account.
    fn update_user(
        &self,
        server: Option<&str>,
        req: &UserUpdateRequest,
    ) -> Result<(), AccountError>;

    /// Sets or resets the password for a user account.
    fn set_user_password(
        &self,
        server: Option<&str>,
        name: &str,
        password: &str,
    ) -> Result<(), AccountError>;

    /// Renames a local user account.
    fn rename_user(
        &self,
        server: Option<&str>,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), AccountError>;

    /// Deletes a local user account.
    fn delete_user(&self, server: Option<&str>, name: &str) -> Result<(), AccountError>;

    /// Lists local groups that contain the specified user account.
    fn get_user_groups(
        &self,
        server: Option<&str>,
        name: &str,
    ) -> Result<Vec<String>, AccountError>;

    /// Lists all local security groups on the target machine.
    fn list_groups(&self, server: Option<&str>) -> Result<Vec<GroupAccount>, AccountError>;

    /// Creates a new local security group.
    fn create_group(
        &self,
        server: Option<&str>,
        name: &str,
        comment: &str,
    ) -> Result<(), AccountError>;

    /// Updates the description of an existing local security group.
    fn update_group_comment(
        &self,
        server: Option<&str>,
        name: &str,
        comment: &str,
    ) -> Result<(), AccountError>;

    /// Renames an existing local security group.
    fn rename_group(
        &self,
        server: Option<&str>,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), AccountError>;

    /// Deletes an existing local security group.
    fn delete_group(&self, server: Option<&str>, name: &str) -> Result<(), AccountError>;

    /// Lists members of a local security group, annotated with local disabled flags.
    fn list_group_members(
        &self,
        server: Option<&str>,
        group_name: &str,
        known_users: &[UserAccount],
    ) -> Result<Vec<GroupMember>, AccountError>;

    /// Adds a member to a local group by SID (preferred) or account name.
    fn add_group_member(
        &self,
        server: Option<&str>,
        group_name: &str,
        member_name: &str,
        member_sid: Option<&str>,
    ) -> Result<(), AccountError>;

    /// Removes a member from a local group by SID (preferred) or account name.
    fn remove_group_member(
        &self,
        server: Option<&str>,
        group_name: &str,
        member_name: &str,
        member_sid: Option<&str>,
    ) -> Result<(), AccountError>;

    /// Lists well-known built-in security principals resolved via LSA.
    fn list_builtin_principals(
        &self,
        server: Option<&str>,
    ) -> Result<Vec<BuiltInPrincipal>, AccountError>;

    /// Connects an authenticated WNet IPC$ session to a remote computer.
    fn connect_remote(
        &self,
        host: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), AccountError>;

    /// Disconnects a previously established WNet IPC$ session.
    fn disconnect_remote(&self, host: &str) -> Result<(), AccountError>;
}

/// Live Windows backend backed by NetAPI32, Advapi32 LSA, and MPR WNet.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsBackend;

#[cfg(windows)]
impl AccountBackend for WindowsBackend {
    fn list_users(&self, server: Option<&str>) -> Result<Vec<UserAccount>, AccountError> {
        netapi::list_users(server)
    }

    fn get_user(&self, server: Option<&str>, name: &str) -> Result<UserAccount, AccountError> {
        netapi::get_user(server, name)
    }

    fn create_user(&self, server: Option<&str>, req: &NewUserRequest) -> Result<(), AccountError> {
        netapi::create_user(server, req)
    }

    fn update_user(
        &self,
        server: Option<&str>,
        req: &UserUpdateRequest,
    ) -> Result<(), AccountError> {
        netapi::update_user(server, req)
    }

    fn set_user_password(
        &self,
        server: Option<&str>,
        name: &str,
        password: &str,
    ) -> Result<(), AccountError> {
        netapi::set_user_password(server, name, password)
    }

    fn rename_user(
        &self,
        server: Option<&str>,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), AccountError> {
        netapi::rename_user(server, old_name, new_name)
    }

    fn delete_user(&self, server: Option<&str>, name: &str) -> Result<(), AccountError> {
        netapi::delete_user(server, name)
    }

    fn get_user_groups(
        &self,
        server: Option<&str>,
        name: &str,
    ) -> Result<Vec<String>, AccountError> {
        netapi::get_user_groups(server, name)
    }

    fn list_groups(&self, server: Option<&str>) -> Result<Vec<GroupAccount>, AccountError> {
        netapi::list_groups(server)
    }

    fn create_group(
        &self,
        server: Option<&str>,
        name: &str,
        comment: &str,
    ) -> Result<(), AccountError> {
        netapi::create_group(server, name, comment)
    }

    fn update_group_comment(
        &self,
        server: Option<&str>,
        name: &str,
        comment: &str,
    ) -> Result<(), AccountError> {
        netapi::update_group_comment(server, name, comment)
    }

    fn rename_group(
        &self,
        server: Option<&str>,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), AccountError> {
        netapi::rename_group(server, old_name, new_name)
    }

    fn delete_group(&self, server: Option<&str>, name: &str) -> Result<(), AccountError> {
        netapi::delete_group(server, name)
    }

    fn list_group_members(
        &self,
        server: Option<&str>,
        group_name: &str,
        known_users: &[UserAccount],
    ) -> Result<Vec<GroupMember>, AccountError> {
        netapi::list_group_members(server, group_name, known_users)
    }

    fn add_group_member(
        &self,
        server: Option<&str>,
        group_name: &str,
        member_name: &str,
        member_sid: Option<&str>,
    ) -> Result<(), AccountError> {
        netapi::add_group_member(server, group_name, member_name, member_sid)
    }

    fn remove_group_member(
        &self,
        server: Option<&str>,
        group_name: &str,
        member_name: &str,
        member_sid: Option<&str>,
    ) -> Result<(), AccountError> {
        netapi::remove_group_member(server, group_name, member_name, member_sid)
    }

    fn list_builtin_principals(
        &self,
        server: Option<&str>,
    ) -> Result<Vec<BuiltInPrincipal>, AccountError> {
        lsa::list_builtin_principals(server)
    }

    fn connect_remote(
        &self,
        host: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), AccountError> {
        wnet::connect_remote(host, username, password)
    }

    fn disconnect_remote(&self, host: &str) -> Result<(), AccountError> {
        wnet::disconnect_remote(host)
    }
}

#[cfg(not(windows))]
impl AccountBackend for WindowsBackend {
    fn list_users(&self, _server: Option<&str>) -> Result<Vec<UserAccount>, AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn get_user(&self, _server: Option<&str>, _name: &str) -> Result<UserAccount, AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn create_user(
        &self,
        _server: Option<&str>,
        _req: &NewUserRequest,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn update_user(
        &self,
        _server: Option<&str>,
        _req: &UserUpdateRequest,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn set_user_password(
        &self,
        _server: Option<&str>,
        _name: &str,
        _password: &str,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn rename_user(
        &self,
        _server: Option<&str>,
        _old_name: &str,
        _new_name: &str,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn delete_user(&self, _server: Option<&str>, _name: &str) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn get_user_groups(
        &self,
        _server: Option<&str>,
        _name: &str,
    ) -> Result<Vec<String>, AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn list_groups(&self, _server: Option<&str>) -> Result<Vec<GroupAccount>, AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn create_group(
        &self,
        _server: Option<&str>,
        _name: &str,
        _comment: &str,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn update_group_comment(
        &self,
        _server: Option<&str>,
        _name: &str,
        _comment: &str,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn rename_group(
        &self,
        _server: Option<&str>,
        _old_name: &str,
        _new_name: &str,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn delete_group(&self, _server: Option<&str>, _name: &str) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn list_group_members(
        &self,
        _server: Option<&str>,
        _group_name: &str,
        _known_users: &[UserAccount],
    ) -> Result<Vec<GroupMember>, AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn add_group_member(
        &self,
        _server: Option<&str>,
        _group_name: &str,
        _member_name: &str,
        _member_sid: Option<&str>,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn remove_group_member(
        &self,
        _server: Option<&str>,
        _group_name: &str,
        _member_name: &str,
        _member_sid: Option<&str>,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn list_builtin_principals(
        &self,
        _server: Option<&str>,
    ) -> Result<Vec<BuiltInPrincipal>, AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn connect_remote(
        &self,
        _host: &str,
        _username: Option<&str>,
        _password: Option<&str>,
    ) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }

    fn disconnect_remote(&self, _host: &str) -> Result<(), AccountError> {
        Err(AccountError::UnsupportedPlatform)
    }
}

/// Returns the local Windows NetBIOS computer name.
#[cfg(windows)]
pub fn local_computer_name() -> String {
    use windows_sys::Win32::System::SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW};
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: Buffer pointer and length are valid for GetComputerNameExW.
    let ok = unsafe { GetComputerNameExW(ComputerNameNetBIOS, buf.as_mut_ptr(), &mut len) };
    if ok != 0 && len > 0 {
        String::from_utf16_lossy(&buf[..len as usize])
    } else {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "LOCALHOST".to_string())
    }
}

/// Returns a placeholder computer name on non-Windows hosts.
#[cfg(not(windows))]
pub fn local_computer_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "LOCALHOST".to_string())
}

/// Checks whether the current process token holds elevated administrative rights.
#[cfg(windows)]
pub fn is_process_elevated() -> bool {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle for OpenProcessToken.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len = 0u32;
    // SAFETY: Token handle is open and elevation buffer matches size_of::<TOKEN_ELEVATION>().
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    // SAFETY: Close the token handle obtained from OpenProcessToken.
    unsafe {
        CloseHandle(token);
    }
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Returns false on non-Windows hosts.
#[cfg(not(windows))]
pub fn is_process_elevated() -> bool {
    false
}

/// Returns the local timezone UTC offset rounded to whole hours for logon-hour display.
pub fn local_tz_offset_hours() -> i32 {
    Local::now().offset().local_minus_utc() / 3600
}

/// Encodes a Rust string as a NUL-terminated UTF-16 vector for Win32 calls.
#[cfg(windows)]
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decodes a NUL-terminated UTF-16 pointer into a Rust String.
#[cfg(windows)]
pub(crate) unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Converts a raw Win32 PSID into its canonical "S-1-..." string form.
#[cfg(windows)]
pub(crate) unsafe fn sid_to_string(psid: windows_sys::Win32::Security::PSID) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    if psid.is_null() {
        return String::new();
    }
    let mut raw_str: *mut u16 = std::ptr::null_mut();
    let ok = ConvertSidToStringSidW(psid, &mut raw_str);
    if ok == 0 || raw_str.is_null() {
        return String::new();
    }
    let text = from_wide_ptr(raw_str);
    LocalFree(raw_str.cast());
    text
}
