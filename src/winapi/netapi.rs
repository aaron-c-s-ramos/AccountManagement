//! NetAPI32 user and local group management operations.

use std::collections::HashMap;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_MORE_DATA};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
    NetLocalGroupDelMembers, NetLocalGroupEnum, NetLocalGroupGetMembers, NetLocalGroupSetInfo,
    NetUserAdd, NetUserDel, NetUserEnum, NetUserGetInfo, NetUserGetLocalGroups, NetUserSetInfo,
    FILTER_NORMAL_ACCOUNT, LG_INCLUDE_INDIRECT, LOCALGROUP_INFO_0, LOCALGROUP_INFO_1,
    LOCALGROUP_INFO_1002, LOCALGROUP_MEMBERS_INFO_0, LOCALGROUP_MEMBERS_INFO_2,
    LOCALGROUP_MEMBERS_INFO_3, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, USER_INFO_0,
    USER_INFO_1, USER_INFO_1003, USER_INFO_1006, USER_INFO_1007, USER_INFO_1008, USER_INFO_1009,
    USER_INFO_1011, USER_INFO_1017, USER_INFO_1020, USER_INFO_1052, USER_INFO_1053, USER_INFO_3,
    USER_INFO_4, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    LookupAccountNameW, SidTypeAlias, SidTypeDeletedAccount, SidTypeGroup, SidTypeUser,
    SidTypeWellKnownGroup, PSID, SID_NAME_USE,
};

use crate::error::AccountError;
use crate::model::{
    user_flags, validate_group_name, validate_username, GroupAccount, GroupMember, LogonHours,
    MemberKind, NewUserRequest, UserAccount, UserUpdateRequest,
};
use crate::winapi::{from_wide_ptr, sid_to_string, to_wide};

/// RAII guard that releases buffers allocated by NetAPI32 functions.
struct NetApiBuffer(*mut u8);

impl Drop for NetApiBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Pointer was allocated by a NetAPI32 call and is freed once.
            unsafe {
                NetApiBufferFree(self.0.cast());
            }
        }
    }
}

/// Converts an optional server name into a UTF-16 buffer and pointer.
fn server_wide(server: Option<&str>) -> (Option<Vec<u16>>, *const u16) {
    match server {
        Some(s) if !s.is_empty() => {
            let buf = to_wide(s);
            let ptr = buf.as_ptr();
            (Some(buf), ptr)
        }
        _ => (None, null()),
    }
}

/// Resolves the canonical SID string for an account name via LookupAccountNameW.
fn lookup_sid_string(server: Option<&str>, account_name: &str) -> String {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let acct_w = to_wide(account_name);
    let mut sid_size = 0u32;
    let mut dom_size = 0u32;
    let mut use_kind: SID_NAME_USE = 0;

    // SAFETY: Sizing call queries required SID and domain buffer lengths.
    unsafe {
        LookupAccountNameW(
            srv_ptr,
            acct_w.as_ptr(),
            null_mut(),
            &mut sid_size,
            null_mut(),
            &mut dom_size,
            &mut use_kind,
        );
    }
    if sid_size == 0 {
        return String::new();
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut dom_buf = vec![0u16; dom_size.max(1) as usize];
    // SAFETY: Buffers match the sizes returned by the first LookupAccountNameW call.
    let ok = unsafe {
        LookupAccountNameW(
            srv_ptr,
            acct_w.as_ptr(),
            sid_buf.as_mut_ptr().cast(),
            &mut sid_size,
            dom_buf.as_mut_ptr(),
            &mut dom_size,
            &mut use_kind,
        )
    };
    if ok == 0 {
        return String::new();
    }
    // SAFETY: sid_buf holds a valid Win32 SID initialized by LookupAccountNameW.
    unsafe { sid_to_string(sid_buf.as_mut_ptr().cast()) }
}

/// Lists all local user accounts on the target machine via NetUserEnum level 3.
pub fn list_users(server: Option<&str>) -> Result<Vec<UserAccount>, AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let mut users = Vec::new();
    let mut resume_handle = 0u32;

    loop {
        let mut raw_buf: *mut u8 = null_mut();
        let mut entries_read = 0u32;
        let mut total_entries = 0u32;

        // SAFETY: Output pointers are valid and freed via NetApiBuffer.
        let status = unsafe {
            NetUserEnum(
                srv_ptr,
                3,
                FILTER_NORMAL_ACCOUNT,
                &mut raw_buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        let _guard = NetApiBuffer(raw_buf);

        if status != NERR_Success && status != ERROR_MORE_DATA {
            return Err(AccountError::win32("NetUserEnum", status));
        }

        if !raw_buf.is_null() && entries_read > 0 {
            // SAFETY: NetUserEnum level 3 returns an array of USER_INFO_3 entries.
            let slice = unsafe {
                std::slice::from_raw_parts(raw_buf.cast::<USER_INFO_3>(), entries_read as usize)
            };
            for info in slice {
                // SAFETY: Strings inside USER_INFO_3 are valid NUL-terminated UTF-16 pointers or NULL.
                let name = unsafe { from_wide_ptr(info.usri3_name) };
                let full_name = unsafe { from_wide_ptr(info.usri3_full_name) };
                let comment = unsafe { from_wide_ptr(info.usri3_comment) };
                let home_dir = unsafe { from_wide_ptr(info.usri3_home_dir) };
                let home_dir_drive = unsafe { from_wide_ptr(info.usri3_home_dir_drive) };
                let profile = unsafe { from_wide_ptr(info.usri3_profile) };
                let script_path = unsafe { from_wide_ptr(info.usri3_script_path) };
                let sid = lookup_sid_string(server, &name);

                users.push(UserAccount {
                    name,
                    full_name,
                    comment,
                    sid,
                    flags: info.usri3_flags,
                    password_expired: info.usri3_password_expired != 0,
                    password_age_secs: info.usri3_password_age,
                    last_logon: info.usri3_last_logon,
                    bad_pw_count: info.usri3_bad_pw_count,
                    acct_expires: info.usri3_acct_expires,
                    home_dir,
                    home_dir_drive,
                    profile,
                    script_path,
                    logon_hours: LogonHours::all_allowed(),
                });
            }
        }

        if status != ERROR_MORE_DATA {
            break;
        }
    }

    users.sort_by_key(|a| a.name.to_lowercase());
    Ok(users)
}

/// Reads complete level-4 details including SID and 21-byte logon hours for one user.
pub fn get_user(server: Option<&str>, name: &str) -> Result<UserAccount, AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name_w = to_wide(name);
    let mut raw_buf: *mut u8 = null_mut();

    // SAFETY: Buffer pointer is initialized by NetUserGetInfo and freed via NetApiBuffer.
    let status = unsafe { NetUserGetInfo(srv_ptr, name_w.as_ptr(), 4, &mut raw_buf) };
    let _guard = NetApiBuffer(raw_buf);

    if status != NERR_Success || raw_buf.is_null() {
        return Err(AccountError::win32("NetUserGetInfo", status));
    }

    // SAFETY: NetUserGetInfo level 4 returns a valid USER_INFO_4 struct.
    let info = unsafe { &*raw_buf.cast::<USER_INFO_4>() };
    // SAFETY: String and SID pointers are owned by NetAPI buffer for the duration of _guard.
    let account_name = unsafe { from_wide_ptr(info.usri4_name) };
    let full_name = unsafe { from_wide_ptr(info.usri4_full_name) };
    let comment = unsafe { from_wide_ptr(info.usri4_comment) };
    let home_dir = unsafe { from_wide_ptr(info.usri4_home_dir) };
    let home_dir_drive = unsafe { from_wide_ptr(info.usri4_home_dir_drive) };
    let profile = unsafe { from_wide_ptr(info.usri4_profile) };
    let script_path = unsafe { from_wide_ptr(info.usri4_script_path) };
    let sid = unsafe { sid_to_string(info.usri4_user_sid) };
    let logon_hours = if info.usri4_logon_hours.is_null() {
        LogonHours::all_allowed()
    } else {
        // SAFETY: Windows USER_INFO_4.usri4_logon_hours points to 21 bytes when non-null.
        let bytes = unsafe { std::slice::from_raw_parts(info.usri4_logon_hours, 21) };
        LogonHours::from_slice_or_all(Some(bytes))
    };

    Ok(UserAccount {
        name: account_name,
        full_name,
        comment,
        sid,
        flags: info.usri4_flags,
        password_expired: info.usri4_password_expired != 0,
        password_age_secs: info.usri4_password_age,
        last_logon: info.usri4_last_logon,
        bad_pw_count: info.usri4_bad_pw_count,
        acct_expires: info.usri4_acct_expires,
        home_dir,
        home_dir_drive,
        profile,
        script_path,
        logon_hours,
    })
}

/// Creates a new local user account, applies extended fields, and adds initial groups.
pub fn create_user(server: Option<&str>, req: &NewUserRequest) -> Result<(), AccountError> {
    validate_username(&req.name)?;
    let (_srv_buf, srv_ptr) = server_wide(server);
    let mut name_w = to_wide(req.name.trim());
    let mut pw_w = to_wide(&req.password);
    let mut comment_w = to_wide(&req.comment);
    let mut home_w = to_wide(&req.home_dir);
    let mut script_w = to_wide(&req.script_path);

    let flags = req.flags | user_flags::UF_NORMAL_ACCOUNT | user_flags::UF_SCRIPT;
    let info = USER_INFO_1 {
        usri1_name: name_w.as_mut_ptr(),
        usri1_password: pw_w.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: home_w.as_mut_ptr(),
        usri1_comment: comment_w.as_mut_ptr(),
        usri1_flags: flags,
        usri1_script_path: script_w.as_mut_ptr(),
    };

    let mut parm_err = 0u32;
    // SAFETY: All wide string buffers remain alive across the NetUserAdd call.
    let status = unsafe {
        NetUserAdd(
            srv_ptr,
            1,
            (&info as *const USER_INFO_1).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserAdd", status));
    }

    let trimmed_name = req.name.trim();
    if !req.full_name.is_empty() {
        set_user_full_name(srv_ptr, trimmed_name, &req.full_name)?;
    }
    if !req.profile.is_empty() {
        set_user_profile(srv_ptr, trimmed_name, &req.profile)?;
    }
    if !req.home_dir_drive.is_empty() {
        set_user_home_drive(srv_ptr, trimmed_name, &req.home_dir_drive)?;
    }
    if req.password_expired {
        set_user_password_expired(srv_ptr, trimmed_name, true)?;
    }

    for group in &req.initial_groups {
        add_group_member(server, group, trimmed_name, None)?;
    }

    Ok(())
}

/// Updates account fields, flags, profile paths, expiration, and logon hours.
pub fn update_user(server: Option<&str>, req: &UserUpdateRequest) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name = req.name.trim();

    set_user_full_name(srv_ptr, name, &req.full_name)?;
    set_user_comment(srv_ptr, name, &req.comment)?;
    set_user_flags(srv_ptr, name, req.flags | user_flags::UF_NORMAL_ACCOUNT)?;
    set_user_home_dir(srv_ptr, name, &req.home_dir)?;
    set_user_home_drive(srv_ptr, name, &req.home_dir_drive)?;
    set_user_profile(srv_ptr, name, &req.profile)?;
    set_user_script_path(srv_ptr, name, &req.script_path)?;
    set_user_expiration(srv_ptr, name, req.acct_expires)?;
    set_user_logon_hours(srv_ptr, name, &req.logon_hours)?;
    set_user_password_expired(srv_ptr, name, req.password_expired)?;

    Ok(())
}

fn set_user_full_name(
    srv_ptr: *const u16,
    name: &str,
    full_name: &str,
) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut val_w = to_wide(full_name);
    let info = USER_INFO_1011 {
        usri1011_full_name: val_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain alive during NetUserSetInfo level 1011.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1011,
            (&info as *const USER_INFO_1011).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(full_name)", status));
    }
    Ok(())
}

fn set_user_comment(srv_ptr: *const u16, name: &str, comment: &str) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut val_w = to_wide(comment);
    let info = USER_INFO_1007 {
        usri1007_comment: val_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain alive during NetUserSetInfo level 1007.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1007,
            (&info as *const USER_INFO_1007).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(comment)", status));
    }
    Ok(())
}

fn set_user_flags(srv_ptr: *const u16, name: &str, flags: u32) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let info = USER_INFO_1008 {
        usri1008_flags: flags,
    };
    let mut parm_err = 0u32;
    // SAFETY: Struct lives across NetUserSetInfo level 1008.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1008,
            (&info as *const USER_INFO_1008).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(flags)", status));
    }
    Ok(())
}

fn set_user_home_dir(srv_ptr: *const u16, name: &str, home_dir: &str) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut val_w = to_wide(home_dir);
    let info = USER_INFO_1006 {
        usri1006_home_dir: val_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain alive during NetUserSetInfo level 1006.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1006,
            (&info as *const USER_INFO_1006).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(home_dir)", status));
    }
    Ok(())
}

fn set_user_home_drive(
    srv_ptr: *const u16,
    name: &str,
    home_dir_drive: &str,
) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut val_w = to_wide(home_dir_drive);
    let info = USER_INFO_1053 {
        usri1053_home_dir_drive: val_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain alive during NetUserSetInfo level 1053.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1053,
            (&info as *const USER_INFO_1053).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32(
            "NetUserSetInfo(home_dir_drive)",
            status,
        ));
    }
    Ok(())
}

fn set_user_profile(srv_ptr: *const u16, name: &str, profile: &str) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut val_w = to_wide(profile);
    let info = USER_INFO_1052 {
        usri1052_profile: val_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain alive during NetUserSetInfo level 1052.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1052,
            (&info as *const USER_INFO_1052).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(profile)", status));
    }
    Ok(())
}

fn set_user_script_path(
    srv_ptr: *const u16,
    name: &str,
    script_path: &str,
) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut val_w = to_wide(script_path);
    let info = USER_INFO_1009 {
        usri1009_script_path: val_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain alive during NetUserSetInfo level 1009.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1009,
            (&info as *const USER_INFO_1009).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(script_path)", status));
    }
    Ok(())
}

fn set_user_expiration(
    srv_ptr: *const u16,
    name: &str,
    acct_expires: u32,
) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let info = USER_INFO_1017 {
        usri1017_acct_expires: acct_expires,
    };
    let mut parm_err = 0u32;
    // SAFETY: Struct lives across NetUserSetInfo level 1017.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1017,
            (&info as *const USER_INFO_1017).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(acct_expires)", status));
    }
    Ok(())
}

fn set_user_logon_hours(
    srv_ptr: *const u16,
    name: &str,
    hours: &LogonHours,
) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut bytes = hours.bytes;
    let info = USER_INFO_1020 {
        usri1020_units_per_week: 168,
        usri1020_logon_hours: bytes.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: 21-byte array stays valid for NetUserSetInfo level 1020.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1020,
            (&info as *const USER_INFO_1020).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(logon_hours)", status));
    }
    Ok(())
}

fn set_user_password_expired(
    srv_ptr: *const u16,
    name: &str,
    expired: bool,
) -> Result<(), AccountError> {
    let name_w = to_wide(name);
    let mut raw_buf: *mut u8 = null_mut();
    // SAFETY: Reads current USER_INFO_3 so password stays untouched when setting password_expired.
    let get_status = unsafe { NetUserGetInfo(srv_ptr, name_w.as_ptr(), 3, &mut raw_buf) };
    let _guard = NetApiBuffer(raw_buf);
    if get_status != NERR_Success || raw_buf.is_null() {
        return Err(AccountError::win32("NetUserGetInfo(3)", get_status));
    }

    // SAFETY: Buffer contains a valid mutable USER_INFO_3 returned by NetUserGetInfo.
    let info = unsafe { &mut *raw_buf.cast::<USER_INFO_3>() };
    let desired = u32::from(expired);
    if (info.usri3_password_expired != 0) == expired {
        return Ok(());
    }
    info.usri3_password = null_mut();
    info.usri3_password_expired = desired;

    let mut parm_err = 0u32;
    // SAFETY: Modified USER_INFO_3 with NULL password leaves password unchanged.
    let set_status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            3,
            (info as *const USER_INFO_3).cast(),
            &mut parm_err,
        )
    };
    if set_status != NERR_Success {
        return Err(AccountError::win32(
            "NetUserSetInfo(password_expired)",
            set_status,
        ));
    }
    Ok(())
}

/// Changes a user account password via NetUserSetInfo level 1003.
pub fn set_user_password(
    server: Option<&str>,
    name: &str,
    password: &str,
) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name_w = to_wide(name);
    let mut pw_w = to_wide(password);
    let info = USER_INFO_1003 {
        usri1003_password: pw_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Wide buffers remain valid across NetUserSetInfo level 1003.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1003,
            (&info as *const USER_INFO_1003).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(password)", status));
    }
    Ok(())
}

/// Renames a local user account via NetUserSetInfo level 0.
pub fn rename_user(
    server: Option<&str>,
    old_name: &str,
    new_name: &str,
) -> Result<(), AccountError> {
    validate_username(new_name)?;
    let (_srv_buf, srv_ptr) = server_wide(server);
    let old_w = to_wide(old_name);
    let mut new_w = to_wide(new_name.trim());
    let info = USER_INFO_0 {
        usri0_name: new_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain valid across NetUserSetInfo level 0.
    let status = unsafe {
        NetUserSetInfo(
            srv_ptr,
            old_w.as_ptr(),
            0,
            (&info as *const USER_INFO_0).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserSetInfo(rename)", status));
    }
    Ok(())
}

/// Deletes a local user account via NetUserDel.
pub fn delete_user(server: Option<&str>, name: &str) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name_w = to_wide(name);
    // SAFETY: Wide string pointers remain valid across NetUserDel.
    let status = unsafe { NetUserDel(srv_ptr, name_w.as_ptr()) };
    if status != NERR_Success {
        return Err(AccountError::win32("NetUserDel", status));
    }
    Ok(())
}

/// Lists all local groups to which the given user belongs.
pub fn get_user_groups(server: Option<&str>, name: &str) -> Result<Vec<String>, AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name_w = to_wide(name);
    let mut raw_buf: *mut u8 = null_mut();
    let mut entries_read = 0u32;
    let mut total_entries = 0u32;

    // SAFETY: Output buffer is released via NetApiBuffer.
    let status = unsafe {
        NetUserGetLocalGroups(
            srv_ptr,
            name_w.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut raw_buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };
    let _guard = NetApiBuffer(raw_buf);

    if status != NERR_Success {
        return Err(AccountError::win32("NetUserGetLocalGroups", status));
    }

    let mut groups = Vec::new();
    if !raw_buf.is_null() && entries_read > 0 {
        // SAFETY: NetUserGetLocalGroups level 0 returns LOCALGROUP_USERS_INFO_0 entries.
        let slice = unsafe {
            std::slice::from_raw_parts(
                raw_buf.cast::<LOCALGROUP_USERS_INFO_0>(),
                entries_read as usize,
            )
        };
        for entry in slice {
            // SAFETY: String pointer is valid inside the NetAPI buffer.
            groups.push(unsafe { from_wide_ptr(entry.lgrui0_name) });
        }
    }
    groups.sort_by_key(|a| a.to_lowercase());
    Ok(groups)
}

/// Lists all local security groups on the target machine via NetLocalGroupEnum level 1.
pub fn list_groups(server: Option<&str>) -> Result<Vec<GroupAccount>, AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let mut groups = Vec::new();
    let mut resume_handle: usize = 0;

    loop {
        let mut raw_buf: *mut u8 = null_mut();
        let mut entries_read = 0u32;
        let mut total_entries = 0u32;

        // SAFETY: Output buffer is released via NetApiBuffer.
        let status = unsafe {
            NetLocalGroupEnum(
                srv_ptr,
                1,
                &mut raw_buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        let _guard = NetApiBuffer(raw_buf);

        if status != NERR_Success && status != ERROR_MORE_DATA {
            return Err(AccountError::win32("NetLocalGroupEnum", status));
        }

        if !raw_buf.is_null() && entries_read > 0 {
            // SAFETY: NetLocalGroupEnum level 1 returns LOCALGROUP_INFO_1 entries.
            let slice = unsafe {
                std::slice::from_raw_parts(
                    raw_buf.cast::<LOCALGROUP_INFO_1>(),
                    entries_read as usize,
                )
            };
            for info in slice {
                // SAFETY: Strings inside LOCALGROUP_INFO_1 are valid UTF-16 pointers or NULL.
                let name = unsafe { from_wide_ptr(info.lgrpi1_name) };
                let comment = unsafe { from_wide_ptr(info.lgrpi1_comment) };
                let sid = lookup_sid_string(server, &name);
                groups.push(GroupAccount { name, comment, sid });
            }
        }

        if status != ERROR_MORE_DATA {
            break;
        }
    }

    groups.sort_by_key(|a| a.name.to_lowercase());
    Ok(groups)
}

/// Creates a new local security group via NetLocalGroupAdd level 1.
pub fn create_group(server: Option<&str>, name: &str, comment: &str) -> Result<(), AccountError> {
    validate_group_name(name)?;
    let (_srv_buf, srv_ptr) = server_wide(server);
    let mut name_w = to_wide(name.trim());
    let mut comment_w = to_wide(comment);
    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: name_w.as_mut_ptr(),
        lgrpi1_comment: comment_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain valid during NetLocalGroupAdd.
    let status = unsafe {
        NetLocalGroupAdd(
            srv_ptr,
            1,
            (&info as *const LOCALGROUP_INFO_1).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetLocalGroupAdd", status));
    }
    Ok(())
}

/// Updates the comment of an existing local security group.
pub fn update_group_comment(
    server: Option<&str>,
    name: &str,
    comment: &str,
) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name_w = to_wide(name);
    let mut comment_w = to_wide(comment);
    let info = LOCALGROUP_INFO_1002 {
        lgrpi1002_comment: comment_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain valid during NetLocalGroupSetInfo level 1002.
    let status = unsafe {
        NetLocalGroupSetInfo(
            srv_ptr,
            name_w.as_ptr(),
            1002,
            (&info as *const LOCALGROUP_INFO_1002).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetLocalGroupSetInfo(comment)", status));
    }
    Ok(())
}

/// Renames an existing local security group via NetLocalGroupSetInfo level 0.
pub fn rename_group(
    server: Option<&str>,
    old_name: &str,
    new_name: &str,
) -> Result<(), AccountError> {
    validate_group_name(new_name)?;
    let (_srv_buf, srv_ptr) = server_wide(server);
    let old_w = to_wide(old_name);
    let mut new_w = to_wide(new_name.trim());
    let info = LOCALGROUP_INFO_0 {
        lgrpi0_name: new_w.as_mut_ptr(),
    };
    let mut parm_err = 0u32;
    // SAFETY: Buffers remain valid during NetLocalGroupSetInfo level 0.
    let status = unsafe {
        NetLocalGroupSetInfo(
            srv_ptr,
            old_w.as_ptr(),
            0,
            (&info as *const LOCALGROUP_INFO_0).cast(),
            &mut parm_err,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetLocalGroupSetInfo(rename)", status));
    }
    Ok(())
}

/// Deletes an existing local security group via NetLocalGroupDel.
pub fn delete_group(server: Option<&str>, name: &str) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let name_w = to_wide(name);
    // SAFETY: Wide pointers remain valid during NetLocalGroupDel.
    let status = unsafe { NetLocalGroupDel(srv_ptr, name_w.as_ptr()) };
    if status != NERR_Success {
        return Err(AccountError::win32("NetLocalGroupDel", status));
    }
    Ok(())
}

/// Maps Win32 SID_NAME_USE values to MemberKind.
fn map_sid_usage(usage: SID_NAME_USE) -> MemberKind {
    match usage {
        x if x == SidTypeUser => MemberKind::User,
        x if x == SidTypeGroup => MemberKind::Group,
        x if x == SidTypeAlias => MemberKind::Alias,
        x if x == SidTypeWellKnownGroup => MemberKind::WellKnownGroup,
        x if x == SidTypeDeletedAccount => MemberKind::Deleted,
        _ => MemberKind::Unknown,
    }
}

/// Lists all members of a local security group via NetLocalGroupGetMembers level 2.
pub fn list_group_members(
    server: Option<&str>,
    group_name: &str,
    known_users: &[UserAccount],
) -> Result<Vec<GroupMember>, AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let group_w = to_wide(group_name);
    let mut members = Vec::new();
    let mut resume_handle: usize = 0;

    let mut disabled_by_sid: HashMap<&str, bool> = HashMap::new();
    let mut disabled_by_name: HashMap<String, bool> = HashMap::new();
    for u in known_users {
        if !u.sid.is_empty() {
            disabled_by_sid.insert(u.sid.as_str(), u.is_disabled());
        }
        disabled_by_name.insert(u.name.to_lowercase(), u.is_disabled());
    }

    loop {
        let mut raw_buf: *mut u8 = null_mut();
        let mut entries_read = 0u32;
        let mut total_entries = 0u32;

        // SAFETY: Output buffer is released via NetApiBuffer.
        let status = unsafe {
            NetLocalGroupGetMembers(
                srv_ptr,
                group_w.as_ptr(),
                2,
                &mut raw_buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        let _guard = NetApiBuffer(raw_buf);

        if status != NERR_Success && status != ERROR_MORE_DATA {
            return Err(AccountError::win32("NetLocalGroupGetMembers", status));
        }

        if !raw_buf.is_null() && entries_read > 0 {
            // SAFETY: Level 2 returns LOCALGROUP_MEMBERS_INFO_2 entries.
            let slice = unsafe {
                std::slice::from_raw_parts(
                    raw_buf.cast::<LOCALGROUP_MEMBERS_INFO_2>(),
                    entries_read as usize,
                )
            };
            for info in slice {
                // SAFETY: Strings and SIDs belong to NetAPI buffer for _guard's lifetime.
                let domain_and_name = unsafe { from_wide_ptr(info.lgrmi2_domainandname) };
                let sid = unsafe { sid_to_string(info.lgrmi2_sid) };
                let kind = map_sid_usage(info.lgrmi2_sidusage);
                let short_name = domain_and_name
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&domain_and_name)
                    .to_string();
                let is_disabled = if kind == MemberKind::User {
                    disabled_by_sid
                        .get(sid.as_str())
                        .copied()
                        .or_else(|| disabled_by_name.get(&short_name.to_lowercase()).copied())
                } else {
                    None
                };

                members.push(GroupMember {
                    name: if short_name.is_empty() {
                        sid.clone()
                    } else {
                        short_name
                    },
                    domain_and_name: if domain_and_name.is_empty() {
                        sid.clone()
                    } else {
                        domain_and_name
                    },
                    sid,
                    kind,
                    is_disabled,
                });
            }
        }

        if status != ERROR_MORE_DATA {
            break;
        }
    }

    members.sort_by_key(|a| a.name.to_lowercase());
    Ok(members)
}

/// Adds a member to a local group by SID (level 0) or domain\name (level 3).
pub fn add_group_member(
    server: Option<&str>,
    group_name: &str,
    member_name: &str,
    member_sid: Option<&str>,
) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let group_w = to_wide(group_name);

    if let Some(sid_str) = member_sid.filter(|s| !s.is_empty()) {
        let sid_w = to_wide(sid_str);
        let mut psid: PSID = null_mut();
        // SAFETY: ConvertStringSidToSidW allocates a PSID freed with LocalFree.
        let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) };
        if ok != 0 && !psid.is_null() {
            let entry = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: psid };
            // SAFETY: psid stays valid across NetLocalGroupAddMembers and is freed below.
            let status = unsafe {
                NetLocalGroupAddMembers(
                    srv_ptr,
                    group_w.as_ptr(),
                    0,
                    (&entry as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
                    1,
                )
            };
            // SAFETY: Free SID allocated by ConvertStringSidToSidW.
            unsafe {
                LocalFree(psid);
            }
            if status == NERR_Success {
                return Ok(());
            }
            return Err(AccountError::win32("NetLocalGroupAddMembers(sid)", status));
        }
    }

    let mut member_w = to_wide(member_name.trim());
    let entry = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: member_w.as_mut_ptr(),
    };
    // SAFETY: Buffer stays valid across NetLocalGroupAddMembers level 3.
    let status = unsafe {
        NetLocalGroupAddMembers(
            srv_ptr,
            group_w.as_ptr(),
            3,
            (&entry as *const LOCALGROUP_MEMBERS_INFO_3).cast(),
            1,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetLocalGroupAddMembers", status));
    }
    Ok(())
}

/// Removes a member from a local group by SID (level 0) or domain\name (level 3).
pub fn remove_group_member(
    server: Option<&str>,
    group_name: &str,
    member_name: &str,
    member_sid: Option<&str>,
) -> Result<(), AccountError> {
    let (_srv_buf, srv_ptr) = server_wide(server);
    let group_w = to_wide(group_name);

    if let Some(sid_str) = member_sid.filter(|s| !s.is_empty()) {
        let sid_w = to_wide(sid_str);
        let mut psid: PSID = null_mut();
        // SAFETY: ConvertStringSidToSidW allocates a PSID freed with LocalFree.
        let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) };
        if ok != 0 && !psid.is_null() {
            let entry = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: psid };
            // SAFETY: psid stays valid across NetLocalGroupDelMembers and is freed below.
            let status = unsafe {
                NetLocalGroupDelMembers(
                    srv_ptr,
                    group_w.as_ptr(),
                    0,
                    (&entry as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
                    1,
                )
            };
            // SAFETY: Free SID allocated by ConvertStringSidToSidW.
            unsafe {
                LocalFree(psid);
            }
            if status == NERR_Success {
                return Ok(());
            }
            return Err(AccountError::win32("NetLocalGroupDelMembers(sid)", status));
        }
    }

    let mut member_w = to_wide(member_name.trim());
    let entry = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: member_w.as_mut_ptr(),
    };
    // SAFETY: Buffer stays valid across NetLocalGroupDelMembers level 3.
    let status = unsafe {
        NetLocalGroupDelMembers(
            srv_ptr,
            group_w.as_ptr(),
            3,
            (&entry as *const LOCALGROUP_MEMBERS_INFO_3).cast(),
            1,
        )
    };
    if status != NERR_Success {
        return Err(AccountError::win32("NetLocalGroupDelMembers", status));
    }
    Ok(())
}
