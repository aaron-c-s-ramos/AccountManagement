//! Windows LSA resolution for built-in well-known security principals.

use std::collections::HashSet;
use std::mem::zeroed;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Security::Authentication::Identity::{
    LsaClose, LsaFreeMemory, LsaLookupSids, LsaNtStatusToWinError, LsaOpenPolicy, LSA_HANDLE,
    LSA_OBJECT_ATTRIBUTES, LSA_REFERENCED_DOMAIN_LIST, LSA_TRANSLATED_NAME, LSA_UNICODE_STRING,
    POLICY_LOOKUP_NAMES,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, SidTypeInvalid, SidTypeUnknown, PSID, SECURITY_MAX_SID_SIZE,
};

use crate::error::AccountError;
use crate::model::{compare_sids, BuiltInPrincipal};
use crate::winapi::{sid_to_string, to_wide};

/// RAII wrapper that closes an LSA_HANDLE automatically.
struct LsaPolicyGuard(LSA_HANDLE);

impl Drop for LsaPolicyGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: Handle came from LsaOpenPolicy and is closed once.
            unsafe {
                LsaClose(self.0);
            }
        }
    }
}

/// Converts an LSA_UNICODE_STRING into a Rust String.
unsafe fn lsa_string_to_rust(ustr: &LSA_UNICODE_STRING) -> String {
    if ustr.Buffer.is_null() || ustr.Length == 0 {
        return String::new();
    }
    let units = (ustr.Length as usize) / 2;
    String::from_utf16_lossy(std::slice::from_raw_parts(ustr.Buffer, units))
}

/// Enumerates well-known Windows security principals resolved through LSA.
pub fn list_builtin_principals(
    server: Option<&str>,
) -> Result<Vec<BuiltInPrincipal>, AccountError> {
    let mut srv_wide = server
        .map(|s| s.trim_start_matches('\\'))
        .filter(|s| !s.is_empty())
        .map(to_wide);

    let srv_lsa = srv_wide.as_mut().map(|buf| {
        let char_len = buf.len().saturating_sub(1);
        LSA_UNICODE_STRING {
            Length: (char_len * 2) as u16,
            MaximumLength: (buf.len() * 2) as u16,
            Buffer: buf.as_mut_ptr(),
        }
    });

    // SAFETY: LSA_OBJECT_ATTRIBUTES is a plain Win32 struct initialized to zero.
    let mut obj_attrs: LSA_OBJECT_ATTRIBUTES = unsafe { zeroed() };
    obj_attrs.Length = std::mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32;

    let mut policy: LSA_HANDLE = 0;
    let srv_ptr = srv_lsa
        .as_ref()
        .map_or(null(), |s| s as *const LSA_UNICODE_STRING);

    // SAFETY: Parameters match LsaOpenPolicy requirements.
    let open_status =
        unsafe { LsaOpenPolicy(srv_ptr, &obj_attrs, POLICY_LOOKUP_NAMES as u32, &mut policy) };
    if open_status < 0 {
        // SAFETY: LsaNtStatusToWinError converts NTSTATUS to Win32 error code.
        let win_err = unsafe { LsaNtStatusToWinError(open_status) };
        return Err(AccountError::win32("LsaOpenPolicy", win_err));
    }
    let _policy_guard = LsaPolicyGuard(policy);

    let mut sid_storage: Vec<Vec<u8>> = Vec::new();
    for well_known_type in 0..=119i32 {
        let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut cb_sid = SECURITY_MAX_SID_SIZE;
        // SAFETY: Buffer has SECURITY_MAX_SID_SIZE capacity for CreateWellKnownSid.
        let ok = unsafe {
            CreateWellKnownSid(
                well_known_type,
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut cb_sid,
            )
        };
        if ok != 0 && cb_sid > 0 {
            buf.truncate(cb_sid as usize);
            sid_storage.push(buf);
        }
    }

    if sid_storage.is_empty() {
        return Ok(Vec::new());
    }

    let sid_ptrs: Vec<PSID> = sid_storage
        .iter_mut()
        .map(|b| b.as_mut_ptr().cast())
        .collect();

    let mut domains_ptr: *mut LSA_REFERENCED_DOMAIN_LIST = null_mut();
    let mut names_ptr: *mut LSA_TRANSLATED_NAME = null_mut();

    // SAFETY: sid_ptrs points into live sid_storage buffers; output memory is freed below.
    let lookup_status = unsafe {
        LsaLookupSids(
            policy,
            sid_ptrs.len() as u32,
            sid_ptrs.as_ptr(),
            &mut domains_ptr,
            &mut names_ptr,
        )
    };

    // STATUS_SOME_NOT_MAPPED (0x00000107) and STATUS_NONE_MAPPED (0xC0000073) can occur when
    // newer or domain-only well-known SIDs do not exist on the target OS version.
    const STATUS_NONE_MAPPED: i32 = -1073741709;
    if lookup_status < 0 && lookup_status != STATUS_NONE_MAPPED {
        // SAFETY: Free any allocated LSA buffers before returning error.
        unsafe {
            if !names_ptr.is_null() {
                LsaFreeMemory(names_ptr.cast());
            }
            if !domains_ptr.is_null() {
                LsaFreeMemory(domains_ptr.cast());
            }
        }
        // SAFETY: Converts NTSTATUS into Win32 error code.
        let win_err = unsafe { LsaNtStatusToWinError(lookup_status) };
        return Err(AccountError::win32("LsaLookupSids", win_err));
    }

    let mut principals = Vec::new();
    let mut seen_sids = HashSet::new();

    if !names_ptr.is_null() {
        // SAFETY: names_ptr holds sid_ptrs.len() LSA_TRANSLATED_NAME structs.
        let names = unsafe { std::slice::from_raw_parts(names_ptr, sid_ptrs.len()) };
        let domains_slice = if !domains_ptr.is_null() {
            // SAFETY: domains_ptr is valid when non-null.
            let list = unsafe { &*domains_ptr };
            if !list.Domains.is_null() && list.Entries > 0 {
                // SAFETY: list.Domains has list.Entries items.
                Some(unsafe { std::slice::from_raw_parts(list.Domains, list.Entries as usize) })
            } else {
                None
            }
        } else {
            None
        };

        for (idx, translated) in names.iter().enumerate() {
            if translated.Use == SidTypeInvalid || translated.Use == SidTypeUnknown {
                continue;
            }
            // SAFETY: Buffer lives inside names_ptr until LsaFreeMemory below.
            let name = unsafe { lsa_string_to_rust(&translated.Name) };
            if name.trim().is_empty() {
                continue;
            }
            // SAFETY: sid_ptrs[idx] points to a valid SID buffer in sid_storage.
            let sid = unsafe { sid_to_string(sid_ptrs[idx]) };
            if sid.is_empty() || !seen_sids.insert(sid.clone()) {
                continue;
            }
            let domain = domains_slice
                .and_then(|slice| {
                    let dom_idx = translated.DomainIndex;
                    if dom_idx >= 0 && (dom_idx as usize) < slice.len() {
                        // SAFETY: Domain entry lives inside domains_ptr until LsaFreeMemory below.
                        Some(unsafe { lsa_string_to_rust(&slice[dom_idx as usize].Name) })
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            principals.push(BuiltInPrincipal { name, domain, sid });
        }
    }

    // SAFETY: Free buffers returned by LsaLookupSids.
    unsafe {
        if !names_ptr.is_null() {
            LsaFreeMemory(names_ptr.cast());
        }
        if !domains_ptr.is_null() {
            LsaFreeMemory(domains_ptr.cast());
        }
    }

    principals.sort_by(|a, b| compare_sids(&a.sid, &b.sid));
    Ok(principals)
}
