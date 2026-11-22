//! Error types for local and remote Windows account operations.

use thiserror::Error;

/// Represents an error from account validation, configuration, or Win32 calls.
#[derive(Debug, Error)]
pub enum AccountError {
    /// Input validation failed before an operating system call.
    #[error("{0}")]
    Validation(String),

    /// A Win32 API call returned a failure status code.
    #[error("{operation} failed (code {code}): {detail}")]
    Win32 {
        /// Name of the failed operation.
        operation: String,
        /// Win32 or NetAPI status code.
        code: u32,
        /// Human-readable reason for the failure.
        detail: String,
    },

    /// A configuration file read or write failed.
    #[error("Configuration I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization step failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The current platform does not support Windows NetAPI32 calls.
    #[error("Windows NetAPI32 account management is only available on Windows.")]
    UnsupportedPlatform,
}

impl AccountError {
    /// Builds a structured Win32 error with a readable explanation.
    pub fn win32(operation: impl Into<String>, code: u32) -> Self {
        Self::Win32 {
            operation: operation.into(),
            code,
            detail: describe_win32_code(code).to_string(),
        }
    }
}

/// Maps common Win32, NetAPI32, LSA, and WNet error codes to clear messages.
pub fn describe_win32_code(code: u32) -> &'static str {
    match code {
        0 => "The operation completed successfully.",
        5 => "Access is denied. Run lusrmgr as Administrator or connect with administrative credentials.",
        53 => "The network path was not found. Check the remote hostname and network connectivity.",
        67 => "The network name cannot be found on the remote computer.",
        86 => "The specified network password is not correct.",
        87 => "One or more parameters are not valid.",
        1219 => "Multiple connections to a server by the same user with different credentials are not permitted.",
        1326 => "Logon failure: unknown user name or incorrect password.",
        1332 => "No mapping between account names and security IDs exists.",
        1376 => "The specified local group does not exist.",
        1377 => "The specified account name is not a member of the local group.",
        1378 => "The specified account name is already a member of the local group.",
        1379 => "The specified local group already exists.",
        1387 => "A member could not be added to or removed from the local group because the member does not exist.",
        1388 => "A new member could not be added to a local group because the member has the wrong account type.",
        1722 => "The RPC server is unavailable on the target computer.",
        2202 => "The specified user name is not valid.",
        2220 => "The group name could not be found.",
        2221 => "The user name could not be found.",
        2223 => "The group already exists.",
        2224 => "The user account already exists.",
        2226 => "This operation is only permitted on the primary domain controller.",
        2236 => "The user already belongs to this group.",
        2237 => "The user is not in this group.",
        2245 => "The password does not meet the password policy requirements (length, complexity, or history).",
        _ => "Windows returned an error code for this operation.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_netapi_codes() {
        assert!(describe_win32_code(5).contains("Access is denied"));
        assert!(describe_win32_code(2224).contains("already exists"));
        assert!(describe_win32_code(2245).contains("password policy"));
    }

    #[test]
    fn formats_win32_error_message() {
        let err = AccountError::win32("NetUserAdd", 5);
        let text = err.to_string();
        assert!(text.contains("NetUserAdd"));
        assert!(text.contains("5"));
        assert!(text.contains("Access is denied"));
    }
}
