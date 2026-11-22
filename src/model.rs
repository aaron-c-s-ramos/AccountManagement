//! Domain models, flag helpers, SID sorting, logon-hour masks, and validation rules.

use chrono::{DateTime, Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::error::AccountError;

/// Windows NetAPI32 user account control bitmask constants.
pub mod user_flags {
    /// Logon script runs when the user signs in.
    pub const UF_SCRIPT: u32 = 0x0001;
    /// User account is disabled.
    pub const UF_ACCOUNTDISABLE: u32 = 0x0002;
    /// Account is locked out because of failed logon attempts.
    pub const UF_LOCKOUT: u32 = 0x0010;
    /// No password is necessary for this account.
    pub const UF_PASSWD_NOTREQD: u32 = 0x0020;
    /// User cannot change the account password.
    pub const UF_PASSWD_CANT_CHANGE: u32 = 0x0040;
    /// Standard local user account flag.
    pub const UF_NORMAL_ACCOUNT: u32 = 0x0200;
    /// Account password never expires.
    pub const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;
    /// Interactive logon requires a smart card.
    pub const UF_SMARTCARD_REQUIRED: u32 = 0x40000;
}

/// Sentinel value in Windows NetAPI32 that indicates an account never expires.
pub const TIMEQ_FOREVER: u32 = u32::MAX;

/// Disallowed characters in Windows local user names.
const INVALID_USER_CHARS: &[char] = &[
    '/', '\\', '[', ']', '"', ':', ';', '|', '<', '>', '+', '=', ',', '?', '*', '%', '@',
];

/// Disallowed characters in Windows local group names.
const INVALID_GROUP_CHARS: &[char] = &[
    '/', '\\', '[', ']', '"', ':', ';', '|', '<', '>', '+', '=', ',', '?', '*',
];

/// Represents the 21-byte (168-hour) Windows logon hours bitmask stored in UTC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogonHours {
    /// Raw 21 bytes (7 days x 24 hours, bit 0 of byte 0 is Sunday 00:00 UTC).
    pub bytes: [u8; 21],
}

impl Default for LogonHours {
    fn default() -> Self {
        Self::all_allowed()
    }
}

impl LogonHours {
    /// Returns a mask that permits logon during all 168 hours of the week.
    pub const fn all_allowed() -> Self {
        Self { bytes: [0xFF; 21] }
    }

    /// Returns a mask that denies logon during all 168 hours of the week.
    pub const fn all_denied() -> Self {
        Self { bytes: [0x00; 21] }
    }

    /// Creates a mask from a 21-byte slice, or returns all-allowed if empty or invalid length.
    pub fn from_slice_or_all(slice: Option<&[u8]>) -> Self {
        match slice {
            Some(data) if data.len() == 21 => {
                let mut bytes = [0xFF; 21];
                bytes.copy_from_slice(data);
                Self { bytes }
            }
            _ => Self::all_allowed(),
        }
    }

    /// Converts a local day (0 = Sunday .. 6 = Saturday) and local hour (0..23) into a UTC bit index (0..167).
    fn local_to_utc_bit(day_sun0: usize, hour: usize, tz_offset_hours: i32) -> usize {
        let local_hour_of_week = (day_sun0 % 7) as i32 * 24 + (hour % 24) as i32;
        let utc_hour = (local_hour_of_week - tz_offset_hours).rem_euclid(168);
        utc_hour as usize
    }

    /// Returns whether the given local day and hour permit logon.
    pub fn is_local_hour_allowed(
        &self,
        day_sun0: usize,
        hour: usize,
        tz_offset_hours: i32,
    ) -> bool {
        let bit_index = Self::local_to_utc_bit(day_sun0, hour, tz_offset_hours);
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        (self.bytes[byte_index] & (1 << bit_offset)) != 0
    }

    /// Sets whether the given local day and hour permit logon.
    pub fn set_local_hour(
        &mut self,
        day_sun0: usize,
        hour: usize,
        allowed: bool,
        tz_offset_hours: i32,
    ) {
        let bit_index = Self::local_to_utc_bit(day_sun0, hour, tz_offset_hours);
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        if allowed {
            self.bytes[byte_index] |= 1 << bit_offset;
        } else {
            self.bytes[byte_index] &= !(1 << bit_offset);
        }
    }

    /// Counts how many hours in the week permit logon.
    pub fn allowed_hour_count(&self) -> u32 {
        self.bytes.iter().map(|b| b.count_ones()).sum()
    }

    /// Returns true when all 168 hours of the week permit logon.
    pub fn is_all_allowed(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0xFF)
    }

    /// Applies Monday through Friday 8:00 AM to 5:00 PM local hours as allowed.
    pub fn set_weekday_business_hours(&mut self, tz_offset_hours: i32) {
        *self = Self::all_denied();
        for day in 1..=5 {
            for hour in 8..17 {
                self.set_local_hour(day, hour, true, tz_offset_hours);
            }
        }
    }
}

/// Represents a Windows local user account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    /// SAM account name (logon name).
    pub name: String,
    /// Display full name.
    pub full_name: String,
    /// Account description or comment.
    pub comment: String,
    /// String security identifier (SID), if resolved.
    pub sid: String,
    /// Windows UF_* account flags bitmask.
    pub flags: u32,
    /// Indicates whether the user must change the password at next logon.
    pub password_expired: bool,
    /// Seconds elapsed since the last password change.
    pub password_age_secs: u32,
    /// Last logon UNIX timestamp in seconds (0 if never signed in).
    pub last_logon: u32,
    /// Count of consecutive failed password attempts.
    pub bad_pw_count: u32,
    /// Account expiration UNIX timestamp, or TIMEQ_FOREVER when never expiring.
    pub acct_expires: u32,
    /// Local home folder path or remote UNC path.
    pub home_dir: String,
    /// Drive letter mapped to a remote home folder (for example, "Z:").
    pub home_dir_drive: String,
    /// User profile directory path.
    pub profile: String,
    /// Logon script file path.
    pub script_path: String,
    /// 21-byte weekly logon hours bitmask.
    pub logon_hours: LogonHours,
}

impl UserAccount {
    /// Returns true when the account has the UF_ACCOUNTDISABLE flag set.
    pub fn is_disabled(&self) -> bool {
        (self.flags & user_flags::UF_ACCOUNTDISABLE) != 0
    }

    /// Returns true when the account has the UF_LOCKOUT flag set.
    pub fn is_locked_out(&self) -> bool {
        (self.flags & user_flags::UF_LOCKOUT) != 0
    }

    /// Returns true when the password never expires.
    pub fn password_never_expires(&self) -> bool {
        (self.flags & user_flags::UF_DONT_EXPIRE_PASSWD) != 0
    }

    /// Returns true when the user cannot change the password.
    pub fn cannot_change_password(&self) -> bool {
        (self.flags & user_flags::UF_PASSWD_CANT_CHANGE) != 0
    }

    /// Returns true when a smart card is necessary for logon.
    pub fn smartcard_required(&self) -> bool {
        (self.flags & user_flags::UF_SMARTCARD_REQUIRED) != 0
    }

    /// Returns true when a blank password is permitted.
    pub fn password_not_required(&self) -> bool {
        (self.flags & user_flags::UF_PASSWD_NOTREQD) != 0
    }

    /// Returns a concise status label for the main Users table.
    pub fn status_label(&self) -> &'static str {
        match (self.is_disabled(), self.is_locked_out()) {
            (true, true) => "Disabled, Locked",
            (true, false) => "Disabled",
            (false, true) => "Locked Out",
            (false, false) => "Active",
        }
    }

    /// Formats the last logon timestamp in 12-hour local time, or "Never".
    pub fn formatted_last_logon(&self) -> String {
        if self.last_logon == 0 {
            return "Never".to_string();
        }
        format_unix_timestamp(self.last_logon)
    }

    /// Formats the estimated last password change time, or "Never".
    pub fn formatted_password_last_set(&self) -> String {
        if self.password_age_secs == 0 {
            return "Not set / Expired".to_string();
        }
        let now = Utc::now().timestamp();
        let set_ts = now.saturating_sub(i64::from(self.password_age_secs));
        if set_ts <= 0 {
            return "Unknown".to_string();
        }
        format_unix_timestamp(set_ts as u32)
    }

    /// Formats the account expiration date in YYYY-MM-DD, or "Never".
    pub fn formatted_expiration(&self) -> String {
        if self.acct_expires == TIMEQ_FOREVER || self.acct_expires == 0 {
            return "Never".to_string();
        }
        format_unix_date(self.acct_expires)
    }
}

/// Request payload to create a new local user account.
#[derive(Debug, Clone)]
pub struct NewUserRequest {
    /// SAM account name.
    pub name: String,
    /// Display full name.
    pub full_name: String,
    /// Account description.
    pub comment: String,
    /// Initial account password.
    pub password: String,
    /// Account control flags (UF_*).
    pub flags: u32,
    /// Require password change at next logon.
    pub password_expired: bool,
    /// Optional profile path.
    pub profile: String,
    /// Optional logon script path.
    pub script_path: String,
    /// Optional home folder path.
    pub home_dir: String,
    /// Optional home drive letter.
    pub home_dir_drive: String,
    /// Initial local group names to add the user to.
    pub initial_groups: Vec<String>,
}

/// Request payload to modify an existing local user account.
#[derive(Debug, Clone)]
pub struct UserUpdateRequest {
    /// Current account name.
    pub name: String,
    /// Updated full name.
    pub full_name: String,
    /// Updated description.
    pub comment: String,
    /// Updated flags bitmask.
    pub flags: u32,
    /// Require password change at next logon.
    pub password_expired: bool,
    /// Expiration UNIX timestamp or TIMEQ_FOREVER.
    pub acct_expires: u32,
    /// Updated profile path.
    pub profile: String,
    /// Updated logon script path.
    pub script_path: String,
    /// Updated home folder path.
    pub home_dir: String,
    /// Updated home folder drive letter.
    pub home_dir_drive: String,
    /// Updated 21-byte logon hours mask.
    pub logon_hours: LogonHours,
}

/// Represents a Windows local security group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAccount {
    /// Local group name.
    pub name: String,
    /// Group description.
    pub comment: String,
    /// String SID, if resolved.
    pub sid: String,
}

/// Classifies the security principal type of a local group member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberKind {
    /// Local or domain user account.
    User,
    /// Domain or security group.
    Group,
    /// Local alias group.
    Alias,
    /// Well-known built-in security principal.
    WellKnownGroup,
    /// Deleted account whose SID remains in the group.
    Deleted,
    /// Other or unresolved principal type.
    Unknown,
}

impl MemberKind {
    /// Returns a readable label for the member kind.
    pub const fn label(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::Alias => "Local Group",
            Self::WellKnownGroup => "Built-in",
            Self::Deleted => "Deleted",
            Self::Unknown => "Other",
        }
    }
}

/// Represents a single member inside a Windows local group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// Display name without domain prefix when available.
    pub name: String,
    /// Qualified DOMAIN\Name returned by Windows.
    pub domain_and_name: String,
    /// String SID of the member.
    pub sid: String,
    /// Principal kind returned by NetLocalGroupGetMembers.
    pub kind: MemberKind,
    /// Disabled state when the member matches a local user account.
    pub is_disabled: Option<bool>,
}

/// Represents a built-in Windows well-known security principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltInPrincipal {
    /// Account name resolved by LSA.
    pub name: String,
    /// Authority or domain name (for example, "NT AUTHORITY").
    pub domain: String,
    /// Canonical SID string (for example, "S-1-5-18").
    pub sid: String,
}

/// Validates a Windows local user name before invoking NetUserAdd or rename.
pub fn validate_username(name: &str) -> Result<(), AccountError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AccountError::Validation(
            "User name cannot be empty.".to_string(),
        ));
    }
    if trimmed.chars().count() > 20 {
        return Err(AccountError::Validation(
            "Windows local user names must be 20 characters or fewer.".to_string(),
        ));
    }
    if trimmed.ends_with('.') {
        return Err(AccountError::Validation(
            "User name cannot end with a period.".to_string(),
        ));
    }
    if trimmed.chars().all(|c| c == '.' || c == ' ') {
        return Err(AccountError::Validation(
            "User name cannot consist only of periods or spaces.".to_string(),
        ));
    }
    if let Some(bad) = trimmed.chars().find(|c| INVALID_USER_CHARS.contains(c)) {
        return Err(AccountError::Validation(format!(
            "User name cannot contain the character '{bad}'."
        )));
    }
    Ok(())
}

/// Validates a Windows local group name before invoking NetLocalGroupAdd or rename.
pub fn validate_group_name(name: &str) -> Result<(), AccountError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AccountError::Validation(
            "Group name cannot be empty.".to_string(),
        ));
    }
    if trimmed.chars().count() > 256 {
        return Err(AccountError::Validation(
            "Windows local group names must be 256 characters or fewer.".to_string(),
        ));
    }
    if trimmed.chars().all(|c| c == '.' || c == ' ') {
        return Err(AccountError::Validation(
            "Group name cannot consist only of periods or spaces.".to_string(),
        ));
    }
    if let Some(bad) = trimmed.chars().find(|c| INVALID_GROUP_CHARS.contains(c)) {
        return Err(AccountError::Validation(format!(
            "Group name cannot contain the character '{bad}'."
        )));
    }
    Ok(())
}

/// Compares two SID strings numerically by each hyphen-delimited component.
pub fn compare_sids(a: &str, b: &str) -> Ordering {
    let mut parts_a = a.split('-');
    let mut parts_b = b.split('-');
    loop {
        match (parts_a.next(), parts_b.next()) {
            (Some(pa), Some(pb)) => {
                let ord = match (pa.parse::<u64>(), pb.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    _ => pa.cmp(pb),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Normalizes a server name into `\\HOST`, or `None` for the local computer.
pub fn normalize_server_name(input: &str, local_name: &str) -> Option<String> {
    let stripped = input.trim().trim_start_matches('\\');
    if stripped.is_empty() || stripped.eq_ignore_ascii_case(local_name) {
        None
    } else {
        Some(format!("\\\\{stripped}"))
    }
}

/// Parses a YYYY-MM-DD expiration date into a local end-of-day UNIX timestamp.
pub fn parse_expiration_date(input: &str) -> Result<u32, AccountError> {
    let trimmed = input.trim();
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() != 3 {
        return Err(AccountError::Validation(
            "Enter expiration date in YYYY-MM-DD format.".to_string(),
        ));
    }
    let year: i32 = parts[0]
        .parse()
        .map_err(|_| AccountError::Validation("Expiration year must be a number.".to_string()))?;
    let month: u32 = parts[1]
        .parse()
        .map_err(|_| AccountError::Validation("Expiration month must be a number.".to_string()))?;
    let day: u32 = parts[2]
        .parse()
        .map_err(|_| AccountError::Validation("Expiration day must be a number.".to_string()))?;

    let dt = Local
        .with_ymd_and_hms(year, month, day, 23, 59, 59)
        .single()
        .ok_or_else(|| AccountError::Validation("Expiration date is not valid.".to_string()))?;
    let ts = dt.timestamp();
    if ts <= 0 || ts > i64::from(u32::MAX - 1) {
        return Err(AccountError::Validation(
            "Expiration date is outside the supported Windows NetAPI range (1970-2038)."
                .to_string(),
        ));
    }
    Ok(ts as u32)
}

/// Formats a UNIX timestamp into 12-hour local date and time.
pub fn format_unix_timestamp(ts: u32) -> String {
    match DateTime::from_timestamp(i64::from(ts), 0) {
        Some(utc) => {
            let local: DateTime<Local> = utc.with_timezone(&Local);
            local.format("%Y-%m-%d %I:%M %p").to_string()
        }
        None => "Unknown".to_string(),
    }
}

/// Formats a UNIX timestamp into YYYY-MM-DD local date.
pub fn format_unix_date(ts: u32) -> String {
    match DateTime::from_timestamp(i64::from(ts), 0) {
        Some(utc) => {
            let local: DateTime<Local> = utc.with_timezone(&Local);
            local.format("%Y-%m-%d").to_string()
        }
        None => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_usernames_strictly() {
        assert!(validate_username("Alice").is_ok());
        assert!(validate_username("dev_user-01").is_ok());
        assert!(validate_username("").is_err());
        assert!(validate_username("   ").is_err());
        assert!(validate_username("a".repeat(21).as_str()).is_err());
        assert!(validate_username("alice.").is_err());
        assert!(validate_username("alice@local").is_err());
        assert!(validate_username("alice\\bob").is_err());
    }

    #[test]
    fn validates_group_names() {
        assert!(validate_group_name("Administrators").is_ok());
        assert!(validate_group_name("Remote Desktop Users").is_ok());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name("...").is_err());
        assert!(validate_group_name("Bad/Group").is_err());
    }

    #[test]
    fn compares_sids_numerically() {
        assert_eq!(compare_sids("S-1-5-2", "S-1-5-11"), Ordering::Less);
        assert_eq!(compare_sids("S-1-5-32-544", "S-1-5-32-555"), Ordering::Less);
        assert_eq!(compare_sids("S-1-1-0", "S-1-5-18"), Ordering::Less);
        assert_eq!(compare_sids("S-1-5-18", "S-1-5-18"), Ordering::Equal);
    }

    #[test]
    fn logon_hours_roundtrip_with_positive_utc_offset() {
        let mut hours = LogonHours::all_denied();
        // UTC+8 (Manila): Sunday 02:00 local == Saturday 18:00 UTC.
        hours.set_local_hour(0, 2, true, 8);
        assert!(hours.is_local_hour_allowed(0, 2, 8));
        assert!(!hours.is_local_hour_allowed(0, 3, 8));
        assert_eq!(hours.allowed_hour_count(), 1);
        // Check exact UTC bit: Saturday (6) * 24 + 18 = 162 -> byte 20, bit 2.
        assert_eq!(hours.bytes[20], 1 << 2);
    }

    #[test]
    fn logon_hours_weekday_preset_sets_45_hours() {
        let mut hours = LogonHours::all_allowed();
        hours.set_weekday_business_hours(8);
        assert_eq!(hours.allowed_hour_count(), 45);
        assert!(hours.is_local_hour_allowed(1, 8, 8));
        assert!(hours.is_local_hour_allowed(5, 16, 8));
        assert!(!hours.is_local_hour_allowed(5, 17, 8));
        assert!(!hours.is_local_hour_allowed(0, 10, 8));
        assert!(!hours.is_local_hour_allowed(6, 10, 8));
    }

    #[test]
    fn status_labels_reflect_disabled_and_locked_flags() {
        let mut user = UserAccount {
            name: "Guest".to_string(),
            full_name: String::new(),
            comment: String::new(),
            sid: "S-1-5-21-1-501".to_string(),
            flags: user_flags::UF_NORMAL_ACCOUNT | user_flags::UF_ACCOUNTDISABLE,
            password_expired: false,
            password_age_secs: 0,
            last_logon: 0,
            bad_pw_count: 0,
            acct_expires: TIMEQ_FOREVER,
            home_dir: String::new(),
            home_dir_drive: String::new(),
            profile: String::new(),
            script_path: String::new(),
            logon_hours: LogonHours::all_allowed(),
        };
        assert!(user.is_disabled());
        assert_eq!(user.status_label(), "Disabled");
        user.flags |= user_flags::UF_LOCKOUT;
        assert_eq!(user.status_label(), "Disabled, Locked");
        user.flags = user_flags::UF_NORMAL_ACCOUNT;
        assert_eq!(user.status_label(), "Active");
    }

    #[test]
    fn normalizes_server_names() {
        assert_eq!(normalize_server_name("", "MYPC"), None);
        assert_eq!(normalize_server_name("mypc", "MYPC"), None);
        assert_eq!(
            normalize_server_name("server01", "MYPC"),
            Some("\\\\server01".to_string())
        );
        assert_eq!(
            normalize_server_name("\\\\192.168.1.20", "MYPC"),
            Some("\\\\192.168.1.20".to_string())
        );
    }
}
