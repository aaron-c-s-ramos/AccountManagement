//! Persistent user interface configuration stored under the user profile.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::error::AccountError;

/// Selects the visual color theme of the desktop window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeMode {
    /// Dark neutral slate interface.
    #[default]
    Dark,
    /// Clean white light interface.
    Light,
}

impl ThemeMode {
    /// Returns the opposite theme mode.
    pub const fn toggled(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        }
    }

    /// Returns a short display label for the theme toggle button.
    pub const fn toggle_label(self) -> &'static str {
        match self {
            Self::Dark => "Light Mode",
            Self::Light => "Dark Mode",
        }
    }
}

/// Persisted user preferences for warnings, theme, and table columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Active visual color theme.
    pub theme: ThemeMode,
    /// Prompt for confirmation before deleting users or groups.
    pub warn_delete: bool,
    /// Show a warning when a user account belongs to no local groups.
    pub warn_no_groups: bool,
    /// Prompt before disconnecting from a remote computer.
    pub warn_disconnect: bool,
    /// Display the SID column in the main Users table.
    pub show_sid_in_users: bool,
    /// Recently connected remote host names for quick reconnect.
    pub recent_hosts: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            warn_delete: true,
            warn_no_groups: true,
            warn_disconnect: true,
            show_sid_in_users: false,
            recent_hosts: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Returns the configuration file path inside `%APPDATA%\AccountManagement`.
    pub fn config_path() -> Option<PathBuf> {
        std::env::var_os("APPDATA")
            .or_else(|| std::env::var_os("HOME"))
            .map(|base| {
                PathBuf::from(base)
                    .join("AccountManagement")
                    .join("config.json")
            })
    }

    /// Loads saved preferences, or falls back to defaults when missing or unreadable.
    pub fn load_or_default() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        let Ok(contents) = fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&contents).unwrap_or_default()
    }

    /// Saves current preferences to disk.
    pub fn save(&self) -> Result<(), AccountError> {
        let Some(path) = Self::config_path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)?;
        fs::write(path, body)?;
        Ok(())
    }

    /// Records a remote host in the MRU list (capped at 10 unique entries).
    pub fn remember_host(&mut self, host: &str) {
        let clean = host.trim().trim_start_matches('\\');
        if clean.is_empty() {
            return;
        }
        self.recent_hosts
            .retain(|existing| !existing.eq_ignore_ascii_case(clean));
        self.recent_hosts.insert(0, clean.to_string());
        self.recent_hosts.truncate(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_enables_safety_warnings() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.theme, ThemeMode::Dark);
        assert!(cfg.warn_delete);
        assert!(cfg.warn_no_groups);
        assert!(cfg.warn_disconnect);
        assert!(!cfg.show_sid_in_users);
    }

    #[test]
    fn remembers_hosts_case_insensitively_with_limit() {
        let mut cfg = AppConfig::default();
        cfg.remember_host("\\\\SERVER01");
        cfg.remember_host("server02");
        cfg.remember_host("server01");
        assert_eq!(cfg.recent_hosts, vec!["server01", "server02"]);
    }
}
