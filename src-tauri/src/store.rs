use crate::nodes::Node;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SETTINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    pub bind_address: String,
    pub socks_port_start: u16,
    pub http_port_start: u16,
    pub port_range: u16,
    pub log_level: String,
    pub auto_start: bool,
    pub auto_start_gateway: bool,
    pub export_protocol: String,
    pub probe_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: SETTINGS_VERSION,
            bind_address: "127.0.0.1".into(),
            socks_port_start: 11080,
            http_port_start: 18080,
            port_range: 100,
            log_level: "info".into(),
            auto_start: false,
            auto_start_gateway: false,
            export_protocol: "http".into(),
            probe_timeout_ms: 8000,
        }
    }
}

pub fn app_dir() -> PathBuf {
    PathBuf::new()
}

pub fn load_nodes() -> Vec<Node> {
    Vec::new()
}

pub fn save_nodes(_nodes: &[Node]) -> Result<(), String> {
    Ok(())
}

pub fn load_settings() -> Settings {
    Settings::default()
}

pub fn save_settings(_settings: &Settings) -> Result<(), String> {
    Ok(())
}

pub fn migrate_settings(_raw: serde_json::Value) -> Result<Settings, String> {
    Ok(Settings::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_match_the_spec() {
        let s = Settings::default();
        assert_eq!(s.version, 1);
        assert_eq!(s.bind_address, "127.0.0.1");
        assert_eq!(s.socks_port_start, 11080);
        assert_eq!(s.http_port_start, 18080);
        assert_eq!(s.port_range, 100);
        assert_eq!(s.log_level, "info");
        assert_eq!(s.export_protocol, "http");
        assert_eq!(s.probe_timeout_ms, 8000);
        assert!(!s.auto_start);
        assert!(!s.auto_start_gateway);
    }

    #[test]
    fn migrates_a_version_0_settings_file() {
        // Version 0 had no `version` field and no `auto_start_gateway`.
        let raw = json!({
            "bind_address": "0.0.0.0",
            "socks_port_start": 20000,
            "http_port_start": 30000,
            "port_range": 50,
            "log_level": "debug"
        });
        let s = migrate_settings(raw).unwrap();
        assert_eq!(s.version, 1);
        assert_eq!(s.bind_address, "0.0.0.0");
        assert_eq!(s.socks_port_start, 20000);
        assert_eq!(s.http_port_start, 30000);
        assert_eq!(s.port_range, 50);
        assert_eq!(s.log_level, "debug");
        // Fields the old file lacked take their defaults.
        assert!(!s.auto_start_gateway);
        assert_eq!(s.export_protocol, "http");
    }

    #[test]
    fn migration_fills_every_missing_field() {
        let s = migrate_settings(json!({})).unwrap();
        let d = Settings::default();
        assert_eq!(s.bind_address, d.bind_address);
        assert_eq!(s.socks_port_start, d.socks_port_start);
        assert_eq!(s.http_port_start, d.http_port_start);
        assert_eq!(s.port_range, d.port_range);
        assert_eq!(s.log_level, d.log_level);
        assert_eq!(s.export_protocol, d.export_protocol);
        assert_eq!(s.probe_timeout_ms, d.probe_timeout_ms);
    }

    #[test]
    fn migration_rejects_a_future_version() {
        let raw = json!({ "version": 99 });
        let err = migrate_settings(raw).unwrap_err();
        assert!(err.contains("99"), "error should name the version: {err}");
    }

    #[test]
    fn migration_accepts_the_current_version() {
        let s = migrate_settings(json!({ "version": 1, "bind_address": "10.0.0.5" })).unwrap();
        assert_eq!(s.bind_address, "10.0.0.5");
    }

    #[test]
    fn settings_round_trip_through_json() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(s.version, back.version);
        assert_eq!(s.bind_address, back.bind_address);
        assert_eq!(s.socks_port_start, back.socks_port_start);
        assert_eq!(s.export_protocol, back.export_protocol);
    }

    #[test]
    fn app_dir_ends_with_portify() {
        let dir = app_dir();
        assert!(dir.ends_with("Portify"), "unexpected dir: {dir:?}");
    }
}
