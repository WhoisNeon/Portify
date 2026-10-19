use crate::nodes::Node;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
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

/// The name of the settings file inside the app directory.
const SETTINGS_FILE: &str = "settings.json";
const NODES_FILE: &str = "nodes.json";

/// `%APPDATA%\Portify`, created if it does not exist.
pub fn app_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("Portify");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn read_json(path: &PathBuf) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_json(path: &PathBuf, value: &impl Serialize) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| format!("could not serialize {}: {e}", path.display()))?;
    fs::write(path, text).map_err(|e| format!("could not write {}: {e}", path.display()))
}

pub fn load_nodes() -> Vec<Node> {
    let path = app_dir().join(NODES_FILE);
    let Some(raw) = read_json(&path) else {
        return Vec::new();
    };
    // A corrupt nodes file must not stop the app from starting; the user
    // can re-import their links.
    serde_json::from_value(raw).unwrap_or_default()
}

pub fn save_nodes(nodes: &[Node]) -> Result<(), String> {
    write_json(&app_dir().join(NODES_FILE), &nodes)
}

pub fn load_settings() -> Settings {
    let path = app_dir().join(SETTINGS_FILE);
    match read_json(&path) {
        Some(raw) => migrate_settings(raw).unwrap_or_default(),
        None => Settings::default(),
    }
}

pub fn save_settings(settings: &Settings) -> Result<(), String> {
    write_json(&app_dir().join(SETTINGS_FILE), settings)
}

/// Brings a settings file forward to the current schema.
///
/// Each step upgrades one version. A file from a *newer* version is refused
/// rather than silently misinterpreted.
pub fn migrate_settings(raw: Value) -> Result<Settings, String> {
    let version = raw.get("version").and_then(Value::as_u64).unwrap_or(0) as u32;

    if version > SETTINGS_VERSION {
        return Err(format!(
            "these settings were written by a newer version of Portify (schema {version}, this build understands {SETTINGS_VERSION}); update Portify or delete {SETTINGS_FILE}"
        ));
    }

    let mut value = raw;
    let mut current = version;

    while current < SETTINGS_VERSION {
        value = match current {
            // 0 -> 1: `auto_start_gateway` and `export_protocol` were added.
            0 => {
                let mut v = value;
                if let Some(obj) = v.as_object_mut() {
                    obj.entry("auto_start_gateway")
                        .or_insert(Value::Bool(false));
                    obj.entry("export_protocol")
                        .or_insert(Value::String("http".into()));
                }
                v
            }
            _ => value,
        };
        current += 1;
    }

    if let Some(obj) = value.as_object_mut() {
        obj.insert("version".into(), Value::from(SETTINGS_VERSION));
    }

    // Every remaining field falls back to its default when absent, so a
    // partial settings file still loads.
    let mut settings: Settings = serde_json::from_value(value).unwrap_or_default();
    settings.version = SETTINGS_VERSION;
    Ok(settings)
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
