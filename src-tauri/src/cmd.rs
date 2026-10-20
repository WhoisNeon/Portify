use crate::config::{allocate_ports, build_config};
use crate::engine;
use crate::fw;
use crate::nodes::{Node, NodeStatus};
use crate::store::{self, Settings};
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::sync::Mutex;
use tauri::{Emitter, Manager};

/// The state of the gateway, as the UI sees it.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatus {
    pub state: String,
    pub bind_address: String,
    pub node_count: usize,
    pub error: Option<String>,
}

/// The running gateway, kept in Tauri's managed state.
pub struct AppState {
    pub child: Mutex<Option<engine::RunningGateway>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            child: Mutex::new(None),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the `protocol://ip:port` list for the given nodes.
///
/// `protocol` is `http`, `socks5` or `both`. The default is `http` because
/// 9Router's proxy-pool request path uses undici 7, which rejects
/// `socks5://` proxy URLs.
pub fn build_endpoints(nodes: &[Node], protocol: &str, bind: &str) -> String {
    let mut lines = Vec::new();
    for node in nodes {
        let Some(http_port) = node.http_port else { continue };
        let Some(socks_port) = node.socks_port else { continue };
        match protocol {
            "socks5" => lines.push(format!("socks5://{bind}:{socks_port}")),
            "both" => {
                lines.push(format!("http://{bind}:{http_port}"));
                lines.push(format!("socks5://{bind}:{socks_port}"));
            }
            _ => lines.push(format!("http://{bind}:{http_port}")),
        }
    }
    lines.join("\n")
}

fn status_value(state: &AppState, settings: &Settings, nodes: &[Node]) -> GatewayStatus {
    let running = state.child.lock().map(|c| c.is_some()).unwrap_or(false);
    GatewayStatus {
        state: if running { "running".into() } else { "stopped".into() },
        bind_address: settings.bind_address.clone(),
        node_count: nodes.iter().filter(|n| n.enabled).count(),
        error: None,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tauri::command]
pub fn list_nodes() -> Vec<Node> {
    store::load_nodes()
}

#[tauri::command]
pub fn import_links(text: String) -> Result<crate::nodes::ImportReport, String> {
    let mut nodes = store::load_nodes();
    let (new_nodes, report) = crate::nodes::import_links(&text, &nodes);
    nodes.extend(new_nodes);
    store::save_nodes(&nodes)?;
    Ok(report)
}

#[tauri::command]
pub fn import_file(path: String) -> Result<crate::nodes::ImportReport, String> {
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    import_links(text)
}

#[tauri::command]
pub fn delete_nodes(ids: Vec<String>) -> Result<(), String> {
    let mut nodes = store::load_nodes();
    nodes.retain(|n| !ids.contains(&n.id));
    store::save_nodes(&nodes)
}

#[tauri::command]
pub fn set_node_enabled(id: String, enabled: bool) -> Result<(), String> {
    let mut nodes = store::load_nodes();
    if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
        node.enabled = enabled;
    }
    store::save_nodes(&nodes)
}

#[tauri::command]
pub fn bulk_set_enabled(ids: Vec<String>, enabled: bool) -> Result<(), String> {
    let mut nodes = store::load_nodes();
    for node in nodes.iter_mut() {
        if ids.contains(&node.id) {
            node.enabled = enabled;
        }
    }
    store::save_nodes(&nodes)
}

#[tauri::command]
pub fn get_settings() -> Settings {
    store::load_settings()
}

#[tauri::command]
pub fn save_settings(app: tauri::AppHandle, settings: Settings) -> Result<(), String> {
    store::save_settings(&settings)?;
    // Keep the start-with-Windows entry in step with the setting.
    set_autostart(app, settings.auto_start)
}

/// Whether Portify is registered to start with Windows.
#[tauri::command]
pub fn get_autostart(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// Registers or unregisters Portify's start-with-Windows entry.
#[tauri::command]
pub fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    let result = if enabled {
        manager.enable()
    } else {
        manager.disable()
    };
    result.map_err(|e| e.to_string())
}

/// The port range each protocol covers, as `netsh` wants it.
fn port_range(start: u16, range: u16) -> String {
    format!("{}-{}", start, start as u32 + range as u32 - 1)
}

#[tauri::command]
pub async fn start_gateway(app: tauri::AppHandle) -> Result<Vec<Node>, String> {
    let state = app.state::<AppState>();
    {
        let child = state.child.lock().map_err(|e| e.to_string())?;
        if child.is_some() {
            return Err("the gateway is already running".into());
        }
    }

    let settings = store::load_settings();
    let mut nodes = store::load_nodes();

    if !nodes.iter().any(|n| n.enabled) {
        return Err("no nodes are enabled; import some links first".into());
    }

    let plan = allocate_ports(
        &nodes,
        settings.socks_port_start,
        settings.http_port_start,
        settings.port_range,
    )?;

    // Write the config and let sing-box itself validate it. The error
    // sing-box prints is the only useful description of what it objected to.
    let config_path = store::app_dir().join("config.json");
    let config = build_config(&nodes, &plan, &settings.bind_address, &settings.log_level);
    std::fs::write(&config_path, &config)
        .map_err(|e| format!("could not write the configuration: {e}"))?;

    let binary = engine::resolve_binary().await?;
    engine::check_config(&binary.path, &config_path)?;

    // The firewall rule is only needed for a non-loopback bind.
    if fw::needs_firewall_rule(&settings.bind_address) {
        fw::add_rule(
            &port_range(settings.socks_port_start, settings.port_range),
            &port_range(settings.http_port_start, settings.port_range),
        )?;
    }

    let mut running = engine::spawn_gateway(&binary.path, &config_path)?;

    // Record the ports each node actually got.
    for node in nodes.iter_mut() {
        if let Some((_, socks, http)) = plan.assignments.iter().find(|(id, _, _)| *id == node.id) {
            node.socks_port = Some(*socks);
            node.http_port = Some(*http);
        }
    }
    store::save_nodes(&nodes)?;

    // Stream sing-box's stderr to the UI. sing-box writes all its logs to
    // stderr and leaves stdout empty.
    let app_for_logs = app.clone();
    if let Some(stderr) = running.child.stderr.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let level = if line.contains("FATAL") || line.contains("ERROR") {
                    "error"
                } else if line.contains("WARN") {
                    "warn"
                } else {
                    "info"
                };
                let _ = app_for_logs.emit(
                    "portify://log",
                    serde_json::json!({ "line": line, "level": level }),
                );
            }
        });
    }

    {
        let mut child = state.child.lock().map_err(|e| e.to_string())?;
        *child = Some(running);
    }

    let _ = app.emit("portify://status", status_value(&state, &settings, &nodes));
    Ok(nodes)
}

#[tauri::command]
pub fn stop_gateway(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    {
        let mut guard = state.child.lock().map_err(|e| e.to_string())?;
        if let Some(mut running) = guard.take() {
            let _ = running.child.kill();
            let _ = running.child.wait();
        }
    }

    let settings = store::load_settings();
    if fw::needs_firewall_rule(&settings.bind_address) {
        let _ = fw::remove_rule();
    }
    Ok(())
}

#[tauri::command]
pub fn gateway_status(app: tauri::AppHandle) -> GatewayStatus {
    let state = app.state::<AppState>();
    let settings = store::load_settings();
    let nodes = store::load_nodes();
    status_value(&state, &settings, &nodes)
}

#[tauri::command]
pub async fn probe_node(app: tauri::AppHandle, id: String) -> Result<Node, String> {
    let settings = store::load_settings();
    let mut nodes = store::load_nodes();
    let node = nodes
        .iter_mut()
        .find(|n| n.id == id)
        .ok_or_else(|| "that node no longer exists".to_string())?;

    let result = crate::probe::probe_node(node, settings.probe_timeout_ms).await;
    node.exit_ip = result.exit_ip;
    node.latency_ms = result.latency_ms;
    node.last_checked = Some(now_secs());
    node.status = match &result.error {
        None => NodeStatus::Ok,
        Some(message) => NodeStatus::Failed {
            message: message.clone(),
        },
    };
    let updated = node.clone();
    store::save_nodes(&nodes)?;
    let _ = app.emit("portify://node", &updated);
    Ok(updated)
}

#[tauri::command]
pub async fn probe_all(app: tauri::AppHandle) -> Result<Vec<Node>, String> {
    let settings = store::load_settings();
    let mut nodes = store::load_nodes();
    let checked_at = now_secs();

    for node in nodes.iter_mut() {
        if !node.enabled {
            continue;
        }
        let result = crate::probe::probe_node(node, settings.probe_timeout_ms).await;
        node.exit_ip = result.exit_ip;
        node.latency_ms = result.latency_ms;
        node.last_checked = Some(checked_at);
        node.status = match &result.error {
            None => NodeStatus::Ok,
            Some(message) => NodeStatus::Failed {
                message: message.clone(),
            },
        };
    }

    store::save_nodes(&nodes)?;
    for node in &nodes {
        let _ = app.emit("portify://node", node);
    }
    Ok(nodes)
}

#[tauri::command]
pub fn export_endpoints(protocol: Option<String>) -> String {
    let settings = store::load_settings();
    let nodes = store::load_nodes();
    build_endpoints(
        &nodes,
        &protocol.unwrap_or(settings.export_protocol),
        &settings.bind_address,
    )
}

#[tauri::command]
pub fn export_to_file(protocol: Option<String>, path: String) -> Result<(), String> {
    let content = export_endpoints(protocol);
    std::fs::write(&path, content).map_err(|e| format!("could not write {path}: {e}"))
}

#[tauri::command]
pub fn copy_endpoints(app: tauri::AppHandle, protocol: Option<String>) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    let content = export_endpoints(protocol);
    app.clipboard()
        .write_text(content)
        .map_err(|e| format!("could not write to the clipboard: {e}"))
}

#[tauri::command]
pub async fn get_singbox_path() -> Result<String, String> {
    let binary = engine::resolve_binary().await?;
    Ok(binary.path.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn update_singbox() -> Result<String, String> {
    let path = engine::download_singbox().await?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::parse_link;

    fn node_with_ports(socks: u16, http: u16) -> Node {
        let mut n =
            parse_link("vless://00000000-0000-4000-8000-000000000000@example.com:443#A").unwrap();
        n.socks_port = Some(socks);
        n.http_port = Some(http);
        n
    }

    #[test]
    fn exports_http_endpoints_by_default() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "http", "127.0.0.1"),
            "http://127.0.0.1:18080"
        );
    }

    #[test]
    fn exports_socks5_endpoints_when_asked() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "socks5", "127.0.0.1"),
            "socks5://127.0.0.1:11080"
        );
    }

    #[test]
    fn exports_both_when_asked() {
        let nodes = vec![node_with_ports(11080, 18080)];
        let out = build_endpoints(&nodes, "both", "127.0.0.1");
        assert_eq!(out, "http://127.0.0.1:18080\nsocks5://127.0.0.1:11080");
    }

    #[test]
    fn an_unknown_protocol_falls_back_to_http() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "gopher", "127.0.0.1"),
            "http://127.0.0.1:18080"
        );
    }

    #[test]
    fn nodes_without_ports_are_skipped() {
        let mut n = node_with_ports(11080, 18080);
        n.socks_port = None;
        let nodes = vec![n];
        assert_eq!(build_endpoints(&nodes, "http", "127.0.0.1"), "");
    }

    #[test]
    fn the_export_uses_the_configured_bind_address() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "http", "192.168.1.10"),
            "http://192.168.1.10:18080"
        );
    }

    #[test]
    fn one_line_per_endpoint() {
        let nodes = vec![
            node_with_ports(11080, 18080),
            node_with_ports(11081, 18081),
        ];
        let out = build_endpoints(&nodes, "http", "127.0.0.1");
        assert_eq!(out.lines().count(), 2);
        assert!(out.lines().all(|l| l.starts_with("http://127.0.0.1:")));
    }
}
