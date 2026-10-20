pub mod cmd;
pub mod config;
pub mod engine;
pub mod fw;
pub mod nodes;
pub mod probe;
pub mod store;

use cmd::AppState;
use tauri::Emitter;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            cmd::list_nodes,
            cmd::import_links,
            cmd::import_file,
            cmd::delete_nodes,
            cmd::set_node_enabled,
            cmd::bulk_set_enabled,
            cmd::get_settings,
            cmd::save_settings,
            cmd::start_gateway,
            cmd::stop_gateway,
            cmd::gateway_status,
            cmd::probe_node,
            cmd::probe_all,
            cmd::export_endpoints,
            cmd::export_to_file,
            cmd::copy_endpoints,
            cmd::get_singbox_path,
            cmd::update_singbox,
            cmd::get_autostart,
            cmd::set_autostart,
        ])
        .setup(|app| {
            // Start the gateway on launch when the user asked for it, and
            // make sure a firewall rule from a previous run does not linger.
            let handle = app.handle().clone();
            let settings = store::load_settings();
            if fw::needs_firewall_rule(&settings.bind_address) {
                let _ = fw::remove_rule();
            }
            if settings.auto_start_gateway {
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = cmd::start_gateway(handle.clone()).await {
                        let _ = handle.emit(
                            "portify://status",
                            cmd::GatewayStatus {
                                state: "error".into(),
                                bind_address: settings.bind_address.clone(),
                                node_count: 0,
                                error: Some(e),
                            },
                        );
                    }
                });
            }
            Ok(())
        })
        .on_window_event(|_window, event| {
            // Remove the firewall rule when the app closes, so a closed
            // Portify never leaves an open rule behind.
            if let tauri::WindowEvent::Destroyed = event {
                let settings = store::load_settings();
                if fw::needs_firewall_rule(&settings.bind_address) {
                    let _ = fw::remove_rule();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
