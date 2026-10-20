import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  GatewayStatus,
  ImportReport,
  LogLine,
  Node,
  Settings,
} from "./types";

export const api = {
  listNodes: () => invoke<Node[]>("list_nodes"),
  importLinks: (text: string) => invoke<ImportReport>("import_links", { text }),
  importFile: (path: string) => invoke<ImportReport>("import_file", { path }),
  deleteNodes: (ids: string[]) => invoke<void>("delete_nodes", { ids }),
  setNodeEnabled: (id: string, enabled: boolean) =>
    invoke<void>("set_node_enabled", { id, enabled }),
  bulkSetEnabled: (ids: string[], enabled: boolean) =>
    invoke<void>("bulk_set_enabled", { ids, enabled }),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<void>("save_settings", { settings }),
  startGateway: () => invoke<Node[]>("start_gateway"),
  stopGateway: () => invoke<void>("stop_gateway"),
  gatewayStatus: () => invoke<GatewayStatus>("gateway_status"),
  probeNode: (id: string) => invoke<Node>("probe_node", { id }),
  probeAll: () => invoke<Node[]>("probe_all"),
  exportEndpoints: (protocol?: string) =>
    invoke<string>("export_endpoints", { protocol }),
  exportToFile: (protocol: string, path: string) =>
    invoke<void>("export_to_file", { protocol, path }),
  copyEndpoints: (protocol?: string) => invoke<void>("copy_endpoints", { protocol }),
  getSingboxPath: () => invoke<string>("get_singbox_path"),
  updateSingbox: () => invoke<string>("update_singbox"),
  getAutostart: () => invoke<boolean>("get_autostart"),
};

export const onLog = (handler: (entry: LogLine) => void) =>
  listen<LogLine>("portify://log", (event) => handler(event.payload));

export const onStatus = (handler: (status: GatewayStatus) => void) =>
  listen<GatewayStatus>("portify://status", (event) => handler(event.payload));

export const onNode = (handler: (node: Node) => void) =>
  listen<Node>("portify://node", (event) => handler(event.payload));
