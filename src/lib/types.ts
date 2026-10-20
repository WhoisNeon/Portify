export type Protocol = "vless" | "shadowsocks";

export type NodeStatus =
  | { kind: "unknown" }
  | { kind: "ok" }
  | { kind: "failed"; message: string };

export interface VlessParams {
  uuid: string;
  flow: string | null;
  server_name: string | null;
  alpn: string[];
  insecure: boolean;
  fingerprint: string | null;
  reality_public_key: string | null;
  reality_short_id: string | null;
}

export interface ShadowsocksParams {
  method: string;
  password: string;
  plugin: string | null;
  plugin_opts: string | null;
}

export interface Transport {
  kind: "tcp" | "ws" | "grpc" | "http" | "httpupgrade";
  path: string | null;
  host: string | null;
  service_name: string | null;
}

export interface Node {
  id: string;
  name: string;
  protocol: Protocol;
  host: string;
  port: number;
  vless: VlessParams | null;
  ss: ShadowsocksParams | null;
  transport: Transport | null;
  enabled: boolean;
  socks_port: number | null;
  http_port: number | null;
  status: NodeStatus;
  exit_ip: string | null;
  latency_ms: number | null;
  last_checked: number | null;
}

export interface LineError {
  line: number;
  message: string;
}

export interface ImportReport {
  imported: number;
  duplicates: number;
  errors: LineError[];
}

export interface Settings {
  version: number;
  bind_address: string;
  socks_port_start: number;
  http_port_start: number;
  port_range: number;
  log_level: string;
  auto_start: boolean;
  auto_start_gateway: boolean;
  export_protocol: string;
  probe_timeout_ms: number;
}

export interface GatewayStatus {
  state: "stopped" | "running" | "starting" | "error";
  bind_address: string;
  node_count: number;
  error: string | null;
}

export interface LogLine {
  line: string;
  level: "info" | "warn" | "error";
}
