import type { Node } from "./types";

export function formatLatency(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function statusKind(status: Node["status"]): "unknown" | "ok" | "failed" {
  return status.kind;
}

export function statusMessage(status: Node["status"]): string {
  return status.kind === "failed" ? status.message : "";
}
