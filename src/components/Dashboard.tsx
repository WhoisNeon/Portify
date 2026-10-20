import type { Node, Settings } from "../lib/types";
import { formatUptime } from "../lib/format";

interface Props {
  nodes: Node[];
  settings: Settings;
  uptime: number | null;
  singboxPath: string | null;
}

export default function Dashboard({ nodes, settings, uptime, singboxPath }: Props) {
  const enabled = nodes.filter((n) => n.enabled);
  const online = enabled.filter((n) => n.status.kind === "ok");
  const offline = enabled.filter((n) => n.status.kind === "failed");
  const latencies = online
    .map((n) => n.latency_ms)
    .filter((v): v is number => v !== null);
  const average = latencies.length
    ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
    : null;

  return (
    <aside className="sidebar">
      <div className="stat">
        <div className="label">Nodes</div>
        <div className="value">{nodes.length}</div>
        <div className="hint">{enabled.length} enabled</div>
      </div>
      <div className="stat">
        <div className="label">Online</div>
        <div className="value" style={{ color: "var(--ok)" }}>
          {online.length}
        </div>
      </div>
      <div className="stat">
        <div className="label">Offline</div>
        <div
          className="value"
          style={{ color: offline.length ? "var(--err)" : undefined }}
        >
          {offline.length}
        </div>
      </div>
      <div className="stat">
        <div className="label">Average latency</div>
        <div className="value">
          {average === null ? "—" : `${average} ms`}
        </div>
      </div>
      <div className="stat">
        <div className="label">Bind address</div>
        <div className="value small">{settings.bind_address}</div>
      </div>
      <div className="stat">
        <div className="label">Uptime</div>
        <div className="value small">
          {uptime === null ? "—" : formatUptime(uptime)}
        </div>
      </div>
      <div className="stat">
        <div className="label">sing-box</div>
        <div className="value small">{singboxPath ?? "—"}</div>
      </div>
    </aside>
  );
}
