import type { Node } from "../lib/types";
import { formatLatency, statusKind, statusMessage } from "../lib/format";

export type Filter = "all" | "enabled" | "disabled" | "online" | "offline";

interface Props {
  nodes: Node[];
  selected: Set<string>;
  filter: Filter;
  query: string;
  onToggleSelect: (id: string) => void;
  onToggleAll: () => void;
  onToggleEnabled: (node: Node) => void;
  onDelete: (node: Node) => void;
  onProbe: (node: Node) => void;
}

export function matchesFilter(node: Node, filter: Filter): boolean {
  switch (filter) {
    case "enabled":
      return node.enabled;
    case "disabled":
      return !node.enabled;
    case "online":
      return node.status.kind === "ok";
    case "offline":
      return node.status.kind === "failed";
    default:
      return true;
  }
}

export function matchesQuery(node: Node, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return (
    node.name.toLowerCase().includes(q) ||
    node.host.toLowerCase().includes(q) ||
    (node.exit_ip ?? "").toLowerCase().includes(q)
  );
}

export default function NodeTable({
  nodes,
  selected,
  filter,
  query,
  onToggleSelect,
  onToggleAll,
  onToggleEnabled,
  onDelete,
  onProbe,
}: Props) {
  const visible = nodes.filter(
    (n) => matchesFilter(n, filter) && matchesQuery(n, query),
  );
  const allSelected = visible.length > 0 && visible.every((n) => selected.has(n.id));

  if (nodes.length === 0) {
    return <div className="empty">No nodes yet. Use Import to add some links.</div>;
  }
  if (visible.length === 0) {
    return <div className="empty">No node matches the current filter.</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: 32 }}>
              <input
                type="checkbox"
                checked={allSelected}
                onChange={onToggleAll}
                style={{ width: "auto" }}
              />
            </th>
            <th>Name</th>
            <th>Protocol</th>
            <th>Server</th>
            <th>SOCKS</th>
            <th>HTTP</th>
            <th>Status</th>
            <th>Exit IP</th>
            <th style={{ textAlign: "right" }}>Latency</th>
            <th style={{ width: 200 }}></th>
          </tr>
        </thead>
        <tbody>
          {visible.map((node) => {
            const kind = statusKind(node.status);
            return (
              <tr key={node.id} className={node.enabled ? "" : "disabled"}>
                <td>
                  <input
                    type="checkbox"
                    checked={selected.has(node.id)}
                    onChange={() => onToggleSelect(node.id)}
                    style={{ width: "auto" }}
                  />
                </td>
                <td title={node.name}>{node.name}</td>
                <td>{node.protocol === "vless" ? "VLESS" : "SS"}</td>
                <td className="mono">
                  {node.host}:{node.port}
                </td>
                <td className="mono">{node.socks_port ?? "—"}</td>
                <td className="mono">{node.http_port ?? "—"}</td>
                <td title={statusMessage(node.status)}>
                  <span className={`dot ${kind}`} />
                </td>
                <td className="mono">{node.exit_ip ?? "—"}</td>
                <td className="num">{formatLatency(node.latency_ms)}</td>
                <td>
                  <button className="ghost" onClick={() => onToggleEnabled(node)}>
                    {node.enabled ? "Disable" : "Enable"}
                  </button>
                  <button className="ghost" onClick={() => onProbe(node)}>
                    Test
                  </button>
                  <button className="ghost danger" onClick={() => onDelete(node)}>
                    ✕
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
