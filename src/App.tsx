import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, onLog, onNode, onStatus } from "./lib/api";
import type { GatewayStatus, LogLine, Node, Settings } from "./lib/types";
import Dashboard from "./components/Dashboard";
import ExportDialog from "./components/ExportDialog";
import ImportDialog from "./components/ImportDialog";
import LogPanel from "./components/LogPanel";
import NodeTable, { type Filter } from "./components/NodeTable";
import SettingsPanel from "./components/SettingsPanel";

export default function App() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [showImport, setShowImport] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [uptime, setUptime] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [singboxPath, setSingboxPath] = useState<string | null>(null);

  const refreshNodes = useCallback(async () => {
    setNodes(await api.listNodes());
  }, []);

  useEffect(() => {
    (async () => {
      try {
        setSettings(await api.getSettings());
        setStatus(await api.gatewayStatus());
        await refreshNodes();
        setSingboxPath(await api.getSingboxPath());
      } catch (e) {
        setError(String(e));
      }
    })();
  }, [refreshNodes]);

  useEffect(() => {
    const unlisten = Promise.all([
      onLog((entry) => setLogs((prev) => [...prev.slice(-499), entry])),
      onStatus((next) => setStatus(next)),
      onNode((node) =>
        setNodes((prev) => prev.map((n) => (n.id === node.id ? node : n))),
      ),
    ]);
    return () => {
      unlisten.then((fns) => fns.forEach((fn) => fn()));
    };
  }, []);

  // The uptime counter ticks on a ref, not on state, so the interval never
  // reads a stale start time.
  const startedAtRef = useRef<number | null>(null);
  useEffect(() => {
    if (status?.state !== "running") {
      startedAtRef.current = null;
      setUptime(0);
      return;
    }
    startedAtRef.current = Date.now();
    const timer = setInterval(() => {
      const since = startedAtRef.current;
      if (since !== null) setUptime(Math.floor((Date.now() - since) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [status?.state]);

  const selectedIds = useMemo(() => [...selected], [selected]);

  const start = async () => {
    setError(null);
    try {
      const updated = await api.startGateway();
      setNodes(updated);
      setStatus(await api.gatewayStatus());
    } catch (e) {
      setError(String(e));
    }
  };

  const stop = async () => {
    setError(null);
    try {
      await api.stopGateway();
      setStatus(await api.gatewayStatus());
    } catch (e) {
      setError(String(e));
    }
  };

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    setSelected((prev) => {
      const all = nodes.length > 0 && nodes.every((n) => prev.has(n.id));
      return all ? new Set() : new Set(nodes.map((n) => n.id));
    });
  };

  const state = status?.state ?? "stopped";

  return (
    <div className="app">
      <header className="header">
        <h1>Portify</h1>
        <span className={`pill ${state}`}>{state.toUpperCase()}</span>
        {state === "running" ? (
          <button className="danger" onClick={stop}>
            Stop
          </button>
        ) : (
          <button className="primary" onClick={start}>
            Start
          </button>
        )}
        <div className="spacer" />
        <button onClick={() => setShowImport(true)}>Import</button>
        <button onClick={() => setShowExport(true)}>Export</button>
        <button onClick={() => setShowSettings(true)}>Settings</button>
      </header>

      <div className="body">
        {settings && (
          <Dashboard
            nodes={nodes}
            settings={settings}
            uptime={uptime}
            singboxPath={singboxPath}
          />
        )}

        <div className="main">
          {error && (
            <div className="banner error" style={{ margin: 12 }}>
              {error}
            </div>
          )}

          <div className="toolbar">
            <input
              className="search"
              placeholder="Search name, host or exit IP"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <div className="chips">
              {(
                ["all", "enabled", "disabled", "online", "offline"] as Filter[]
              ).map((f) => (
                <button
                  key={f}
                  className={`chip${filter === f ? " active" : ""}`}
                  onClick={() => setFilter(f)}
                >
                  {f}
                </button>
              ))}
            </div>
            <div style={{ flex: 1 }} />
            {selectedIds.length > 0 && (
              <>
                <span style={{ color: "var(--fg-dim)" }}>
                  {selectedIds.length} selected
                </span>
                <button
                  onClick={async () => {
                    await api.bulkSetEnabled(selectedIds, true);
                    await refreshNodes();
                  }}
                >
                  Enable
                </button>
                <button
                  onClick={async () => {
                    await api.bulkSetEnabled(selectedIds, false);
                    await refreshNodes();
                  }}
                >
                  Disable
                </button>
                <button
                  className="danger"
                  onClick={async () => {
                    await api.deleteNodes(selectedIds);
                    setSelected(new Set());
                    await refreshNodes();
                  }}
                >
                  Delete
                </button>
              </>
            )}
            <button onClick={async () => setNodes(await api.probeAll())}>
              Test all
            </button>
          </div>

          <NodeTable
            nodes={nodes}
            selected={selected}
            filter={filter}
            query={query}
            onToggleSelect={toggleSelect}
            onToggleAll={toggleAll}
            onToggleEnabled={async (node) => {
              await api.setNodeEnabled(node.id, !node.enabled);
              await refreshNodes();
            }}
            onDelete={async (node) => {
              await api.deleteNodes([node.id]);
              await refreshNodes();
            }}
            onProbe={async (node) => {
              const updated = await api.probeNode(node.id);
              setNodes((prev) =>
                prev.map((n) => (n.id === updated.id ? updated : n)),
              );
            }}
          />

          <LogPanel lines={logs} onClear={() => setLogs([])} />
        </div>
      </div>

      {showImport && (
        <ImportDialog
          onClose={() => setShowImport(false)}
          onImported={refreshNodes}
        />
      )}
      {showExport && <ExportDialog onClose={() => setShowExport(false)} />}
      {showSettings && settings && (
        <div className="modal-backdrop" onClick={() => setShowSettings(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <header>
              <h2>Settings</h2>
            </header>
            <SettingsPanel
              settings={settings}
              onSaved={(next) => {
                setSettings(next);
                setShowSettings(false);
              }}
            />
            <footer>
              <button onClick={() => setShowSettings(false)}>Close</button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
