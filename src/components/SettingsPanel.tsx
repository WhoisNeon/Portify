import { useState } from "react";
import { api } from "../lib/api";
import type { Settings } from "../lib/types";

interface Props {
  settings: Settings;
  onSaved: (settings: Settings) => void;
}

export default function SettingsPanel({ settings, onSaved }: Props) {
  const [draft, setDraft] = useState(settings);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [singboxPath, setSingboxPath] = useState<string | null>(null);

  const set = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    setDraft({ ...draft, [key]: value });

  const save = async () => {
    setError(null);
    setMessage(null);
    try {
      await api.saveSettings(draft);
      // The Rust side keeps the Windows registry entry in step with the
      // saved setting, so there is nothing extra to do here.
      onSaved(draft);
      setMessage("Settings saved.");
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="content">
      {error && <div className="banner error">{error}</div>}
      {message && <div className="banner ok">{message}</div>}

      <div className="field">
        <label>Bind address</label>
        <input
          value={draft.bind_address}
          onChange={(e) => set("bind_address", e.target.value)}
        />
        <div className="hint">
          127.0.0.1 keeps the gateway on this machine. A LAN address opens the
          ports to your network and adds a firewall rule scoped to the local
          subnet.
        </div>
      </div>

      <div className="row">
        <div className="field">
          <label>SOCKS port start</label>
          <input
            type="number"
            value={draft.socks_port_start}
            onChange={(e) => set("socks_port_start", Number(e.target.value))}
          />
        </div>
        <div className="field">
          <label>HTTP port start</label>
          <input
            type="number"
            value={draft.http_port_start}
            onChange={(e) => set("http_port_start", Number(e.target.value))}
          />
        </div>
        <div className="field">
          <label>Port range</label>
          <input
            type="number"
            value={draft.port_range}
            onChange={(e) => set("port_range", Number(e.target.value))}
          />
        </div>
      </div>

      <div className="row">
        <div className="field">
          <label>Log level</label>
          <select
            value={draft.log_level}
            onChange={(e) => set("log_level", e.target.value)}
          >
            {["trace", "debug", "info", "warn", "error"].map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Export protocol</label>
          <select
            value={draft.export_protocol}
            onChange={(e) => set("export_protocol", e.target.value)}
          >
            <option value="http">http</option>
            <option value="socks5">socks5</option>
            <option value="both">both</option>
          </select>
        </div>
      </div>

      <div className="field">
        <label>Probe timeout (ms)</label>
        <input
          type="number"
          value={draft.probe_timeout_ms}
          onChange={(e) => set("probe_timeout_ms", Number(e.target.value))}
        />
      </div>

      <div className="field">
        <label>
          <input
            type="checkbox"
            checked={draft.auto_start}
            onChange={(e) => set("auto_start", e.target.checked)}
            style={{ width: "auto", marginRight: 8 }}
          />
          Start Portify when Windows starts
        </label>
        <label>
          <input
            type="checkbox"
            checked={draft.auto_start_gateway}
            onChange={(e) => set("auto_start_gateway", e.target.checked)}
            style={{ width: "auto", marginRight: 8 }}
          />
          Start the gateway when Portify launches
        </label>
      </div>

      <div className="field">
        <label>sing-box binary</label>
        <div className="hint" style={{ fontFamily: "var(--mono)" }}>
          {singboxPath ?? "not resolved yet"}
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <button onClick={async () => setSingboxPath(await api.getSingboxPath())}>
            Show path
          </button>
          <button onClick={async () => setSingboxPath(await api.updateSingbox())}>
            Re-download
          </button>
        </div>
      </div>

      <button className="primary" onClick={save}>
        Save settings
      </button>
    </div>
  );
}
