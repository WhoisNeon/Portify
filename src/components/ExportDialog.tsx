import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api } from "../lib/api";

interface Props {
  onClose: () => void;
}

export default function ExportDialog({ onClose }: Props) {
  const [protocol, setProtocol] = useState("http");
  const [content, setContent] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load the endpoints as soon as the dialog opens, and again whenever the
  // protocol changes, so the preview always matches the selection.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const text = await api.exportEndpoints(protocol);
        if (!cancelled) {
          setContent(text);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [protocol]);

  const copy = async () => {
    try {
      await api.copyEndpoints(protocol);
      setMessage("Copied to the clipboard.");
    } catch (e) {
      setError(String(e));
    }
  };

  const saveToFile = async () => {
    const path = await save({ filters: [{ name: "Text", extensions: ["txt"] }] });
    if (typeof path !== "string") return;
    try {
      await api.exportToFile(protocol, path);
      setMessage(`Saved to ${path}`);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header>
          <h2>Export endpoints</h2>
        </header>
        <div className="content">
          {error && <div className="banner error">{error}</div>}
          {message && <div className="banner ok">{message}</div>}
          <div className="field">
            <label>Protocol</label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
            >
              <option value="http">http</option>
              <option value="socks5">socks5</option>
              <option value="both">both</option>
            </select>
            <div className="hint">
              9Router's proxy pool only accepts http:// endpoints, so http is the
              default.
            </div>
          </div>
          <div className="field">
            <label>Endpoints</label>
            <textarea
              rows={12}
              readOnly
              value={content}
              style={{ fontFamily: "var(--mono)", fontSize: 12 }}
            />
          </div>
        </div>
        <footer>
          <button onClick={saveToFile}>Save to file…</button>
          <button className="primary" onClick={copy}>
            Copy
          </button>
          <button onClick={onClose}>Close</button>
        </footer>
      </div>
    </div>
  );
}
