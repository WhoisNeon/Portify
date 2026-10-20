import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api } from "../lib/api";
import type { ImportReport } from "../lib/types";

interface Props {
  onClose: () => void;
  onImported: () => void;
}

export default function ImportDialog({ onClose, onImported }: Props) {
  const [text, setText] = useState("");
  const [report, setReport] = useState<ImportReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<ImportReport>) => {
    setBusy(true);
    setError(null);
    try {
      setReport(await fn());
      onImported();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const importText = () => run(() => api.importLinks(text));
  const importFile = async () => {
    const picked = await open({
      multiple: false,
      directory: false,
      filters: [
        { name: "Text", extensions: ["txt", "list", "conf", "yaml", "yml"] },
      ],
    });
    if (typeof picked === "string") await run(() => api.importFile(picked));
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header>
          <h2>Import links</h2>
        </header>
        <div className="content">
          {error && <div className="banner error">{error}</div>}
          <div className="field">
            <label>Paste links (one per line)</label>
            <textarea
              rows={10}
              value={text}
              placeholder={"vless://...\nss://..."}
              onChange={(e) => setText(e.target.value)}
              style={{ fontFamily: "var(--mono)", fontSize: 12 }}
            />
          </div>
          <div className="row">
            <button onClick={importFile} disabled={busy}>
              Choose file…
            </button>
            <button
              className="primary"
              onClick={importText}
              disabled={busy || !text.trim()}
            >
              Import
            </button>
          </div>
          {report && (
            <div className="report">
              <div className="banner ok">
                Imported {report.imported}, skipped {report.duplicates} duplicate
                {report.duplicates === 1 ? "" : "s"}.
              </div>
              {report.errors.length > 0 && (
                <>
                  <div style={{ color: "var(--err)" }}>
                    {report.errors.length} line(s) failed:
                  </div>
                  {report.errors.map((e) => (
                    <div key={e.line} className="line-error">
                      Line {e.line}: {e.message}
                    </div>
                  ))}
                </>
              )}
            </div>
          )}
        </div>
        <footer>
          <button onClick={onClose}>Close</button>
        </footer>
      </div>
    </div>
  );
}
