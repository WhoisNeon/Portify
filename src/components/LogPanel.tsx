import { useEffect, useRef, useState } from "react";
import type { LogLine } from "../lib/types";

interface Props {
  lines: LogLine[];
  onClear: () => void;
}

export default function LogPanel({ lines, onClear }: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [paused, setPaused] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused) return;
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines, paused]);

  return (
    <div className={`log-panel${collapsed ? " collapsed" : ""}`}>
      <div className="log-head">
        <button className="ghost" onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? "▸" : "▾"} Logs
        </button>
        <span>{lines.length} lines</span>
        <div style={{ flex: 1 }} />
        {!collapsed && (
          <>
            <button className="ghost" onClick={() => setPaused(!paused)}>
              {paused ? "Resume" : "Pause"}
            </button>
            <button className="ghost" onClick={onClear}>
              Clear
            </button>
          </>
        )}
      </div>
      {!collapsed && (
        <div className="log-body" ref={bodyRef}>
          {lines.length === 0 && (
            <span style={{ color: "var(--fg-dim)" }}>No output yet.</span>
          )}
          {lines.map((entry, i) => (
            <div key={i} className={entry.level}>
              {entry.line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
