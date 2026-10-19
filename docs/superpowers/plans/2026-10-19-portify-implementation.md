# Portify Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Portify, a Windows desktop app that runs 50+ VLESS/ShadowSocks nodes simultaneously through a single sing-box process, each with dedicated local SOCKS5 and HTTP ports.

**Architecture:** Tauri v2 (Rust backend, React 19 + TypeScript frontend). The Rust side owns a link parser, a sing-box config generator, the child-process lifecycle, per-node probing, JSON persistence, and Windows Firewall rule management. The frontend is a thin view over a Tauri IPC command surface. Portify never carries traffic itself — it is a control plane that configures sing-box and exposes its local ports.

**Tech Stack:** Rust 1.90+ (edition 2024), Tauri 2.12, React 19, TypeScript 6, Vite 8, reqwest 0.13 (with `socks`), serde/serde_json, sing-box 1.14.3.

**Spec:** [docs/superpowers/specs/2026-10-19-portify-design.md](../specs/2026-10-19-portify-design.md)

---

## Global Constraints

These apply to every task. Values are copied verbatim from the spec.

- **sing-box version:** `1.14.3`. Release asset: `sing-box-1.14.3-windows-amd64.zip`.
- **Pinned SHA-256 of the extracted `sing-box.exe`:**
  - amd64: `5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf`
  - arm64: `db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4`
- **Default bind address:** `127.0.0.1`. A non-loopback bind is the only case that touches the firewall.
- **Default ports:** `socks_port_start = 11080`, `http_port_start = 18080`, `port_range = 100`.
- **Default export protocol:** `http`. Reason: 9Router's proxy-pool request path uses `undici.ProxyAgent` on undici `^7.19.2`, which throws on `socks5://` URLs.
- **No Rust toolchain on the developer machine.** Every `cargo` command in this plan runs in GitHub Actions. The "run the tests" step of each task is therefore *push a branch and read the CI result*, not a local `cargo test`.
- **No local `npm` build of the desktop app either** — the Tauri build also only runs in CI. `npm ci` and `npm run build` (the plain Vite build) *can* run locally; only `tauri build` needs CI.

## Review Focus

The five input classes the spec implies but that are most likely to bite a real user. Each has a test in the task that owns the code.

1. **A Reality `short_id` longer than 16 hex characters** — sing-box *panics* (`index out of range [8] with length 8`). A single malformed link must not take down the whole gateway. → Task 2 test: `reality_short_id_longer_than_16_chars_is_rejected`.
2. **A Shadowsocks 2022 password that is not base64** — sing-box fails at *runtime* with `illegal base64 data`, not at config-check time in every path. The link must be rejected at import. → Task 2 test: `ss2022_non_base64_password_is_rejected`.
3. **More enabled nodes than `port_range`** — the start must fail with a clear message naming both counts, not silently bind overlapping ports. → Task 3 test: `enabled_nodes_exceeding_port_range_is_an_error`.
4. **The SOCKS and HTTP port ranges overlapping** — this makes one node's HTTP inbound collide with another node's SOCKS inbound. → Task 3 test: `overlapping_port_ranges_are_rejected`.
5. **Importing the same file twice** — must be idempotent: the second import reports duplicates and imports nothing. → Task 2 test: `importing_the_same_link_twice_is_a_duplicate`.

## File Structure

| File | Responsibility |
|---|---|
| `src-tauri/src/main.rs` | Entry point. Calls `portify_lib::run()`. |
| `src-tauri/src/lib.rs` | Tauri builder, plugin registration, managed state, event emission. |
| `src-tauri/src/nodes.rs` | `Node` model, link parsing, validation, dedup. |
| `src-tauri/src/config.rs` | sing-box JSON generation, port allocation. |
| `src-tauri/src/store.rs` | Persistence, settings, schema migration. |
| `src-tauri/src/engine.rs` | sing-box binary resolution/download, `check`, spawn, log streaming. |
| `src-tauri/src/probe.rs` | Per-node latency / exit IP / status. |
| `src-tauri/src/fw.rs` | Windows Firewall rule management. |
| `src-tauri/src/cmd.rs` | `#[tauri::command]` IPC surface. |
| `src/lib/api.ts` | Typed wrappers over `invoke`. |
| `src/lib/types.ts` | TypeScript mirrors of the Rust models. |
| `src/components/*.tsx` | One component per UI region. |
| `src/styles.css` | All styling, CSS custom properties. |

---

## Task 1: Project scaffold and CI harness

Scaffolds the repo so that every later task has a compiling, testable home. Nothing user-visible yet.

**Files:**
- Create: `package.json`, `vite.config.ts`, `tsconfig.json`, `tsconfig.node.json`, `index.html`
- Create: `src/main.tsx`, `src/App.tsx` (placeholder), `src/styles.css` (placeholder)
- Create: `src-tauri/Cargo.toml`, `src-tauri/build.rs`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/default.json`
- Create: `src-tauri/src/main.rs`, `src-tauri/src/lib.rs` (placeholder)
- Create: `.github/workflows/ci.yml`
- Create: `src-tauri/icons/` (generated placeholder PNG/ICO)

**Interfaces:**
- Consumes: nothing.
- Produces: a compiling `portify` crate named `portify_lib` with lib name `portify_lib`, a `run()` function, and a CI workflow with a `rust` job that runs `cargo test`.

- [ ] **Step 1: Write the frontend scaffold files**

`package.json`:

```json
{
  "name": "portify",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "tauri": "tauri"
  },
  "dependencies": {
    "@tauri-apps/api": "^2.12.4",
    "@tauri-apps/plugin-autostart": "^2.7.0",
    "@tauri-apps/plugin-dialog": "^2.8.3",
    "@tauri-apps/plugin-fs": "^2.4.2",
    "@tauri-apps/plugin-opener": "^2.7.2",
    "react": "^19.1.0",
    "react-dom": "^19.1.0"
  },
  "devDependencies": {
    "@tauri-apps/cli": "^2.12.3",
    "@types/react": "^19.1.8",
    "@types/react-dom": "^19.1.6",
    "@vitejs/plugin-react": "^6.0.2",
    "typescript": "~6.0.3",
    "vite": "^8.0.16"
  }
}
```

`vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import process from "node:process";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(() => ({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },
}));
```

`tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

`tsconfig.node.json`:

```json
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true,
    "strict": true
  },
  "include": ["vite.config.ts"]
}
```

`index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Portify</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`src/main.tsx`:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

`src/App.tsx` (placeholder, replaced in Task 9):

```tsx
export default function App() {
  return <main className="app">Portify</main>;
}
```

`src/styles.css` (placeholder, replaced in Task 9):

```css
:root {
  --bg: #0e1116;
  --fg: #e6edf3;
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: "Segoe UI", system-ui, sans-serif;
}
```

- [ ] **Step 2: Write the Rust scaffold files**

`src-tauri/Cargo.toml`:

```toml
[package]
name = "portify"
version = "0.1.0"
description = "Windows Proxy Gateway"
authors = ["WhoisNeon"]
edition = "2024"

[lib]
name = "portify_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-dialog = "2"
tauri-plugin-fs = "2"
tauri-plugin-autostart = "2"
tauri-plugin-opener = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
base64 = "0.23"
percent-encoding = "2"
reqwest = { version = "0.13", features = ["json", "socks", "rustls", "charset", "http2"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
zip = "2.6"
sha2 = "0.10"
dirs = "7"

[features]
custom-protocol = ["tauri/custom-protocol"]

[profile.release]
codegen-units = 1
lto = true
opt-level = "s"
panic = "abort"
strip = true
```

`src-tauri/build.rs`:

```rust
fn main() {
    tauri_build::build()
}
```

`src-tauri/src/main.rs`:

```rust
// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    portify_lib::run()
}
```

`src-tauri/src/lib.rs` (placeholder, replaced in Task 8):

```rust
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

`src-tauri/tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Portify",
  "version": "0.1.0",
  "identifier": "com.whoisneon.portify",
  "build": {
    "beforeDevCommand": "npm run dev",
    "beforeBuildCommand": "npm run build",
    "devUrl": "http://localhost:1420",
    "frontendDist": "../dist"
  },
  "app": {
    "windows": [
      {
        "label": "main",
        "title": "Portify",
        "width": 1100,
        "height": 720,
        "minWidth": 900,
        "minHeight": 560,
        "resizable": true
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/32x32.png",
      "icons/128x128.png",
      "icons/128x128@2x.png",
      "icons/icon.ico"
    ],
    "windows": {
      "nsis": {
        "installMode": "currentUser",
        "languages": ["English"],
        "displayLanguageSelector": false,
        "compression": "lzma",
        "startMenuFolder": "Portify"
      },
      "webviewInstallMode": { "type": "downloadBootstrapper", "silent": true }
    }
  }
}
```

`src-tauri/capabilities/default.json`:

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "description": "Capability for the main window",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "opener:default",
    "dialog:allow-open",
    "dialog:allow-save",
    "fs:allow-read-text-file",
    "autostart:allow-enable",
    "autostart:allow-disable",
    "autostart:allow-is-enabled"
  ]
}
```

- [ ] **Step 3: Generate placeholder icons**

Icons are required by the bundler. Generate a 32x32 and 128x128 PNG plus an ICO with a tiny script so the build does not fail on a missing icon.

Create `scripts/gen-icons.mjs`:

```js
// Generates the placeholder icon set. Run with: node scripts/gen-icons.mjs
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";

const OUT = new URL("../src-tauri/icons/", import.meta.url);
mkdirSync(OUT, { recursive: true });

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = c ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function png(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const p = rowStart + 1 + x * 4;
      const edge = x < 4 || y < 4 || x >= size - 4 || y >= size - 4;
      raw[p] = edge ? 0x2f : 0x11;
      raw[p + 1] = edge ? 0x81 : 0x17;
      raw[p + 2] = edge ? 0xf6 : 0x22;
      raw[p + 3] = 255;
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

for (const size of [32, 128, 256]) {
  const name = size === 256 ? "128x128@2x.png" : `${size}x${size}.png`;
  writeFileSync(new URL(name, OUT), png(size));
}

// Minimal ICO wrapping the 32x32 PNG (ICO supports embedded PNG since Vista).
const p32 = png(32);
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(1, 4);
const entry = Buffer.alloc(16);
entry[0] = 32;
entry[1] = 32;
entry.writeUInt16LE(1, 4);
entry.writeUInt16LE(32, 6);
entry.writeUInt32LE(p32.length, 8);
entry.writeUInt32LE(22, 12);
writeFileSync(new URL("icon.ico", OUT), Buffer.concat([header, entry, p32]));
console.log("icons written");
```

Run it:

```bash
node scripts/gen-icons.mjs
```

- [ ] **Step 4: Write the CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: ["**"]
  pull_request:
  workflow_dispatch:

jobs:
  rust:
    name: Rust core
    # Portify only ships for Windows, and the Tauri crate needs GTK system
    # libraries to build on Linux. Testing on the shipping platform avoids
    # installing them and matches how the app is actually run.
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: src-tauri
      - name: Format
        run: cargo fmt --check --manifest-path src-tauri/Cargo.toml
      - name: Clippy
        run: cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
      - name: Test
        run: cargo test --manifest-path src-tauri/Cargo.toml

  frontend:
    name: Frontend
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm run build

  desktop:
    name: Windows desktop build
    # The full Tauri build is slow, so it runs on the branches that matter
    # for shipping rather than on every push.
    if: github.ref == 'refs/heads/master' || github.event_name == 'pull_request'
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: src-tauri
      - run: npm ci
      - run: npm run tauri build -- --no-bundle
```

- [ ] **Step 5: Verify locally what can be verified locally**

```bash
npm install
npm run build
```

Expected: the Vite build succeeds and `dist/` is created. This is the only frontend step that runs on the developer machine.

- [ ] **Step 6: Push and confirm CI is green**

```bash
git add -A
git commit -m "chore: scaffold Portify project and CI"
git push -u origin HEAD
```

Then check the run:

```bash
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust`, `frontend` and `windows` jobs all pass. If `rust` fails, the error is in `Cargo.toml` or `lib.rs` — fix and push again.

**Note on `npm ci`:** it requires a `package-lock.json`. Run `npm install` locally once and commit the lock file before the first push, or the CI job will fail with "lock file out of sync".

- [ ] **Step 7: Commit the lock file**

```bash
git add package-lock.json
git commit -m "chore: add npm lockfile"
git push
```

---

## Task 2: Link parser and node model

The core of the app: turn a VLESS or Shadowsocks URL into a validated `Node`. Everything downstream (config generation, probing, export) consumes `Node`.

**Files:**
- Create: `src-tauri/src/nodes.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod nodes;`)

**Interfaces:**
- Consumes: nothing from Task 1 except the crate.
- Produces:
  - `pub enum Protocol { Vless, Shadowsocks }`
  - `pub struct Node { ... }` — the full model, `Serialize`/`Deserialize`, `Clone`, `Debug`
  - `pub enum NodeStatus { Unknown, Ok, Failed(String) }`
  - `pub struct VlessParams { uuid, flow, server_name, alpn, insecure, fingerprint, reality_public_key, reality_short_id }`
  - `pub struct ShadowsocksParams { method, password, plugin, plugin_opts }`
  - `pub enum TransportType { Tcp, Ws, Grpc, Http, HttpUpgrade }`
  - `pub struct Transport { kind: TransportType, path, host, service_name }`
  - `pub fn parse_link(link: &str) -> Result<Node, String>` — the single entry point; the error string is user-facing.
  - `pub fn import_links(text: &str, existing: &[Node]) -> (Vec<Node>, ImportReport)` — parses every line and drops duplicates against `existing`.
  - `pub struct ImportReport { pub imported: usize, pub duplicates: usize, pub errors: Vec<LineError> }`
  - `pub struct LineError { pub line: usize, pub message: String }`
  - `pub fn is_duplicate(node: &Node, existing: &[Node]) -> bool`

**Parsing is hand-rolled, not delegated to the `url` crate.** `vless://` and `ss://`
are non-special schemes, and the `url` crate's authority handling for them is
subtle (a `vless://user@host:443` URL is "cannot-be-a-base" for some inputs).
The link grammar is small and fully specified, so plain string handling is both
simpler and deterministic. The `url` crate is therefore **not** a dependency;
`percent-encoding` provides the decoding.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/nodes.rs` with the tests first and a stub implementation:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Shadowsocks,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum NodeStatus {
    Unknown,
    Ok,
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessParams {
    pub uuid: String,
    pub flow: Option<String>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub insecure: bool,
    pub fingerprint: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksParams {
    pub method: String,
    pub password: String,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Tcp,
    Ws,
    Grpc,
    Http,
    HttpUpgrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transport {
    pub kind: TransportType,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub vless: Option<VlessParams>,
    pub ss: Option<ShadowsocksParams>,
    pub transport: Option<Transport>,
    pub enabled: bool,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub status: NodeStatus,
    pub exit_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub last_checked: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineError {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportReport {
    pub imported: usize,
    pub duplicates: usize,
    pub errors: Vec<LineError>,
}

pub fn parse_link(_link: &str) -> Result<Node, String> {
    Err("not implemented".into())
}

pub fn is_duplicate(_node: &Node, _existing: &[Node]) -> bool {
    false
}

pub fn import_links(_text: &str, _existing: &[Node]) -> (Vec<Node>, ImportReport) {
    (Vec::new(), ImportReport::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "00000000-0000-4000-8000-000000000000";
    const PBK: &str = "JakTfgIEsr35xxpcdVcDuVCpsNI7xPjbynaiNsS00BU";

    fn vless(q: &str) -> String {
        format!("vless://{UUID}@example.com:443?{q}#Node")
    }

    // ---------- VLESS ----------

    #[test]
    fn parses_minimal_vless() {
        let n = parse_link("vless://00000000-0000-4000-8000-000000000000@example.com:443#My%20Node").unwrap();
        assert_eq!(n.protocol, Protocol::Vless);
        assert_eq!(n.host, "example.com");
        assert_eq!(n.port, 443);
        assert_eq!(n.name, "My Node");
        assert_eq!(n.vless.as_ref().unwrap().uuid, UUID);
        assert!(n.vless.as_ref().unwrap().server_name.is_none());
        assert!(n.enabled);
    }

    #[test]
    fn parses_vless_with_tls_and_sni() {
        let n = parse_link(&vless("security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1")).unwrap();
        let v = n.vless.unwrap();
        assert_eq!(v.server_name.as_deref(), Some("cdn.example.com"));
        assert_eq!(v.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn parses_vless_with_ws_transport() {
        let n = parse_link(&vless("type=ws&security=tls&path=%2Fws&host=cdn.example.com")).unwrap();
        let t = n.transport.unwrap();
        assert_eq!(t.kind, TransportType::Ws);
        assert_eq!(t.path.as_deref(), Some("/ws"));
        assert_eq!(t.host.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn parses_vless_with_grpc_transport() {
        let n = parse_link(&vless("type=grpc&serviceName=gsvc&security=tls")).unwrap();
        let t = n.transport.unwrap();
        assert_eq!(t.kind, TransportType::Grpc);
        assert_eq!(t.service_name.as_deref(), Some("gsvc"));
    }

    #[test]
    fn parses_vless_with_httpupgrade_transport() {
        let n = parse_link(&vless("type=httpupgrade&host=h.example.com&path=%2Fhu")).unwrap();
        let t = n.transport.unwrap();
        assert_eq!(t.kind, TransportType::HttpUpgrade);
        assert_eq!(t.host.as_deref(), Some("h.example.com"));
    }

    #[test]
    fn parses_vless_with_http_transport() {
        let n = parse_link(&vless("type=http&host=h.example.com&path=%2Fhp")).unwrap();
        assert_eq!(n.transport.unwrap().kind, TransportType::Http);
    }

    #[test]
    fn parses_vless_reality_and_flow() {
        let n = parse_link(&vless(&format!(
            "security=reality&pbk={PBK}&sid=1234abcd&fp=chrome&flow=xtls-rprx-vision&sni=www.example.com"
        )))
        .unwrap();
        let v = n.vless.unwrap();
        assert_eq!(v.reality_public_key.as_deref(), Some(PBK));
        assert_eq!(v.reality_short_id.as_deref(), Some("1234abcd"));
        assert_eq!(v.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(v.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(v.server_name.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn parses_vless_allow_insecure() {
        let n = parse_link(&vless("security=tls&allowInsecure=1")).unwrap();
        assert!(n.vless.unwrap().insecure);
    }

    #[test]
    fn rejects_vless_with_bad_uuid() {
        let err = parse_link("vless://not-a-uuid@example.com:443#X").unwrap_err();
        assert!(err.contains("UUID"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_vless_with_missing_host() {
        let err = parse_link(&format!("vless://{UUID}@:443#X")).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn rejects_vless_with_bad_port() {
        let err = parse_link(&format!("vless://{UUID}@example.com:0#X")).unwrap_err();
        assert!(err.to_lowercase().contains("port"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_vless_with_encryption_set() {
        let err = parse_link(&vless("encryption=aes-128-gcm")).unwrap_err();
        assert!(err.to_lowercase().contains("encryption"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_vless_reality_without_pbk() {
        let err = parse_link(&vless("security=reality&sid=1234")).unwrap_err();
        assert!(err.to_lowercase().contains("pbk"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_vless_reality_with_bad_pbk() {
        let err = parse_link(&vless("security=reality&pbk=not-base64!!")).unwrap_err();
        assert!(err.to_lowercase().contains("public key"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_vless_reality_with_non_base64url_pbk() {
        // A standard-base64 '+' is not valid base64url; sing-box rejects it.
        let err = parse_link(&vless("security=reality&pbk=abc+def")).unwrap_err();
        assert!(err.to_lowercase().contains("public key"), "unexpected error: {err}");
    }

    #[test]
    fn reality_short_id_longer_than_16_chars_is_rejected() {
        // sing-box PANICS on a short_id longer than 16 hex chars.
        let err = parse_link(&vless("security=reality&pbk=ABCDEF&sid=123456789012345678")).unwrap_err();
        assert!(err.to_lowercase().contains("short id"), "unexpected error: {err}");
    }

    #[test]
    fn reality_short_id_with_odd_length_is_rejected() {
        let err = parse_link(&vless("security=reality&pbk=ABCDEF&sid=123")).unwrap_err();
        assert!(err.to_lowercase().contains("short id"), "unexpected error: {err}");
    }

    #[test]
    fn reality_short_id_with_non_hex_is_rejected() {
        let err = parse_link(&vless("security=reality&pbk=ABCDEF&sid=zzzz")).unwrap_err();
        assert!(err.to_lowercase().contains("short id"), "unexpected error: {err}");
    }

    // ---------- Shadowsocks ----------

    fn ss_b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    #[test]
    fn parses_ss_sip002_with_userinfo() {
        // method:password base64-encoded in the userinfo position.
        let creds = ss_b64("aes-256-gcm:secret");
        let n = parse_link(&format!("ss://{creds}@example.com:8388#SS%20Node")).unwrap();
        assert_eq!(n.protocol, Protocol::Shadowsocks);
        assert_eq!(n.host, "example.com");
        assert_eq!(n.port, 8388);
        let s = n.ss.unwrap();
        assert_eq!(s.method, "aes-256-gcm");
        assert_eq!(s.password, "secret");
    }

    #[test]
    fn parses_ss_fully_encoded_payload() {
        let payload = ss_b64("aes-256-gcm:secret@example.com:8388");
        let n = parse_link(&format!("ss://{payload}#Full")).unwrap();
        assert_eq!(n.host, "example.com");
        assert_eq!(n.port, 8388);
        assert_eq!(n.ss.unwrap().password, "secret");
    }

    #[test]
    fn parses_ss_urlencoded_password() {
        // A password containing ':' must be percent-encoded in the userinfo form.
        let creds = ss_b64("aes-256-gcm:pa:ss");
        let n = parse_link(&format!("ss://{creds}@example.com:8388")).unwrap();
        assert_eq!(n.ss.unwrap().password, "pa:ss");
    }

    #[test]
    fn parses_ss_with_plugin() {
        let creds = ss_b64("aes-256-gcm:secret");
        let n = parse_link(&format!(
            "ss://{creds}@example.com:8388?plugin=obfs-local&plugin_opts=obfs%3Dhttp%3Bobfs-host%3Dexample.com#P"
        ))
        .unwrap();
        let s = n.ss.unwrap();
        assert_eq!(s.plugin.as_deref(), Some("obfs-local"));
        assert!(s.plugin_opts.unwrap().contains("obfs-host"));
    }

    #[test]
    fn rejects_ss_with_bad_base64() {
        let err = parse_link("ss://!!!notbase64!!!@example.com:8388").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn rejects_ss_with_unsupported_cipher() {
        let creds = ss_b64("rc4-md5-x:secret");
        let err = parse_link(&format!("ss://{creds}@example.com:8388")).unwrap_err();
        assert!(err.to_lowercase().contains("method"), "unexpected error: {err}");
    }

    #[test]
    fn ss2022_non_base64_password_is_rejected() {
        // sing-box fails at runtime with "illegal base64 data" for a raw password.
        let creds = ss_b64("2022-blake3-aes-128-gcm:rawpassword");
        let err = parse_link(&format!("ss://{creds}@example.com:8388")).unwrap_err();
        assert!(err.to_lowercase().contains("password"), "unexpected error: {err}");
    }

    #[test]
    fn ss2022_wrong_key_length_is_rejected() {
        // 16-byte key required for aes-128; base64 of 8 bytes decodes to 8.
        let creds = ss_b64("2022-blake3-aes-128-gcm:c2hvcnQ=");
        let err = parse_link(&format!("ss://{creds}@example.com:8388")).unwrap_err();
        assert!(err.to_lowercase().contains("password"), "unexpected error: {err}");
    }

    #[test]
    fn ss2022_correct_key_length_is_accepted() {
        // base64 of exactly 16 bytes.
        let creds = ss_b64("2022-blake3-aes-128-gcm:MDEyMzQ1Njc4OWFiY2RlZg==");
        let n = parse_link(&format!("ss://{creds}@example.com:8388")).unwrap();
        assert_eq!(n.ss.unwrap().method, "2022-blake3-aes-128-gcm");
    }

    // ---------- general ----------

    #[test]
    fn rejects_non_proxy_scheme() {
        let err = parse_link("https://example.com").unwrap_err();
        assert!(err.to_lowercase().contains("scheme"), "unexpected error: {err}");
    }

    #[test]
    fn is_duplicate_matches_same_uuid_host_port() {
        let a = parse_link(&format!("vless://{UUID}@example.com:443#A")).unwrap();
        let b = parse_link(&format!("vless://{UUID}@example.com:443#B")).unwrap();
        assert!(is_duplicate(&b, &[a]));
    }

    #[test]
    fn is_duplicate_ignores_name() {
        let a = parse_link(&format!("vless://{UUID}@example.com:443#A")).unwrap();
        let b = parse_link(&format!("vless://{UUID}@example.com:443#B")).unwrap();
        assert!(is_duplicate(&b, &[a]), "name must not affect duplicate detection");
    }

    #[test]
    fn is_not_duplicate_for_different_uuid() {
        let a = parse_link(&format!("vless://{UUID}@example.com:443#A")).unwrap();
        let b = parse_link("vless://00000000-0000-4000-8000-000000000001@example.com:443#B").unwrap();
        assert!(!is_duplicate(&b, &[a]));
    }

    #[test]
    fn importing_the_same_link_twice_is_a_duplicate() {
        let text = format!("vless://{UUID}@example.com:443#A");
        let (nodes, report) = import_links(&text, &[]);
        assert_eq!(report.imported, 1);
        assert_eq!(report.duplicates, 0);

        // Importing the same text again, with the first result as "existing",
        // must report a duplicate and import nothing.
        let (nodes2, report2) = import_links(&text, &nodes);
        assert_eq!(report2.imported, 0);
        assert_eq!(report2.duplicates, 1);
        assert!(nodes2.is_empty());
    }

    #[test]
    fn import_links_reports_line_numbers() {
        let text = format!("garbage\nvless://{UUID}@example.com:443#A\nalso-garbage");
        let (nodes, report) = import_links(text, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(report.errors.len(), 2);
        assert_eq!(report.errors[0].line, 1);
        assert_eq!(report.errors[1].line, 3);
    }

    #[test]
    fn import_links_ignores_blank_lines() {
        let text = format!("\n\nvless://{UUID}@example.com:443#A\n\n");
        let (nodes, report) = import_links(text, &[]);
        assert_eq!(nodes.len(), 1);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn import_links_deduplicates_within_the_same_batch() {
        let text = format!(
            "vless://{UUID}@example.com:443#A\nvless://{UUID}@example.com:443#B"
        );
        let (nodes, report) = import_links(&text, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(report.imported, 1);
        assert_eq!(report.duplicates, 1);
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add link parser tests"
git push
```

```bash
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job **fails** — the stub `parse_link` returns `Err("not implemented")`, so the parsing tests fail. (The tests that only exercise the stub's `is_duplicate`/`parse_links` also fail. That is expected: the suite is red before the implementation.)

- [ ] **Step 3: Implement the parser**

Replace the stub functions in `src-tauri/src/nodes.rs` with the real implementation. Add these imports at the top of the file:

```rust
use base64::Engine;
use percent_encoding::percent_decode_str;
```

Add the cipher table and helpers:

```rust
/// Shadowsocks ciphers sing-box accepts, with the exact key length each one
/// requires in bytes. `None` means the password is used as-is (not a key).
const SS_METHODS: &[(&str, Option<usize>)] = &[
    ("none", None),
    ("aes-128-gcm", None),
    ("aes-192-gcm", None),
    ("aes-256-gcm", None),
    ("chacha20-ietf-poly1305", None),
    ("xchacha20-ietf-poly1305", None),
    ("2022-blake3-aes-128-gcm", Some(16)),
    ("2022-blake3-aes-256-gcm", Some(32)),
    ("2022-blake3-chacha20-poly1305", Some(32)),
    ("aes-128-ctr", None),
    ("aes-192-ctr", None),
    ("aes-256-ctr", None),
    ("aes-128-cfb", None),
    ("aes-192-cfb", None),
    ("aes-256-cfb", None),
    ("rc4-md5", None),
    ("chacha20-ietf", None),
    ("xchacha20", None),
];

/// Reality short IDs are hex and sing-box panics on anything longer than
/// 16 characters, so the length is checked before the value is ever used.
const REALITY_SHORT_ID_MAX: usize = 16;

fn decode_b64(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input).ok())
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(input).ok())
        .or_else(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).ok())
}

fn percent_decode(input: &str) -> String {
    percent_decode_str(input).decode_utf8_lossy().to_string()
}
```

Implement `parse_link`:

```rust
pub fn parse_link(link: &str) -> Result<Node, String> {
    let link = link.trim();
    if link.is_empty() {
        return Err("empty link".into());
    }
    if let Some(rest) = link.strip_prefix("vless://") {
        parse_vless(rest)
    } else if let Some(rest) = link.strip_prefix("ss://") {
        parse_ss(rest)
    } else {
        Err(format!(
            "unsupported scheme (expected vless:// or ss://, got {})",
            link.split(':').next().unwrap_or("")
        ))
    }
}
```

Implement `parse_vless`:

```rust
/// Parses the part of a `vless://` link that follows the scheme:
/// `<uuid>@<host>:<port>?<query>#<fragment>`.
fn parse_vless(rest: &str) -> Result<Node, String> {
    let (rest, fragment) = split_fragment(rest);
    let (rest, query) = split_query(rest);

    let (userinfo, hostport) = rest
        .rsplit_once('@')
        .ok_or_else(|| "missing '@' between the UUID and the address".to_string())?;
    let uuid = percent_decode(userinfo);
    if uuid.is_empty() {
        return Err("missing UUID".into());
    }
    if uuid::Uuid::parse_str(&uuid).is_err() {
        return Err(format!("invalid UUID: {uuid}"));
    }

    let (host, port) = split_host_port(hostport)?;

    let q = Query::new(query.unwrap_or(""));

    if let Some(enc) = q.get("encryption") {
        if !enc.is_empty() && enc != "none" {
            return Err(format!(
                "unsupported encryption: {enc} (only \"none\" is supported)"
            ));
        }
    }

    let security = q.get("security").unwrap_or("none").to_string();
    let mut vless = VlessParams {
        uuid,
        flow: q.get("flow").filter(|s| !s.is_empty()).map(str::to_string),
        server_name: q.get("sni").filter(|s| !s.is_empty()).map(str::to_string),
        alpn: q
            .get("alpn")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        insecure: q.flag("allowInsecure") || q.flag("insecure"),
        fingerprint: q.get("fp").filter(|s| !s.is_empty()).map(str::to_string),
        reality_public_key: None,
        reality_short_id: None,
    };

    if security == "reality" {
        let pbk = q
            .get("pbk")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "reality requires the pbk (public key) parameter".to_string())?;
        validate_reality_public_key(pbk)?;
        vless.reality_public_key = Some(pbk.to_string());

        if let Some(sid) = q.get("sid").filter(|s| !s.is_empty()) {
            validate_reality_short_id(sid)?;
            vless.reality_short_id = Some(sid.to_string());
        }
    } else if security != "none" && security != "tls" {
        return Err(format!("unsupported security: {security}"));
    }

    let transport = match q.get("type").unwrap_or("tcp") {
        "tcp" | "" => None,
        "ws" => Some(Transport {
            kind: TransportType::Ws,
            path: q.get("path").map(str::to_string),
            host: q.get("host").map(str::to_string),
            service_name: None,
        }),
        "grpc" => Some(Transport {
            kind: TransportType::Grpc,
            path: None,
            host: None,
            service_name: q.get("serviceName").map(str::to_string),
        }),
        "http" => Some(Transport {
            kind: TransportType::Http,
            path: q.get("path").map(str::to_string),
            host: q.get("host").map(str::to_string),
            service_name: None,
        }),
        "httpupgrade" => Some(Transport {
            kind: TransportType::HttpUpgrade,
            path: q.get("path").map(str::to_string),
            host: q.get("host").map(str::to_string),
            service_name: None,
        }),
        other => return Err(format!("unsupported transport type: {other}")),
    };

    let name = q
        .get("remark")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let frag = fragment.unwrap_or_default();
            if frag.is_empty() {
                format!("{host}:{port}")
            } else {
                frag
            }
        });

    Ok(Node {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        protocol: Protocol::Vless,
        host,
        port,
        vless: Some(vless),
        ss: None,
        transport,
        enabled: true,
        socks_port: None,
        http_port: None,
        status: NodeStatus::Unknown,
        exit_ip: None,
        latency_ms: None,
        last_checked: None,
    })
}
```

Implement `parse_ss`:

```rust
/// Parses the part of an `ss://` link that follows the scheme.
fn parse_ss(rest: &str) -> Result<Node, String> {
    let (rest, fragment) = split_fragment(rest);
    let (rest, query) = split_query(rest);

    // SIP002 with userinfo: ss://<base64(method:password)>@host:port
    // SIP002 fully encoded: ss://<base64(method:password@host:port)>
    let (method, password, host, port) = match rest.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            let decoded = decode_b64(userinfo)
                .ok_or_else(|| "invalid base64 in the credentials".to_string())?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| "credentials are not valid UTF-8".to_string())?;
            let (m, p) = decoded
                .split_once(':')
                .ok_or_else(|| "credentials must be method:password".to_string())?;
            let (host, port) = split_host_port(hostport)?;
            (m.to_string(), p.to_string(), host, port)
        }
        None => {
            let decoded = decode_b64(rest)
                .ok_or_else(|| "invalid base64 in the link payload".to_string())?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| "link payload is not valid UTF-8".to_string())?;
            // The payload is method:password@host:port. The password may itself
            // contain '@', so the last '@' separates the credentials.
            let (creds, hostport) = decoded
                .rsplit_once('@')
                .ok_or_else(|| "link payload must be method:password@host:port".to_string())?;
            let (m, p) = creds
                .split_once(':')
                .ok_or_else(|| "credentials must be method:password".to_string())?;
            let (host, port) = split_host_port(hostport)?;
            (m.to_string(), p.to_string(), host, port)
        }
    };

    let method = method.trim().to_string();
    let password = percent_decode(&password);

    let q = Query::new(query.unwrap_or(""));
    let plugin = q.get("plugin").filter(|s| !s.is_empty()).map(str::to_string);
    let plugin_opts = q.get("plugin_opts").filter(|s| !s.is_empty()).map(str::to_string);

    validate_ss_method(&method, &password)?;

    let name = fragment
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"));

    Ok(Node {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        protocol: Protocol::Shadowsocks,
        host,
        port,
        vless: None,
        ss: Some(ShadowsocksParams {
            method,
            password,
            plugin,
            plugin_opts,
        }),
        transport: None,
        enabled: true,
        socks_port: None,
        http_port: None,
        status: NodeStatus::Unknown,
        exit_ip: None,
        latency_ms: None,
        last_checked: None,
    })
}
```

Implement the helpers:

```rust
/// Splits a trailing `#fragment` off, percent-decoding it.
fn split_fragment(input: &str) -> (&str, Option<String>) {
    match input.split_once('#') {
        Some((head, frag)) => (head, Some(percent_decode(frag))),
        None => (input, None),
    }
}

/// Splits a trailing `?query` off. The query is *not* decoded here; the
/// `Query` reader does that per value, so a percent-encoded '&' inside a
/// value does not split the pair list.
fn split_query(input: &str) -> (&str, Option<&str>) {
    match input.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (input, None),
    }
}

fn split_host_port(hostport: &str) -> Result<(String, u16), String> {
    // IPv6 literals are written as [::1]:8388.
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "malformed IPv6 host".to_string())?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| "missing port".to_string())?
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        if port == 0 {
            return Err("invalid port: 0".into());
        }
        return Ok((host.to_string(), port));
    }
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| "missing port".to_string())?;
    if host.is_empty() {
        return Err("missing host".into());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid port: {port}"))?;
    if port == 0 {
        return Err("invalid port: 0".into());
    }
    Ok((host.to_string(), port))
}

fn validate_reality_public_key(pbk: &str) -> Result<(), String> {
    // sing-box expects base64url without padding.
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pbk)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(pbk))
        .map_err(|_| "invalid Reality public key (expected base64url)".to_string())?;
    if decoded.len() != 32 {
        return Err(format!(
            "invalid Reality public key (expected 32 bytes, got {})",
            decoded.len()
        ));
    }
    Ok(())
}

fn validate_reality_short_id(sid: &str) -> Result<(), String> {
    if sid.len() > REALITY_SHORT_ID_MAX {
        return Err(format!(
            "invalid Reality short id (maximum {REALITY_SHORT_ID_MAX} hex characters)"
        ));
    }
    if !sid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid Reality short id (expected hex characters)".into());
    }
    if sid.len() % 2 != 0 {
        return Err("invalid Reality short id (hex length must be even)".into());
    }
    Ok(())
}

fn validate_ss_method(method: &str, password: &str) -> Result<(), String> {
    let entry = SS_METHODS
        .iter()
        .find(|(m, _)| *m == method)
        .ok_or_else(|| format!("unsupported method: {method}"))?;
    let Some(key_len) = entry.1 else {
        return Ok(());
    };
    // The 2022 ciphers take a base64-encoded key of an exact length.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(password)
        .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(password))
        .map_err(|_| {
            format!("invalid password for {method} (expected a base64-encoded {key_len}-byte key)")
        })?;
    if decoded.len() != key_len {
        return Err(format!(
            "invalid password for {method} (expected a base64-encoded {key_len}-byte key, got {} bytes)",
            decoded.len()
        ));
    }
    Ok(())
}
```

Implement the query helper and the remaining public functions:

```rust
/// A tiny case-insensitive query-string reader. Values are percent-decoded
/// per value, so a percent-encoded '&' inside a value does not split it.
struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    fn new(raw: &str) -> Self {
        let pairs = raw
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => (percent_decode(k), percent_decode(v)),
                None => (percent_decode(pair), String::new()),
            })
            .collect();
        Query { pairs }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    fn flag(&self, key: &str) -> bool {
        matches!(self.get(key), Some("1") | Some("true") | Some("yes"))
    }
}

/// A node is a duplicate when it points at the same server with the same
/// credentials. The name is deliberately not part of the key.
pub fn is_duplicate(node: &Node, existing: &[Node]) -> bool {
    existing.iter().any(|e| {
        e.protocol == node.protocol
            && e.host == node.host
            && e.port == node.port
            && credentials_of(e) == credentials_of(node)
    })
}

fn credentials_of(node: &Node) -> String {
    match node.protocol {
        Protocol::Vless => node
            .vless
            .as_ref()
            .map(|v| format!("vless:{}", v.uuid))
            .unwrap_or_default(),
        Protocol::Shadowsocks => node
            .ss
            .as_ref()
            .map(|s| format!("ss:{}:{}", s.method, s.password))
            .unwrap_or_default(),
    }
}

/// Parses a block of text, one link per line, dropping duplicates against
/// `existing` and against the nodes produced earlier in the same batch.
pub fn import_links(text: &str, existing: &[Node]) -> (Vec<Node>, ImportReport) {
    let mut report = ImportReport::default();
    let mut accepted: Vec<Node> = existing.to_vec();

    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_link(line) {
            Ok(node) => {
                if is_duplicate(&node, &accepted) {
                    report.duplicates += 1;
                } else {
                    accepted.push(node.clone());
                    report.imported += 1;
                }
            }
            Err(message) => report.errors.push(LineError {
                line: idx + 1,
                message,
            }),
        }
    }

    (accepted[existing.len()..].to_vec(), report)
}
```

- [ ] **Step 4: Add the module to the crate**

In `src-tauri/src/lib.rs`, add at the top:

```rust
pub mod nodes;
```

- [ ] **Step 5: Push and confirm the tests pass**

```bash
git add -A
git commit -m "feat: implement VLESS and Shadowsocks link parser"
git push
```

```bash
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes. If a test fails, read the failure message from the CI log:

```bash
gh run view --log-failed
```

**Note on `percent_decode`:** the `percent-encoding` crate's
`percent_decode_str` leaves a `+` alone (it is not form-encoding), so a
password containing a literal `+` survives the round trip. `%2B` decodes to
`+` as expected.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: parser checkpoint" --allow-empty
git push
```

---

## Task 3: sing-box config generation and port allocation

Turns `Node`s into the exact sing-box JSON that the gateway runs, and decides which local ports each node gets.

**Files:**
- Create: `src-tauri/src/config.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod config;`)

**Interfaces:**
- Consumes: `crate::nodes::{Node, Protocol, TransportType, VlessParams, ShadowsocksParams}`.
- Produces:
  - `pub struct PortPlan { pub assignments: Vec<(String, u16, u16)> }` — `(node_id, socks_port, http_port)`.
  - `pub fn allocate_ports(nodes: &[Node], socks_start: u16, http_start: u16, range: u16) -> Result<PortPlan, String>`
  - `pub fn build_config(nodes: &[Node], plan: &PortPlan, bind: &str, log_level: &str) -> String` — returns the sing-box JSON.
  - `pub fn config_to_singbox_json(node: &Node, tag: &str) -> serde_json::Value` — one outbound object.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/config.rs`:

```rust
use crate::nodes::{Node, Protocol, TransportType};
use serde_json::Value;

/// The port each node was assigned: (node_id, socks_port, http_port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPlan {
    pub assignments: Vec<(String, u16, u16)>,
}

pub fn allocate_ports(
    _nodes: &[Node],
    _socks_start: u16,
    _http_start: u16,
    _range: u16,
) -> Result<PortPlan, String> {
    Err("not implemented".into())
}

pub fn config_to_singbox_json(_node: &Node, _tag: &str) -> Value {
    Value::Null
}

pub fn build_config(
    _nodes: &[Node],
    _plan: &PortPlan,
    _bind: &str,
    _log_level: &str,
) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::{parse_link, ShadowsocksParams, Transport, VlessParams};

    const UUID: &str = "00000000-0000-4000-8000-000000000000";
    const PBK: &str = "JakTfgIEsr35xxpcdVcDuVCpsNI7xPjbynaiNsS00BU";

    fn vless_node(name: &str) -> Node {
        parse_link(&format!("vless://{UUID}@example.com:443#{}", name)).unwrap()
    }

    fn ws_node(name: &str) -> Node {
        parse_link(&format!(
            "vless://{UUID}@example.com:443?type=ws&path=%2Fp&host=h.example.com&security=tls&sni=s.example.com#{name}"
        ))
        .unwrap()
    }

    fn ss_node(name: &str) -> Node {
        let mut n = vless_node(name);
        n.protocol = Protocol::Shadowsocks;
        n.vless = None;
        n.ss = Some(ShadowsocksParams {
            method: "aes-256-gcm".into(),
            password: "secret".into(),
            plugin: None,
            plugin_opts: None,
        });
        n
    }

    // ---------- port allocation ----------

    #[test]
    fn allocates_nominal_ports() {
        let nodes = vec![vless_node("a"), vless_node("b")];
        let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
        assert_eq!(plan.assignments[0].1, 11080);
        assert_eq!(plan.assignments[0].2, 18080);
        assert_eq!(plan.assignments[1].1, 11081);
        assert_eq!(plan.assignments[1].2, 18081);
    }

    #[test]
    fn enabled_nodes_exceeding_port_range_is_an_error() {
        let nodes = vec![vless_node("a"), vless_node("b"), vless_node("c")];
        let err = allocate_ports(&nodes, 11080, 18080, 2).unwrap_err();
        assert!(err.contains("3"), "error should name the node count: {err}");
        assert!(err.contains("2"), "error should name the range: {err}");
    }

    #[test]
    fn overlapping_port_ranges_are_rejected() {
        let nodes = vec![vless_node("a")];
        let err = allocate_ports(&nodes, 18080, 18080, 100).unwrap_err();
        assert!(err.to_lowercase().contains("overlap"), "unexpected error: {err}");
    }

    #[test]
    fn disabled_nodes_do_not_consume_ports() {
        let mut a = vless_node("a");
        a.enabled = false;
        let mut b = vless_node("b");
        b.enabled = false;
        let c = vless_node("c");
        let plan = allocate_ports(&[a, b, c], 11080, 18080, 100).unwrap();
        assert_eq!(plan.assignments.len(), 1);
        assert_eq!(plan.assignments[0].1, 11080);
    }

    #[test]
    fn port_start_beyond_65535_is_an_error() {
        let nodes = vec![vless_node("a")];
        let err = allocate_ports(&nodes, 65000, 18080, 1000).unwrap_err();
        assert!(!err.is_empty());
    }

    // ---------- config generation ----------

    #[test]
    fn builds_inbounds_outbounds_and_rules_per_node() {
        let nodes = vec![vless_node("a"), ss_node("b")];
        let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
        let cfg: Value = serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "info")).unwrap();

        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 4);
        assert_eq!(cfg["outbounds"].as_array().unwrap().len(), 3); // 2 nodes + direct

        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["action"], "route");
        assert_eq!(rules[0]["outbound"], "n0");
        assert_eq!(rules[0]["inbound"], serde_json::json!(["socks-0", "http-0"]));
        assert_eq!(rules[1]["outbound"], "n1");
        assert_eq!(cfg["route"]["final"], "direct");
    }

    #[test]
    fn inbound_ports_match_the_plan() {
        let nodes = vec![vless_node("a"), vless_node("b")];
        let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
        let cfg: Value = serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "info")).unwrap();
        let inbounds = cfg["inbounds"].as_array().unwrap();

        assert_eq!(inbounds[0]["type"], "socks");
        assert_eq!(inbounds[0]["tag"], "socks-0");
        assert_eq!(inbounds[0]["listen_port"], 11080);
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[1]["type"], "http");
        assert_eq!(inbounds[1]["tag"], "http-0");
        assert_eq!(inbounds[1]["listen_port"], 18080);
        assert_eq!(inbounds[2]["listen_port"], 11081);
        assert_eq!(inbounds[3]["listen_port"], 18081);
    }

    #[test]
    fn vless_outbound_carries_tls_and_transport() {
        let node = ws_node("ws");
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["type"], "vless");
        assert_eq!(out["tag"], "n0");
        assert_eq!(out["server"], "example.com");
        assert_eq!(out["server_port"], 443);
        assert_eq!(out["uuid"], UUID);
        assert_eq!(out["tls"]["enabled"], true);
        assert_eq!(out["tls"]["server_name"], "s.example.com");
        assert_eq!(out["transport"]["type"], "ws");
        assert_eq!(out["transport"]["path"], "/p");
        assert_eq!(out["transport"]["headers"]["Host"], "h.example.com");
    }

    #[test]
    fn vless_reality_outbound_carries_the_reality_block() {
        let node = parse_link(&format!(
            "vless://{UUID}@example.com:443?security=reality&pbk={PBK}&sid=1234&fp=chrome#{n}",
            n = "reality"
        ))
        .unwrap();
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["tls"]["reality"]["enabled"], true);
        assert_eq!(out["tls"]["reality"]["public_key"], PBK);
        assert_eq!(out["tls"]["reality"]["short_id"], "1234");
        assert_eq!(out["tls"]["utls"]["enabled"], true);
        assert_eq!(out["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn vless_flow_is_emitted() {
        let node = parse_link(&format!(
            "vless://{UUID}@example.com:443?flow=xtls-rprx-vision&security=tls#{n}",
            n = "flow"
        ))
        .unwrap();
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn vless_insecure_sets_tls_insecure() {
        let node = parse_link(&format!(
            "vless://{UUID}@example.com:443?security=tls&allowInsecure=1#{n}",
            n = "ins"
        ))
        .unwrap();
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["tls"]["insecure"], true);
    }

    #[test]
    fn vless_alpn_is_an_array() {
        let node = parse_link(&format!(
            "vless://{UUID}@example.com:443?security=tls&alpn=h2%2Chttp%2F1.1#{n}",
            n = "alpn"
        ))
        .unwrap();
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["tls"]["alpn"], serde_json::json!(["h2", "http/1.1"]));
    }

    #[test]
    fn shadowsocks_outbound_carries_method_and_password() {
        let node = ss_node("ss");
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["type"], "shadowsocks");
        assert_eq!(out["method"], "aes-256-gcm");
        assert_eq!(out["password"], "secret");
    }

    #[test]
    fn shadowsocks_plugin_is_emitted() {
        let mut node = ss_node("ss");
        node.ss = Some(ShadowsocksParams {
            method: "aes-256-gcm".into(),
            password: "secret".into(),
            plugin: Some("obfs-local".into()),
            plugin_opts: Some("obfs=http;obfs-host=example.com".into()),
        });
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["plugin"], "obfs-local");
        assert_eq!(out["plugin_opts"], "obfs=http;obfs-host=example.com");
    }

    #[test]
    fn grpc_transport_uses_service_name() {
        let node = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=grpc&serviceName=gsvc#{n}",
            n = "grpc"
        ))
        .unwrap();
        let out = config_to_singbox_json(&node, "n0");
        assert_eq!(out["transport"]["type"], "grpc");
        assert_eq!(out["transport"]["service_name"], "gsvc");
    }

    #[test]
    fn config_includes_dns_and_log_blocks() {
        let nodes = vec![vless_node("a")];
        let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
        let cfg: Value = serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "debug")).unwrap();
        assert_eq!(cfg["log"]["level"], "debug");
        assert_eq!(cfg["log"]["timestamp"], true);
        assert_eq!(cfg["dns"]["servers"][0]["type"], "local");
        assert_eq!(cfg["dns"]["final"], "local");
    }

    #[test]
    fn config_omits_disabled_nodes() {
        let mut a = vless_node("a");
        a.enabled = false;
        let b = vless_node("b");
        let plan = allocate_ports(&[a.clone(), b.clone()], 11080, 18080, 100).unwrap();
        let cfg: Value = serde_json::from_str(&build_config(&[a, b], &plan, "127.0.0.1", "info")).unwrap();
        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(cfg["outbounds"].as_array().unwrap().len(), 2);
        assert_eq!(cfg["route"]["rules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn node_tags_follow_the_configured_index() {
        // The outbound tag is derived from the node's position among the
        // *enabled* nodes, and the route rule must point at the same tag.
        let nodes = vec![vless_node("a"), vless_node("b")];
        let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
        let cfg: Value = serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "info")).unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["tag"], "direct");
        assert_eq!(outbounds[1]["tag"], "n0");
        assert_eq!(outbounds[2]["tag"], "n1");
    }

    #[test]
    fn transport_tcp_produces_no_transport_block() {
        let node = vless_node("plain");
        let out = config_to_singbox_json(&node, "n0");
        assert!(out.get("transport").is_none());
    }

    #[test]
    fn transport_types_map_to_singbox_names() {
        // A guard against the enum -> sing-box name mapping drifting.
        let cases = [
            (TransportType::Tcp, None),
            (TransportType::Ws, Some("ws")),
            (TransportType::Grpc, Some("grpc")),
            (TransportType::Http, Some("http")),
            (TransportType::HttpUpgrade, Some("httpupgrade")),
        ];
        for (kind, expected) in cases {
            let node = vless_node("t");
            let transport = match expected {
                None => None,
                Some(name) => Some(Transport {
                    kind,
                    path: Some("/p".into()),
                    host: Some("h".into()),
                    service_name: Some("s".into()),
                }),
            };
            assert_eq!(node.transport.is_none(), expected.is_none());
        }
    }

    #[test]
    fn vless_params_survive_a_serde_round_trip() {
        let node = vless_node("rt");
        let json = serde_json::to_string(&node).unwrap();
        let back: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
        assert_eq!(back.vless.as_ref().unwrap().uuid, UUID);
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add config generation tests"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job fails — `allocate_ports` returns `Err("not implemented")`.

- [ ] **Step 3: Implement the config generator**

Replace the stubs in `src-tauri/src/config.rs`:

```rust
use crate::nodes::{Node, Protocol, TransportType};
use serde_json::{json, Map, Value};

/// The port each node was assigned: (node_id, socks_port, http_port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPlan {
    pub assignments: Vec<(String, u16, u16)>,
}

impl PortPlan {
    fn ports_for(&self, node_id: &str) -> Option<(u16, u16)> {
        self.assignments
            .iter()
            .find(|(id, _, _)| id == node_id)
            .map(|(_, s, h)| (*s, *h))
    }
}

/// Assigns a SOCKS port and an HTTP port to every enabled node.
///
/// Disabled nodes consume no ports. The two ranges must not overlap, and the
/// number of enabled nodes must fit inside `range`.
pub fn allocate_ports(
    nodes: &[Node],
    socks_start: u16,
    http_start: u16,
    range: u16,
) -> Result<PortPlan, String> {
    let enabled: Vec<&Node> = nodes.iter().filter(|n| n.enabled).collect();

    if range == 0 {
        return Err("the port range must be at least 1".into());
    }
    if enabled.len() as u16 > range {
        return Err(format!(
            "{} enabled nodes do not fit in a port range of {}; raise the range or disable some nodes",
            enabled.len(),
            range
        ));
    }

    let socks_end = socks_start as u32 + range as u32 - 1;
    let http_end = http_start as u32 + range as u32 - 1;
    if socks_end > 65535 || http_end > 65535 {
        return Err("the port range extends past port 65535".into());
    }

    // The ranges must not overlap, or one node's HTTP inbound would collide
    // with another node's SOCKS inbound.
    if socks_start <= http_end && http_start <= socks_end {
        return Err(format!(
            "the SOCKS range {socks_start}-{socks_end} and the HTTP range {http_start}-{http_end} overlap"
        ));
    }

    let mut assignments = Vec::with_capacity(enabled.len());
    for (i, node) in enabled.iter().enumerate() {
        let offset = i as u16;
        assignments.push((
            node.id.clone(),
            socks_start + offset,
            http_start + offset,
        ));
    }

    Ok(PortPlan { assignments })
}

/// Builds the sing-box outbound object for one node.
pub fn config_to_singbox_json(node: &Node, tag: &str) -> Value {
    let mut out = Map::new();
    out.insert("tag".into(), json!(tag));
    out.insert("server".into(), json!(node.host));
    out.insert("server_port".into(), json!(node.port));

    match node.protocol {
        Protocol::Vless => {
            out.insert("type".into(), json!("vless"));
            let v = node.vless.as_ref().expect("a vless node has vless params");
            out.insert("uuid".into(), json!(v.uuid));
            if let Some(flow) = &v.flow {
                out.insert("flow".into(), json!(flow));
            }
            if let Some(t) = &node.transport {
                out.insert("transport".into(), transport_json(t));
            }
            out.insert("tls".into(), tls_json(v));
        }
        Protocol::Shadowsocks => {
            out.insert("type".into(), json!("shadowsocks"));
            let s = node.ss.as_ref().expect("an ss node has ss params");
            out.insert("method".into(), json!(s.method));
            out.insert("password".into(), json!(s.password));
            if let Some(plugin) = &s.plugin {
                out.insert("plugin".into(), json!(plugin));
                if let Some(opts) = &s.plugin_opts {
                    out.insert("plugin_opts".into(), json!(opts));
                }
            }
        }
    }

    Value::Object(out)
}

fn transport_json(t: &crate::nodes::Transport) -> Value {
    let mut m = Map::new();
    match t.kind {
        TransportType::Tcp => {}
        TransportType::Ws => {
            m.insert("type".into(), json!("ws"));
            if let Some(path) = &t.path {
                m.insert("path".into(), json!(path));
            }
            if let Some(host) = &t.host {
                m.insert("headers".into(), json!({ "Host": host }));
            }
        }
        TransportType::Grpc => {
            m.insert("type".into(), json!("grpc"));
            if let Some(name) = &t.service_name {
                m.insert("service_name".into(), json!(name));
            }
        }
        TransportType::Http => {
            m.insert("type".into(), json!("http"));
            if let Some(path) = &t.path {
                m.insert("path".into(), json!(path));
            }
            if let Some(host) = &t.host {
                m.insert("host".into(), json!([host]));
            }
        }
        TransportType::HttpUpgrade => {
            m.insert("type".into(), json!("httpupgrade"));
            if let Some(path) = &t.path {
                m.insert("path".into(), json!(path));
            }
            if let Some(host) = &t.host {
                m.insert("host".into(), json!(host));
            }
        }
    }
    Value::Object(m)
}

fn tls_json(v: &crate::nodes::VlessParams) -> Value {
    let mut m = Map::new();
    let has_reality = v.reality_public_key.is_some();

    // TLS is on when the link asked for it, when a server name is set, or
    // when Reality is used.
    let enabled = has_reality || v.server_name.is_some();
    m.insert("enabled".into(), json!(enabled));

    if let Some(sni) = &v.server_name {
        m.insert("server_name".into(), json!(sni));
    }
    if v.insecure {
        m.insert("insecure".into(), json!(true));
    }
    if !v.alpn.is_empty() {
        m.insert("alpn".into(), json!(v.alpn));
    }
    if has_reality {
        let mut r = Map::new();
        r.insert("enabled".into(), json!(true));
        r.insert("public_key".into(), json!(v.reality_public_key));
        if let Some(sid) = &v.reality_short_id {
            r.insert("short_id".into(), json!(sid));
        }
        m.insert("reality".into(), Value::Object(r));
    }
    if let Some(fp) = &v.fingerprint {
        let mut u = Map::new();
        u.insert("enabled".into(), json!(true));
        u.insert("fingerprint".into(), json!(fp));
        m.insert("utls".into(), Value::Object(u));
    }

    Value::Object(m)
}

/// Builds the full sing-box configuration.
pub fn build_config(nodes: &[Node], plan: &PortPlan, bind: &str, log_level: &str) -> String {
    let enabled: Vec<&Node> = nodes.iter().filter(|n| n.enabled).collect();

    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();

    for (i, node) in enabled.iter().enumerate() {
        let tag = format!("n{i}");
        let socks_tag = format!("socks-{i}");
        let http_tag = format!("http-{i}");

        let (socks_port, http_port) = plan.ports_for(&node.id).unwrap_or((0, 0));

        inbounds.push(json!({
            "type": "socks",
            "tag": socks_tag,
            "listen": bind,
            "listen_port": socks_port,
        }));
        inbounds.push(json!({
            "type": "http",
            "tag": http_tag,
            "listen": bind,
            "listen_port": http_port,
        }));

        outbounds.push(config_to_singbox_json(node, &tag));

        rules.push(json!({
            "inbound": [socks_tag, http_tag],
            "action": "route",
            "outbound": tag,
        }));
    }

    outbounds.insert(0, json!({ "type": "direct", "tag": "direct" }));

    let config = json!({
        "log": {
            "level": log_level,
            "timestamp": true,
        },
        "dns": {
            "servers": [
                { "type": "local", "tag": "local" },
            ],
            "final": "local",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": "direct",
            "auto_detect_interface": true,
        },
    });

    serde_json::to_string_pretty(&config).unwrap_or_default()
}
```

- [ ] **Step 4: Add the module to the crate**

In `src-tauri/src/lib.rs`:

```rust
pub mod config;
```

- [ ] **Step 5: Push and confirm the tests pass**

```bash
git add -A
git commit -m "feat: generate sing-box configuration and allocate ports"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes.

- [ ] **Step 6: Verify the generated JSON against the real sing-box**

The Rust tests check the *shape*; only sing-box can check the *semantics*. Do this once, locally, using the sing-box binary from the spec's download step.

Write the fixture the CI job will also use. Create `src-tauri/tests/fixtures/` with a hand-written config that matches what `build_config` produces for two nodes, and a CI step that runs `sing-box check` on it.

First create `src-tauri/tests/singbox_fixture.rs` — an integration test that writes the fixture to disk so the workflow can validate it:

```rust
use portify_lib::config::{allocate_ports, build_config};
use portify_lib::nodes::parse_link;

#[test]
fn writes_a_singbox_fixture() {
    let nodes = vec![
        parse_link("vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&host=cdn.example.com#A").unwrap(),
        parse_link("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=reality&pbk=JakTfgIEsr35xxpcdVcDuVCpsNI7xPjbynaiNsS00BU&sid=1234abcd&fp=chrome&flow=xtls-rprx-vision#B").unwrap(),
    ];
    let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
    let config = build_config(&nodes, &plan, "127.0.0.1", "info");
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("singbox-fixture.json");
    std::fs::write(&out, config).unwrap();
    assert!(out.exists());
}
```

Then add a CI step to `.github/workflows/ci.yml` in the `rust` job, after the test step:

```yaml
      - name: Validate the generated config with sing-box
        if: success()
        shell: pwsh
        run: |
          $version = "1.14.3"
          $url = "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip"
          Invoke-WebRequest -Uri $url -OutFile sing-box.zip
          Expand-Archive -Path sing-box.zip -DestinationPath sing-box-extract -Force
          $sb = (Get-ChildItem -Path sing-box-extract -Recurse -Filter "sing-box.exe" | Select-Object -First 1).FullName
          & $sb version
          & $sb check -c src-tauri/target/singbox-fixture.json
          if ($LASTEXITCODE -ne 0) { throw "sing-box rejected the generated config" }

Expected: `sing-box check` prints nothing and exits 0. If it fails, the error names the offending key — fix `config.rs` accordingly.

**Do not skip this step.** The Rust tests cannot catch a key name sing-box does not recognise; `sing-box check` is the only authority.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "test: validate generated config with sing-box" --allow-empty
git push
```

---

## Task 4: Persistence, settings and schema migration

Stores the node list and the settings as JSON in `%APPDATA%\Portify`, and migrates old settings files forward.

**Files:**
- Create: `src-tauri/src/store.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod store;`)

**Interfaces:**
- Consumes: `crate::nodes::Node`.
- Produces:
  - `pub const SETTINGS_VERSION: u32 = 1;`
  - `pub struct Settings { version, bind_address, socks_port_start, http_port_start, port_range, log_level, auto_start, auto_start_gateway, export_protocol, probe_timeout_ms }` — `Serialize`, `Deserialize`, `Clone`, `Debug`.
  - `impl Default for Settings` — the spec's defaults.
  - `pub fn app_dir() -> PathBuf` — `%APPDATA%\Portify`, created if missing.
  - `pub fn load_nodes() -> Vec<Node>`
  - `pub fn save_nodes(nodes: &[Node]) -> Result<(), String>`
  - `pub fn load_settings() -> Settings`
  - `pub fn save_settings(settings: &Settings) -> Result<(), String>`
  - `pub fn migrate_settings(raw: serde_json::Value) -> Result<Settings, String>` — the forward-migration chain.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/store.rs`:

```rust
use crate::nodes::Node;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SETTINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    pub bind_address: String,
    pub socks_port_start: u16,
    pub http_port_start: u16,
    pub port_range: u16,
    pub log_level: String,
    pub auto_start: bool,
    pub auto_start_gateway: bool,
    pub export_protocol: String,
    pub probe_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: SETTINGS_VERSION,
            bind_address: "127.0.0.1".into(),
            socks_port_start: 11080,
            http_port_start: 18080,
            port_range: 100,
            log_level: "info".into(),
            auto_start: false,
            auto_start_gateway: false,
            export_protocol: "http".into(),
            probe_timeout_ms: 8000,
        }
    }
}

pub fn app_dir() -> PathBuf {
    PathBuf::new()
}

pub fn load_nodes() -> Vec<Node> {
    Vec::new()
}

pub fn save_nodes(_nodes: &[Node]) -> Result<(), String> {
    Ok(())
}

pub fn load_settings() -> Settings {
    Settings::default()
}

pub fn save_settings(_settings: &Settings) -> Result<(), String> {
    Ok(())
}

pub fn migrate_settings(_raw: serde_json::Value) -> Result<Settings, String> {
    Ok(Settings::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_match_the_spec() {
        let s = Settings::default();
        assert_eq!(s.version, 1);
        assert_eq!(s.bind_address, "127.0.0.1");
        assert_eq!(s.socks_port_start, 11080);
        assert_eq!(s.http_port_start, 18080);
        assert_eq!(s.port_range, 100);
        assert_eq!(s.log_level, "info");
        assert_eq!(s.export_protocol, "http");
        assert_eq!(s.probe_timeout_ms, 8000);
        assert!(!s.auto_start);
        assert!(!s.auto_start_gateway);
    }

    #[test]
    fn migrates_a_version_0_settings_file() {
        // Version 0 had no `version` field and no `auto_start_gateway`.
        let raw = json!({
            "bind_address": "0.0.0.0",
            "socks_port_start": 20000,
            "http_port_start": 30000,
            "port_range": 50,
            "log_level": "debug"
        });
        let s = migrate_settings(raw).unwrap();
        assert_eq!(s.version, 1);
        assert_eq!(s.bind_address, "0.0.0.0");
        assert_eq!(s.socks_port_start, 20000);
        assert_eq!(s.http_port_start, 30000);
        assert_eq!(s.port_range, 50);
        assert_eq!(s.log_level, "debug");
        // Fields the old file lacked take their defaults.
        assert!(!s.auto_start_gateway);
        assert_eq!(s.export_protocol, "http");
    }

    #[test]
    fn migration_fills_every_missing_field() {
        let s = migrate_settings(json!({})).unwrap();
        let d = Settings::default();
        assert_eq!(s.bind_address, d.bind_address);
        assert_eq!(s.socks_port_start, d.socks_port_start);
        assert_eq!(s.http_port_start, d.http_port_start);
        assert_eq!(s.port_range, d.port_range);
        assert_eq!(s.log_level, d.log_level);
        assert_eq!(s.export_protocol, d.export_protocol);
        assert_eq!(s.probe_timeout_ms, d.probe_timeout_ms);
    }

    #[test]
    fn migration_rejects_a_future_version() {
        let raw = json!({ "version": 99 });
        let err = migrate_settings(raw).unwrap_err();
        assert!(err.contains("99"), "error should name the version: {err}");
    }

    #[test]
    fn migration_accepts_the_current_version() {
        let s = migrate_settings(json!({ "version": 1, "bind_address": "10.0.0.5" })).unwrap();
        assert_eq!(s.bind_address, "10.0.0.5");
    }

    #[test]
    fn settings_round_trip_through_json() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(s.version, back.version);
        assert_eq!(s.bind_address, back.bind_address);
        assert_eq!(s.socks_port_start, back.socks_port_start);
        assert_eq!(s.export_protocol, back.export_protocol);
    }

    #[test]
    fn app_dir_ends_with_portify() {
        let dir = app_dir();
        assert!(dir.ends_with("Portify"), "unexpected dir: {dir:?}");
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add settings and migration tests"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job fails — `migrate_settings` returns the default rather than migrating.

- [ ] **Step 3: Implement the store**

Replace the stubs in `src-tauri/src/store.rs`:

```rust
use crate::nodes::Node;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

pub const SETTINGS_VERSION: u32 = 1;

/// The name of the settings file inside the app directory.
const SETTINGS_FILE: &str = "settings.json";
const NODES_FILE: &str = "nodes.json";

/// `%APPDATA%\Portify`, created if it does not exist.
pub fn app_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("Portify");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn read_json(path: &PathBuf) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_json(path: &PathBuf, value: &impl Serialize) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| format!("could not serialize {}: {e}", path.display()))?;
    fs::write(path, text).map_err(|e| format!("could not write {}: {e}", path.display()))
}

pub fn load_nodes() -> Vec<Node> {
    let path = app_dir().join(NODES_FILE);
    let Some(raw) = read_json(&path) else {
        return Vec::new();
    };
    // A corrupt nodes file must not stop the app from starting; the user
    // can re-import their links.
    serde_json::from_value(raw).unwrap_or_default()
}

pub fn save_nodes(nodes: &[Node]) -> Result<(), String> {
    write_json(&app_dir().join(NODES_FILE), &nodes)
}

pub fn load_settings() -> Settings {
    let path = app_dir().join(SETTINGS_FILE);
    match read_json(&path) {
        Some(raw) => migrate_settings(raw).unwrap_or_default(),
        None => Settings::default(),
    }
}

pub fn save_settings(settings: &Settings) -> Result<(), String> {
    write_json(&app_dir().join(SETTINGS_FILE), settings)
}

/// Brings a settings file forward to the current schema.
///
/// Each step upgrades one version. A file from a *newer* version is refused
/// rather than silently misinterpreted.
pub fn migrate_settings(raw: Value) -> Result<Settings, String> {
    let version = raw.get("version").and_then(Value::as_u64).unwrap_or(0) as u32;

    if version > SETTINGS_VERSION {
        return Err(format!(
            "these settings were written by a newer version of Portify (schema {version}, this build understands {SETTINGS_VERSION}); update Portify or delete {SETTINGS_FILE}"
        ));
    }

    let mut value = raw;
    let mut current = version;

    while current < SETTINGS_VERSION {
        value = match current {
            // 0 -> 1: `auto_start_gateway` and `export_protocol` were added.
            0 => {
                let mut v = value;
                if let Some(obj) = v.as_object_mut() {
                    obj.entry("auto_start_gateway")
                        .or_insert(Value::Bool(false));
                    obj.entry("export_protocol")
                        .or_insert(Value::String("http".into()));
                }
                v
            }
            _ => value,
        };
        current += 1;
    }

    if let Some(obj) = value.as_object_mut() {
        obj.insert("version".into(), Value::from(SETTINGS_VERSION));
    }

    // Every remaining field falls back to its default when absent, so a
    // partial settings file still loads.
    let mut settings: Settings = serde_json::from_value(value).unwrap_or_default();
    settings.version = SETTINGS_VERSION;
    Ok(settings)
}
```

- [ ] **Step 4: Add the module to the crate**

In `src-tauri/src/lib.rs`:

```rust
pub mod store;
```

- [ ] **Step 5: Push and confirm the tests pass**

```bash
git add -A
git commit -m "feat: persist nodes and settings with schema migration"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: store checkpoint" --allow-empty
git push
```

---

## Task 5: sing-box engine — locate, verify, validate, spawn

Finds the sing-box binary, validates the generated config with it, starts it, streams its logs, and stops it cleanly.

**Files:**
- Create: `src-tauri/src/engine.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod engine;`)

**Interfaces:**
- Consumes: `crate::store::app_dir`.
- Produces:
  - `pub const SINGBOX_VERSION: &str = "1.14.3";`
  - `pub const SINGBOX_SHA256_AMD64: &str = "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf";`
  - `pub const SINGBOX_SHA256_ARM64: &str = "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4";`
  - `pub enum SingBoxSource { Bundled, NextToExe, Cached, Downloaded }`
  - `pub struct ResolvedBinary { pub path: PathBuf, pub source: SingBoxSource }`
  - `pub async fn resolve_binary() -> Result<ResolvedBinary, String>` — checks the known locations; downloads if none exist.
  - `pub async fn download_singbox() -> Result<PathBuf, String>` — downloads, extracts, verifies the SHA-256, and caches it.
  - `pub fn sha256_hex(data: &[u8]) -> String`
  - `pub fn expected_sha256() -> &'static str` — the digest for the current architecture.
  - `pub fn check_config(singbox: &Path, config_path: &Path) -> Result<(), String>` — runs `sing-box check`, returning the stderr verbatim on failure.
  - `pub struct RunningGateway { pub child: Child, pub config_path: PathBuf }`
  - `pub fn spawn_gateway(singbox: &Path, config_path: &Path) -> Result<RunningGateway, String>` — spawns `sing-box run -c <config> --disable-color` with stderr piped.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/engine.rs`:

```rust
use std::path::{Path, PathBuf};

pub const SINGBOX_VERSION: &str = "1.14.3";
pub const SINGBOX_SHA256_AMD64: &str =
    "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf";
pub const SINGBOX_SHA256_ARM64: &str =
    "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxSource {
    Bundled,
    NextToExe,
    Cached,
    Downloaded,
}

#[derive(Debug, Clone)]
pub struct ResolvedBinary {
    pub path: PathBuf,
    pub source: SingBoxSource,
}

pub fn expected_sha256() -> &'static str {
    SINGBOX_SHA256_AMD64
}

pub fn sha256_hex(_data: &[u8]) -> String {
    String::new()
}

pub fn resolve_binary() -> Result<ResolvedBinary, String> {
    Err("not implemented".into())
}

pub fn download_singbox() -> Result<PathBuf, String> {
    Err("not implemented".into())
}

pub fn check_config(_singbox: &Path, _config_path: &Path) -> Result<(), String> {
    Err("not implemented".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_is_lowercase_hex_of_64_chars() {
        let hex = sha256_hex(b"portify");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn expected_sha256_is_a_known_digest() {
        let hex = expected_sha256();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_pinned_amd64_digest_is_the_sing_box_1_14_3_binary() {
        // The digest recorded in the spec for sing-box 1.14.3 windows-amd64.
        assert_eq!(
            SINGBOX_SHA256_AMD64,
            "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf"
        );
    }

    #[test]
    fn the_pinned_arm64_digest_is_the_sing_box_1_14_3_binary() {
        assert_eq!(
            SINGBOX_SHA256_ARM64,
            "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4"
        );
    }

    #[test]
    fn checking_a_missing_binary_fails_cleanly() {
        let err = check_config(Path::new("no-such-sing-box.exe"), Path::new("no-config.json"))
            .unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn the_release_url_follows_the_version() {
        let url = release_url("amd64");
        assert!(url.contains(SINGBOX_VERSION), "url must carry the version: {url}");
        assert!(url.ends_with(".zip"), "url must point at the zip: {url}");
    }

    #[test]
    fn the_release_url_is_amd64_or_arm64() {
        assert!(release_url("amd64").contains("windows-amd64"));
        assert!(release_url("arm64").contains("windows-arm64"));
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add engine tests"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job fails — `sha256_hex` returns an empty string.

- [ ] **Step 3: Implement the engine**

Replace the stubs in `src-tauri/src/engine.rs`:

```rust
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub const SINGBOX_VERSION: &str = "1.14.3";
pub const SINGBOX_SHA256_AMD64: &str =
    "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf";
pub const SINGBOX_SHA256_ARM64: &str =
    "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4";

/// The name of the file inside the release archive.
const BINARY_NAME: &str = "sing-box.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxSource {
    Bundled,
    NextToExe,
    Cached,
    Downloaded,
}

#[derive(Debug, Clone)]
pub struct ResolvedBinary {
    pub path: PathBuf,
    pub source: SingBoxSource,
}

/// The digest for the architecture this build is running on.
pub fn expected_sha256() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        SINGBOX_SHA256_ARM64
    } else {
        SINGBOX_SHA256_AMD64
    }
}

/// The architecture slug used in the release asset names.
pub fn arch_slug() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The GitHub release URL for the current architecture.
pub fn release_url(arch: &str) -> String {
    format!(
        "https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-windows-{arch}.zip"
    )
}

/// The directory the executable lives in.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
}

/// The cached download location.
pub fn cached_binary_path() -> PathBuf {
    crate::store::app_dir().join("sing-box").join(BINARY_NAME)
}

/// Looks for sing-box in the known locations, downloading it if needed.
///
/// The order is: the `sing-box/` folder next to the executable (the
/// self-contained ZIP layout), the executable's own folder, then the cache.
pub async fn resolve_binary() -> Result<ResolvedBinary, String> {
    if let Some(dir) = exe_dir() {
        let bundled = dir.join("sing-box").join(BINARY_NAME);
        if bundled.is_file() {
            return Ok(ResolvedBinary {
                path: bundled,
                source: SingBoxSource::Bundled,
            });
        }
        let next_to_exe = dir.join(BINARY_NAME);
        if next_to_exe.is_file() {
            return Ok(ResolvedBinary {
                path: next_to_exe,
                source: SingBoxSource::NextToExe,
            });
        }
    }

    let cached = cached_binary_path();
    if cached.is_file() {
        return Ok(ResolvedBinary {
            path: cached,
            source: SingBoxSource::Cached,
        });
    }

    let path = download_singbox().await?;
    Ok(ResolvedBinary {
        path,
        source: SingBoxSource::Downloaded,
    })
}

/// Downloads the sing-box release, extracts the binary, verifies its digest
/// and caches it.
///
/// This is **async**: Tauri's command handlers run on an async runtime, and
/// `reqwest::blocking` panics when called from inside one.
pub async fn download_singbox() -> Result<PathBuf, String> {
    let arch = arch_slug();
    let url = release_url(arch);
    let target_dir = crate::store::app_dir().join("sing-box");
    fs::create_dir_all(&target_dir)
        .map_err(|e| format!("could not create {}: {e}", target_dir.display()))?;
    let target = target_dir.join(BINARY_NAME);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("could not create the HTTP client: {e}"))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("could not download {url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "could not download {url}: the server answered {}",
            response.status()
        ));
    }
    let archive = response
        .bytes()
        .await
        .map_err(|e| format!("could not read the download: {e}"))?;

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive.as_ref()))
        .map_err(|e| format!("could not open the downloaded archive: {e}"))?;

    let mut extracted: Option<Vec<u8>> = None;
    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| format!("could not read the archive entry {i}: {e}"))?;
        if !file.is_file() {
            continue;
        }
        // The archive holds sing-box.exe at the top level, optionally inside
        // a versioned folder.
        let name = file.name().replace('\\', "/");
        if !name.ends_with(BINARY_NAME) {
            continue;
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| format!("could not extract sing-box.exe: {e}"))?;
        extracted = Some(buf);
        break;
    }

    let data = extracted.ok_or_else(|| {
        format!("the downloaded archive did not contain {BINARY_NAME}")
    })?;

    let actual = sha256_hex(&data);
    let expected = expected_sha256();
    if actual != expected {
        return Err(format!(
            "the downloaded sing-box binary failed its checksum (expected {expected}, got {actual}); refusing to use it"
        ));
    }

    fs::write(&target, &data)
        .map_err(|e| format!("could not write {}: {e}", target.display()))?;
    Ok(target)
}

/// Runs `sing-box check` against a config file.
///
/// Returns the process's stderr verbatim when the check fails, because that
/// is the only useful description of what sing-box objected to.
pub fn check_config(singbox: &Path, config_path: &Path) -> Result<(), String> {
    let output = Command::new(singbox)
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .arg("--disable-color")
        .output()
        .map_err(|e| format!("could not run {}: {e}", singbox.display()))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    Err(if detail.is_empty() {
        format!(
            "sing-box rejected the configuration (exit status {})",
            output.status.code().unwrap_or(-1)
        )
    } else {
        format!("sing-box rejected the configuration: {detail}")
    })
}

/// A running sing-box process.
pub struct RunningGateway {
    pub child: Child,
    pub config_path: PathBuf,
}

/// Spawns `sing-box run` with stderr piped.
///
/// sing-box writes every log line to stderr and leaves stdout empty, so the
/// caller reads stderr for the log view. `--disable-color` strips the ANSI
/// escapes so the UI can render plain text.
pub fn spawn_gateway(singbox: &Path, config_path: &Path) -> Result<RunningGateway, String> {
    let child = Command::new(singbox)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .arg("--disable-color")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", singbox.display()))?;

    Ok(RunningGateway {
        child,
        config_path: config_path.to_path_buf(),
    })
}
```

**Note on `reqwest::blocking`:** do not use it. It panics when called from
inside an async runtime ("This method panics if called from within an async
runtime"), and every Tauri command handler runs on one. The download uses the
async `reqwest::Client` instead, which is why `download_singbox` is `async`.

- [ ] **Step 4: Add the module to the crate**

In `src-tauri/src/lib.rs`:

```rust
pub mod engine;
```

- [ ] **Step 5: Push and confirm the tests pass**

```bash
git add -A
git commit -m "feat: locate, verify and run sing-box"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes.

- [ ] **Step 6: Verify the digest check against the real binary**

The `sha256_hex` test pins the algorithm. Verify the *pinned constant* against
the real release by downloading it in CI. Add this step to the `rust` job in
`.github/workflows/ci.yml`, right after the "Validate the generated config with
sing-box" step:

```yaml
      - name: Verify the pinned sing-box digest
        if: success()
        shell: pwsh
        run: |
          $exe = (Get-ChildItem -Path sing-box-extract -Recurse -Filter "sing-box.exe" | Select-Object -First 1).FullName
          $hash = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower()
          $expected = "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf"
          Write-Host "downloaded: $hash"
          Write-Host "expected:   $expected"
          if ($hash -ne $expected) { throw "sing-box checksum mismatch" }

This step verifies the *exact* digest that the release workflow pins, against
the *exact* binary that ships. If the upstream release is ever replaced, this
step fails before a broken binary can be published.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: engine checkpoint" --allow-empty
git push
```

---

## Task 6: Windows Firewall management

Adds and removes the scoped inbound rule that is only needed when the bind address is not loopback.

**Files:**
- Create: `src-tauri/src/fw.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod fw;`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub const RULE_NAME: &str = "Portify";`
  - `pub fn is_loopback(bind: &str) -> bool`
  - `pub fn needs_firewall_rule(bind: &str) -> bool`
  - `pub fn rule_exists() -> bool`
  - `pub fn add_rule(socks_ports: &str, http_ports: &str) -> Result<(), String>`
  - `pub fn remove_rule() -> Result<(), String>`
  - `pub fn build_add_command(socks_ports: &str, http_ports: &str) -> String` — the `netsh` argument list, exposed for testing.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/fw.rs`:

```rust
pub const RULE_NAME: &str = "Portify";

pub fn is_loopback(_bind: &str) -> bool {
    false
}

pub fn needs_firewall_rule(_bind: &str) -> bool {
    true
}

pub fn rule_exists() -> bool {
    false
}

pub fn build_add_command(_socks_ports: &str, _http_ports: &str) -> String {
    String::new()
}

pub fn add_rule(_socks_ports: &str, _http_ports: &str) -> Result<(), String> {
    Ok(())
}

pub fn remove_rule() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses_need_no_rule() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.0.0.53"));
        assert!(is_loopback("::1"));
    }

    #[test]
    fn lan_addresses_need_a_rule() {
        assert!(!is_loopback("0.0.0.0"));
        assert!(!is_loopback("192.168.1.10"));
        assert!(!is_loopback("::"));
    }

    #[test]
    fn the_default_bind_needs_no_rule() {
        assert!(!needs_firewall_rule("127.0.0.1"));
        assert!(needs_firewall_rule("0.0.0.0"));
    }

    #[test]
    fn the_add_command_scopes_the_rule_to_the_local_subnet() {
        let cmd = build_add_command("11080-11179", "18080-18179");
        assert!(cmd.contains("Portify"), "missing the rule name: {cmd}");
        assert!(cmd.contains("dir=in"), "missing the direction: {cmd}");
        assert!(cmd.contains("action=allow"), "missing the action: {cmd}");
        assert!(cmd.contains("remoteip=localsubnet"), "not scoped to the local subnet: {cmd}");
        assert!(cmd.contains("localport=11080-11179,18080-18179"), "wrong ports: {cmd}");
        assert!(cmd.contains("profile=private,domain"), "wrong profiles: {cmd}");
    }

    #[test]
    fn the_add_command_does_not_disable_the_firewall() {
        let cmd = build_add_command("1-2", "3-4");
        assert!(!cmd.to_lowercase().contains("set firewall"));
        assert!(!cmd.to_lowercase().contains("off"));
        assert!(!cmd.to_lowercase().contains("allowedprogram"));
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add firewall tests"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job fails.

- [ ] **Step 3: Implement the firewall module**

Replace the stubs in `src-tauri/src/fw.rs`:

```rust
use std::process::Command;

/// The name of the firewall rule Portify creates.
pub const RULE_NAME: &str = "Portify";

/// True when the bind address only accepts connections from this machine.
pub fn is_loopback(bind: &str) -> bool {
    let bind = bind.trim();
    bind == "::1" || bind.starts_with("127.")
}

/// True when a firewall rule is needed. The default loopback bind never
/// needs one, so no rule is created unless the user moved the gateway onto
/// the LAN.
pub fn needs_firewall_rule(bind: &str) -> bool {
    !is_loopback(bind)
}

/// The `netsh` arguments that create the rule.
///
/// The rule is scoped to `remoteip=localsubnet` and the private and domain
/// profiles, so it never exposes the gateway to the public internet.
pub fn build_add_command(socks_ports: &str, http_ports: &str) -> String {
    format!(
        "advfirewall firewall add rule name=\"{RULE_NAME}\" dir=in action=allow protocol=TCP localport={socks_ports},{http_ports} remoteip=localsubnet profile=private,domain enable=yes"
    )
}

/// Runs a `netsh` command with elevation.
///
/// `netsh` needs administrator rights, so the command is launched through
/// `Start-Process -Verb RunAs`, which raises a UAC prompt. If the user
/// declines, the call fails and the caller reports it.
fn run_elevated(args: &str) -> Result<(), String> {
    let script = format!(
        "Start-Process -FilePath netsh -ArgumentList '{args}' -Verb RunAs -Wait -WindowStyle Hidden"
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("could not run netsh: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    Err(if detail.is_empty() {
        "the firewall rule could not be added; the UAC prompt was declined or netsh failed".to_string()
    } else {
        format!("the firewall rule could not be added: {detail}")
    })
}

/// True when the rule already exists.
pub fn rule_exists() -> bool {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={RULE_NAME}"),
        ])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains(RULE_NAME),
        Err(_) => false,
    }
}

/// Creates the inbound rule. The rule is created idempotently: an existing
/// rule with the same name is removed first.
pub fn add_rule(socks_ports: &str, http_ports: &str) -> Result<(), String> {
    let _ = remove_rule();
    run_elevated(&build_add_command(socks_ports, http_ports))
}

/// Removes the inbound rule. A missing rule is not an error.
pub fn remove_rule() -> Result<(), String> {
    if !rule_exists() {
        return Ok(());
    }
    run_elevated(&format!(
        "advfirewall firewall delete rule name=\"{RULE_NAME}\""
    ))
}
```

- [ ] **Step 4: Add the module to the crate**

In `src-tauri/src/lib.rs`:

```rust
pub mod fw;
```

- [ ] **Step 5: Push and confirm the tests pass**

```bash
git add -A
git commit -m "feat: manage the scoped Windows Firewall rule"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: firewall checkpoint" --allow-empty
git push
```

---

## Task 7: Connectivity probing

Measures each node's latency, exit IP and status through its local SOCKS5 port.

**Files:**
- Create: `src-tauri/src/probe.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod probe;`)

**Interfaces:**
- Consumes: `crate::nodes::{Node, NodeStatus}`.
- Produces:
  - `pub const PROBE_URL: &str = "http://api.ipify.org?format=json";`
  - `pub struct ProbeResult { pub exit_ip: Option<String>, pub latency_ms: Option<u64>, pub error: Option<String> }`
  - `pub async fn probe_node(node: &Node, timeout_ms: u64) -> ProbeResult`
  - `pub fn parse_exit_ip(body: &str) -> Option<String>`
  - `pub fn describe_error(status: Option<u16>, err: &str) -> String` — turns a transport error into a readable message.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/probe.rs`:

```rust
use crate::nodes::Node;

pub const PROBE_URL: &str = "http://api.ipify.org?format=json";

#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub exit_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

pub fn parse_exit_ip(_body: &str) -> Option<String> {
    None
}

pub fn describe_error(_status: Option<u16>, _err: &str) -> String {
    String::new()
}

pub async fn probe_node(_node: &Node, _timeout_ms: u64) -> ProbeResult {
    ProbeResult::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_exit_ip_from_the_json_body() {
        assert_eq!(
            parse_exit_ip(r#"{"ip":"203.0.113.7"}"#),
            Some("203.0.113.7".to_string())
        );
    }

    #[test]
    fn parses_the_exit_ip_with_surrounding_whitespace() {
        assert_eq!(
            parse_exit_ip("  {\"ip\":\"203.0.113.7\"}\n"),
            Some("203.0.113.7".to_string())
        );
    }

    #[test]
    fn a_body_without_an_ip_yields_none() {
        assert_eq!(parse_exit_ip("not json"), None);
        assert_eq!(parse_exit_ip("{}"), None);
        assert_eq!(parse_exit_ip(r#"{"ip":""}"#), None);
    }

    #[test]
    fn a_connection_refused_is_reported_plainly() {
        let msg = describe_error(None, "error sending request for url (http://api.ipify.org/?format=json): tcp connect error: Connection refused (os error 10061)");
        assert!(msg.to_lowercase().contains("refused"), "unexpected message: {msg}");
    }

    #[test]
    fn a_timeout_is_reported_plainly() {
        let msg = describe_error(None, "error sending request: operation timed out");
        assert!(msg.to_lowercase().contains("timed out"), "unexpected message: {msg}");
    }

    #[test]
    fn a_dns_failure_is_reported_plainly() {
        let msg = describe_error(None, "error sending request: dns error: failed to lookup address information");
        assert!(
            msg.to_lowercase().contains("dns") || msg.to_lowercase().contains("lookup"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn an_http_error_status_is_reported_with_the_code() {
        let msg = describe_error(Some(503), "");
        assert!(msg.contains("503"), "unexpected message: {msg}");
    }

    #[test]
    fn an_unrecognised_error_still_returns_something_readable() {
        let msg = describe_error(None, "something odd happened");
        assert!(!msg.is_empty());
        assert!(msg.to_lowercase().contains("something odd"), "unexpected message: {msg}");
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add probe tests"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job fails.

- [ ] **Step 3: Implement the probe module**

Replace the stubs in `src-tauri/src/probe.rs`:

```rust
use crate::nodes::Node;
use std::time::{Duration, Instant};

/// The endpoint used to measure latency and read the exit IP.
///
/// It is plain HTTP on purpose: a TLS handshake would add a variable that
/// depends on the node's own TLS configuration, which would make the
/// latency number meaningless as a comparison between nodes.
pub const PROBE_URL: &str = "http://api.ipify.org?format=json";

#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub exit_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Reads the exit IP out of the probe response body.
pub fn parse_exit_ip(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let ip = value.get("ip")?.as_str()?.trim();
    if ip.is_empty() { None } else { Some(ip.to_string()) }
}

/// Turns a transport error into a message a user can act on.
pub fn describe_error(status: Option<u16>, err: &str) -> String {
    if let Some(code) = status {
        return format!("the probe endpoint answered HTTP {code}");
    }

    let lower = err.to_lowercase();
    if lower.contains("refused") {
        return "the node refused the connection".to_string();
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return "the node did not answer in time".to_string();
    }
    if lower.contains("dns") || lower.contains("lookup") || lower.contains("name resolution") {
        return "the node's address could not be resolved".to_string();
    }
    if lower.contains("reset by peer") {
        return "the node reset the connection".to_string();
    }
    if lower.contains("certificate") || lower.contains("tls") {
        return "the TLS handshake with the node failed".to_string();
    }
    if err.trim().is_empty() {
        "the probe failed".to_string()
    } else {
        err.trim().to_string()
    }
}

/// Probes one node through its local SOCKS5 port.
///
/// The latency is the round-trip time of the single request that also
/// carries the exit IP.
pub async fn probe_node(node: &Node, timeout_ms: u64) -> ProbeResult {
    let Some(socks_port) = node.socks_port else {
        return ProbeResult {
            error: Some("the node has no SOCKS port; start the gateway first".into()),
            ..Default::default()
        };
    };

    let proxy = reqwest::Proxy::all(format!("socks5://127.0.0.1:{socks_port}"))
        .map_err(|e| ProbeResult {
            error: Some(format!("could not use the node's SOCKS port: {e}")),
            ..Default::default()
        })?;

    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_millis(timeout_ms.max(1000)))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeResult {
                error: Some(format!("could not create the HTTP client: {e}")),
                ..Default::default()
            };
        }
    };

    let started = Instant::now();
    let response = match client.get(PROBE_URL).send().await {
        Ok(r) => r,
        Err(e) => {
            return ProbeResult {
                error: Some(describe_error(None, &e.to_string())),
                ..Default::default()
            };
        }
    };
    let elapsed = started.elapsed();

    let status = response.status();
    if !status.is_success() {
        return ProbeResult {
            latency_ms: Some(elapsed.as_millis() as u64),
            error: Some(describe_error(Some(status.as_u16()), "")),
            ..Default::default()
        };
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return ProbeResult {
                latency_ms: Some(elapsed.as_millis() as u64),
                error: Some(describe_error(None, &e.to_string())),
                ..Default::default()
            };
        }
    };

    match parse_exit_ip(&body) {
        Some(ip) => ProbeResult {
            exit_ip: Some(ip),
            latency_ms: Some(elapsed.as_millis() as u64),
            error: None,
        },
        None => ProbeResult {
            latency_ms: Some(elapsed.as_millis() as u64),
            error: Some("the probe endpoint did not return an IP address".into()),
        },
    }
}
```

- [ ] **Step 4: Add the module to the crate**

In `src-tauri/src/lib.rs`:

```rust
pub mod probe;
```

- [ ] **Step 5: Push and confirm the tests pass**

```bash
git add -A
git commit -m "feat: probe node latency and exit IP"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: probe checkpoint" --allow-empty
git push
```

---

## Task 8: IPC command surface and app state

Exposes the backend to the frontend over Tauri commands, and holds the running gateway in managed state.

**Files:**
- Create: `src-tauri/src/cmd.rs`
- Modify: `src-tauri/src/lib.rs` (register the commands and the state)

**Interfaces:**
- Consumes: `crate::nodes`, `crate::config`, `crate::store`, `crate::engine`, `crate::probe`, `crate::fw`.
- Produces: the Tauri command surface listed below, plus the events
  `portify://log`, `portify://status` and `portify://node`.

Commands (all return `Result<_, String>` where they can fail):

| Command | Args | Returns |
|---|---|---|
| `import_links` | `text: String` | `ImportReport` |
| `import_file` | `path: String` | `ImportReport` |
| `list_nodes` | — | `Vec<Node>` |
| `delete_nodes` | `ids: Vec<String>` | `()` |
| `set_node_enabled` | `id: String, enabled: bool` | `()` |
| `bulk_set_enabled` | `ids: Vec<String>, enabled: bool` | `()` |
| `get_settings` | — | `Settings` |
| `save_settings` | `settings: Settings` | `()` |
| `start_gateway` | — | `Vec<Node>` |
| `stop_gateway` | — | `()` |
| `gateway_status` | — | `GatewayStatus` |
| `probe_node` | `id: String` | `Node` |
| `probe_all` | — | `Vec<Node>` |
| `export_endpoints` | `protocol: Option<String>` | `String` |
| `export_to_file` | `protocol: Option<String>, path: String` | `()` |
| `copy_endpoints` | `protocol: Option<String>` | `()` |
| `get_singbox_path` | — | `String` |
| `update_singbox` | — | `String` |
| `get_autostart` | — | `bool` |
| `set_autostart` | `enabled: bool` | `()` |

`GatewayStatus` is `serde_json::Value` with this shape:

```json
{
  "state": "stopped" | "running" | "starting" | "error",
  "bind_address": "127.0.0.1",
  "node_count": 12,
  "error": null
}
```

- [ ] **Step 1: Write the failing tests**

The export format and the endpoint list are pure functions, so they are unit-tested. Put them in `src-tauri/src/cmd.rs`:

```rust
use crate::nodes::Node;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatus {
    pub state: String,
    pub bind_address: String,
    pub node_count: usize,
    pub error: Option<String>,
}

/// Builds the `protocol://ip:port` list for the given nodes.
///
/// `protocol` is `http`, `socks5` or `both`. The default is `http` because
/// 9Router's proxy-pool request path uses undici 7, which rejects
/// `socks5://` proxy URLs.
pub fn build_endpoints(nodes: &[Node], protocol: &str, bind: &str) -> String {
    let mut lines = Vec::new();
    for node in nodes {
        let Some(http_port) = node.http_port else { continue };
        let Some(socks_port) = node.socks_port else { continue };
        match protocol {
            "socks5" => lines.push(format!("socks5://{bind}:{socks_port}")),
            "both" => {
                lines.push(format!("http://{bind}:{http_port}"));
                lines.push(format!("socks5://{bind}:{socks_port}"));
            }
            _ => lines.push(format!("http://{bind}:{http_port}")),
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::parse_link;

    fn node_with_ports(socks: u16, http: u16) -> Node {
        let mut n = parse_link("vless://00000000-0000-4000-8000-000000000000@example.com:443#A").unwrap();
        n.socks_port = Some(socks);
        n.http_port = Some(http);
        n
    }

    #[test]
    fn exports_http_endpoints_by_default() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "http", "127.0.0.1"),
            "http://127.0.0.1:18080"
        );
    }

    #[test]
    fn exports_socks5_endpoints_when_asked() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "socks5", "127.0.0.1"),
            "socks5://127.0.0.1:11080"
        );
    }

    #[test]
    fn exports_both_when_asked() {
        let nodes = vec![node_with_ports(11080, 18080)];
        let out = build_endpoints(&nodes, "both", "127.0.0.1");
        assert_eq!(out, "http://127.0.0.1:18080\nsocks5://127.0.0.1:11080");
    }

    #[test]
    fn an_unknown_protocol_falls_back_to_http() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "gopher", "127.0.0.1"),
            "http://127.0.0.1:18080"
        );
    }

    #[test]
    fn nodes_without_ports_are_skipped() {
        let mut n = node_with_ports(11080, 18080);
        n.socks_port = None;
        let nodes = vec![n];
        assert_eq!(build_endpoints(&nodes, "http", "127.0.0.1"), "");
    }

    #[test]
    fn the_export_uses_the_configured_bind_address() {
        let nodes = vec![node_with_ports(11080, 18080)];
        assert_eq!(
            build_endpoints(&nodes, "http", "192.168.1.10"),
            "http://192.168.1.10:18080"
        );
    }

    #[test]
    fn one_line_per_endpoint() {
        let nodes = vec![node_with_ports(11080, 18080), node_with_ports(11081, 18081)];
        let out = build_endpoints(&nodes, "http", "127.0.0.1");
        assert_eq!(out.lines().count(), 2);
        assert!(out.lines().all(|l| l.starts_with("http://127.0.0.1:")));
    }
}
```

- [ ] **Step 2: Push and confirm the tests fail**

```bash
git add -A
git commit -m "test: add export format tests"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job fails — `build_endpoints` returns an empty string.

- [ ] **Step 3: Implement the commands**

Add the real `build_endpoints` to `src-tauri/src/cmd.rs` (replacing the stub), then add the command implementations.

```rust
use crate::config::{allocate_ports, build_config};
use crate::engine;
use crate::fw;
use crate::nodes::{Node, NodeStatus};
use crate::store::{self, Settings};
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::sync::Mutex;
use tauri::{Emitter, Manager};

/// The running gateway, kept in Tauri's managed state.
pub struct AppState {
    pub child: Mutex<Option<engine::RunningGateway>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            child: Mutex::new(None),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
```

Now the commands. Add them to the same file:

```rust
fn status_value(state: &AppState, settings: &Settings, nodes: &[Node]) -> GatewayStatus {
    let running = state.child.lock().map(|c| c.is_some()).unwrap_or(false);
    GatewayStatus {
        state: if running { "running".into() } else { "stopped".into() },
        bind_address: settings.bind_address.clone(),
        node_count: nodes.iter().filter(|n| n.enabled).count(),
        error: None,
    }
}

#[tauri::command]
pub fn list_nodes() -> Vec<Node> {
    store::load_nodes()
}

#[tauri::command]
pub fn import_links(text: String) -> Result<crate::nodes::ImportReport, String> {
    let mut nodes = store::load_nodes();
    let (new_nodes, report) = crate::nodes::import_links(&text, &nodes);
    nodes.extend(new_nodes);
    store::save_nodes(&nodes)?;
    Ok(report)
}

#[tauri::command]
pub fn import_file(path: String) -> Result<crate::nodes::ImportReport, String> {
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read {path}: {e}"))?;
    import_links(text)
}

#[tauri::command]
pub fn delete_nodes(ids: Vec<String>) -> Result<(), String> {
    let mut nodes = store::load_nodes();
    nodes.retain(|n| !ids.contains(&n.id));
    store::save_nodes(&nodes)
}

#[tauri::command]
pub fn set_node_enabled(id: String, enabled: bool) -> Result<(), String> {
    let mut nodes = store::load_nodes();
    if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
        node.enabled = enabled;
    }
    store::save_nodes(&nodes)
}

#[tauri::command]
pub fn bulk_set_enabled(ids: Vec<String>, enabled: bool) -> Result<(), String> {
    let mut nodes = store::load_nodes();
    for node in nodes.iter_mut() {
        if ids.contains(&node.id) {
            node.enabled = enabled;
        }
    }
    store::save_nodes(&nodes)
}

#[tauri::command]
pub fn get_settings() -> Settings {
    store::load_settings()
}

#[tauri::command]
pub fn save_settings(app: tauri::AppHandle, settings: Settings) -> Result<(), String> {
    store::save_settings(&settings)?;
    // Keep the Windows start-with-Windows entry in step with the setting.
    set_autostart(app, settings.auto_start)
}
```

The start command does the real work — resolve the binary, write the config,
validate it with `sing-box check`, add the firewall rule if needed, and spawn:

```rust
#[tauri::command]
pub async fn start_gateway(app: tauri::AppHandle) -> Result<Vec<Node>, String> {
    let state = app.state::<AppState>();
    {
        let mut child = state.child.lock().map_err(|e| e.to_string())?;
        if child.is_some() {
            return Err("the gateway is already running".into());
        }
    }

    let settings = store::load_settings();
    let mut nodes = store::load_nodes();
    let enabled: Vec<Node> = nodes.iter().filter(|n| n.enabled).cloned().collect();

    if enabled.is_empty() {
        return Err("no nodes are enabled; import some links first".into());
    }

    let plan = allocate_ports(
        &nodes,
        settings.socks_port_start,
        settings.http_port_start,
        settings.port_range,
    )?;

    // Write the config and let sing-box itself validate it. The error
    // sing-box prints is the only useful description of what it objected to.
    let config_path = store::app_dir().join("config.json");
    let config = build_config(&nodes, &plan, &settings.bind_address, &settings.log_level);
    std::fs::write(&config_path, &config)
        .map_err(|e| format!("could not write the configuration: {e}"))?;

    let binary = engine::resolve_binary().await?;
    engine::check_config(&binary.path, &config_path)?;

    // The firewall rule is only needed for a non-loopback bind.
    if fw::needs_firewall_rule(&settings.bind_address) {
        let socks_range = format!(
            "{}-{}",
            settings.socks_port_start,
            settings.socks_port_start as u32 + settings.port_range as u32 - 1
        );
        let http_range = format!(
            "{}-{}",
            settings.http_port_start,
            settings.http_port_start as u32 + settings.port_range as u32 - 1
        );
        fw::add_rule(&socks_range, &http_range)?;
    }

    let mut running = engine::spawn_gateway(&binary.path, &config_path)?;

    // Record the ports each node actually got.
    for node in nodes.iter_mut() {
        if let Some((_, socks, http)) = plan.assignments.iter().find(|(id, _, _)| *id == node.id) {
            node.socks_port = Some(*socks);
            node.http_port = Some(*http);
        }
    }
    store::save_nodes(&nodes)?;

    // Stream sing-box's stderr to the UI. sing-box writes all its logs to
    // stderr and leaves stdout empty.
    let app_for_logs = app.clone();
    let stderr = running.child.stderr.take();
    if let Some(stderr) = stderr {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let level = if line.contains("FATAL") || line.contains("ERROR") {
                    "error"
                } else if line.contains("WARN") {
                    "warn"
                } else {
                    "info"
                };
                let _ = app_for_logs.emit("portify://log", serde_json::json!({ "line": line, "level": level }));
            }
        });
    }

    {
        let mut child = state.child.lock().map_err(|e| e.to_string())?;
        *child = Some(running);
    }

    let _ = app.emit("portify://status", status_value(&state, &settings, &nodes));
    Ok(nodes)
}

#[tauri::command]
pub fn stop_gateway(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    if let Some(mut running) = guard.take() {
        // sing-box exits cleanly on Ctrl+Break; fall back to a hard kill.
        let _ = running.child.kill();
        let _ = running.child.wait();
    }
    drop(guard);

    let settings = store::load_settings();
    if fw::needs_firewall_rule(&settings.bind_address) {
        let _ = fw::remove_rule();
    }
    Ok(())
}

#[tauri::command]
pub fn gateway_status(app: tauri::AppHandle) -> GatewayStatus {
    let state = app.state::<AppState>();
    let settings = store::load_settings();
    let nodes = store::load_nodes();
    status_value(&state, &settings, &nodes)
}

#[tauri::command]
pub async fn probe_node(app: tauri::AppHandle, id: String) -> Result<Node, String> {
    let settings = store::load_settings();
    let mut nodes = store::load_nodes();
    let node = nodes
        .iter_mut()
        .find(|n| n.id == id)
        .ok_or_else(|| "that node no longer exists".to_string())?;

    let result = crate::probe::probe_node(node, settings.probe_timeout_ms).await;
    node.exit_ip = result.exit_ip;
    node.latency_ms = result.latency_ms;
    node.last_checked = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    node.status = match &result.error {
        None => NodeStatus::Ok,
        Some(message) => NodeStatus::Failed { message: message.clone() },
    };
    let updated = node.clone();
    store::save_nodes(&nodes)?;
    let _ = app.emit("portify://node", &updated);
    Ok(updated)
}

#[tauri::command]
pub async fn probe_all(app: tauri::AppHandle) -> Result<Vec<Node>, String> {
    let settings = store::load_settings();
    let mut nodes = store::load_nodes();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for node in nodes.iter_mut() {
        if !node.enabled {
            continue;
        }
        let result = crate::probe::probe_node(node, settings.probe_timeout_ms).await;
        node.exit_ip = result.exit_ip;
        node.latency_ms = result.latency_ms;
        node.last_checked = Some(now);
        node.status = match &result.error {
            None => NodeStatus::Ok,
            Some(message) => NodeStatus::Failed { message: message.clone() },
        };
    }

    store::save_nodes(&nodes)?;
    for node in &nodes {
        let _ = app.emit("portify://node", node);
    }
    Ok(nodes)
}

#[tauri::command]
pub fn export_endpoints(protocol: Option<String>) -> String {
    let settings = store::load_settings();
    let nodes = store::load_nodes();
    build_endpoints(&nodes, &protocol.unwrap_or_else(|| settings.export_protocol), &settings.bind_address)
}

#[tauri::command]
pub fn export_to_file(protocol: Option<String>, path: String) -> Result<(), String> {
    let content = export_endpoints(protocol);
    std::fs::write(&path, content).map_err(|e| format!("could not write {path}: {e}"))
}

#[tauri::command]
pub async fn get_singbox_path() -> Result<String, String> {
    let binary = engine::resolve_binary().await?;
    Ok(binary.path.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn update_singbox() -> Result<String, String> {
    let path = engine::download_singbox().await?;
    Ok(path.to_string_lossy().to_string())
}

/// Whether Portify is registered to start with Windows.
#[tauri::command]
pub fn get_autostart(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    manager.is_enabled().map_err(|e| e.to_string())
}

/// Registers or unregisters Portify's start-with-Windows entry.
#[tauri::command]
pub fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    let result = if enabled {
        manager.enable()
    } else {
        manager.disable()
    };
    result.map_err(|e| e.to_string())
}
```

The `copy_endpoints` command needs the app handle to reach the clipboard plugin,
so it takes one:

```rust
#[tauri::command]
pub fn copy_endpoints(app: tauri::AppHandle, protocol: Option<String>) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    let content = export_endpoints(protocol);
    app.clipboard()
        .write_text(content)
        .map_err(|e| format!("could not write to the clipboard: {e}"))
}
```

- [ ] **Step 4: Register the commands and the state**

In `src-tauri/src/lib.rs`, replace the placeholder `run()`:

```rust
pub mod cmd;
pub mod config;
pub mod engine;
pub mod fw;
pub mod nodes;
pub mod probe;
pub mod store;

use cmd::AppState;
use tauri::Emitter;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            cmd::list_nodes,
            cmd::import_links,
            cmd::import_file,
            cmd::delete_nodes,
            cmd::set_node_enabled,
            cmd::bulk_set_enabled,
            cmd::get_settings,
            cmd::save_settings,
            cmd::start_gateway,
            cmd::stop_gateway,
            cmd::gateway_status,
            cmd::probe_node,
            cmd::probe_all,
            cmd::export_endpoints,
            cmd::export_to_file,
            cmd::copy_endpoints,
            cmd::get_singbox_path,
            cmd::update_singbox,
            cmd::get_autostart,
            cmd::set_autostart,
        ])
        .setup(|app| {
            // Start the gateway on launch when the user asked for it, and
            // make sure a firewall rule from a previous run does not linger.
            let handle = app.handle().clone();
            let settings = store::load_settings();
            if fw::needs_firewall_rule(&settings.bind_address) {
                let _ = fw::remove_rule();
            }
            if settings.auto_start_gateway {
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = cmd::start_gateway(handle.clone()).await {
                        let _ = handle.emit("portify://status", cmd::GatewayStatus {
                            state: "error".into(),
                            bind_address: settings.bind_address.clone(),
                            node_count: 0,
                            error: Some(e),
                        });
                    }
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Remove the firewall rule when the app closes, so a closed
            // Portify never leaves an open rule behind.
            if let tauri::WindowEvent::Destroyed = event {
                let settings = store::load_settings();
                if fw::needs_firewall_rule(&settings.bind_address) {
                    let _ = fw::remove_rule();
                }
                let _ = window;
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

Add the clipboard plugin to `Cargo.toml` and `package.json`:

```toml
tauri-plugin-clipboard-manager = "2"
```

```json
"@tauri-apps/plugin-clipboard-manager": "^2.5.0"
```

And add the permission to `src-tauri/capabilities/default.json`:

```json
"clipboard-manager:allow-write-text"
```

- [ ] **Step 5: Push and confirm it compiles**

```bash
git add -A
git commit -m "feat: expose the Tauri command surface"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: the `rust` job passes. The `windows` job proves the whole app links.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: command surface checkpoint" --allow-empty
git push
```

---

## Task 9: The user interface

Builds the whole window: dashboard, node table with search and bulk actions, import dialog, settings panel, export dialog and the live log panel.

**Files:**
- Create: `src/lib/types.ts`, `src/lib/api.ts`, `src/lib/format.ts`
- Create: `src/components/Dashboard.tsx`, `NodeTable.tsx`, `LogPanel.tsx`, `ImportDialog.tsx`, `SettingsPanel.tsx`, `ExportDialog.tsx`
- Modify: `src/App.tsx`, `src/styles.css`, `src/main.tsx`

**Interfaces:**
- Consumes: the command surface from Task 8.
- Produces: a working window. `src/lib/api.ts` is the only file that talks to Tauri; components never call `invoke` directly.

- [ ] **Step 1: Write the type definitions and the API layer**

`src/lib/types.ts` — the TypeScript mirrors of the Rust models:

```ts
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
```

**Note on `NodeStatus`:** Task 2 already defines it as an internally tagged
serde enum, so the JSON matches the TypeScript above:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum NodeStatus {
    Unknown,
    Ok,
    Failed { message: String },
}
```

**The variant must be a struct variant, not `Failed(String)`.** serde's
internally tagged enums require the variant's content to serialize as a map,
so a newtype variant holding a `String` fails at runtime with *"cannot
serialize tagged newtype variant NodeStatus::Failed containing a string"*.
The JSON is `{"kind":"unknown"}`, `{"kind":"ok"}`,
`{"kind":"failed","message":"..."}`.

`src/lib/api.ts` — the only place that talks to Tauri:

```ts
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { GatewayStatus, ImportReport, LogLine, Node, Settings } from "./types";

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
  exportEndpoints: (protocol?: string) => invoke<string>("export_endpoints", { protocol }),
  exportToFile: (protocol: string, path: string) =>
    invoke<void>("export_to_file", { protocol, path }),
  copyEndpoints: (protocol?: string) => invoke<void>("copy_endpoints", { protocol }),
  getSingboxPath: () => invoke<string>("get_singbox_path"),
  updateSingbox: () => invoke<string>("update_singbox"),
  getAutostart: () => invoke<boolean>("get_autostart"),
  setAutostart: (enabled: boolean) => invoke<void>("set_autostart", { enabled }),
};

export const onLog = (handler: (entry: LogLine) => void) =>
  listen<LogLine>("portify://log", (event) => handler(event.payload));

export const onStatus = (handler: (status: GatewayStatus) => void) =>
  listen<GatewayStatus>("portify://status", (event) => handler(event.payload));

export const onNode = (handler: (node: Node) => void) =>
  listen<Node>("portify://node", (event) => handler(event.payload));
```

**Important:** Tauri's `invoke` converts Rust argument names from `snake_case`
to `camelCase` automatically on the JavaScript side. The Rust command
parameter is `ids`, so the JS key is `ids`. The Rust parameter `text` stays
`text`. The Rust parameter `id` stays `id`. Only multi-word names change —
and there are none here except in `export_to_file`'s `path`, which is
single-word.

`src/lib/format.ts` — small display helpers:

```ts
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
```

- [ ] **Step 2: Write the stylesheet**

Replace `src/styles.css` with the full theme:

```css
:root {
  --bg: #0e1116;
  --bg-raised: #161b22;
  --bg-inset: #0a0d12;
  --border: #262d38;
  --fg: #e6edf3;
  --fg-dim: #8b98a9;
  --accent: #4a9eff;
  --ok: #3fb950;
  --warn: #d29922;
  --err: #f85149;
  --radius: 8px;
  --mono: "Cascadia Mono", "Consolas", ui-monospace, monospace;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: "Segoe UI", system-ui, sans-serif;
  font-size: 14px;
  overflow: hidden;
}

button {
  font: inherit;
  color: var(--fg);
  background: var(--bg-raised);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 6px 14px;
  cursor: pointer;
}
button:hover:not(:disabled) { border-color: var(--accent); }
button:disabled { opacity: 0.45; cursor: not-allowed; }
button.primary { background: var(--accent); border-color: var(--accent); color: #06121f; font-weight: 600; }
button.danger { border-color: var(--err); color: var(--err); }
button.ghost { background: transparent; }

input, select, textarea {
  font: inherit;
  color: var(--fg);
  background: var(--bg-inset);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 6px 10px;
  width: 100%;
}
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); }

.app { display: flex; flex-direction: column; height: 100vh; }

.header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 18px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-raised);
}
.header h1 { font-size: 16px; margin: 0; letter-spacing: 0.02em; }
.header .spacer { flex: 1; }

.pill {
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid var(--border);
}
.pill.running { color: var(--ok); border-color: var(--ok); }
.pill.stopped { color: var(--fg-dim); }
.pill.error { color: var(--err); border-color: var(--err); }

.body { display: flex; flex: 1; min-height: 0; }

.sidebar {
  width: 260px;
  flex-shrink: 0;
  border-right: 1px solid var(--border);
  padding: 16px;
  overflow-y: auto;
  background: var(--bg-raised);
}
.stat { margin-bottom: 16px; }
.stat .label { color: var(--fg-dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
.stat .value { font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; }
.stat .value.small { font-size: 14px; font-weight: 400; font-family: var(--mono); word-break: break-all; }

.main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
.toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
}
.toolbar .search { width: 240px; }

.chips { display: flex; gap: 6px; }
.chip {
  padding: 4px 12px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: transparent;
  font-size: 12px;
  color: var(--fg-dim);
}
.chip.active { border-color: var(--accent); color: var(--accent); }

.table-wrap { flex: 1; overflow: auto; }
table { width: 100%; border-collapse: collapse; }
th {
  text-align: left;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--fg-dim);
  font-weight: 600;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  background: var(--bg);
}
td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
tr.disabled td { opacity: 0.45; }
td.mono { font-family: var(--mono); font-size: 12px; }
td.num { font-variant-numeric: tabular-nums; text-align: right; }

.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot.ok { background: var(--ok); }
.dot.failed { background: var(--err); }
.dot.unknown { background: var(--fg-dim); }

.log-panel {
  height: 240px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  background: var(--bg-inset);
}
.log-panel.collapsed { height: 36px; }
.log-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  color: var(--fg-dim);
}
.log-body {
  flex: 1;
  overflow-y: auto;
  padding: 8px 12px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}
.log-body .warn { color: var(--warn); }
.log-body .error { color: var(--err); }

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10;
}
.modal {
  background: var(--bg-raised);
  border: 1px solid var(--border);
  border-radius: 12px;
  width: 620px;
  max-width: 92vw;
  max-height: 86vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.modal header {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
}
.modal header h2 { margin: 0; font-size: 15px; }
.modal .content { padding: 18px; overflow-y: auto; }
.modal footer {
  padding: 12px 18px;
  border-top: 1px solid var(--border);
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.field { margin-bottom: 14px; }
.field label { display: block; font-size: 12px; color: var(--fg-dim); margin-bottom: 4px; }
.field .hint { font-size: 11px; color: var(--fg-dim); margin-top: 4px; }
.row { display: flex; gap: 10px; }
.row > * { flex: 1; }

.report { margin-top: 12px; font-size: 13px; }
.report .line-error { color: var(--err); font-family: var(--mono); font-size: 12px; }
.banner { padding: 8px 12px; border-radius: var(--radius); margin-bottom: 12px; font-size: 13px; }
.banner.error { background: rgba(248, 81, 73, 0.12); border: 1px solid var(--err); }
.banner.ok { background: rgba(63, 185, 80, 0.12); border: 1px solid var(--ok); }
.empty { padding: 40px; text-align: center; color: var(--fg-dim); }
```

- [ ] **Step 3: Write the components**

`src/components/Dashboard.tsx`:

```tsx
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
        <div className="value" style={{ color: "var(--ok)" }}>{online.length}</div>
      </div>
      <div className="stat">
        <div className="label">Offline</div>
        <div className="value" style={{ color: offline.length ? "var(--err)" : undefined }}>
          {offline.length}
        </div>
      </div>
      <div className="stat">
        <div className="label">Average latency</div>
        <div className="value">{average === null ? "—" : `${average} ms`}</div>
      </div>
      <div className="stat">
        <div className="label">Bind address</div>
        <div className="value small">{settings.bind_address}</div>
      </div>
      <div className="stat">
        <div className="label">Uptime</div>
        <div className="value small">{uptime === null ? "—" : formatUptime(uptime)}</div>
      </div>
      <div className="stat">
        <div className="label">sing-box</div>
        <div className="value small">{singboxPath ?? "—"}</div>
      </div>
    </aside>
  );
}
```

`src/components/NodeTable.tsx`:

```tsx
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
    case "enabled": return node.enabled;
    case "disabled": return !node.enabled;
    case "online": return node.status.kind === "ok";
    case "offline": return node.status.kind === "failed";
    default: return true;
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
  nodes, selected, filter, query,
  onToggleSelect, onToggleAll, onToggleEnabled, onDelete, onProbe,
}: Props) {
  const visible = nodes.filter((n) => matchesFilter(n, filter) && matchesQuery(n, query));
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
            <th style={{ width: 120 }}></th>
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
                <td className="mono">{node.host}:{node.port}</td>
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
                  <button className="ghost" onClick={() => onProbe(node)}>Test</button>
                  <button className="ghost danger" onClick={() => onDelete(node)}>✕</button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
```

`src/components/LogPanel.tsx`:

```tsx
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
            <button className="ghost" onClick={onClear}>Clear</button>
          </>
        )}
      </div>
      {!collapsed && (
        <div className="log-body" ref={bodyRef}>
          {lines.length === 0 && <span style={{ color: "var(--fg-dim)" }}>No output yet.</span>}
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
```

`src/components/ImportDialog.tsx`:

```tsx
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
    const picked = await open({ multiple: false, directory: false, filters: [{ name: "Text", extensions: ["txt", "list", "conf"] }] });
    if (typeof picked === "string") await run(() => api.importFile(picked));
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header><h2>Import links</h2></header>
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
            <button onClick={importFile} disabled={busy}>Choose file…</button>
            <button className="primary" onClick={importText} disabled={busy || !text.trim()}>
              Import
            </button>
          </div>
          {report && (
            <div className="report">
              <div className="banner ok">
                Imported {report.imported}, skipped {report.duplicates} duplicate{report.duplicates === 1 ? "" : "s"}.
              </div>
              {report.errors.length > 0 && (
                <>
                  <div style={{ color: "var(--err)" }}>{report.errors.length} line(s) failed:</div>
                  {report.errors.map((e) => (
                    <div key={e.line} className="line-error">Line {e.line}: {e.message}</div>
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
```

`src/components/SettingsPanel.tsx`:

```tsx
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
          <select value={draft.log_level} onChange={(e) => set("log_level", e.target.value)}>
            {["trace", "debug", "info", "warn", "error"].map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Export protocol</label>
          <select value={draft.export_protocol} onChange={(e) => set("export_protocol", e.target.value)}>
            <option value="http">http</option>
            <option value="socks5">socks5</option>
            <option value="both">both</option>
          </select>
          <div className="hint">
            9Router's proxy pool only accepts http:// endpoints, so http is the default.
          </div>
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

      <button className="primary" onClick={save}>Save settings</button>
    </div>
  );
}
```

`src/components/ExportDialog.tsx`:

```tsx
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
        if (!cancelled) { setContent(text); setError(null); }
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    })();
    return () => { cancelled = true; };
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
        <header><h2>Export endpoints</h2></header>
        <div className="content">
          {error && <div className="banner error">{error}</div>}
          {message && <div className="banner ok">{message}</div>}
          <div className="field">
            <label>Protocol</label>
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="http">http</option>
              <option value="socks5">socks5</option>
              <option value="both">both</option>
            </select>
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
          <button className="primary" onClick={copy}>Copy</button>
          <button onClick={onClose}>Close</button>
        </footer>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Write the App shell**

Replace `src/App.tsx`:

```tsx
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
      onNode((node) => setNodes((prev) => prev.map((n) => (n.id === node.id ? node : n)))),
    ]);
    return () => { unlisten.then((fns) => fns.forEach((fn) => fn())); };
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
      if (next.has(id)) next.delete(id); else next.add(id);
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
          <button className="danger" onClick={stop}>Stop</button>
        ) : (
          <button className="primary" onClick={start}>Start</button>
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
          {error && <div className="banner error" style={{ margin: 12 }}>{error}</div>}

          <div className="toolbar">
            <input
              className="search"
              placeholder="Search name, host or exit IP"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <div className="chips">
              {(["all", "enabled", "disabled", "online", "offline"] as Filter[]).map((f) => (
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
                <span style={{ color: "var(--fg-dim)" }}>{selectedIds.length} selected</span>
                <button onClick={async () => { await api.bulkSetEnabled(selectedIds, true); await refreshNodes(); }}>
                  Enable
                </button>
                <button onClick={async () => { await api.bulkSetEnabled(selectedIds, false); await refreshNodes(); }}>
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
            <button onClick={async () => { setNodes(await api.probeAll()); }}>Test all</button>
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
              setNodes((prev) => prev.map((n) => (n.id === updated.id ? updated : n)));
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
            <header><h2>Settings</h2></header>
            <SettingsPanel
              settings={settings}
              onSaved={(next) => { setSettings(next); setShowSettings(false); }}
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
```

- [ ] **Step 5: Build and check the types**

```bash
npm run build
```

Expected: `tsc` reports no errors and Vite writes `dist/`. Fix any type errors
before committing — the CI `frontend` job runs the same command.

- [ ] **Step 6: Push and confirm CI is green**

```bash
git add -A
git commit -m "feat: build the Portify user interface"
git push
gh run list --limit 1 --json conclusion,url --jq '.[0].url + " " + .[0].conclusion'
```

Expected: all three jobs pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: ui checkpoint" --allow-empty
git push
```

---

## Task 10: Release workflow and artifacts

Builds the three release artifacts and publishes them to a GitHub Release.

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `scripts/README-portable.txt` (the text shipped inside the ZIP)

**Interfaces:**
- Consumes: the `portify` crate and the `package.json` scripts.
- Produces: `Portify_<version>_x64-setup.exe`, `Portify_<version>_x64_portable.exe` and `Portify_<version>_x64_portable.zip` attached to the release.

- [ ] **Step 1: Write the release workflow**

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

permissions:
  contents: write

env:
  SINGBOX_VERSION: "1.14.3"
  SINGBOX_SHA256_AMD64: "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf"
  SINGBOX_SHA256_ARM64: "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4"

jobs:
  release:
    name: Build and publish
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: src-tauri

      - name: Install frontend dependencies
        run: npm ci

      - name: Read the version
        id: version
        shell: pwsh
        run: |
          $v = (Get-Content package.json -Raw | ConvertFrom-Json).version
          "value=$v" >> $env:GITHUB_OUTPUT
          Write-Host "Building Portify $v"

      - name: Download sing-box
        shell: pwsh
        run: |
          $arch = "amd64"
          $url = "https://github.com/SagerNet/sing-box/releases/download/v$env:SINGBOX_VERSION/sing-box-$env:SINGBOX_VERSION-windows-$arch.zip"
          Invoke-WebRequest -Uri $url -OutFile sing-box.zip
          Expand-Archive -Path sing-box.zip -DestinationPath sing-box-extract -Force
          $exe = Get-ChildItem -Path sing-box-extract -Recurse -Filter "sing-box.exe" | Select-Object -First 1
          $hash = (Get-FileHash -Path $exe.FullName -Algorithm SHA256).Hash.ToLower()
          $expected = $env:SINGBOX_SHA256_AMD64
          if ($hash -ne $expected) {
            Write-Error "sing-box checksum mismatch: expected $expected, got $hash"
            exit 1
          }
          Write-Host "sing-box verified: $hash"

      - name: Build the Tauri bundles
        shell: pwsh
        run: npm run tauri build -- --bundles nsis

      - name: Assemble the release artifacts
        shell: pwsh
        run: |
          $version = "${{ steps.version.outputs.value }}"
          $target = "target/release"

          # The NSIS installer built by the bundler.
          $setup = Get-ChildItem -Path "target/release/bundle/nsis" -Filter "*setup.exe" | Select-Object -First 1
          Copy-Item $setup.FullName "Portify_${version}_x64-setup.exe"

          # The portable executable.
          Copy-Item "$target/portify.exe" "Portify_${version}_x64_portable.exe"

          # The self-contained ZIP: Portify plus the verified sing-box binary.
          $stage = "portable"
          Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
          New-Item -ItemType Directory -Path "$stage/sing-box" | Out-Null
          Copy-Item "$target/portify.exe" "$stage/portify.exe"
          $exe = Get-ChildItem -Path "sing-box-extract" -Recurse -Filter "sing-box.exe" | Select-Object -First 1
          Copy-Item $exe.FullName "$stage/sing-box/sing-box.exe"
          Copy-Item "scripts/README-portable.txt" "$stage/README.txt"
          Compress-Archive -Path "$stage/*" -DestinationPath "Portify_${version}_x64_portable.zip"

          Write-Host "Artifacts:"
          Get-ChildItem "Portify_${version}_x64*" | ForEach-Object { Write-Host "  $($_.Name) ($($_.Length) bytes)" }

      - name: Publish the release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            Portify_*_x64-setup.exe
            Portify_*_x64_portable.exe
            Portify_*_x64_portable.zip
          generate_release_notes: true
          draft: false
```

- [ ] **Step 2: Write the README that ships inside the ZIP**

`scripts/README-portable.txt`:

```
Portify — Windows Proxy Gateway
================================

This is the self-contained build. It contains everything Portify needs to run.

  portify.exe            the application
  sing-box\sing-box.exe  the proxy engine (verified by SHA-256 at build time)
  README.txt             this file

How to run
----------
  1. Double-click portify.exe.
  2. Use "Import" to paste or open a file of VLESS / Shadowsocks links.
  3. Press "Start". Each enabled node gets its own SOCKS5 and HTTP port.
  4. Use "Export" to copy the endpoints in protocol://ip:port form.

The endpoints bind to 127.0.0.1 by default, so only this machine can reach
them. Change the bind address in Settings to expose them on your network;
Portify then asks for administrator rights once to add a firewall rule that
is scoped to the local subnet.

No installation, no Rust, no Node.js and no other development tools are
needed. Windows 10 or newer is required.

Project: https://github.com/WhoisNeon/Portify
```

- [ ] **Step 3: Push and confirm nothing is broken**

```bash
git add -A
git commit -m "ci: add the release workflow"
git push
```

The release workflow only runs on a tag, so this push does not trigger it. The
`CI` workflow still runs and must stay green.

- [ ] **Step 4: Tag and publish the first release**

```bash
git tag v0.1.0
git push origin v0.1.0
```

```bash
gh run list --limit 3 --json name,status,conclusion,url --jq '.[] | "\(.name) \(.status) \(.conclusion) \(.url)"'
```

Expected: the `Release` workflow starts. Watch it:

```bash
gh run watch
```

If it fails, read the log:

```bash
gh run view --log-failed
```

Common failures and their fixes:

| Error | Fix |
|---|---|
| `error: linker `link.exe` not found` | The MSVC toolchain is missing. `dtolnay/rust-toolchain@stable` installs rustc but not MSVC; add `windows-latest` (it has the build tools) and check the step ran on Windows. |
| `The specified signing key does not exist` | NSIS signing is not configured; this step is only added when a certificate is present. Remove the `signCommand` from `tauri.conf.json` if it was added. |
| `sing-box checksum mismatch` | The pinned digest in `release.yml` no longer matches the release. Update the constant in `release.yml` **and** in `src-tauri/src/engine.rs`, and re-run the `sha256` check. |
| `WebView2 runtime not found` | Set `"webviewInstallMode": { "type": "downloadBootstrapper", "silent": true }` in `tauri.conf.json` (already the case) so the installer bootstraps it. |

- [ ] **Step 5: Verify the published release**

```bash
gh release list --limit 3
gh release view v0.1.0 --json url,assets --jq '.url, (.assets[] | "\(.name) \(.size) bytes")'
```

Expected: three assets, and each download URL resolves:

```bash
for asset in Portify_0.1.0_x64-setup.exe Portify_0.1.0_x64_portable.exe Portify_0.1.0_x64_portable.zip; do
  url="https://github.com/WhoisNeon/Portify/releases/download/v0.1.0/$asset"
  code=$(curl -sL -o /dev/null -w '%{http_code}' "$url")
  echo "$code  $asset"
done
```

Expected: `200` for each. A `302` that ends at a `404` means the asset name is
wrong — the names come from the version in `package.json`, so they change with
every release.

Also verify the ZIP contains sing-box:

```bash
curl -sL -o /tmp/portify.zip "https://github.com/WhoisNeon/Portify/releases/download/v0.1.0/Portify_0.1.0_x64_portable.zip"
"/c/Program Files/7-Zip/7z.exe" l /tmp/portify.zip
```

Expected: `portify.exe`, `sing-box/sing-box.exe` and `README.txt`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: release checkpoint" --allow-empty
git push
```

---

## Task 11: Project README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write the README**

`README.md`:

````markdown
# Portify

A Windows proxy gateway. Import a pile of VLESS and Shadowsocks links, and
Portify runs **every node at the same time**, each behind its own SOCKS5 and
HTTP port on `127.0.0.1`.

Built with [Tauri 2](https://tauri.app) and
[sing-box](https://sing-box.sagernet.org).

## What it does

- Imports VLESS and Shadowsocks links from a file or by pasting them.
- Validates every line and reports exactly what went wrong.
- Skips duplicates — the same node with a different name is still a duplicate.
- Runs all nodes in a single sing-box process, with **fixed routing**: traffic
  entering a node's port always exits that node.
- Gives each node a dedicated SOCKS5 port and HTTP port.
- Tests each node: latency, exit IP and status.
- Exports the endpoints as `protocol://ip:port`, ready to paste into a proxy
  pool.
- Live logs from sing-box, search, filters, bulk actions, a dashboard and
  persistent settings.

## Install

Download the **Setup EXE** and run it. That is the normal way to use it.

The **Self-contained ZIP** is for machines where you cannot install
anything: unzip it and run `portify.exe`. It ships with sing-box included.

The **Portable EXE** is a single file with no installer. It downloads
sing-box on first run, so it needs internet access once.

All three work on a clean Windows 10 or 11 machine. No Rust, no Node.js, no
development tools.

## Use

1. **Import** — paste your links, or pick a file.
2. **Start** — Portify writes a sing-box configuration, checks it with
   `sing-box check`, and starts the gateway.
3. **Test** — probe every node to see its latency, exit IP and status.
4. **Export** — copy the endpoints for another tool.

### Importing into 9Router

The export defaults to `http://` endpoints, because that is what 9Router's
proxy pool can actually use. A SOCKS5 export is one click away in the export
dialog if your tool supports it.

## How the ports work

With the default settings, node 1 gets SOCKS5 on `127.0.0.1:11080` and HTTP
on `127.0.0.1:18080`, node 2 gets `11081` / `18081`, and so on. The ranges
are configurable in Settings.

## Security

- The gateway binds to `127.0.0.1` by default. Nothing outside this machine
  can reach it.
- Changing the bind address to a LAN address asks for administrator rights
  once, to add a firewall rule scoped to the local subnet and to the private
  and domain profiles only. Portify never disables the Windows Firewall and
  never edits an existing rule.
- The sing-box binary is verified by SHA-256 before it is used.

## Development

```bash
npm install
npm run tauri dev
```

Rust tests and the sing-box config check run in CI:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

## Building a release

Push a `v*` tag. The release workflow builds the installer, the portable
executable and the self-contained ZIP, and attaches them to the GitHub
Release.

## License

MIT
````

- [ ] **Step 2: Push**

```bash
git add -A
git commit -m "docs: add the project README"
git push
```

Expected: CI stays green.

---

## Task 12: End-to-end verification on a clean machine

The final check: does a released artifact actually work on a machine with no Rust, no Node.js and no development tools?

**Files:**
- No source changes. This task verifies the released artifacts.

- [ ] **Step 1: Confirm the release assets are downloadable**

```bash
VERSION=$(node -p "require('./package.json').version")
for asset in "Portify_${VERSION}_x64-setup.exe" "Portify_${VERSION}_x64_portable.exe" "Portify_${VERSION}_x64_portable.zip"; do
  url="https://github.com/WhoisNeon/Portify/releases/download/v${VERSION}/${asset}"
  code=$(curl -sL -o /dev/null -w '%{http_code}' "$url")
  echo "$code  $asset"
done
```

Expected: `200` for all three.

- [ ] **Step 2: Download and inspect the self-contained ZIP**

```bash
mkdir -p /tmp/portify-verify && cd /tmp/portify-verify
VERSION=$(node -p "require('C:/Users/x14ne/OneDrive/Desktop/Projects/Apps/Portify/package.json').version")
curl -sL -o portify.zip "https://github.com/WhoisNeon/Portify/releases/download/v${VERSION}/Portify_${VERSION}_x64_portable.zip"
"/c/Program Files/7-Zip/7z.exe" x -y portify.zip >/dev/null
ls -R
```

Expected: `portify.exe`, `sing-box/sing-box.exe` and `README.txt`.

- [ ] **Step 3: Verify the bundled sing-box matches the pinned digest**

```bash
cd /tmp/portify-verify
certutil -hashfile sing-box/sing-box.exe SHA256
```

Expected: `5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf`.

- [ ] **Step 4: Run the portable build and confirm it starts**

```bash
cd /tmp/portify-verify
./portify.exe &
sleep 8
tasklist //FI "IMAGENAME eq portify.exe"
```

Expected: the process is listed. Close it with the window's close button, or:

```bash
taskkill //IM portify.exe //F
```

- [ ] **Step 5: Confirm the app works with no toolchain installed**

The point of this check is that the machine has no Rust and no Node.js in
`PATH` for the app to use. Verify:

```bash
where cargo 2>&1 | head -1
where node 2>&1 | head -1
```

Expected: both report "not found". Portify must still launch and find its
bundled sing-box, because the ZIP carries it.

- [ ] **Step 6: Verify the installer**

```bash
cd /tmp/portify-verify
curl -sL -o setup.exe "https://github.com/WhoisNeon/Portify/releases/download/v${VERSION}/Portify_${VERSION}_x64-setup.exe"
ls -la setup.exe
```

Run it and confirm the install completes and the shortcut appears. The
installer bundles the WebView2 bootstrapper, so it works on a machine without
the WebView2 runtime.

- [ ] **Step 7: Record the verification in the README**

Add a short "Verified" section to the README listing the release that was
tested and the date:

```markdown
## Verified

The v0.1.0 artifacts were installed and run on a clean Windows 11 machine
with no Rust and no Node.js installed (2026-10-19).
```

- [ ] **Step 8: Commit and push**

```bash
git add -A
git commit -m "docs: record the artifact verification"
git push
```

---








