# Portify — Windows Proxy Gateway — Design Spec

Date: 2026-10-19
Status: Approved
Repo: https://github.com/WhoisNeon/Portify

## 1. Purpose

Portify is a Windows desktop application that turns a list of VLESS / Shadowsocks
subscription links into a pool of simultaneously-running local proxy endpoints.
Each imported node gets its own dedicated SOCKS5 port and HTTP port on
`127.0.0.1`, backed by a single `sing-box` process that runs every node at once.

The end goal is that any tool that consumes "one proxy endpoint per node" — such
as 9Router's Proxy Pool — can be pointed at Portify's ports directly.

Success criteria:

- 50+ links import in one action, with per-line validation and duplicate detection.
- All nodes run **simultaneously**, each on its own ports, with fixed routing
  (traffic entering node N's port always exits node N).
- Connectivity, exit IP, latency and status are visible per node.
- The gateway is startable/stoppable, survives restarts with persisted settings,
  and can auto-start with Windows.
- Endpoints export in `protocol://ip:port` form for bulk import elsewhere.
- Releases work on a clean Windows machine with no Rust, Node.js or dev tools.

## 2. Non-goals

Explicitly out of scope (not requested):

- System proxy toggle (Windows `WinINET` settings).
- TUN / transparent mode.
- User-authored routing rules, domain-based split routing, or ad-block rule sets.
- In-app editing of a node's raw link after import (delete + re-import instead).
- In-app self-update (the GitHub Release page is the update channel).
- Protocols other than VLESS and Shadowsocks.

## 3. Architecture

```
┌──────────────┐   Tauri IPC (invoke)   ┌──────────────────────────┐
│  React 19    │ ──────────────────────► │  Rust backend            │
│  + TypeScript│ ◄────── events ──────── │                          │
└──────────────┘                         │  nodes.rs   link parser  │
                                         │  config.rs  sing-box cfg │
                                         │  engine.rs  process ctl  │
                                         │  probe.rs   connectivity │
                                         │  store.rs   persistence  │
                                         │  fw.rs      firewall     │
                                         └────────────┬─────────────┘
                                                      │ spawn + stderr
                                                      ▼
                                            ┌──────────────────┐
                                            │   sing-box.exe   │
                                            │  N outbounds     │
                                            │  2N inbounds     │
                                            │  fixed routing   │
                                            └──────────────────┘
```

Portify never carries traffic itself. It is a control plane: it owns the
sing-box configuration, the child process lifecycle, and the local ports that
other applications connect to.

### 3.1 Module layout (Rust, `src-tauri/src/`)

| File | Responsibility |
|---|---|
| `main.rs` | Entry point, calls `portify_lib::run()`. |
| `lib.rs` | Tauri builder, plugin registration, command registration, managed state. |
| `nodes.rs` | `Node` model, link parsing (VLESS/SS), validation, dedup, serialization. |
| `config.rs` | Build the sing-box JSON config from nodes + settings; port allocation. |
| `engine.rs` | Locate/download sing-box, `check` the config, spawn/kill the process, stream logs. |
| `probe.rs` | Per-node connectivity, exit IP and latency measurement. |
| `store.rs` | Persist and load `nodes.json` and `settings.json` in `%APPDATA%\Portify`. |
| `fw.rs` | Windows Firewall inbound rule management via `netsh`. |
| `cmd.rs` | `#[tauri::command]` surface — the IPC API. |

### 3.2 Rust dependencies

| Crate | Version | Purpose |
|---|---|---|
| `tauri` | 2 | App shell, IPC, state management. |
| `tauri-build` | 2 | Build script (context generation). |
| `serde` / `serde_json` | 1 | Config + persistence models. |
| `percent-encoding` | 2 | Percent-decoding link components. |
| `uuid` | 1 | UUID validation for VLESS. |
| `base64` | 0.23 | SS2022 password validation, Reality key decode. |
| `reqwest` | 0.13 | Probe traffic, sing-box auto-download. Features: `json`, `socks`, `rustls`, `charset`, `http2`. |
| `zip` | 2.6 | Extract the sing-box release archive. |
| `sha2` | 0.10 | Verify the SHA-256 of a downloaded sing-box binary. |
| `tokio` | 1 | Async runtime for probes. |
| `dirs` | 7 | `%APPDATA%` / user data dirs. |
| `tauri-plugin-dialog` | 2 | Native file picker for link files. |
| `tauri-plugin-fs` | 2 | Read picked link files. |
| `tauri-plugin-autostart` | 2 | Windows auto-start. |
| `tauri-plugin-opener` | 2 | Open URLs in the system browser. |

No async runtime abstraction layer, no ORM, no state-management library in the
frontend — a single `useReducer` plus a plain module-level event bus.

### 3.3 Frontend

- React 19 + TypeScript 6, Vite 8, `@vitejs/plugin-react` 6.
- `@tauri-apps/api` 2, `@tauri-apps/cli` 2.
- Styling: one hand-written `styles.css` with CSS custom properties. No UI
  framework, no Tailwind, no component library.
- State: `useReducer` in a single `App` component tree, plus a small
  `useTauriEvent` hook for `portify://` events.

## 4. Link parsing

### 4.1 VLESS

Format: `vless://<uuid>@<host>:<port>?<params>#<name>`

Recognised query parameters:

| Param | Meaning | Maps to sing-box |
|---|---|---|
| `encryption` | Must be `none`. Rejected otherwise. | — |
| `security` | `none`, `tls`, `reality` | `tls.enabled` |
| `sni` | TLS server name | `tls.server_name` |
| `host` | WS/HTTP host header | `transport.headers.Host` |
| `path` | WS / HTTP / HTTPUpgrade path | `transport.path` |
| `type` | `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `quic` | `transport.type` |
| `serviceName` | gRPC service name | `transport.service_name` |
| `mode` | gRPC mode | (ignored; sing-box has one gRPC mode) |
| `headerType` | `none` only | (no header obfuscation support) |
| `flow` | `xtls-rprx-vision` | `flow` |
| `pbk` | Reality public key | `tls.reality.public_key` |
| `sid` | Reality short ID | `tls.reality.short_id` |
| `fp` | uTLS fingerprint | `tls.utls.fingerprint` |
| `alpn` | Comma-separated ALPN | `tls.alpn[]` |
| `allowInsecure` / `insecure` | `1`/`true` → skip verification | `tls.insecure` |
| `spx` | Reality spiderX | (ignored) |
| `remark` | Name override | node name |

Validation failures (per line, reported to the user, line skipped):

- Not a `vless://` URL.
- Missing or malformed UUID.
- Missing host or port, or port outside 1–65535.
- `encryption` present and not `none`.
- `security=reality` without `pbk`.
- `security=reality` with a `pbk` that is not base64**url**-safe (no `+` or `/`)
  or does not decode to exactly 32 bytes. Verified: a standard-base64 `+`
  fails with `decode public_key: illegal base64 data at input byte 42`.
- `security=reality` with a `sid` that is not valid hex, has an **odd** length,
  or is **longer than 16 hex characters**. Verified: an odd length fails with
  `decode short_id: encoding/hex: odd length hex string`, a non-hex character
  fails with `invalid byte`, and a `sid` longer than 16 characters makes
  sing-box **panic** (`index out of range [8] with length 8`) — Portify must
  reject it at import rather than hand it to sing-box.

### 4.2 Shadowsocks

Format: `ss://<base64(method:password)>@<host>:<port>#<name>`
or `ss://<base64(method:password@host:port)>#<name>`

Both SIP002 forms are accepted. `plugin` / `plugin_opts` query parameters are
supported, as is the `obfs-local` / `v2ray-plugin` plugin string, which maps to
sing-box `plugin` + `plugin_opts`.

Validation failures:

- Not an `ss://` URL.
- Undecodable base64 payload.
- Missing `method` or `password` in the decoded payload.
- `method` not in sing-box's supported cipher list
  (`none`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`,
  `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`,
  `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`,
  `2022-blake3-chacha20-poly1305`, plus the legacy ciphers
  `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`,
  `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20`).
- For the `2022-blake3-*` methods, the password must be valid base64 **and** must
  decode to an exact key length. Verified against `sing-box 1.14.3 check`:
  - `2022-blake3-aes-128-gcm` → 16 bytes
  - `2022-blake3-aes-256-gcm` → 32 bytes
  - `2022-blake3-chacha20-poly1305` → 32 bytes

  A non-base64 password fails with `illegal base64 data`; a wrong length fails
  with `bad key length, required 16, got 5`.

### 4.3 Duplicate detection

A node is a duplicate when `(protocol, host, port, credential-material)` matches
an existing node, where credential-material is the VLESS UUID or the SS
`method:password`. Name is **not** part of the key — a renamed node is still the
same node.

On import, duplicates are skipped and reported as a count. The same rule is
applied when re-importing the same file twice, so import is idempotent.

## 5. sing-box configuration generation

### 5.1 Shape

For N enabled nodes, Portify generates:

- **Inbounds (2N):** for node `i` (0-based),
  `{ "type": "socks", "tag": "socks-<i>", "listen": <bind>, "listen_port": <socksPort(i)> }`
  and
  `{ "type": "http", "tag": "http-<i>", "listen": <bind>, "listen_port": <httpPort(i)> }`.

  sing-box's `mixed` inbound serves SOCKS5 and HTTP on **one** port; since the
  requirement is a *dedicated* SOCKS5 port *and* a *dedicated* HTTP port per
  node, two separate inbounds per node are required. Verified against
  `sing-box 1.14.3 check`.

- **Outbounds (N + 1):** one per node with `tag: "n<i>"`, plus
  `{ "type": "direct", "tag": "direct" }`.

- **Route:** one fixed rule per node:

  ```json
  { "inbound": ["socks-<i>", "http-<i>"], "action": "route", "outbound": "n<i>" }
  ```

  plus `{ "final": "direct" }`. This is what makes routing *fixed*: traffic
  entering a node's ports always exits that node's outbound.

- **Log:** `{ "level": "<settings.log_level>", "timestamp": true }`.

- **DNS:** `{ "servers": [{ "type": "local", "tag": "local" }], "final": "local" }`.
  Included explicitly so outbound hostnames resolve predictably.

- `route.auto_detect_interface: true` so sing-box binds to the default NIC and
  avoids routing loops.

### 5.2 Validation before start

The generated config is written to `%APPDATA%\Portify\config.json` and validated
with `sing-box check -c <path>`. If the check fails, the error output is
surfaced to the user verbatim and the process is **not** started. This is the
authoritative validator — the Rust-side generator produces the same JSON that
`sing-box check` parses.

### 5.3 Port allocation

- `socks_port_start` (default 11080) and `http_port_start` (default 18080) in
  settings, each configurable, with a `port_range` limit (default 100).
- Node `i` gets `socks_port_start + i` and `http_port_start + i`.
- On start, Portify probes each port; if one is occupied by another process it
  searches forward within the range for a free port and records the actual
  assignment. The UI shows the real port, not the nominal one.
- The SOCKS range and HTTP range are validated to not overlap. If they do, the
  start fails with a clear error rather than silently rebinding.
- `port_range` bounds the number of **enabled** nodes. Import accepts any
  number of nodes; the limit is checked at start, because disabled nodes
  consume no ports. If more nodes are enabled than the range allows, the start
  fails with a message naming both counts.

## 6. sing-box lifecycle

### 6.1 Binary resolution

Searched in order, first hit wins:

1. `sing-box/sing-box.exe` in the directory containing Portify's executable
   (the self-contained ZIP layout).
2. `sing-box.exe` in the same directory as Portify's executable.
3. `%APPDATA%\Portify\sing-box\sing-box.exe` (cached download).
4. Auto-download: fetch
   `https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-windows-amd64.zip`,
   extract `sing-box.exe`, verify SHA-256 against the pinned digest, cache it.
   (the arm64 variant is used when the process architecture is arm64).

If none succeed, the error explains each attempted location.

### 6.2 Spawn and monitor

- Spawned with `sing-box run -c <config> --disable-color`, with stderr piped.
  **sing-box writes all logs to stderr; stdout is empty.** Verified on
  1.14.3. `--disable-color` strips ANSI escapes so the log view can render
  plain text.
- stderr lines are parsed for `FATAL` / `ERROR` and streamed to the frontend as
  `portify://log` events; the last 500 lines are kept in memory.
- A `FATAL` line, or the process exiting unexpectedly, transitions the state to
  `Stopped` with the error attached.

### 6.3 Stop

- Send `CTRL_BREAK_EVENT` to the process group; fall back to `taskkill /T /F`
  after a 3-second grace period.
- On stop, the firewall rule (if one was added) is removed.

## 7. Windows Firewall

- Only relevant when the bind address is not loopback. With the default
  `127.0.0.1` **no firewall rule is ever created**.
- When the bind is changed to a LAN address, Portify adds an inbound rule:

  ```
  netsh advfirewall firewall add rule name="Portify" dir=in action=allow
      protocol=TCP localport=<socksStart>-<socksEnd>,<httpStart>-<httpEnd>
      profile=private,domain remoteip=localsubnet
  ```

  `remoteip=localsubnet` and the private/domain profiles keep the exposure on
  the local network and off the public internet.
- `netsh` needs elevation, so the command is run via
  `Start-Process -Verb RunAs -Wait`. If the user declines the UAC prompt,
  the operation fails with a clear error and the bind address is left
  unchanged — Portify never silently exposes a port to the internet.
- The rule is removed on stop and on app exit, and a stale rule from a previous
  crash is removed on next start (rule is created idempotently by name).
- Portify never disables the Windows Firewall and never modifies existing
  rules.

## 8. Connectivity probing

For each node (sequentially, with a bounded concurrency of 8):

1. **Latency** — issue an HTTP request through the node's SOCKS5 port to
   `http://api.ipify.org?format=json` and time the full exchange. The measured
   value is the round-trip time of that request, which is the number the UI
   shows.
2. **Exit IP** — the same request's response body carries the exit IP.
3. **Status** — `ok` if the probe completes, `failed` with an error message
   otherwise.

Both steps come from a single request, so a probe costs one round trip.

The probe endpoint is `http://api.ipify.org?format=json` (plain HTTP) so the
measurement does not include a TLS handshake that would vary with the node's
TLS configuration. The response is JSON: `{"ip":"1.2.3.4"}`.

Probing uses `reqwest` with a SOCKS5 proxy. reqwest 0.13 supports the `socks`
feature, backed by `hyper-util`'s `SocksV5` connector, so no extra dependency
is needed.

A probe failure is reported per node with a human-readable error (DNS
resolution failure, connection refused, timeout, TLS error) and never aborts
the other probes.

## 9. Export format

Endpoints are exported as one `protocol://ip:port` per line, e.g.

```
http://127.0.0.1:18080
socks5://127.0.0.1:11080
```

**Default is `http://`.** Justification, verified against the 9Router source:
its proxy-pool importer accepts any `://` URL, but its request path builds an
`undici.ProxyAgent`, and undici `^7.19.2` **rejects** `socks5://` with
*"Invalid URL protocol: the URL must start with `http:` or `https:`"*. undici 8
added SOCKS support, but 9Router is pinned to 7. The `http://` endpoint is
therefore the one that works end-to-end today. The UI offers a
SOCKS5/HTTP/Both selector so a `socks5://` export is one click away for tools
that support it.

Export goes to the clipboard and to a file via the native save dialog.

## 10. Persistence

`%APPDATA%\Portify\`

| File | Contents |
|---|---|
| `nodes.json` | Array of `Node` records. |
| `settings.json` | The `Settings` record. |
| `config.json` | The generated sing-box config (regenerated on every start). |
| `sing-box/sing-box.exe` | Cached auto-downloaded binary. |
| `logs/` | Rotating sing-box log files, one per start. |

`Node` record:

```rust
struct Node {
    id: String,            // uuid v4
    name: String,          // from the link fragment, or a generated name
    protocol: Protocol,    // Vless | Shadowsocks
    host: String,
    port: u16,
    vless: Option<VlessParams>,   // uuid, flow, sni, alpn, insecure, fp, reality
    ss: Option<ShadowsocksParams>, // method, password, plugin, plugin_opts
    transport: Option<Transport>,  // type, path, host, service_name
    enabled: bool,
    socks_port: Option<u16>,  // actual assigned port, filled at start
    http_port: Option<u16>,
    status: NodeStatus,       // Unknown | Ok | Failed(String)
    exit_ip: Option<String>,
    latency_ms: Option<u128>,
    last_checked: Option<u64>, // unix seconds
}
```

**Config migration:** `settings.json` carries a `version` field. On load, an
older version is migrated forward by a chain of small step functions in
`store.rs`. Unknown future versions are rejected with a clear error rather than
being silently misinterpreted. The first release ships version `1`.

## 11. Settings

| Setting | Default | Notes |
|---|---|---|
| `bind_address` | `127.0.0.1` | Loopback by default. |
| `socks_port_start` | `11080` | |
| `http_port_start` | `18080` | |
| `port_range` | `100` | Nodes beyond this are rejected at import with a clear message. |
| `log_level` | `info` | sing-box log level. |
| `auto_start` | `false` | Windows auto-start via `tauri-plugin-autostart`. |
| `auto_start_gateway` | `false` | Start the gateway on app launch. |
| `export_protocol` | `http` | `http` \| `socks5` \| `both`. |
| `probe_timeout_ms` | `8000` | |
| `version` | `1` | Schema version for migration. |

## 12. IPC surface

All commands live in `cmd.rs` and are registered in `lib.rs`.

| Command | Args | Returns |
|---|---|---|
| `import_links` | `text: String` | `ImportReport { imported, duplicates, failed: Vec<LineError> }` |
| `import_file` | `path: String` | `ImportReport` |
| `list_nodes` | — | `Vec<Node>` |
| `delete_nodes` | `ids: Vec<String>` | `()` |
| `set_node_enabled` | `id: String, enabled: bool` | `()` |
| `bulk_set_enabled` | `ids: Vec<String>, enabled: bool` | `()` |
| `bulk_delete` | `ids: Vec<String>` | `()` |
| `get_settings` | — | `Settings` |
| `save_settings` | `settings: Settings` | `()` |
| `start_gateway` | — | `Result<Vec<Node>, String>` |
| `stop_gateway` | — | `()` |
| `gateway_status` | — | `GatewayStatus { state, ports, error }` |
| `probe_node` | `id: String` | `Node` (with fresh status) |
| `probe_all` | — | `Vec<Node>` |
| `export_endpoints` | `protocol: Option<String>` | `String` (the endpoint list) |
| `export_to_file` | `protocol: Option<String>` | `Option<String>` (path written) |
| `copy_endpoints` | `protocol: Option<String>` | `()` |
| `get_singbox_path` | — | `String` |
| `update_singbox` | — | `String` (new version) |

Events emitted to the frontend:

| Event | Payload | When |
|---|---|---|
| `portify://log` | `{ line: String, level: String }` | Every sing-box stderr line. |
| `portify://status` | `GatewayStatus` | State change. |
| `portify://node` | `Node` | A node's probe result changed. |

## 13. User interface

A single window, 1100×720, dark theme.

**Header** — app name, gateway state pill (Running / Stopped / Error), and the
Start / Stop button.

**Left column — dashboard:**
- Nodes total, nodes online, nodes offline, average latency.
- Gateway uptime, sing-box version, and the effective bind address.

**Main column — node table** (virtualised not needed; a plain table is fine for
hundreds of rows):
- Columns: Name, Protocol, Server, SOCKS port, HTTP port, Status dot, Exit IP,
  Latency, and a per-row toggle + delete.
- **Search box** filters by name / host / exit IP (client-side, instant).
- **Filter chips:** All / Enabled / Disabled / Online / Offline.
- **Bulk selection** with checkboxes; a bulk toolbar offers Enable, Disable,
  Delete, and Probe.

**Right column — log panel** (collapsible): live sing-box output, auto-scroll
with a "pause" toggle, and a clear button.

**Import modal:** a textarea for bulk paste, and a "Choose file…" button that
opens the native picker. Shows a per-line result list: imported / duplicate /
failed with the reason.

**Settings panel:** bind address, port ranges, log level, auto-start toggles,
export protocol, and a "sing-box binary" section showing the resolved path
with a "Re-download" action.

**Export modal:** protocol selector, a preview textarea of the endpoint list,
Copy and Save buttons.

## 14. Error reporting

Every failure surfaces a message a user can act on. A single error type
carries a message and an optional detail string; the UI renders the message
prominently and the detail in a monospace, scrollable block.

Examples:

- `Failed to parse link` / detail: `Line 12: invalid UUID in "vless://bad@host:443"`.
- `sing-box rejected the generated configuration` / detail: the verbatim
  stderr from `sing-box check`.
- `Could not start sing-box` / detail: the process's exit status and stderr.
- `Failed to add the firewall rule` / detail: `netsh` output and the UAC
  decline message.

## 15. Testing

Because the machine has no Rust toolchain, all Rust compilation and test
execution happen in CI.

**Rust unit tests** (`cargo test`), in `nodes.rs` and `config.rs`:

- VLESS parsing: minimal, with TLS, with Reality, with WS transport, with gRPC,
  with `xtls-rprx-vision` flow, with ALPN, with `allowInsecure`.
- VLESS rejection: bad UUID, bad port, `encryption` set, Reality without `pbk`,
  Reality with a bad `pbk`, over-long `sid`.
- SS parsing: SIP002 with userinfo, SIP002 fully-base64 payload, plugin params.
- SS rejection: bad base64, missing method, unsupported cipher, non-base64
  SS2022 password.
- Duplicate detection: same node twice is a duplicate; a renamed node is a
  duplicate; a different UUID on the same host is not.
- Config generation: node count → inbound/outbound/rule counts; the exact
  tags and port numbers; a disabled node is excluded; the JSON round-trips
  through `serde_json` and matches the shape `sing-box check` accepts.
- Port allocation: nominal ports, collision avoidance, out-of-range rejection.

**Integration test in CI:** a job step runs the real `sing-box check` against
configs generated by the test suite (the test writes a fixture config, the
workflow runs `sing-box check -c` on it). This is the only true validator of
the generated JSON, and it is why the generated config is also written to disk
by the unit tests.

**Frontend:** TypeScript type-check (`tsc --noEmit`) and a production Vite
build, both run in CI.

**CI matrix:** `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`,
`npm ci && npm run build`, and the `sing-box check` fixture step.

## 16. CI/CD

### 16.1 `.github/workflows/ci.yml` (on push and PR)

- `ubuntu-latest` job: `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test`.
- `windows-latest` job: full build (`npm ci`, `npm run tauri build`).

### 16.2 `.github/workflows/release.yml` (on tag `v*`)

1. Checkout, set up Node 20, `npm ci`.
2. Install the Rust toolchain (stable) with the MSVC target and the Tauri
   prerequisites (`cargo tauri` handles the WebView2 and NSIS tooling).
3. Download `sing-box-1.14.3-windows-amd64.zip` and verify its SHA-256 against
   the pinned digest before bundling.
4. `npm run tauri build -- --bundles nsis` → the **Setup EXE**
   (`Portify_<version>_x64-setup.exe`).
5. Copy the raw `portify.exe` → the **Portable EXE**
   (`Portify_<version>_x64_portable.exe`).
6. Assemble the **Self-contained ZIP**: `portify.exe` + `sing-box/sing-box.exe`
   + a `README.txt` explaining the layout. zipped to
   `Portify_<version>_x64_portable.zip`.
7. `softprops/action-gh-release` publishes all three as release assets.

### 16.3 Release artifact names

| Artifact | Name |
|---|---|
| Setup EXE | `Portify_<version>_x64-setup.exe` |
| Portable EXE | `Portify_<version>_x64_portable.exe` |
| Self-contained ZIP | `Portify_<version>_x64_portable.zip` |

### 16.4 sing-box digests (pinned)

```
amd64  5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf
arm64  db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4
```

Both are recorded in `src-tauri/src/engine.rs` as constants and in the release
workflow. The digest verified is that of the extracted `sing-box.exe`, not of
the release zip — the CI step extracts first, then verifies the binary.

## 17. Repository layout

```
Portify/
├── .github/workflows/ci.yml
├── .github/workflows/release.yml
├── docs/superpowers/specs/2026-10-19-portify-design.md
├── src/                                (React frontend)
│   ├── App.tsx
│   ├── components/{Dashboard,NodeTable,LogPanel,ImportDialog,SettingsPanel,ExportDialog}.tsx
│   ├── lib/{api.ts,types.ts,format.ts}
│   ├── styles.css
│   └── main.tsx
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── capabilities/default.json
│   ├── icons/
│   └── src/
│       ├── main.rs
│       ├── lib.rs
│       ├── cmd.rs
│       ├── nodes.rs
│       ├── config.rs
│       ├── engine.rs
│       ├── probe.rs
│       ├── store.rs
│       └── fw.rs
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

**The sing-box binary is not committed to git.** It is 78 MB, and a binary
blob in the repository would bloat every clone forever. Instead the release
workflow downloads it from the official GitHub release and verifies its
SHA-256, then places it into the artifacts it builds. The application itself
never depends on the binary being committed — it has the auto-download path
(§6.1) — so the source tree stays clean and the artifacts are still
self-contained.

## 18. Implementation order

1. `nodes.rs` — model + link parsing + dedup, with unit tests.
2. `config.rs` — config generation + port allocation, with unit tests.
3. `store.rs` — persistence + settings + migration.
4. `engine.rs` — binary resolution, `check`, spawn, log streaming.
5. `fw.rs` — firewall rule management.
6. `probe.rs` — latency / exit IP / status.
7. `cmd.rs` + `lib.rs` — the IPC surface.
8. Frontend — dashboard, table, import, settings, export, logs.
9. CI workflows.
10. README, then a tagged release and link verification.

## 19. Verified facts this spec depends on

All verified locally against the real binaries on 2026-10-19:

- `sing-box 1.14.3` `check` accepts: VLESS with reality + `xtls-rprx-vision` +
  uTLS, VLESS with grpc / ws / httpupgrade / http transports, and SS with the
  `obfs-local` plugin. A config with `{"inbound": [...], "action": "route",
  "outbound": "..."}` rules passes.
- sing-box writes **all** logs to stderr; stdout is empty on a successful run.
- `--disable-color` is a valid global flag.
- An SS2022 password must be base64; a raw string fails with
  `decode key: illegal base64 data at input byte 20`.
- A Reality public key must be base64url and decode to 32 bytes; a standard-base64
  `+` fails, a short key fails with `invalid public_key`.
- A Reality `short_id` must be even-length hex of at most 16 characters. An
  odd length fails with `odd length hex string`; a non-hex character fails with
  `invalid byte`; **more than 16 characters makes sing-box panic** with
  `index out of range [8] with length 8`.
- A config with no `dns` block still starts, but an explicit `local` DNS
  server makes outbound hostname resolution predictable.
- `undici 7.19.2`'s `ProxyAgent` throws on a `socks5://` URL; 9Router uses
  `undici ^7.19.2`, hence the `http://` default export.
- 9Router's proxy-pool importer accepts any `scheme://host:port` string.
- `reqwest 0.13.5` exposes the `socks` feature, backed by
  `hyper-util 0.1.12`'s `SocksV4` / `SocksV5` connector.
- `tauri-plugin-dialog` re-exports `FilePath` from `tauri-plugin-fs` and
  provides `blocking_pick_file()`.
- `tauri-plugin-autostart` v2: `MacosLauncher::LaunchAgent` +
  `Some(vec![...])` args, and `ManagerExt::autolaunch()`.
