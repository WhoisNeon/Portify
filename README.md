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
