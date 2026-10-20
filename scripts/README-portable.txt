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
