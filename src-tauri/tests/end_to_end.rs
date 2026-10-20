//! An end-to-end test of the whole chain: a Portify node points at a real
//! sing-box server, Portify generates a configuration from it, a second
//! sing-box runs that configuration, and an HTTP request made through
//! Portify's HTTP port is forwarded all the way to a local echo server.
//!
//! That exercises the claim the whole application rests on: traffic entering
//! a node's port exits that node.
//!
//! The test needs a real sing-box binary. CI downloads one and sets
//! `SINGBOX_PATH`; without it the test reports that it was skipped.

use portify_lib::config::{allocate_ports, build_config};
use portify_lib::nodes::parse_link;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A port is free if nothing is listening on it.
fn port_is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Waits until a port accepts a connection, or the timeout expires.
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// A tiny HTTP server that answers every request with `body`.
///
/// It runs as a PowerShell child process, so the test needs no extra
/// dependency. The listener is bound by the child; the test waits for the
/// port rather than assuming it is ready.
fn spawn_echo_server(port: u16, body: &'static str) -> Child {
    let script = format!(
        "$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, {port})\n\
         $l.Start()\n\
         while ($true) {{\n\
         $c = $l.AcceptTcpClient()\n\
         $s = $c.GetStream()\n\
         $buf = New-Object byte[] 4096\n\
         $null = $s.Read($buf, 0, $buf.Length)\n\
         $resp = 'HTTP/1.1 200 OK' + \"`r`n\" + 'Content-Length: {len}' + \"`r`n\" + 'Connection: close' + \"`r`n`r`n{body}\"\n\
         $bytes = [System.Text.Encoding]::ASCII.GetBytes($resp)\n\
         $s.Write($bytes, 0, $bytes.Length)\n\
         $s.Flush()\n\
         $c.Close()\n\
         }}\n"
    )
    .replace("{len}", &body.len().to_string())
    .replace("{body}", body);

    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the echo server")
}

/// Reads a complete HTTP response from a stream.
fn read_response(stream: &mut TcpStream) -> String {
    let mut text = String::new();
    let mut buf = [0u8; 1024];
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("set a read timeout");
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                text.push_str(&String::from_utf8_lossy(&buf[..n]));
                if text.contains("\r\n\r\n") {
                    // The body follows the headers; read what is left.
                    let head_len = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
                    let body_len = text.len() - head_len;
                    let expected = text
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body_len >= expected {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    text
}

fn singbox_path() -> Option<PathBuf> {
    let raw = std::env::var("SINGBOX_PATH").ok()?;
    let path = PathBuf::from(raw);
    path.is_file().then_some(path)
}

#[test]
fn traffic_through_a_node_port_exits_that_node() {
    let Some(singbox) = singbox_path() else {
        eprintln!("skipped: set SINGBOX_PATH to run the end-to-end test");
        return;
    };

    // Pick free ports for every part of the chain.
    let upstream_port = 18388;
    let socks_port = 19080;
    let http_port = 19081;
    let echo_port = 18000;
    for port in [upstream_port, socks_port, http_port, echo_port] {
        assert!(
            port_is_free(port),
            "port {port} is already in use; the test cannot run"
        );
    }

    // A sing-box server that speaks Shadowsocks, so Portify has a real
    // upstream to route through.
    let upstream_config = format!(
        r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [
    {{ "type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": {upstream_port},
       "method": "aes-256-gcm", "password": "portify-e2e" }}
  ],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#
    );
    let upstream_config_path = std::env::temp_dir().join("portify-e2e-upstream.json");
    std::fs::write(&upstream_config_path, upstream_config).unwrap();

    let _echo = spawn_echo_server(echo_port, "portify-e2e-ok");

    let mut upstream = Command::new(&singbox)
        .arg("run")
        .arg("-c")
        .arg(&upstream_config_path)
        .arg("--disable-color")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the upstream sing-box");

    let cleanup = || {
        let _ = upstream.kill();
        let _ = upstream.wait();
        let _ = std::fs::remove_file(&upstream_config_path);
    };

    assert!(
        wait_for_port(upstream_port, Duration::from_secs(20)),
        "the upstream sing-box did not start listening"
    );

    // The node Portify will route through: a Shadowsocks link pointing at
    // the upstream server.
    let creds = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b"aes-256-gcm:portify-e2e")
    };
    let link = format!("ss://{creds}@127.0.0.1:{upstream_port}#E2E");
    let node = parse_link(&link).expect("the link parses");

    // Portify's own configuration for that node.
    let nodes = vec![node];
    let plan = allocate_ports(&nodes, socks_port, http_port, 10).expect("ports are allocated");
    let config = build_config(&nodes, &plan, "127.0.0.1", "info");
    let config_path = std::env::temp_dir().join("portify-e2e-config.json");
    std::fs::write(&config_path, &config).unwrap();

    let mut gateway = Command::new(&singbox)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .arg("--disable-color")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the gateway sing-box");

    let gateway_cleanup = || {
        let _ = gateway.kill();
        let _ = gateway.wait();
        let _ = std::fs::remove_file(&config_path);
    };

    assert!(
        wait_for_port(socks_port, Duration::from_secs(20)),
        "the SOCKS port did not start listening"
    );
    assert!(
        wait_for_port(http_port, Duration::from_secs(20)),
        "the HTTP port did not start listening"
    );

    // Send an HTTP request *through* the HTTP proxy port. The proxy must
    // forward it to the echo server via the node's Shadowsocks upstream.
    let mut stream = TcpStream::connect(("127.0.0.1", http_port)).expect("connect to the proxy");
    let request = format!(
        "GET http://127.0.0.1:{echo_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write the request");
    stream.flush().ok();

    let response = read_response(&mut stream);

    gateway_cleanup();
    cleanup();

    assert!(
        response.contains("portify-e2e-ok"),
        "the request did not reach the echo server through the node; got: {response}"
    );
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
}

/// The log stream carries sing-box's stderr, which is where every line goes.
#[test]
fn singbox_writes_its_log_to_stderr() {
    let Some(singbox) = singbox_path() else {
        eprintln!("skipped: set SINGBOX_PATH to run the end-to-end test");
        return;
    };

    let config = std::env::temp_dir().join("portify-e2e-log.json");
    std::fs::write(
        &config,
        r#"{
  "log": { "level": "info" },
  "inbounds": [ { "type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": 19099 } ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "final": "direct" }
}"#,
    )
    .unwrap();

    let mut child = Command::new(&singbox)
        .arg("run")
        .arg("-c")
        .arg(&config)
        .arg("--disable-color")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sing-box");

    std::thread::sleep(Duration::from_secs(3));
    let _ = child.kill();
    let out = child.wait_with_output().expect("collect the output");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_file(&config);

    assert!(
        stdout.trim().is_empty(),
        "sing-box should leave stdout empty; got: {stdout}"
    );
    assert!(
        stderr.contains("sing-box started"),
        "the start message should be on stderr; got: {stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "--disable-color should leave no ANSI escapes; got: {stderr}"
    );
}
