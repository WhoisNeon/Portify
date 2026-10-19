use base64::Engine;
use percent_encoding::percent_decode_str;
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
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(password))
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

/// Parses one VLESS or Shadowsocks link.
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
        let err = parse_link(&vless(&format!("security=reality&pbk={PBK}&sid=123456789012345678"))).unwrap_err();
        assert!(err.to_lowercase().contains("short id"), "unexpected error: {err}");
    }

    #[test]
    fn reality_short_id_with_odd_length_is_rejected() {
        let err = parse_link(&vless(&format!("security=reality&pbk={PBK}&sid=123"))).unwrap_err();
        assert!(err.to_lowercase().contains("short id"), "unexpected error: {err}");
    }

    #[test]
    fn reality_short_id_with_non_hex_is_rejected() {
        let err = parse_link(&vless(&format!("security=reality&pbk={PBK}&sid=zzzz"))).unwrap_err();
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
        let (nodes, report) = import_links(&text, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(report.errors.len(), 2);
        assert_eq!(report.errors[0].line, 1);
        assert_eq!(report.errors[1].line, 3);
    }

    #[test]
    fn import_links_ignores_blank_lines() {
        let text = format!("\n\nvless://{UUID}@example.com:443#A\n\n");
        let (nodes, report) = import_links(&text, &[]);
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
