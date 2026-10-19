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
