use crate::nodes::{Node, Protocol, Transport, TransportType, VlessParams};
use serde_json::{Map, Value, json};

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
    if socks_start as u32 <= http_end && http_start as u32 <= socks_end {
        return Err(format!(
            "the SOCKS range {socks_start}-{socks_end} and the HTTP range {http_start}-{http_end} overlap"
        ));
    }

    let mut assignments = Vec::with_capacity(enabled.len());
    for (i, node) in enabled.iter().enumerate() {
        let offset = i as u16;
        assignments.push((node.id.clone(), socks_start + offset, http_start + offset));
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
            let v = node
                .vless
                .as_ref()
                .expect("a vless node always has vless params");
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
            let s = node
                .ss
                .as_ref()
                .expect("a shadowsocks node always has ss params");
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

fn transport_json(t: &Transport) -> Value {
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

fn tls_json(v: &VlessParams) -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::{parse_link, ShadowsocksParams, Transport};

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
        let cfg: Value =
            serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "info")).unwrap();

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
        let cfg: Value =
            serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "info")).unwrap();
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
        let cfg: Value =
            serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "debug")).unwrap();
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
        let cfg: Value =
            serde_json::from_str(&build_config(&[a, b], &plan, "127.0.0.1", "info")).unwrap();
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
        let cfg: Value =
            serde_json::from_str(&build_config(&nodes, &plan, "127.0.0.1", "info")).unwrap();
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
            let mut node = vless_node("t");
            node.transport = expected.map(|_| Transport {
                kind,
                path: Some("/p".into()),
                host: Some("h".into()),
                service_name: Some("s".into()),
            });
            let out = config_to_singbox_json(&node, "n0");
            match expected {
                None => assert!(
                    out.get("transport").is_none(),
                    "{kind:?} should not produce a transport block"
                ),
                Some(name) => assert_eq!(out["transport"]["type"], name),
            }
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
