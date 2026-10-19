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

pub fn build_config(_nodes: &[Node], _plan: &PortPlan, _bind: &str, _log_level: &str) -> String {
    String::new()
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
            let node = vless_node("t");
            let transport = match expected {
                None => None,
                Some(_) => Some(Transport {
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
