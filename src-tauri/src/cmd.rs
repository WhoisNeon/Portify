use crate::nodes::Node;
use serde::Serialize;

/// The state of the gateway, as the UI sees it.
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
pub fn build_endpoints(_nodes: &[Node], _protocol: &str, _bind: &str) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::parse_link;

    fn node_with_ports(socks: u16, http: u16) -> Node {
        let mut n =
            parse_link("vless://00000000-0000-4000-8000-000000000000@example.com:443#A").unwrap();
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
        let nodes = vec![
            node_with_ports(11080, 18080),
            node_with_ports(11081, 18081),
        ];
        let out = build_endpoints(&nodes, "http", "127.0.0.1");
        assert_eq!(out.lines().count(), 2);
        assert!(out.lines().all(|l| l.starts_with("http://127.0.0.1:")));
    }
}
