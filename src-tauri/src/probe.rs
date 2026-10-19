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
    if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
    }
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

    let proxy = match reqwest::Proxy::all(format!("socks5://127.0.0.1:{socks_port}")) {
        Ok(p) => p,
        Err(e) => {
            return ProbeResult {
                error: Some(format!("could not use the node's SOCKS port: {e}")),
                ..Default::default()
            };
        }
    };

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
        let msg = describe_error(
            None,
            "error sending request: dns error: failed to lookup address information",
        );
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
        assert!(
            msg.to_lowercase().contains("something odd"),
            "unexpected message: {msg}"
        );
    }
}
