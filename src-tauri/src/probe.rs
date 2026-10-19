use crate::nodes::Node;

pub const PROBE_URL: &str = "http://api.ipify.org?format=json";

#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub exit_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

pub fn parse_exit_ip(_body: &str) -> Option<String> {
    None
}

pub fn describe_error(_status: Option<u16>, _err: &str) -> String {
    String::new()
}

pub async fn probe_node(_node: &Node, _timeout_ms: u64) -> ProbeResult {
    ProbeResult::default()
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
