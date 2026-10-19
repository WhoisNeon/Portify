pub const RULE_NAME: &str = "Portify";

pub fn is_loopback(_bind: &str) -> bool {
    false
}

pub fn needs_firewall_rule(_bind: &str) -> bool {
    true
}

pub fn rule_exists() -> bool {
    false
}

pub fn build_add_command(_socks_ports: &str, _http_ports: &str) -> String {
    String::new()
}

pub fn add_rule(_socks_ports: &str, _http_ports: &str) -> Result<(), String> {
    Ok(())
}

pub fn remove_rule() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses_need_no_rule() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.0.0.53"));
        assert!(is_loopback("::1"));
    }

    #[test]
    fn lan_addresses_need_a_rule() {
        assert!(!is_loopback("0.0.0.0"));
        assert!(!is_loopback("192.168.1.10"));
        assert!(!is_loopback("::"));
    }

    #[test]
    fn the_default_bind_needs_no_rule() {
        assert!(!needs_firewall_rule("127.0.0.1"));
        assert!(needs_firewall_rule("0.0.0.0"));
    }

    #[test]
    fn the_add_command_scopes_the_rule_to_the_local_subnet() {
        let cmd = build_add_command("11080-11179", "18080-18179");
        assert!(cmd.contains("Portify"), "missing the rule name: {cmd}");
        assert!(cmd.contains("dir=in"), "missing the direction: {cmd}");
        assert!(cmd.contains("action=allow"), "missing the action: {cmd}");
        assert!(
            cmd.contains("remoteip=localsubnet"),
            "not scoped to the local subnet: {cmd}"
        );
        assert!(
            cmd.contains("localport=11080-11179,18080-18179"),
            "wrong ports: {cmd}"
        );
        assert!(
            cmd.contains("profile=private,domain"),
            "wrong profiles: {cmd}"
        );
    }

    #[test]
    fn the_add_command_does_not_disable_the_firewall() {
        let cmd = build_add_command("1-2", "3-4");
        assert!(!cmd.to_lowercase().contains("set firewall"));
        assert!(!cmd.to_lowercase().contains("off"));
        assert!(!cmd.to_lowercase().contains("allowedprogram"));
    }
}
