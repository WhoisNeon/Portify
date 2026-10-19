use std::process::Command;

/// The name of the firewall rule Portify creates.
pub const RULE_NAME: &str = "Portify";

/// True when the bind address only accepts connections from this machine.
pub fn is_loopback(bind: &str) -> bool {
    let bind = bind.trim();
    bind == "::1" || bind.starts_with("127.")
}

/// True when a firewall rule is needed. The default loopback bind never
/// needs one, so no rule is created unless the user moved the gateway onto
/// the LAN.
pub fn needs_firewall_rule(bind: &str) -> bool {
    !is_loopback(bind)
}

/// The `netsh` arguments that create the rule.
///
/// The rule is scoped to `remoteip=localsubnet` and the private and domain
/// profiles, so it never exposes the gateway to the public internet.
pub fn build_add_command(socks_ports: &str, http_ports: &str) -> String {
    format!(
        "advfirewall firewall add rule name=\"{RULE_NAME}\" dir=in action=allow protocol=TCP localport={socks_ports},{http_ports} remoteip=localsubnet profile=private,domain enable=yes"
    )
}

/// Runs a `netsh` command with elevation.
///
/// `netsh` needs administrator rights, so the command is launched through
/// `Start-Process -Verb RunAs`, which raises a UAC prompt. If the user
/// declines, the call fails and the caller reports it.
fn run_elevated(args: &str) -> Result<(), String> {
    let script = format!(
        "Start-Process -FilePath netsh -ArgumentList '{args}' -Verb RunAs -Wait -WindowStyle Hidden"
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("could not run netsh: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    Err(if detail.is_empty() {
        "the firewall rule could not be added; the UAC prompt was declined or netsh failed".to_string()
    } else {
        format!("the firewall rule could not be added: {detail}")
    })
}

/// True when the rule already exists.
pub fn rule_exists() -> bool {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={RULE_NAME}"),
        ])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains(RULE_NAME),
        Err(_) => false,
    }
}

/// Creates the inbound rule. The rule is created idempotently: an existing
/// rule with the same name is removed first.
pub fn add_rule(socks_ports: &str, http_ports: &str) -> Result<(), String> {
    let _ = remove_rule();
    run_elevated(&build_add_command(socks_ports, http_ports))
}

/// Removes the inbound rule. A missing rule is not an error.
pub fn remove_rule() -> Result<(), String> {
    if !rule_exists() {
        return Ok(());
    }
    run_elevated(&format!("advfirewall firewall delete rule name=\"{RULE_NAME}\""))
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
