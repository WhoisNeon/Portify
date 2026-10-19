//! Writes a sing-box configuration to disk so CI can validate it with the
//! real `sing-box check`. The Rust unit tests check the *shape* of the
//! generated JSON; only sing-box itself can tell whether it accepts every
//! key.

use portify_lib::config::{allocate_ports, build_config};
use portify_lib::nodes::parse_link;

#[test]
fn writes_a_singbox_fixture() {
    let nodes = vec![
        parse_link("vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&host=cdn.example.com#A")
            .unwrap(),
        parse_link("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=reality&pbk=JakTfgIEsr35xxpcdVcDuVCpsNI7xPjbynaiNsS00BU&sid=1234abcd&fp=chrome&flow=xtls-rprx-vision#B")
            .unwrap(),
    ];
    let plan = allocate_ports(&nodes, 11080, 18080, 100).unwrap();
    let config = build_config(&nodes, &plan, "127.0.0.1", "info");

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("singbox-fixture.json");
    std::fs::write(&out, config).unwrap();
    assert!(out.exists());
}
