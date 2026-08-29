//! Real hardware-in-the-loop test against an actual Tuya LAN device. Ignored by default (no
//! device is available in CI) -- run explicitly with real credentials:
//!   TUYA_TEST_IP=192.168.1.x TUYA_TEST_KEY=xxxxxxxxxxxxxxxx TUYA_TEST_VERSION=5 \
//!       cargo test --test live_lamp -- --ignored --nocapture
//!
//! This is the strongest verification available for this crate: it proves a real device on a
//! real network still accepts the exact bytes this library produces, and that this library
//! correctly parses the exact bytes a real device sends back -- not just that the code compiles
//! against assumptions about the protocol.

use tuya_lan_rs::TuyaLamp;

fn env_config() -> Option<([u8; 4], [u8; 16], u8)> {
    let ip_str = std::env::var("TUYA_TEST_IP").ok()?;
    let key_str = std::env::var("TUYA_TEST_KEY").ok()?;
    let version: u8 = std::env::var("TUYA_TEST_VERSION")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let mut ip = [0u8; 4];
    for (i, part) in ip_str.split('.').enumerate().take(4) {
        ip[i] = part.parse().ok()?;
    }

    let key_bytes = key_str.as_bytes();
    if key_bytes.len() != 16 {
        panic!(
            "TUYA_TEST_KEY must be exactly 16 bytes, got {} bytes",
            key_bytes.len()
        );
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(key_bytes);

    Some((ip, key, version))
}

#[test]
#[ignore = "requires a real Tuya device on the LAN; run with --ignored and TUYA_TEST_* env vars"]
fn real_device_status_query_round_trips() {
    let (ip, key, version) =
        env_config().expect("set TUYA_TEST_IP, TUYA_TEST_KEY, TUYA_TEST_VERSION to run this");

    let lamp = TuyaLamp::new(key, ip, 6668, version);
    let status = lamp.refresh_status();
    println!("real device status: {status:?}");
    assert!(
        status.is_some(),
        "expected a real on/off status back from the device -- got None (connect, key \
         negotiation, or status parsing failed against real hardware)"
    );
}
