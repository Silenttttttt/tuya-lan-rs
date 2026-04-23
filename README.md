# tuya-lan-rs

Rust implementation of the Tuya LAN protocol versions 3.4 and 3.5.

Supports both pure `std` targets (Linux, macOS, Windows) and ESP32 via `esp-idf-sys` — controlled by a single Cargo feature flag.

## Protocol coverage

- **3.4** — 55AA framing, AES-128-ECB, CRC32
- **3.5** — 6699 framing, AES-128-GCM, HMAC-SHA256 key negotiation

## Usage

```rust
use tuya_lan_rs::LampHandle;

// 16-byte device key from the Tuya developer portal
let key: [u8; 16] = *b"1234567890abcdef";
let ip:  [u8; 4]  = [192, 168, 1, 100];
let port: u16     = 6668;
let version: u8   = 5; // 4 = protocol 3.4, 5 = protocol 3.5

let lamp = LampHandle::new(key, ip, port, version);

// Toggle power
lamp.flip_target(false);

// Drive commands from a background thread
loop {
    lamp.poll();
    std::thread::sleep(std::time::Duration::from_millis(100));
}
```

Or use `TuyaLamp` directly for one-shot calls:

```rust
use tuya_lan_rs::TuyaLamp;

let lamp = TuyaLamp::new(key, ip, port, version);
lamp.set_warm_dim();
lamp.set_bright_white();
lamp.set_on(false);
let is_on: Option<bool> = lamp.refresh_status();
```

## Features

| Feature | Description |
|---------|-------------|
| *(default)* | Pure `std` — works on any platform |
| `esp` | Uses `esp_idf_sys` for timestamps (required on ESP32 targets) |

Add to `Cargo.toml`:

```toml
# Standard targets
tuya-lan-rs = { path = "..." }

# ESP32
tuya-lan-rs = { path = "...", features = ["esp"] }
```

## Crate layout

```
src/
  lib.rs       TuyaLamp, LampHandle, LampState (high-level API)
  session.rs   TCP session, key negotiation, DPS commands
  protocol.rs  55AA / 6699 frame building and parsing
  crypto.rs    AES-ECB, AES-GCM, HMAC-SHA256, session key derivation
```

## License

MIT
