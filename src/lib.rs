mod crypto;
mod protocol;
mod session;

use log::warn;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

/// Lamp state visible to the rest of the app.
#[derive(Clone, Copy, Debug, Default)]
pub struct LampState {
    pub on: bool,
    pub known: bool,
}

/// High-level Tuya LAN lamp controller.
///
/// Supports protocol versions 3.4 and 3.5.
pub struct TuyaLamp {
    key: [u8; 16],
    ip: [u8; 4],
    port: u16,
    version: u8,
}

impl TuyaLamp {
    /// Create a new lamp controller.
    ///
    /// - `key`: 16-byte device local key from the Tuya developer portal
    /// - `ip`: device IPv4 address
    /// - `port`: typically 6668
    /// - `version`: 4 for protocol 3.4, 5 for protocol 3.5
    pub fn new(key: [u8; 16], ip: [u8; 4], port: u16, version: u8) -> Self {
        Self { key, ip, port, version }
    }

    /// Query the lamp's current power state from DPS key 20.
    pub fn refresh_status(&self) -> Option<bool> {
        match session::Session::connect(self.ip, self.port, &self.key, self.version) {
            Ok(mut sess) => {
                if !sess.negotiate_key() {
                    warn!("[tuya] key negotiation failed");
                    return None;
                }
                match sess.query_status() {
                    Some(json) => parse_dps20(&json),
                    None => {
                        warn!("[tuya] status query failed");
                        None
                    }
                }
            }
            Err(e) => {
                warn!("[tuya] connect failed: {e}");
                None
            }
        }
    }

    /// Send an explicit on/off command.
    pub fn set_on(&self, on: bool) -> Option<bool> {
        let dps = if on { r#""20":true"# } else { r#""20":false"# };
        self.send_dps(dps).map(|_| on)
    }

    /// Warm white, minimum brightness (DPS 20=on, 21=white, 22=10, 23=0).
    pub fn set_warm_dim(&self) -> Option<bool> {
        self.send_dps(r#""20":true,"21":"white","22":10,"23":0"#).map(|_| true)
    }

    /// Cool white, maximum brightness (DPS 20=on, 21=white, 22=1000, 23=1000).
    pub fn set_bright_white(&self) -> Option<bool> {
        self.send_dps(r#""20":true,"21":"white","22":1000,"23":1000"#).map(|_| true)
    }

    fn send_dps(&self, dps_inner: &str) -> Option<()> {
        match session::Session::connect(self.ip, self.port, &self.key, self.version) {
            Ok(mut sess) => {
                if !sess.negotiate_key() {
                    warn!("[tuya] key negotiation failed");
                    return None;
                }
                if sess.send_dps_command(dps_inner) { Some(()) } else {
                    warn!("[tuya] command failed");
                    None
                }
            }
            Err(e) => { warn!("[tuya] connect failed: {e}"); None }
        }
    }
}

fn parse_dps20(json: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let dps20 = v
        .get("dps")
        .and_then(|d| d.get("20"))
        .or_else(|| v.get("data").and_then(|d| d.get("dps")).and_then(|d| d.get("20")));
    dps20.and_then(|v| v.as_bool().or_else(|| v.as_i64().map(|i| i != 0)))
}

/// Thread-safe lamp controller with queued targets and retry/suppress logic.
///
/// `target` values: -1=OFF, 0=idle, 1=ON, 2=warm-dim, 3=bright-white.
pub struct LampHandle {
    lamp: TuyaLamp,
    pub state: Mutex<LampState>,
    target: Mutex<i8>,
    suppress_until_ms: AtomicU32,
    retry_after_ms: AtomicU32,
}

impl LampHandle {
    pub fn new(key: [u8; 16], ip: [u8; 4], port: u16, version: u8) -> Self {
        Self {
            lamp: TuyaLamp::new(key, ip, port, version),
            state: Mutex::new(LampState::default()),
            target: Mutex::new(0),
            suppress_until_ms: AtomicU32::new(0),
            retry_after_ms: AtomicU32::new(0),
        }
    }

    /// Toggle between on and off. Returns the new desired state for optimistic display.
    pub fn flip_target(&self, current_displayed_on: bool) -> bool {
        let mut t = self.target.lock().unwrap();
        *t = if *t == 0 {
            if current_displayed_on { -1 } else { 1 }
        } else if *t > 0 {
            -1
        } else {
            1
        };
        let want_on = *t > 0;
        drop(t);
        self.retry_after_ms.store(0, Ordering::Relaxed);
        self.suppress_until_ms.store(now_ms().wrapping_add(10_000), Ordering::Relaxed);
        want_on
    }

    pub fn queue_warm_dim(&self) {
        *self.target.lock().unwrap() = 2;
        self.retry_after_ms.store(0, Ordering::Relaxed);
        self.suppress_until_ms.store(now_ms().wrapping_add(10_000), Ordering::Relaxed);
    }

    pub fn queue_bright_white(&self) {
        *self.target.lock().unwrap() = 3;
        self.retry_after_ms.store(0, Ordering::Relaxed);
        self.suppress_until_ms.store(now_ms().wrapping_add(10_000), Ordering::Relaxed);
    }

    /// Execute any pending target command. Call this from a background thread.
    /// Returns true when a command completes and state changed.
    pub fn poll(&self) -> bool {
        let target = *self.target.lock().unwrap();
        if target == 0 { return false; }

        let now = now_ms();
        let retry_at = self.retry_after_ms.load(Ordering::Relaxed);
        if retry_at > 0 && now.wrapping_sub(retry_at) > u32::MAX / 2 {
            return false;
        }

        let result = match target {
             1 => self.lamp.set_on(true),
            -1 => self.lamp.set_on(false),
             2 => self.lamp.set_warm_dim(),
             3 => self.lamp.set_bright_white(),
             _ => return false,
        };

        if let Some(actual_on) = result {
            let mut st = self.state.lock().unwrap();
            st.on = actual_on;
            st.known = true;
            drop(st);

            let mut t = self.target.lock().unwrap();
            if *t == target { *t = 0; }
            drop(t);

            self.retry_after_ms.store(0, Ordering::Relaxed);
            self.suppress_until_ms.store(now_ms().wrapping_add(5_000), Ordering::Relaxed);
            return true;
        }

        self.retry_after_ms.store(now_ms().wrapping_add(5_000), Ordering::Relaxed);
        false
    }

    /// State to display: pending target (optimistic) or last confirmed.
    pub fn display_state(&self) -> LampState {
        let target = *self.target.lock().unwrap();
        if target != 0 {
            LampState { on: target > 0, known: true }
        } else {
            *self.state.lock().unwrap()
        }
    }

    /// Refresh lamp status. No-op within the suppress window after a command.
    pub fn refresh(&self) {
        let deadline = self.suppress_until_ms.load(Ordering::Relaxed);
        if deadline > 0 && now_ms().wrapping_sub(deadline) > u32::MAX / 2 {
            return;
        }
        if let Some(on) = self.lamp.refresh_status() {
            let mut st = self.state.lock().unwrap();
            st.on = on;
            st.known = true;
        }
    }
}

#[cfg(feature = "esp")]
fn now_ms() -> u32 {
    (unsafe { esp_idf_sys::esp_timer_get_time() } / 1000) as u32
}

#[cfg(not(feature = "esp"))]
fn now_ms() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32
}
