use serde::{Deserialize, Serialize};

/// A structured alert record produced by a network security sensor
/// (e.g. Suricata eve.json alert events). Persisted in the `alerts` table so
/// manifest-driven analyzer rules can turn them into traceable findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: String,
    pub signature: String,
    /// Signature rule identifier as reported by the sensor (may be a number
    /// or a named rule id depending on the sensor and rule format).
    pub signature_id: String,
    /// Sensor severity level (Suricata uses 1=critical, 2=high, 3=medium,
    /// 4=low).
    pub severity: u32,
    pub category: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}
