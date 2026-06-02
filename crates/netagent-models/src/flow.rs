use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Inbound,
    Outbound,
    Unknown,
}

/// Lightweight flow placeholder used in Phase 1-6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSummary {
    pub id: String,
    pub direction: FlowDirection,
    pub summary: String,
}

/// Structured 5-tuple flow record matching the `flows` SQLite table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub id: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    #[serde(default)]
    pub service: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}
