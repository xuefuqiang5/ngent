use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEvent {
    pub id: String,
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub query_name: String,
    pub query_type: String,
    pub response_code: String,
    pub response_code_num: u8,
    #[serde(default)]
    pub answers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsNxdomainSpike {
    pub host: String,
    pub nxdomain_count: usize,
    pub total_count: usize,
    pub ratio: f64,
}
