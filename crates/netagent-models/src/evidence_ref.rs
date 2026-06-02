use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub id: String,
    pub summary: String,
}
