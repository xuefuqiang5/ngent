use serde::{Deserialize, Serialize};

use crate::EvidenceRef;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub created_at: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub description: String,
    pub entities: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
    pub recommended_actions: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}
