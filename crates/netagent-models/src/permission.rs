use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionKind {
    CaptureLive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionReplyKind {
    Once,
    Always,
    Reject,
    RejectWithFeedback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Pending,
    AllowedOnce,
    AllowedAlways,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRef {
    pub message_id: String,
    pub call_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionMetadata {
    pub tool: String,
    pub command_preview: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub id: String,
    pub session_id: String,
    pub permission: PermissionKind,
    pub patterns: Vec<String>,
    pub always: Vec<String>,
    pub risk: RiskLevel,
    pub metadata: PermissionMetadata,
    pub tool: ToolRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionReply {
    pub request_id: String,
    pub decision: PermissionReplyKind,
    pub feedback: Option<String>,
}
