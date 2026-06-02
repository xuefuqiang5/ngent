use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPhase {
    Phase0WorkspaceSkeleton,
    Phase1ProtocolAndHarness,
    Phase2AgentRuntimeFoundation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceStatus {
    pub phase: AgentPhase,
    pub note: String,
}
