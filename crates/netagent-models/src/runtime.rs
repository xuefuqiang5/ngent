use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPhase {
    Phase0WorkspaceSkeleton,
    Phase1ProtocolAndHarness,
    Phase2AgentRuntimeFoundation,
    Phase3PermissionStateMachine,
    Phase4ToolRuntimeAndArtifactStore,
    Phase5MinimalUi,
    Phase6RealCaptureMvp,
    Phase7ParsingAndFirstFinding,
    Phase8Reports,
    Phase9UserAssistantInteractionMaturity,
    Phase10SessionPersistenceAndSnapshot,
    Phase11LlmToolCallingFoundation,
    Phase12AgentControlledCaptureTool,
    Phase13AdvancedAnalysisAndResponsePlanning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceStatus {
    pub phase: AgentPhase,
    pub note: String,
}
