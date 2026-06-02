use netagent_models::{AgentMode, ArtifactRef};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::storage::artifact_store::ArtifactStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub id: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub timeout_ms: Option<u64>,
    pub truncate_at: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContext {
    pub session_id: String,
    pub message_id: String,
    pub call_id: String,
    pub agent: AgentMode,
    pub abort: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub title: String,
    pub summary: String,
    pub structured: Value,
    pub artifacts: Vec<ArtifactRef>,
    pub truncated: bool,
    pub raw_output_artifact: Option<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolProgressUpdate {
    pub tool_call_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct ToolRegistry;

impl ToolRegistry {
    pub fn list_defs(&self) -> Vec<ToolDef> {
        vec![ToolDef {
            id: String::from("mock.large_output"),
            description: String::from(
                "Produces large mock output and stores the raw body as an artifact.",
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "summary": { "type": "string" },
                    "artifacts": { "type": "array" }
                }
            }),
            timeout_ms: Some(5_000),
            truncate_at: 120,
        }]
    }

    pub fn run_mock_large_output(
        &self,
        context: &ToolContext,
        query: &str,
        artifact_store: &mut ArtifactStore,
    ) -> (ToolResult, Vec<ToolProgressUpdate>) {
        let mut tool_defs = self.list_defs();
        let tool_def = tool_defs.remove(0);
        let raw_output = format!(
            "Mock network summary for query: {query}\n{}\n{}\n{}",
            "interface=mock0 dns=12 flows=4".repeat(6),
            "interface=mock1 dns=8 flows=7".repeat(6),
            "top_talker=10.0.0.10 protocol_mix=tcp,dns".repeat(6),
        );
        let truncated = raw_output.len() > tool_def.truncate_at;
        let summary = if truncated {
            format!(
                "{}...",
                &raw_output[..tool_def.truncate_at.min(raw_output.len())]
            )
        } else {
            raw_output.clone()
        };
        let artifact = artifact_store.write_raw_output(&tool_def.id, &raw_output);

        (
            ToolResult {
                title: String::from("Mock Large Output"),
                summary: String::from(
                    "Large raw output was truncated for the model and stored as an artifact.",
                ),
                structured: json!({
                    "query": query,
                    "preview": summary,
                    "tool_call_id": context.call_id,
                    "timeout_ms": tool_def.timeout_ms,
                }),
                artifacts: vec![artifact.clone()],
                truncated,
                raw_output_artifact: Some(artifact),
            },
            vec![
                ToolProgressUpdate {
                    tool_call_id: context.call_id.clone(),
                    status: String::from("running"),
                    message: String::from("Validating mock tool input."),
                },
                ToolProgressUpdate {
                    tool_call_id: context.call_id.clone(),
                    status: String::from("running"),
                    message: String::from("Writing raw output to artifact store."),
                },
            ],
        )
    }
}
