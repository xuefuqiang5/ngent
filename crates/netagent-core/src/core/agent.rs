use netagent_models::{
    AgentMode, Message, MessagePart, MessagePartKind, MessageRole, RunState, Session, Step,
    StepStatus, ToolCall, ToolCallStatus,
};
use serde_json::{Value, json};

use crate::runtime::tool_registry::ToolResult;

const DEFAULT_MAX_STEPS: u32 = 4;

#[derive(Debug, Clone)]
pub struct MockAgentRun {
    pub session_started: Session,
    pub session_finished: Session,
    pub user_message: Message,
    pub assistant_message: Message,
    pub step: Step,
    pub tool_call: ToolCall,
    pub final_run_state: RunState,
}

#[derive(Debug, Default)]
pub struct MockAgentRuntime {
    session_counter: u64,
    message_counter: u64,
    part_counter: u64,
    step_counter: u64,
    tool_counter: u64,
}

impl MockAgentRuntime {
    pub fn run_mock_turn(&mut self, input: &str) -> MockAgentRun {
        let session_id = Self::next_id("ses", &mut self.session_counter);
        let user_message_id = Self::next_id("msg", &mut self.message_counter);
        let assistant_message_id = Self::next_id("msg", &mut self.message_counter);
        let step_id = Self::next_id("step", &mut self.step_counter);
        let tool_call_id = Self::next_id("call", &mut self.tool_counter);
        let user_part_id = Self::next_id("part", &mut self.part_counter);
        let assistant_text_part_id = Self::next_id("part", &mut self.part_counter);
        let assistant_tool_part_id = Self::next_id("part", &mut self.part_counter);
        let assistant_result_part_id = Self::next_id("part", &mut self.part_counter);

        let session_started = Session {
            id: session_id.clone(),
            mode: AgentMode::Observe,
            run_state: RunState::Busy,
            max_steps: DEFAULT_MAX_STEPS,
        };

        let session_finished = Session {
            id: session_id.clone(),
            mode: AgentMode::Observe,
            run_state: RunState::Idle,
            max_steps: DEFAULT_MAX_STEPS,
        };

        let user_message = Message {
            id: user_message_id,
            session_id: session_id.clone(),
            role: MessageRole::User,
            parts: vec![MessagePart {
                id: user_part_id,
                kind: MessagePartKind::Text,
                content: input.to_string(),
            }],
        };

        let assistant_message = Message {
            id: assistant_message_id,
            session_id: session_id.clone(),
            role: MessageRole::Assistant,
            parts: vec![
                MessagePart {
                    id: assistant_text_part_id,
                    kind: MessagePartKind::Text,
                    content: String::from(
                        "I will inspect a mock interface summary before responding.",
                    ),
                },
                MessagePart {
                    id: assistant_tool_part_id,
                    kind: MessagePartKind::ToolCall,
                    content: String::from("{\"tool\":\"mock.large_output\"}"),
                },
                MessagePart {
                    id: assistant_result_part_id,
                    kind: MessagePartKind::ToolResult,
                    content: String::from(
                        "Tool result is summarized and raw output is stored as an artifact.",
                    ),
                },
            ],
        };

        let step = Step {
            id: step_id.clone(),
            session_id: session_id.clone(),
            status: StepStatus::Completed,
            attempt: 1,
        };

        let tool_call = ToolCall {
            id: tool_call_id,
            session_id: session_id.clone(),
            step_id,
            tool_name: String::from("mock.large_output"),
            input: format!("{{\"query\":\"{input}\"}}"),
            status: ToolCallStatus::Completed,
        };

        MockAgentRun {
            session_started,
            session_finished,
            user_message,
            assistant_message,
            step,
            tool_call,
            final_run_state: RunState::Idle,
        }
    }

    pub fn build_agent_response(run: &MockAgentRun) -> Value {
        json!({
            "phase": "phase2",
            "session": run.session_finished,
            "step": run.step,
            "assistant_message": run.assistant_message,
            "run_state": run.final_run_state,
            "tool_call": run.tool_call,
        })
    }

    pub fn build_agent_response_with_tool_result(
        run: &MockAgentRun,
        tool_result: &ToolResult,
    ) -> Value {
        json!({
            "phase": "phase4",
            "session": run.session_finished,
            "step": run.step,
            "assistant_message": run.assistant_message,
            "run_state": run.final_run_state,
            "tool_call": run.tool_call,
            "tool_result": tool_result,
        })
    }

    fn next_id(prefix: &str, counter: &mut u64) -> String {
        *counter += 1;
        format!("{prefix}_{counter:04}")
    }
}
