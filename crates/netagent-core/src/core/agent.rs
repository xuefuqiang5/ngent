use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use netagent_models::{
    AgentMode, ArtifactRef, Message, MessagePart, MessagePartKind, MessageRole, RunState, Session,
    Step, StepStatus, ToolCall, ToolCallStatus,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::runtime::tool_registry::ToolResult;

const DEFAULT_MAX_STEPS: u32 = 8;
const MAX_REPEATED_TOOL_CALLS: u32 = 2;
const MAX_LLM_ERROR_BODY_CHARS: usize = 2_000;
const DEFAULT_SYSTEM_PROMPT: &str = "You are NetAgent, a network investigation assistant. \
Use the supplied typed tools when evidence is needed. Answer concisely, stay grounded in \
tool results, and do not invent packet evidence. If evidence is missing, say what is known and \
what is uncertain. Never claim that a capture or system action ran unless a tool result proves it. \
When you call capture.start, the Core pauses the loop and asks the user for explicit approval; \
do not assume the capture ran until a later tool result says so. If approval is rejected, revise \
the plan (shorter duration, narrower filter, or offline pcap analysis) instead of retrying \
unchanged.";

#[derive(Debug, Clone)]
pub struct AgentTurn {
    pub session_created: bool,
    pub session_started: Session,
    pub session_finished: Session,
    pub messages: Vec<Message>,
    pub user_message: Message,
    pub plan_message: Message,
    pub assistant_message: Message,
    pub goal_analysis: GoalAnalysis,
    pub step: Step,
    pub tool_activities: Vec<AgentToolActivity>,
    pub final_run_state: RunState,
    pub llm_used: bool,
    pub llm_model: Option<String>,
    pub stop_reason: Option<String>,
    pub pending_permission: Option<AgentPendingPermission>,
    pub resumed: bool,
}

#[derive(Debug, Clone)]
pub struct AgentPendingPermission {
    pub request_id: String,
    pub summary: String,
    pub tool_call: ToolCall,
    pub call_message: Message,
    pub call_part: MessagePart,
    pub provider_call_id: String,
    pub plan: serde_json::Value,
}

/// Outcome of a single typed tool execution inside the Agent loop.
#[derive(Debug, Clone)]
pub enum ToolOutcome {
    Completed(ToolResult),
    PermissionPending { request_id: String, summary: String, plan: serde_json::Value },
}

#[derive(Debug, Clone, Serialize)]
pub struct GoalAnalysis {
    pub objective: String,
    pub mode: AgentMode,
    pub scope: String,
    pub candidate_tools: Vec<String>,
    pub selected_tools: Vec<String>,
    pub constraints: Vec<String>,
    pub success_criteria: Vec<String>,
    pub requires_permission: bool,
}

#[derive(Debug, Clone)]
pub struct AgentToolActivity {
    pub call_message: Message,
    pub result_message: Message,
    pub tool_call: ToolCall,
    pub result: ToolResult,
}

#[derive(Debug, Clone)]
pub struct AgentToolExecutionRequest {
    pub session_id: String,
    pub message_id: String,
    pub part_id: String,
    pub step_id: String,
    pub call_id: String,
    pub provider_call_id: String,
    pub tool_name: String,
    pub input: Value,
    pub agent: AgentMode,
}

#[derive(Debug, Clone)]
pub struct AgentAskInput {
    pub session_id: Option<String>,
    pub mode: AgentMode,
    pub input: String,
    pub context_summary: String,
}

#[derive(Debug, Clone)]
pub struct AgentResumeInput {
    pub session_id: String,
    pub mode: AgentMode,
    pub context_summary: String,
    /// Bounded, model-facing permission outcome:
    /// `{ status: "approved"|"rejected"|"failed", request_id, feedback, capture, artifact }`.
    pub outcome: Value,
    /// Short bounded text summarizing the outcome for the model.
    pub outcome_summary: String,
}

impl AgentResumeInput {
    pub fn outcome_approved(&self) -> bool {
        self.outcome
            .get("status")
            .and_then(Value::as_str)
            .map(|status| matches!(status, "approved" | "completed"))
            .unwrap_or(false)
    }
}

#[derive(Debug)]
struct LoopResult {
    final_text: String,
    stop_reason: Option<String>,
    activities: Vec<AgentToolActivity>,
    pending_permission: Option<AgentPendingPermission>,
    aborted: bool,
}

#[derive(Debug, Clone, Copy)]
enum FallbackMode<'a> {
    Plain { input: &'a str },
    Resume { input: &'a str, outcome: &'a Value, outcome_summary: &'a str },
}

#[derive(Debug, Clone, Serialize)]
pub struct LlmStatus {
    pub enabled: bool,
    pub provider: String,
    pub model: Option<String>,
    pub api_base: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session: Session,
    pub messages: Vec<Message>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone)]
struct LlmConfig {
    api_base: String,
    api_key: String,
    model: String,
    system_prompt: String,
    timeout_secs: u64,
    stream: bool,
    thinking: bool,
}

#[derive(Debug)]
pub struct AgentRuntime {
    session_counter: u64,
    message_counter: u64,
    part_counter: u64,
    step_counter: u64,
    sessions: HashMap<String, SessionRecord>,
    llm: Option<LlmConfig>,
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self::disabled()
    }
}

impl AgentRuntime {
    pub fn from_env() -> Self {
        Self {
            llm: LlmConfig::from_env(),
            ..Self::disabled()
        }
    }

    pub fn disabled() -> Self {
        Self {
            session_counter: 0,
            message_counter: 0,
            part_counter: 0,
            step_counter: 0,
            sessions: HashMap::new(),
            llm: None,
        }
    }

    pub fn llm_status(&self) -> LlmStatus {
        match &self.llm {
            Some(config) => LlmStatus {
                enabled: true,
                provider: String::from("openai_compatible"),
                model: Some(config.model.clone()),
                api_base: Some(config.api_base.clone()),
            },
            None => LlmStatus {
                enabled: false,
                provider: String::from("deterministic_tool_fallback"),
                model: None,
                api_base: None,
            },
        }
    }

    /// Load persisted session records into the in-memory store and bump counters
    /// so new IDs don't collide with existing rows.
    pub fn restore_sessions(&mut self, records: Vec<SessionRecord>) {
        let ses_max = records
            .iter()
            .filter_map(|r| Self::id_suffix(&r.session.id))
            .max()
            .unwrap_or(0);
        self.session_counter = self.session_counter.max(ses_max);

        let msg_max = records
            .iter()
            .flat_map(|r| r.messages.iter())
            .filter_map(|m| Self::id_suffix(&m.id))
            .max()
            .unwrap_or(0);
        self.message_counter = self.message_counter.max(msg_max);

        let part_max = records
            .iter()
            .flat_map(|r| r.messages.iter())
            .flat_map(|m| m.parts.iter())
            .filter_map(|p| Self::id_suffix(&p.id))
            .max()
            .unwrap_or(0);
        self.part_counter = self.part_counter.max(part_max);

        let step_max = records
            .iter()
            .flat_map(|r| r.steps.iter())
            .filter_map(|s| Self::id_suffix(&s.id))
            .max()
            .unwrap_or(0);
        self.step_counter = self.step_counter.max(step_max);

        for record in records {
            self.sessions.insert(record.session.id.clone(), record);
        }
    }

    pub fn set_session_run_state(&mut self, session_id: &str, run_state: RunState) {
        if let Some(record) = self.sessions.get_mut(session_id) {
            record.session.run_state = run_state;
        }
    }

    pub fn run_turn_with_tools<F>(
        &mut self,
        input: AgentAskInput,
        tools: &[Value],
        execute_tool: F,
    ) -> Result<AgentTurn, String>
    where
        F: FnMut(&AgentToolExecutionRequest) -> Result<ToolOutcome, String>,
    {
        let abort = AtomicBool::new(false);
        let mut noop = |_: &str| {};
        self.run_turn_with_tools_streaming(input, tools, &abort, &mut noop, execute_tool)
    }

    pub fn run_turn_with_tools_streaming<F>(
        &mut self,
        input: AgentAskInput,
        tools: &[Value],
        abort: &AtomicBool,
        on_text_delta: &mut dyn FnMut(&str),
        execute_tool: F,
    ) -> Result<AgentTurn, String>
    where
        F: FnMut(&AgentToolExecutionRequest) -> Result<ToolOutcome, String>,
    {
        let session_created = input
            .session_id
            .as_ref()
            .map(|id| !self.sessions.contains_key(id))
            .unwrap_or(true);
        let session_id = input
            .session_id
            .unwrap_or_else(|| Self::next_id("ses", &mut self.session_counter));

        let mut record = self
            .sessions
            .get(&session_id)
            .cloned()
            .unwrap_or_else(|| SessionRecord {
                session: Session {
                    id: session_id.clone(),
                    mode: input.mode,
                    run_state: RunState::Idle,
                    max_steps: DEFAULT_MAX_STEPS,
                },
                messages: Vec::new(),
                steps: Vec::new(),
            });

        record.session.mode = input.mode;
        record.session.run_state = RunState::Busy;
        let session_started = record.session.clone();

        let user_message = self.build_message(
            &session_id,
            MessageRole::User,
            MessagePartKind::Text,
            input.input.clone(),
        );
        record.messages.push(user_message.clone());

        let mut step = Step {
            id: Self::next_id("step", &mut self.step_counter),
            session_id: session_id.clone(),
            status: StepStatus::Running,
            attempt: 1,
        };

        let preview_calls = Self::fallback_plan(&input.input, &step.id);
        let candidate_tools = Self::unique_tool_names(
            preview_calls
                .iter()
                .map(|call| Self::canonical_tool_name(&call.function.name)),
        );
        let mut goal_analysis = Self::build_goal_analysis(&input.input, input.mode, candidate_tools);
        let mut plan_message = self.build_message(
            &session_id,
            MessageRole::Assistant,
            MessagePartKind::Reasoning,
            serde_json::to_string(&goal_analysis).unwrap_or_else(|_| String::from("{}")),
        );
        record.messages.push(plan_message.clone());

        let llm_config = self.llm.clone();
        let mut provider_messages = llm_config.as_ref().map(|config| {
            self.build_provider_history(config, &record.messages, &input.context_summary, &goal_analysis)
        });
        let fallback_calls = if llm_config.is_none() {
            preview_calls
        } else {
            Vec::new()
        };

        let loop_result = Self::drive_loop(
            self,
            &mut record,
            &step.id,
            step.id.trim_start_matches("step_"),
            llm_config.as_ref(),
            &mut provider_messages,
            fallback_calls,
            tools,
            abort,
            on_text_delta,
            FallbackMode::Plain {
                input: input.input.as_str(),
            },
            execute_tool,
        )?;

        goal_analysis.selected_tools = Self::unique_tool_names(
            loop_result
                .activities
                .iter()
                .map(|activity| activity.tool_call.tool_name.clone()),
        );
        plan_message.parts[0].content =
            serde_json::to_string(&goal_analysis).unwrap_or_else(|_| String::from("{}"));
        if let Some(stored_plan) = record
            .messages
            .iter_mut()
            .find(|message| message.id == plan_message.id)
        {
            *stored_plan = plan_message.clone();
        }

        if let Some(pending) = loop_result.pending_permission {
            step.status = StepStatus::WaitingPermission;
            record.steps.push(step.clone());
            record.session.run_state = RunState::WaitingPermission;
            let session_finished = record.session.clone();
            let turn_messages = record.messages.clone();
            let assistant_message = self.build_message(
                &session_id,
                MessageRole::Assistant,
                MessagePartKind::Text,
                format!(
                    "Waiting for user approval of {} ({}). The investigation continues after the permission decision.",
                    pending.tool_call.tool_name, pending.request_id
                ),
            );
            self.sessions.insert(session_id, record);
            return Ok(AgentTurn {
                session_created,
                session_started,
                session_finished,
                messages: turn_messages,
                user_message,
                plan_message,
                assistant_message,
                goal_analysis,
                step,
                tool_activities: loop_result.activities,
                final_run_state: RunState::WaitingPermission,
                llm_used: llm_config.is_some(),
                llm_model: llm_config.map(|config| config.model),
                stop_reason: loop_result.stop_reason,
                pending_permission: Some(pending),
                resumed: false,
            });
        }

        step.status = if loop_result.aborted {
            StepStatus::Aborted
        } else {
            StepStatus::Completed
        };
        record.steps.push(step.clone());
        let assistant_message = self.build_message(
            &session_id,
            MessageRole::Assistant,
            MessagePartKind::Text,
            loop_result.final_text,
        );
        record.messages.push(assistant_message.clone());
        record.session.run_state = RunState::Idle;
        let session_finished = record.session.clone();

        let turn_messages = record
            .messages
            .iter()
            .rev()
            .take(loop_result.activities.len() * 2 + 3)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        self.sessions.insert(session_id, record);

        Ok(AgentTurn {
            session_created,
            session_started,
            session_finished,
            messages: turn_messages,
            user_message,
            plan_message,
            assistant_message,
            goal_analysis,
            step,
            tool_activities: loop_result.activities,
            final_run_state: RunState::Idle,
            llm_used: llm_config.is_some(),
            llm_model: llm_config.map(|config| config.model),
            stop_reason: loop_result.stop_reason,
            pending_permission: None,
            resumed: false,
        })
    }

    /// Continue a turn that paused on a `capture.start` permission request.
    /// The permission outcome (approved/rejected/failed + feedback) is injected
    /// as the missing tool result, the model (or deterministic planner) revises
    /// the plan, and the loop runs to the final answer. If the revised plan
    /// requests capture again, the turn pauses again for a new permission.
    pub fn continue_turn_with_tools<F>(
        &mut self,
        input: AgentResumeInput,
        tools: &[Value],
        execute_tool: F,
    ) -> Result<AgentTurn, String>
    where
        F: FnMut(&AgentToolExecutionRequest) -> Result<ToolOutcome, String>,
    {
        let abort = AtomicBool::new(false);
        let mut noop = |_: &str| {};
        self.continue_turn_with_tools_streaming(input, tools, &abort, &mut noop, execute_tool)
    }

    pub fn continue_turn_with_tools_streaming<F>(
        &mut self,
        input: AgentResumeInput,
        tools: &[Value],
        abort: &AtomicBool,
        on_text_delta: &mut dyn FnMut(&str),
        execute_tool: F,
    ) -> Result<AgentTurn, String>
    where
        F: FnMut(&AgentToolExecutionRequest) -> Result<ToolOutcome, String>,
    {
        let session_id = input.session_id.clone();
        let mut record = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or_else(|| format!("session not found: {session_id}"))?;
        let original_input = record
            .messages
            .iter()
            .find(|message| message.role == MessageRole::User)
            .map(|message| {
                message
                    .parts
                    .iter()
                    .map(|part| part.content.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| String::from("Resume the investigation."));

        let step_index = record
            .steps
            .iter()
            .rposition(|candidate| candidate.status == StepStatus::WaitingPermission)
            .ok_or_else(|| format!("no waiting agent step to resume for session {session_id}"))?;
        let mut step = record.steps[step_index].clone();
        step.status = StepStatus::Running;
        step.attempt += 1;

        let session_started = record.session.clone();
        record.session.run_state = RunState::Busy;

        let mut waiting_part_index = None;
        for (index, message) in record.messages.iter().enumerate().rev() {
            let waiting = message
                .parts
                .iter()
                .any(|part| part.kind == MessagePartKind::ToolCall && part_waits_for_permission(part));
            if waiting {
                waiting_part_index = Some(index);
                break;
            }
        }
        let waiting_message_index = waiting_part_index.ok_or_else(|| {
            format!("session {session_id} has a waiting step but no waiting tool-call part")
        })?;

        let (provider_call_id, call_id, tool_name, tool_input) = {
            let message = &record.messages[waiting_message_index];
            let part = message
                .parts
                .iter()
                .find(|part| part.kind == MessagePartKind::ToolCall)
                .expect("waiting part exists");
            let content: Value =
                serde_json::from_str(&part.content).unwrap_or_else(|_| json!({}));
            (
                content
                    .get("provider_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                content
                    .get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                content
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or("capture.start")
                    .to_string(),
                content.get("input").cloned().unwrap_or_else(|| json!({})),
            )
        };

        let resolved_tool_call = ToolCall {
            id: call_id.clone(),
            session_id: session_id.clone(),
            step_id: step.id.clone(),
            tool_name: tool_name.clone(),
            input: tool_input.to_string(),
            status: if input.outcome_approved() {
                ToolCallStatus::Completed
            } else {
                ToolCallStatus::Aborted
            },
        };
        let result_message = self.build_message(
            &session_id,
            MessageRole::Tool,
            MessagePartKind::ToolResult,
            json!({
                "call_id": call_id,
                "provider_call_id": provider_call_id,
                "tool_name": tool_name,
                "result": input.outcome,
            })
            .to_string(),
        );

        let candidate_tools = Self::unique_tool_names(
            Self::fallback_resume_plan(&input)
                .into_iter()
                .map(|(name, _)| name)
                .chain(std::iter::once(String::from("capture.start"))),
        );
        let mut goal_analysis = Self::build_goal_analysis(
            &format!(
                "{original_input} — resumed after the capture permission decision: {}",
                input.outcome_summary
            ),
            input.mode,
            candidate_tools,
        );
        let mut plan_message = self.build_message(
            &session_id,
            MessageRole::Assistant,
            MessagePartKind::Reasoning,
            serde_json::to_string(&goal_analysis).unwrap_or_else(|_| String::from("{}")),
        );

        let llm_config = self.llm.clone();
        record.messages.push(plan_message.clone());
        record.messages.push(result_message.clone());
        let resumed_turn_messages = record.messages.clone();
        // The provider history must include the injected permission outcome
        // (the tool result for the waiting call) so every assistant tool_calls
        // message has its matching tool message.
        let mut provider_messages = llm_config.as_ref().map(|config| {
            self.build_provider_history(config, &record.messages, &input.context_summary, &goal_analysis)
        });
        let fallback_calls = if llm_config.is_none() {
            Self::fallback_resume_plan(&input)
                .into_iter()
                .map(|(name, arguments)| ChatToolCall {
                    id: format!("resume_{}_{}", step.id, name.replace('.', "_")),
                    kind: String::from("function"),
                    function: ChatFunctionCall {
                        name: name.replace('.', "_"),
                        arguments: arguments.to_string(),
                    },
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let resolved_activity = AgentToolActivity {
            call_message: record.messages[waiting_message_index].clone(),
            result_message: result_message.clone(),
            tool_call: resolved_tool_call,
            result: ToolResult {
                title: String::from("Capture permission outcome"),
                summary: input.outcome_summary.clone(),
                structured: input.outcome.clone(),
                artifacts: input
                    .outcome
                    .get("artifact")
                    .and_then(|artifact| serde_json::from_value::<ArtifactRef>(artifact.clone()).ok())
                    .map(|artifact| vec![artifact])
                    .unwrap_or_default(),
                truncated: false,
                raw_output_artifact: None,
            },
        };

        let loop_result = Self::drive_loop(
            self,
            &mut record,
            &step.id,
            &format!(
                "{}_{}",
                step.id.trim_start_matches("step_"),
                step.attempt
            ),
            llm_config.as_ref(),
            &mut provider_messages,
            fallback_calls,
            tools,
            abort,
            on_text_delta,
            FallbackMode::Resume {
                input: original_input.as_str(),
                outcome: &input.outcome,
                outcome_summary: input.outcome_summary.as_str(),
            },
            execute_tool,
        )?;
        let LoopResult {
            final_text,
            stop_reason,
            mut activities,
            pending_permission,
            aborted,
        } = loop_result;
        activities.insert(0, resolved_activity);

        goal_analysis.selected_tools = Self::unique_tool_names(
            activities
                .iter()
                .map(|activity| activity.tool_call.tool_name.clone()),
        );
        plan_message.parts[0].content =
            serde_json::to_string(&goal_analysis).unwrap_or_else(|_| String::from("{}"));
        if let Some(stored_plan) = record
            .messages
            .iter_mut()
            .find(|message| message.id == plan_message.id)
        {
            *stored_plan = plan_message.clone();
        }

        if let Some(pending) = pending_permission {
            step.status = StepStatus::WaitingPermission;
            if let Some(existing) = record
                .steps
                .iter_mut()
                .find(|existing| existing.id == step.id)
            {
                *existing = step.clone();
            }
            record.session.run_state = RunState::WaitingPermission;
            let session_finished = record.session.clone();
            let assistant_message = self.build_message(
                &session_id,
                MessageRole::Assistant,
                MessagePartKind::Text,
                format!(
                    "Waiting for user approval of {} ({}). The investigation continues after the permission decision.",
                    pending.tool_call.tool_name, pending.request_id
                ),
            );
            self.sessions.insert(session_id.clone(), record);
            return Ok(AgentTurn {
                session_created: false,
                session_started,
                session_finished,
                messages: resumed_turn_messages,
                user_message: result_message.clone(),
                plan_message,
                assistant_message,
                goal_analysis,
                step,
                tool_activities: activities,
                final_run_state: RunState::WaitingPermission,
                llm_used: llm_config.is_some(),
                llm_model: llm_config.map(|config| config.model),
                stop_reason,
                pending_permission: Some(pending),
                resumed: true,
            });
        }

        step.status = if aborted {
            StepStatus::Aborted
        } else {
            StepStatus::Completed
        };
        if let Some(existing) = record
            .steps
            .iter_mut()
            .find(|existing| existing.id == step.id)
        {
            *existing = step.clone();
        }
        let assistant_message = self.build_message(
            &session_id,
            MessageRole::Assistant,
            MessagePartKind::Text,
            final_text,
        );
        record.messages.push(assistant_message.clone());
        record.session.run_state = RunState::Idle;
        let session_finished = record.session.clone();

        let turn_messages = record
            .messages
            .iter()
            .rev()
            .take(activities.len() * 2 + 5)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        self.sessions.insert(session_id, record);

        Ok(AgentTurn {
            session_created: false,
            session_started,
            session_finished,
            messages: turn_messages,
            user_message: result_message,
            plan_message,
            assistant_message,
            goal_analysis,
            step,
            tool_activities: activities,
            final_run_state: RunState::Idle,
            llm_used: llm_config.is_some(),
            llm_model: llm_config.map(|config| config.model),
            stop_reason,
            pending_permission: None,
            resumed: true,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_loop<F>(
        &mut self,
        record: &mut SessionRecord,
        step_id: &str,
        call_id_prefix: &str,
        llm_config: Option<&LlmConfig>,
        provider_messages: &mut Option<Vec<ChatMessage>>,
        fallback_calls: Vec<ChatToolCall>,
        tools: &[Value],
        abort: &AtomicBool,
        on_text_delta: &mut dyn FnMut(&str),
        fallback_mode: FallbackMode<'_>,
        mut execute_tool: F,
    ) -> Result<LoopResult, String>
    where
        F: FnMut(&AgentToolExecutionRequest) -> Result<ToolOutcome, String>,
    {
        let mut activities = Vec::new();
        let mut repeated_calls: HashMap<String, u32> = HashMap::new();
        let mut model_rounds = 0_u32;
        let mut total_calls = 0_u32;
        let mut fallback_index = 0_usize;
        let mut stop_reason = None;
        let mut pending_permission = None;
        let mut aborted = false;
        let final_text = loop {
            if abort.load(Ordering::Relaxed) {
                let reason = String::from("Agent turn aborted by the user.");
                stop_reason = Some(reason.clone());
                aborted = true;
                break reason;
            }
            let action = if let (Some(config), Some(messages)) =
                (llm_config, provider_messages.as_ref())
            {
                if model_rounds >= record.session.max_steps {
                    let reason = format!(
                        "Stopped after the configured maximum of {} model steps.",
                        record.session.max_steps
                    );
                    stop_reason = Some(reason.clone());
                    break reason;
                }
                model_rounds += 1;
                if config.stream {
                    match Self::complete_with_llm_streaming(
                        config,
                        messages,
                        tools,
                        abort,
                        on_text_delta,
                    ) {
                        Ok(action) => action,
                        Err(message) if message.contains("aborted") => {
                            let reason = String::from("Agent turn aborted by the user.");
                            stop_reason = Some(reason.clone());
                            aborted = true;
                            break reason;
                        }
                        Err(message) => return Err(message),
                    }
                } else {
                    Self::complete_with_llm(config, messages, tools)?
                }
            } else if fallback_index < fallback_calls.len() {
                let call = fallback_calls[fallback_index].clone();
                fallback_index += 1;
                ModelAction::ToolCalls(vec![call])
            } else {
                ModelAction::Text(match fallback_mode {
                    FallbackMode::Plain { input } => Self::fallback_response(input, &activities),
                    FallbackMode::Resume { input, outcome, outcome_summary } => {
                        Self::fallback_resume_response(input, outcome, outcome_summary, &activities)
                    }
                })
            };

            match action {
                ModelAction::Text(text) => break text,
                ModelAction::ToolCalls(calls) => {
                    if calls.is_empty() {
                        let reason = String::from(
                            "The model returned an empty tool call list, so the run stopped safely.",
                        );
                        stop_reason = Some(reason.clone());
                        break reason;
                    }

                    if let Some(messages) = provider_messages.as_mut() {
                        messages.push(ChatMessage::assistant_tool_calls(calls.clone()));
                    }

                    let mut stopped = None;
                    for call in calls {
                        let tool_name = Self::canonical_tool_name(&call.function.name);
                        if total_calls >= record.session.max_steps {
                            stopped = Some(format!(
                                "Stopped after the configured maximum of {} tool calls.",
                                record.session.max_steps
                            ));
                            break;
                        }

                        let arguments =
                            match serde_json::from_str::<Value>(&call.function.arguments) {
                                Ok(Value::Object(map)) => Value::Object(map),
                                Ok(_) => json!({
                                    "__validation_error": "tool arguments must be a JSON object"
                                }),
                                Err(error) => json!({
                                    "__validation_error": format!("invalid JSON arguments: {error}")
                                }),
                            };
                        if Self::repeated_tool_call_exceeded(
                            &mut repeated_calls,
                            &tool_name,
                            &arguments,
                        ) {
                            stopped = Some(format!(
                                "Stopped a repeated tool-call loop for {} with unchanged input.",
                                tool_name
                            ));
                            break;
                        }

                        total_calls += 1;
                        let call_message_id = Self::next_id("msg", &mut self.message_counter);
                        let call_part_id = Self::next_id("part", &mut self.part_counter);
                        let call_id = format!("call_{}_{}", call_id_prefix, total_calls);
                        let request = AgentToolExecutionRequest {
                            session_id: record.session.id.clone(),
                            message_id: call_message_id.clone(),
                            part_id: call_part_id.clone(),
                            step_id: step_id.to_string(),
                            call_id: call_id.clone(),
                            provider_call_id: call.id.clone(),
                            tool_name: tool_name.clone(),
                            input: arguments.clone(),
                            agent: record.session.mode,
                        };
                        let execution = execute_tool(&request);
                        match execution {
                            Ok(ToolOutcome::PermissionPending {
                                request_id,
                                summary,
                                plan,
                            }) => {
                                let tool_call = ToolCall {
                                    id: call_id.clone(),
                                    session_id: record.session.id.clone(),
                                    step_id: step_id.to_string(),
                                    tool_name: tool_name.clone(),
                                    input: arguments.to_string(),
                                    status: ToolCallStatus::WaitingPermission,
                                };
                                let call_part = MessagePart {
                                    id: call_part_id,
                                    kind: MessagePartKind::ToolCall,
                                    content: json!({
                                        "call_id": call_id,
                                        "provider_call_id": call.id,
                                        "tool_name": tool_name,
                                        "input": arguments,
                                        "status": ToolCallStatus::WaitingPermission,
                                    })
                                    .to_string(),
                                };
                                let call_message = Message {
                                    id: call_message_id,
                                    session_id: record.session.id.clone(),
                                    role: MessageRole::Assistant,
                                    parts: vec![call_part.clone()],
                                };
                                record.messages.push(call_message.clone());
                                pending_permission = Some(AgentPendingPermission {
                                    request_id,
                                    summary: summary.clone(),
                                    tool_call,
                                    call_message,
                                    call_part,
                                    provider_call_id: call.id.clone(),
                                    plan,
                                });
                                stopped = Some(summary);
                                break;
                            }
                            Ok(ToolOutcome::Completed(result)) => {
                                let tool_call = ToolCall {
                                    id: call_id.clone(),
                                    session_id: record.session.id.clone(),
                                    step_id: step_id.to_string(),
                                    tool_name: tool_name.clone(),
                                    input: arguments.to_string(),
                                    status: ToolCallStatus::Completed,
                                };
                                let call_part = MessagePart {
                                    id: call_part_id,
                                    kind: MessagePartKind::ToolCall,
                                    content: json!({
                                        "call_id": call_id,
                                        "provider_call_id": call.id,
                                        "tool_name": tool_name,
                                        "input": arguments,
                                        "status": ToolCallStatus::Completed,
                                    })
                                    .to_string(),
                                };
                                let call_message = Message {
                                    id: call_message_id,
                                    session_id: record.session.id.clone(),
                                    role: MessageRole::Assistant,
                                    parts: vec![call_part],
                                };
                                let result_message = self.build_message(
                                    &record.session.id,
                                    MessageRole::Tool,
                                    MessagePartKind::ToolResult,
                                    json!({
                                        "call_id": tool_call.id,
                                        "provider_call_id": request.provider_call_id,
                                        "tool_name": tool_call.tool_name,
                                        "result": result,
                                    })
                                    .to_string(),
                                );

                                if let Some(messages) = provider_messages.as_mut() {
                                    messages.push(ChatMessage::tool_result(
                                        &request.provider_call_id,
                                        &result,
                                    ));
                                }
                                record.messages.push(call_message.clone());
                                record.messages.push(result_message.clone());
                                activities.push(AgentToolActivity {
                                    call_message,
                                    result_message,
                                    tool_call,
                                    result,
                                });
                            }
                            Err(message) => {
                                let result = ToolResult::bounded_error(&tool_name, &message);
                                let tool_call = ToolCall {
                                    id: call_id.clone(),
                                    session_id: record.session.id.clone(),
                                    step_id: step_id.to_string(),
                                    tool_name: tool_name.clone(),
                                    input: arguments.to_string(),
                                    status: ToolCallStatus::Error,
                                };
                                let call_part = MessagePart {
                                    id: call_part_id,
                                    kind: MessagePartKind::ToolCall,
                                    content: json!({
                                        "call_id": call_id,
                                        "provider_call_id": call.id,
                                        "tool_name": tool_name,
                                        "input": arguments,
                                        "status": ToolCallStatus::Error,
                                    })
                                    .to_string(),
                                };
                                let call_message = Message {
                                    id: call_message_id,
                                    session_id: record.session.id.clone(),
                                    role: MessageRole::Assistant,
                                    parts: vec![call_part],
                                };
                                let result_message = self.build_message(
                                    &record.session.id,
                                    MessageRole::Tool,
                                    MessagePartKind::ToolResult,
                                    json!({
                                        "call_id": tool_call.id,
                                        "provider_call_id": request.provider_call_id,
                                        "tool_name": tool_call.tool_name,
                                        "result": result,
                                    })
                                    .to_string(),
                                );

                                if let Some(messages) = provider_messages.as_mut() {
                                    messages.push(ChatMessage::tool_result(
                                        &request.provider_call_id,
                                        &result,
                                    ));
                                }
                                record.messages.push(call_message.clone());
                                record.messages.push(result_message.clone());
                                activities.push(AgentToolActivity {
                                    call_message,
                                    result_message,
                                    tool_call,
                                    result,
                                });
                            }
                        }
                    }

                    if let Some(reason) = stopped {
                        stop_reason = Some(reason.clone());
                        break reason;
                    }
                }
            }
        };

        Ok(LoopResult {
            final_text,
            stop_reason,
            activities,
            pending_permission,
            aborted,
        })
    }

    pub fn build_agent_response(turn: &AgentTurn) -> Value {
        let mut response = json!({
            "phase": "phase15",
            "session_created": turn.session_created,
            "session": turn.session_finished,
            "step": turn.step,
            "goal_analysis": turn.goal_analysis,
            "assistant_message": turn.assistant_message,
            "tool_calls": turn.tool_activities.iter().map(|activity| &activity.tool_call).collect::<Vec<_>>(),
            "run_state": turn.final_run_state,
            "aborted": turn.step.status == StepStatus::Aborted,
            "llm": {
                "used": turn.llm_used,
                "model": turn.llm_model,
            },
            "safety": {
                "max_steps": turn.session_finished.max_steps,
                "stop_reason": turn.stop_reason,
            },
            "resumed": turn.resumed,
        });
        if let Some(pending) = &turn.pending_permission {
            response["permission_request_id"] = json!(pending.request_id);
            response["capture_proposal"] = json!({
                "status": "waiting_permission",
                "request_id": pending.request_id,
                "capture": pending.plan,
            });
        }
        response
    }

    fn build_message(
        &mut self,
        session_id: &str,
        role: MessageRole,
        kind: MessagePartKind,
        content: String,
    ) -> Message {
        Message {
            id: Self::next_id("msg", &mut self.message_counter),
            session_id: session_id.to_string(),
            role,
            parts: vec![MessagePart {
                id: Self::next_id("part", &mut self.part_counter),
                kind,
                content,
            }],
        }
    }

    fn id_suffix(id: &str) -> Option<u64> {
        id.rsplit('_').next()?.parse::<u64>().ok()
    }

    fn build_goal_analysis(
        input: &str,
        mode: AgentMode,
        candidate_tools: Vec<String>,
    ) -> GoalAnalysis {
        let objective = Self::truncate_chars(input.trim(), 320);
        let scope = if candidate_tools.is_empty() {
            String::from(
                "Clarify or answer the network-investigation request without inventing evidence.",
            )
        } else {
            String::from(
                "Inspect existing NetAgent structured evidence with typed tools; live capture only with explicit user approval.",
            )
        };
        GoalAnalysis {
            objective,
            mode,
            scope,
            candidate_tools: candidate_tools.clone(),
            selected_tools: Vec::new(),
            constraints: vec![
                String::from("Observe mode"),
                String::from("No arbitrary shell or direct system command execution"),
                String::from("Only bounded summaries, structured output, and ArtifactRef values"),
                String::from("capture.start pauses for explicit user approval"),
                String::from("State uncertainty when stored evidence is missing"),
            ],
            success_criteria: vec![
                String::from("Use tools when stored evidence is needed"),
                String::from("Ground every factual conclusion in returned evidence"),
                String::from("Separate known facts from unknown live-network state"),
            ],
            requires_permission: candidate_tools.contains(&String::from("capture.start")),
        }
    }

    fn unique_tool_names<I>(names: I) -> Vec<String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut unique = Vec::new();
        for name in names {
            if !unique.contains(&name) {
                unique.push(name);
            }
        }
        unique
    }

    fn fallback_plan(input: &str, step_id: &str) -> Vec<ChatToolCall> {
        let lower = input.to_lowercase();

        if let Some(path) = Self::extract_pcap_path(input) {
            return Self::fallback_plan_from_pairs(
                step_id,
                vec![
                    ("pcap.open", json!({ "path": path })),
                    (
                        "dns.detect_anomalies",
                        json!({ "threshold_ratio": 0.3, "min_queries": 2 }),
                    ),
                    (
                        "report.generate",
                        json!({ "title": "NetAgent Offline Investigation Report" }),
                    ),
                    ("ioc.export", json!({})),
                ],
            );
        }

        if Self::wants_respond_action(&lower) {
            let mut plan = vec![("finding.list", json!({ "limit": 12 }))];
            if let Some(target) = Self::extract_ip_target(input) {
                let mut arguments = json!({
                    "target": target,
                    "action": "block",
                    "reason": "User requested a firewall response for this target during the investigation.",
                });
                if let Some(finding_id) = Self::extract_finding_id(input) {
                    arguments["finding_id"] = json!(finding_id);
                }
                plan.push(("respond.propose_firewall_rule", arguments));
            }
            if plan.len() > 1 {
                return Self::fallback_plan_from_pairs(step_id, plan);
            }
        }

        if Self::wants_live_evidence(&lower, input) {
            return Self::fallback_plan_from_pairs(
                step_id,
                vec![(
                    "capture.start",
                    json!({ "interface": "mock1", "filter": "tcp or dns", "duration": 10 }),
                )],
            );
        }

        let wants_summary = Self::contains_any(
            &lower,
            &[
                "summarize",
                "summary",
                "analyze",
                "investigate",
                "investigation",
                "current",
                "state",
                "evidence",
            ],
        ) || Self::contains_any(
            input,
            &[
                "总结", "摘要", "分析", "调查", "当前", "状态", "证据", "已有",
            ],
        );
        let mut names = Vec::new();

        if Self::contains_any(&lower, &["flow", "connection", "traffic"])
            || Self::contains_any(input, &["流量", "连接", "会话"])
            || wants_summary
        {
            names.push(("flow.list", json!({ "limit": 12 })));
        }
        if Self::contains_any(&lower, &["finding", "alert", "risk", "anomal"])
            || Self::contains_any(input, &["发现", "告警", "风险", "异常"])
            || wants_summary
        {
            names.push(("finding.list", json!({ "limit": 12 })));
        }
        if (Self::contains_any(&lower, &["capture status", "capture state"])
            || Self::contains_any(input, &["抓包状态", "采集状态"]))
            || wants_summary
        {
            names.push(("capture.status", json!({})));
        }

        let artifact_id = Self::extract_artifact_id(input);
        let wants_artifact = Self::contains_any(&lower, &["artifact", "report"])
            || Self::contains_any(input, &["制品", "报告"])
            || wants_summary;
        if wants_artifact {
            names.push(("artifact.list", json!({ "limit": 12 })));
        }
        if let Some(artifact_id) = artifact_id {
            names.push(("artifact.summary", json!({ "artifact_id": artifact_id })));
        }

        Self::fallback_plan_from_pairs(step_id, names)
    }

    /// Deterministic offline planner used after a permission decision. Prefers
    /// the captured pcap when approval succeeded, otherwise a pcap path given
    /// in the rejection feedback. Never re-requests live capture here, so the
    /// offline loop cannot loop on permissions.
    fn fallback_resume_plan(input: &AgentResumeInput) -> Vec<(String, Value)> {
        let mut path = input
            .outcome
            .get("capture")
            .and_then(|capture| capture.get("pcap_path"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if path.is_none() {
            let feedback = input
                .outcome
                .get("feedback")
                .and_then(Value::as_str)
                .unwrap_or("");
            path = Self::extract_pcap_path(feedback);
        }

        match path {
            Some(path) => vec![
                ("pcap.open".to_string(), json!({ "path": path })),
                (
                    "dns.detect_anomalies".to_string(),
                    json!({ "threshold_ratio": 0.3, "min_queries": 2 }),
                ),
                (
                    "report.generate".to_string(),
                    json!({ "title": "NetAgent Investigation Report" }),
                ),
                ("ioc.export".to_string(), json!({})),
            ],
            None => Vec::new(),
        }
    }

    fn fallback_resume_response(
        input: &str,
        outcome: &Value,
        outcome_summary: &str,
        activities: &[AgentToolActivity],
    ) -> String {
        let status = outcome
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("rejected");
        let chinese = input
            .chars()
            .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character));

        if let Some(proposal) = outcome.get("proposal") {
            let target = proposal
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let artifact = outcome
                .pointer("/artifact/id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return if chinese {
                format!(
                    "防火墙规则提案已创建（preview only，未执行）。\n\n- 目标: {target}（action=block）\n- 状态: proposed，防火墙未被修改\n- 提案与证据引用: artifact {artifact}\n\n此提案仅用于评审；任何实际防火墙修改都需要独立的高风险确认。"
                )
            } else {
                format!(
                    "Firewall rule proposal created (preview only, not executed).\n\n- Target: {target} (action=block)\n- Status: proposed; the firewall was NOT modified\n- Proposal and evidence refs: artifact {artifact}\n\nThis proposal is for review only; any real firewall change requires a separate high-risk approval."
                )
            };
        }

        let heading = if chinese {
            match status {
                "approved" | "completed" => {
                    "抓包已获批准，已用抓取到的 pcap 完成离线分析。"
                }
                "rejected" => "实时抓包权限被拒绝；已改用本地 pcap 离线分析。",
                _ => "抓包启动失败；已尝试用离线证据继续调查。",
            }
        } else {
            match status {
                "approved" | "completed" => {
                    "The capture was approved and the resulting pcap has been analyzed offline."
                }
                "rejected" => "Live capture was rejected; the investigation switched to offline pcap analysis.",
                _ => "The capture could not start; the investigation fell back to offline evidence.",
            }
        };

        let mut lines = vec![heading.to_string()];
        if !outcome_summary.is_empty() {
            lines.push(format!("Decision context: {outcome_summary}"));
        }
        if activities.is_empty() {
            lines.push(if chinese {
                "没有可用的离线分析结果。替代方案：提供本地 .pcap 文件路径、缩短抓包时长并缩小 filter，或基于已存储证据继续。".to_string()
            } else {
                "No offline analysis result was produced. Alternatives: provide a local .pcap path, approve a shorter capture with a narrower filter, or continue with stored evidence.".to_string()
            });
        } else {
            for activity in activities {
                lines.push(format!(
                    "- `{}`: {}",
                    activity.tool_call.tool_name, activity.result.summary
                ));
            }
            let conclusion = if chinese {
                "\n结论：以上结论仅基于已存储的结构化证据；若记录为空，不能据此断言当前网络正常或异常。"
            } else {
                "\nConclusion: this answer is limited to stored structured evidence. Empty records do not prove that the live network is healthy or unhealthy."
            };
            lines.push(conclusion.to_string());
        }
        lines.join("\n")
    }

    fn fallback_plan_from_pairs(step_id: &str, names: Vec<(&str, Value)>) -> Vec<ChatToolCall> {
        names
            .into_iter()
            .enumerate()
            .map(|(index, (name, input))| ChatToolCall {
                id: format!("fallback_{}_{}", step_id, index + 1),
                kind: String::from("function"),
                function: ChatFunctionCall {
                    name: name.to_string(),
                    arguments: input.to_string(),
                },
            })
            .collect()
    }

    fn wants_live_evidence(lower: &str, input: &str) -> bool {
        if Self::contains_any(
            lower,
            &[
                "stop capture",
                "停止抓包",
                "不要抓包",
                "不用抓包",
                "capture status",
                "capture state",
                "抓包状态",
                "采集状态",
            ],
        ) {
            return false;
        }
        Self::contains_any(
            lower,
            &["抓包", "capture", "packet", "live", "实时", "当前网络", "现在网络", "流量", "可疑", "异常"],
        ) || Self::contains_any(input, &["抓包", "实时", "当前网络", "现在网络", "流量", "可疑", "异常"])
    }

    fn wants_respond_action(lower: &str) -> bool {
        Self::contains_any(
            lower,
            &["firewall", "防火墙", "封禁", "阻断", "block", "响应", "respond"],
        )
    }

    fn extract_ip_target(input: &str) -> Option<String> {
        input
            .split(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '.' | ':' | '/'))
            })
            .find(|token| Self::looks_like_ip_or_cidr(token))
            .map(str::to_string)
    }

    fn extract_finding_id(input: &str) -> Option<String> {
        input
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
            })
            .find(|token| token.starts_with("finding_") && token.len() > "finding_".len())
            .map(str::to_string)
    }

    fn looks_like_ip_or_cidr(value: &str) -> bool {
        if let Some(cidr) = value.split_once('/') {
            return cidr.1.parse::<u8>().is_ok() && Self::looks_like_ip(cidr.0);
        }
        Self::looks_like_ip(value)
    }

    fn looks_like_ip(value: &str) -> bool {
        if value.contains(':') {
            return value
                .split(':')
                .all(|part| part.is_empty() || u16::from_str_radix(part, 16).is_ok());
        }
        let octets = value.split('.').collect::<Vec<_>>();
        octets.len() == 4
            && octets.iter().all(|octet| {
                octet.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
            })
    }

    fn extract_pcap_path(input: &str) -> Option<String> {
        input
            .split(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '.' | '_' | '-' | '\\' | ':'))
            })
            .find(|token| token.to_lowercase().ends_with(".pcap"))
            .filter(|token| token.len() > ".pcap".len())
            .map(str::to_string)
    }

    fn fallback_response(input: &str, activities: &[AgentToolActivity]) -> String {
        if activities.is_empty() {
            return format!(
                "NetAgent is running in deterministic local mode. Your request was recorded: {input}\n\nAsk about stored flows, findings, capture status, artifacts, or a local pcap file to run the typed tool loop."
            );
        }

        let chinese = input
            .chars()
            .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character));
        let heading = if chinese {
            "已完成只读工具调查（本地可复现模式）。"
        } else {
            "Completed a read-only investigation using the deterministic local planner."
        };
        let details = activities
            .iter()
            .map(|activity| {
                format!(
                    "- `{}`: {}",
                    activity.tool_call.tool_name, activity.result.summary
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let conclusion = if chinese {
            "\n\n结论：以上结论仅基于已存储的结构化证据；若记录为空，不能据此断言当前网络正常或异常。"
        } else {
            "\n\nConclusion: this answer is limited to stored structured evidence. Empty records do not prove that the live network is healthy or unhealthy."
        };
        format!("{heading}\n\n{details}{conclusion}")
    }

    fn contains_any(input: &str, needles: &[&str]) -> bool {
        needles.iter().any(|needle| input.contains(needle))
    }

    fn extract_artifact_id(input: &str) -> Option<String> {
        input
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
            })
            .find(|token| token.starts_with("artifact_") && token.len() > "artifact_".len())
            .map(str::to_string)
    }

    fn repeated_tool_call_exceeded(
        repeated_calls: &mut HashMap<String, u32>,
        tool_name: &str,
        input: &Value,
    ) -> bool {
        let fingerprint = format!("{tool_name}:{input}");
        let repetitions = repeated_calls.entry(fingerprint).or_default();
        *repetitions += 1;
        *repetitions > MAX_REPEATED_TOOL_CALLS
    }

    fn canonical_tool_name(provider_name: &str) -> String {
        match provider_name {
            "flow_list" => String::from("flow.list"),
            "finding_list" => String::from("finding.list"),
            "capture_status" => String::from("capture.status"),
            "capture_start" => String::from("capture.start"),
            "artifact_list" => String::from("artifact.list"),
            "artifact_summary" => String::from("artifact.summary"),
            "pcap_open" => String::from("pcap.open"),
            "tshark_extract_flows" => String::from("tshark.extract_flows"),
            "tshark_extract_dns" => String::from("tshark.extract_dns"),
            "dns_detect_anomalies" => String::from("dns.detect_anomalies"),
            "report_generate" => String::from("report.generate"),
            "ioc_export" => String::from("ioc.export"),
            "respond_propose_firewall_rule" => String::from("respond.propose_firewall_rule"),
            other => other.to_string(),
        }
    }

    fn provider_tool_name(tool_name: &str) -> String {
        tool_name.replace('.', "_")
    }

    fn build_provider_history(
        &self,
        config: &LlmConfig,
        messages: &[Message],
        context_summary: &str,
        goal_analysis: &GoalAnalysis,
    ) -> Vec<ChatMessage> {
        let mut provider_messages = vec![
            ChatMessage::text("system", config.system_prompt.clone()),
            ChatMessage::text(
                "system",
                format!("Current NetAgent structured context:\n{context_summary}"),
            ),
            ChatMessage::text(
                "system",
                format!(
                    "Execution brief (a concise plan, not hidden reasoning):\n{}",
                    serde_json::to_string(goal_analysis).unwrap_or_else(|_| String::from("{}"))
                ),
            ),
        ];

        for message in messages
            .iter()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if let Some(provider_message) = ChatMessage::from_persisted(message) {
                provider_messages.push(provider_message);
            }
        }
        provider_messages
    }

    fn complete_with_llm(
        config: &LlmConfig,
        messages: &[ChatMessage],
        tools: &[Value],
    ) -> Result<ModelAction, String> {
        let request = ChatCompletionRequest {
            model: config.model.clone(),
            messages: messages.to_vec(),
            tools: tools.to_vec(),
            tool_choice: String::from("auto"),
            parallel_tool_calls: false,
            temperature: 0.2,
            stream: false,
            thinking: Self::thinking_control(config),
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|error| format!("failed to create llm client: {error}"))?;
        let endpoint = format!("{}/chat/completions", config.api_base.trim_end_matches('/'));
        let response = client
            .post(endpoint)
            .bearer_auth(&config.api_key)
            .json(&request)
            .send()
            .map_err(|error| format!("llm request failed: {error}"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .unwrap_or_else(|_| String::from("<failed to read llm error body>"));
            return Err(format!(
                "llm request returned {status}: {}",
                Self::truncate_chars(&body, MAX_LLM_ERROR_BODY_CHARS)
            ));
        }
        let payload: ChatCompletionResponse = response
            .json()
            .map_err(|error| format!("failed to parse llm response: {error}"))?;
        let message = payload
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message)
            .ok_or_else(|| String::from("llm response did not contain a choice"))?;

        if !message.tool_calls.is_empty() {
            return Ok(ModelAction::ToolCalls(message.tool_calls));
        }
        message
            .content
            .map(|content| content.trim().to_string())
            .filter(|content| !content.is_empty())
            .map(ModelAction::Text)
            .ok_or_else(|| String::from("llm response contained neither content nor tool_calls"))
    }

    /// Stream an OpenAI-compatible `chat/completions` request over SSE.
    /// Content deltas are forwarded through `on_text_delta` as they arrive and
    /// tool-call fragments are aggregated by index. The `abort` flag is checked
    /// before every chunk so mid-turn cancellation works.
    fn complete_with_llm_streaming(
        config: &LlmConfig,
        messages: &[ChatMessage],
        tools: &[Value],
        abort: &AtomicBool,
        on_text_delta: &mut dyn FnMut(&str),
    ) -> Result<ModelAction, String> {
        let request = ChatCompletionRequest {
            model: config.model.clone(),
            messages: messages.to_vec(),
            tools: tools.to_vec(),
            tool_choice: String::from("auto"),
            parallel_tool_calls: false,
            temperature: 0.2,
            stream: true,
            thinking: Self::thinking_control(config),
        };
        if std::env::var("NETAGENT_DEBUG_PROVIDER").is_ok() {
            eprintln!(
                "DBG provider messages:\n{}",
                serde_json::to_string_pretty(&request.messages).unwrap_or_default()
            );
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|error| format!("failed to create llm client: {error}"))?;
        let endpoint = format!("{}/chat/completions", config.api_base.trim_end_matches('/'));
        let response = client
            .post(endpoint)
            .bearer_auth(&config.api_key)
            .json(&request)
            .send()
            .map_err(|error| {
                let mut chain = format!("llm request failed: {error}");
                let mut source = error.source();
                while let Some(cause) = source {
                    chain.push_str(&format!(": {cause}"));
                    source = cause.source();
                }
                chain
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .unwrap_or_else(|_| String::from("<failed to read llm error body>"));
            return Err(format!(
                "llm request returned {status}: {}",
                Self::truncate_chars(&body, MAX_LLM_ERROR_BODY_CHARS)
            ));
        }

        let mut content = String::new();
        let mut tool_calls: std::collections::BTreeMap<usize, (String, String, String)> =
            std::collections::BTreeMap::new();
        let reader = BufReader::new(response);
        for line in reader.lines() {
            if abort.load(Ordering::Relaxed) {
                return Err(String::from("agent turn aborted by the user"));
            }
            let line = line.map_err(|error| format!("failed to read llm stream: {error}"))?;
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            if let Some(message) = data.strip_prefix("{\"error\"") {
                return Err(format!("llm stream error: {}", Self::truncate_chars(message, MAX_LLM_ERROR_BODY_CHARS)));
            }
            let chunk: ChatStreamChunk = serde_json::from_str(data)
                .map_err(|error| format!("failed to parse llm stream chunk: {error}"))?;
            let Some(delta) = chunk
                .choices
                .into_iter()
                .next()
                .and_then(|choice| choice.delta)
            else {
                continue;
            };
            if let Some(delta_content) = delta.content {
                if !delta_content.is_empty() {
                    content.push_str(&delta_content);
                    on_text_delta(&delta_content);
                }
            }
            for tool_call in delta.tool_calls {
                let index = tool_call.index;
                let entry = tool_calls
                    .entry(index)
                    .or_insert_with(|| (String::new(), String::new(), String::new()));
                if let Some(id) = tool_call.id {
                    entry.0 = id;
                }
                if let Some(function) = tool_call.function {
                    if let Some(name) = function.name {
                        if !name.is_empty() {
                            entry.1.push_str(&name);
                        }
                    }
                    if let Some(arguments) = function.arguments {
                        entry.2.push_str(&arguments);
                    }
                }
            }
        }

        if !tool_calls.is_empty() {
            return Ok(ModelAction::ToolCalls(
                tool_calls
                    .into_values()
                    .map(|(id, name, arguments)| ChatToolCall {
                        id,
                        kind: String::from("function"),
                        function: ChatFunctionCall { name, arguments },
                    })
                    .collect(),
            ));
        }
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            return Err(String::from(
                "llm stream ended without content or tool_calls",
            ));
        }
        Ok(ModelAction::Text(trimmed))
    }

    /// Serialize the provider thinking control. Thinking is disabled unless
    /// `NETAGENT_LLM_THINKING=1`, which keeps persisted-history rebuilds
    /// (resume) compatible with DeepSeek's reasoning_content round-trip rule.
    fn thinking_control(config: &LlmConfig) -> Option<Value> {
        if config.thinking {
            None
        } else {
            Some(json!({ "type": "disabled" }))
        }
    }

    fn truncate_chars(value: &str, limit: usize) -> String {        let mut characters = value.chars();
        let truncated = characters.by_ref().take(limit).collect::<String>();
        if characters.next().is_some() {
            format!("{truncated}…")
        } else {
            truncated
        }
    }

    fn next_id(prefix: &str, counter: &mut u64) -> String {
        *counter += 1;
        format!("{prefix}_{counter:04}")
    }
}

fn part_waits_for_permission(part: &MessagePart) -> bool {
    let content: Value = serde_json::from_str(&part.content).unwrap_or_else(|_| json!({}));
    content
        .get("status")
        .and_then(Value::as_str)
        .map(|status| status == "waiting_permission")
        .unwrap_or(false)
}

impl LlmConfig {
    fn from_env() -> Option<Self> {
        let disabled = Self::config_value("NETAGENT_LLM_DISABLED")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
        if disabled {
            return None;
        }
        let api_key = Self::config_value("NETAGENT_LLM_API_KEY")
            .ok()
            .filter(|value| !value.is_empty())?;
        let model = Self::config_value("NETAGENT_LLM_MODEL")
            .ok()
            .filter(|value| !value.is_empty())?;
        let api_base = Self::config_value("NETAGENT_LLM_API_BASE")
            .unwrap_or_else(|_| String::from("https://api.openai.com/v1"));
        let system_prompt = Self::config_value("NETAGENT_LLM_SYSTEM_PROMPT")
            .unwrap_or_else(|_| String::from(DEFAULT_SYSTEM_PROMPT));
        let timeout_secs = Self::config_value("NETAGENT_LLM_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(5, 300);
        let stream = Self::config_value("NETAGENT_LLM_STREAM")
            .map(|value| {
                !matches!(
                    value.as_str(),
                    "0" | "false" | "no" | "off" | "disabled"
                )
            })
            .unwrap_or(true);
        let thinking = Self::config_value("NETAGENT_LLM_THINKING")
            .map(|value| {
                matches!(value.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);

        Some(Self {
            api_base,
            api_key,
            model,
            system_prompt,
            timeout_secs,
            stream,
            thinking,
        })
    }

    fn config_value(key: &str) -> Result<String, ()> {
        if let Ok(value) = std::env::var(key) {
            return Ok(value);
        }

        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for filename in [".env.local", ".env"] {
            let Ok(contents) = std::fs::read_to_string(workspace_root.join(filename)) else {
                continue;
            };
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let line = line.strip_prefix("export ").unwrap_or(line);
                let Some((name, raw_value)) = line.split_once('=') else {
                    continue;
                };
                if name.trim() == key {
                    return Ok(raw_value.trim().trim_matches(['\"', '\'']).to_string());
                }
            }
        }
        Err(())
    }
}

#[derive(Debug, Clone)]
enum ModelAction {
    Text(String),
    ToolCalls(Vec<ChatToolCall>),
}

#[derive(Debug, Clone, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    tools: Vec<Value>,
    tool_choice: String,
    parallel_tool_calls: bool,
    temperature: f32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    /// DeepSeek-style thinking control. Disabled by default so assistant
    /// messages (including tool-call rounds) never require passing back
    /// `reasoning_content` when history is rebuilt from persistence.
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ChatMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ChatToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

impl ChatMessage {
    fn text(role: &str, content: String) -> Self {
        Self {
            role: role.to_string(),
            content: Some(content),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    fn assistant_tool_calls(tool_calls: Vec<ChatToolCall>) -> Self {
        Self {
            role: String::from("assistant"),
            content: None,
            tool_calls: Some(tool_calls),
            tool_call_id: None,
        }
    }

    fn tool_result(provider_call_id: &str, result: &ToolResult) -> Self {
        Self {
            role: String::from("tool"),
            content: Some(serde_json::to_string(result).unwrap_or_else(|_| String::from("{}"))),
            tool_calls: None,
            tool_call_id: Some(provider_call_id.to_string()),
        }
    }

    fn from_persisted(message: &Message) -> Option<Self> {
        let text = message
            .parts
            .iter()
            .filter(|part| matches!(part.kind, MessagePartKind::Text))
            .map(|part| part.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if !text.trim().is_empty() {
            let role = match message.role {
                MessageRole::User => "user",
                MessageRole::Assistant => "assistant",
                MessageRole::Tool => "tool",
            };
            return Some(Self::text(role, text));
        }

        let part = message.parts.first()?;
        let content: Value = serde_json::from_str(&part.content).ok()?;
        match part.kind {
            MessagePartKind::ToolCall => {
                let provider_call_id = content.get("provider_call_id")?.as_str()?;
                let tool_name = content.get("tool_name")?.as_str()?;
                let arguments = content.get("input").cloned().unwrap_or_else(|| json!({}));
                Some(Self::assistant_tool_calls(vec![ChatToolCall {
                    id: provider_call_id.to_string(),
                    kind: String::from("function"),
                    function: ChatFunctionCall {
                        name: AgentRuntime::provider_tool_name(tool_name),
                        arguments: arguments.to_string(),
                    },
                }]))
            }
            MessagePartKind::ToolResult => Some(Self {
                role: String::from("tool"),
                content: Some(
                    content
                        .get("result")
                        .cloned()
                        .unwrap_or_else(|| json!({}))
                        .to_string(),
                ),
                tool_calls: None,
                tool_call_id: Some(content.get("provider_call_id")?.as_str()?.to_string()),
            }),
            MessagePartKind::Text | MessagePartKind::Reasoning => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: ChatFunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatFunctionCall {
    name: String,
    arguments: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatChoice {
    message: ChatAssistantMessage,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatStreamChunk {
    #[serde(default)]
    choices: Vec<ChatStreamChoice>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatStreamChoice {
    #[serde(default)]
    delta: Option<ChatStreamDelta>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ChatStreamDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ChatStreamToolCall>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatStreamToolCall {
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<ChatStreamFunction>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ChatStreamFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatAssistantMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ChatToolCall>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    fn read_http_body(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = stream.read(&mut buffer).expect("read request");
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                return String::from_utf8(
                    bytes[header_end + 4..header_end + 4 + content_length].to_vec(),
                )
                .expect("utf8 request body");
            }
        }
        panic!("request ended before the HTTP body was complete")
    }

    fn write_json_response(stream: &mut TcpStream, body: &Value) {
        let body = body.to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("write response");
        stream.flush().expect("flush response");
    }

    #[test]
    fn parses_openai_compatible_tool_call_response() {
        let payload: ChatCompletionResponse = serde_json::from_value(json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": "call_provider_1",
                        "type": "function",
                        "function": {
                            "name": "flow.list",
                            "arguments": "{\"limit\":5}"
                        }
                    }]
                }
            }]
        }))
        .expect("parse response");

        assert_eq!(
            payload.choices[0].message.tool_calls[0].function.name,
            "flow.list"
        );
    }

    #[test]
    fn openai_compatible_loop_returns_tool_result_for_final_answer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
        let address = listener.local_addr().expect("fake provider address");
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let responses = [
                json!({
                    "choices": [{
                        "message": {
                            "content": null,
                            "tool_calls": [{
                                "id": "provider_call_1",
                                "type": "function",
                                "function": {
                                    "name": "flow_list",
                                    "arguments": "{\"limit\":3}"
                                }
                            }]
                        }
                    }]
                }),
                json!({
                    "choices": [{
                        "message": {
                            "content": "There are no stored flows, so live network health is unknown."
                        }
                    }]
                }),
            ];

            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                request_sender
                    .send(read_http_body(&mut stream))
                    .expect("record request");
                write_json_response(&mut stream, &response);
            }
        });

        let mut runtime = AgentRuntime::disabled();
        runtime.llm = Some(LlmConfig {
            api_base: format!("http://{address}/v1"),
            api_key: String::from("test-key"),
            model: String::from("test-model"),
            system_prompt: String::from(DEFAULT_SYSTEM_PROMPT),
            timeout_secs: 5,
            stream: false,
            thinking: false,
        });
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "flow_list",
                "description": "List flows",
                "parameters": { "type": "object" }
            }
        })];
        let turn = runtime
            .run_turn_with_tools(
                AgentAskInput {
                    session_id: None,
                    mode: AgentMode::Observe,
                    input: String::from("List flows."),
                    context_summary: String::from("flows=0"),
                },
                &tools,
                |request| {
                    assert_eq!(request.tool_name, "flow.list");
                    assert_eq!(request.input, json!({ "limit": 3 }));
                    Ok(ToolOutcome::Completed(ToolResult {
                        title: String::from("Stored flows"),
                        summary: String::from("Found 0 stored flow records."),
                        structured: json!({ "total": 0, "flows": [] }),
                        artifacts: Vec::new(),
                        truncated: false,
                        raw_output_artifact: None,
                    }))
                },
            )
            .expect("complete tool loop");
        server.join().expect("fake provider server");

        assert!(turn.llm_used);
        assert_eq!(turn.tool_activities.len(), 1);
        assert_eq!(
            turn.assistant_message.parts[0].content,
            "There are no stored flows, so live network health is unknown."
        );
        let first_request: Value =
            serde_json::from_str(&request_receiver.recv().expect("first request")).unwrap();
        let second_request: Value =
            serde_json::from_str(&request_receiver.recv().expect("second request")).unwrap();
        assert_eq!(first_request["tools"][0]["function"]["name"], "flow_list");
        let returned_tool_message = second_request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "tool")
            .expect("tool result returned to provider");
        assert_eq!(returned_tool_message["tool_call_id"], "provider_call_1");
        assert!(
            returned_tool_message["content"]
                .as_str()
                .unwrap()
                .contains("Found 0 stored flow records")
        );
    }

    #[test]
    fn fallback_plan_only_exposes_phase12_allowlist_tools() {
        let calls = AgentRuntime::fallback_plan(
            "分析当前已有 flow、finding、抓包状态和 artifact_0001",
            "step_0001",
        );
        let names = calls
            .iter()
            .map(|call| call.function.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"flow.list"));
        assert!(names.contains(&"finding.list"));
        assert!(names.contains(&"capture.status"));
        assert!(names.contains(&"artifact.list"));
        assert!(names.contains(&"artifact.summary"));
        assert!(!names.contains(&"capture.start"));
    }

    #[test]
    fn fallback_plan_requests_capture_start_for_live_evidence_intent() {
        let calls = AgentRuntime::fallback_plan("请实时抓包分析当前网络", "step_0002");
        let names = calls
            .iter()
            .map(|call| call.function.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["capture.start"]);
        assert!(calls[0].function.arguments.contains("\"duration\":10"));
    }

    #[test]
    fn fallback_plan_uses_offline_pcap_plan_when_path_is_given() {
        let calls = AgentRuntime::fallback_plan(
            "请分析 /tmp/netagent-demo/dns.pcap 中的 DNS 异常",
            "step_0003",
        );
        let names = calls
            .iter()
            .map(|call| call.function.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["pcap.open", "dns.detect_anomalies", "report.generate", "ioc.export"]
        );
        assert!(calls[0].function.arguments.contains("/tmp/netagent-demo/dns.pcap"));
    }

    #[test]
    fn capture_start_tool_pauses_loop_with_waiting_permission_state() {
        let mut runtime = AgentRuntime::disabled();
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "capture_start",
                "description": "Request capture",
                "parameters": { "type": "object" }
            }
        })];
        let turn = runtime
            .run_turn_with_tools(
                AgentAskInput {
                    session_id: None,
                    mode: AgentMode::Observe,
                    input: String::from("请抓包分析当前网络"),
                    context_summary: String::from("flows=0"),
                },
                &tools,
                |_| {
                    Ok(ToolOutcome::PermissionPending {
                        request_id: String::from("per_0099"),
                        summary: String::from("Waiting for capture approval."),
                        plan: json!({
                            "interface": "mock1",
                            "filter": "tcp or dns",
                            "duration": 10,
                        }),
                    })
                },
            )
            .expect("pause for permission");

        assert_eq!(turn.final_run_state, RunState::WaitingPermission);
        assert_eq!(turn.step.status, StepStatus::WaitingPermission);
        let pending = turn.pending_permission.expect("pending permission");
        assert_eq!(pending.request_id, "per_0099");
        assert_eq!(pending.tool_call.tool_name, "capture.start");
        assert_eq!(pending.tool_call.status, ToolCallStatus::WaitingPermission);
        assert_eq!(turn.tool_activities.len(), 0);
    }

    #[test]
    fn rejected_capture_outcome_resumes_loop_with_offline_replanning() {
        let mut runtime = AgentRuntime::disabled();
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "pcap_open",
                "description": "Open pcap",
                "parameters": { "type": "object" }
            }
        })];
        let first = runtime
            .run_turn_with_tools(
                AgentAskInput {
                    session_id: None,
                    mode: AgentMode::Observe,
                    input: String::from("请抓包分析当前网络"),
                    context_summary: String::from("flows=0"),
                },
                &tools,
                |_| {
                    Ok(ToolOutcome::PermissionPending {
                        request_id: String::from("per_0001"),
                        summary: String::from("Waiting for capture approval."),
                        plan: json!({ "interface": "mock1", "filter": "tcp or dns", "duration": 10 }),
                    })
                },
            )
            .expect("pause for permission");
        let session_id = first.session_finished.id.clone();
        assert_eq!(first.final_run_state, RunState::WaitingPermission);

        let resumed = runtime
            .continue_turn_with_tools(
                AgentResumeInput {
                    session_id: session_id.clone(),
                    mode: AgentMode::Observe,
                    context_summary: String::from("flows=0"),
                    outcome: json!({
                        "status": "rejected",
                        "request_id": "per_0001",
                        "feedback": "不要实时抓包，请分析本地 pcap 文件 /tmp/demo/dns.pcap",
                        "capture": null,
                    }),
                    outcome_summary: String::from(
                        "Live capture rejected. User asked to analyze /tmp/demo/dns.pcap instead.",
                    ),
                },
                &tools,
                |request| {
                    assert_ne!(request.tool_name, "capture.start");
                    assert_eq!(request.session_id, session_id);
                    Ok(ToolOutcome::Completed(ToolResult {
                        title: format!("{} completed", request.tool_name),
                        summary: format!(
                            "{}: bounded summary for {}",
                            request.tool_name, request.call_id
                        ),
                        structured: json!({ "status": "ok", "tool": request.tool_name }),
                        artifacts: Vec::new(),
                        truncated: false,
                        raw_output_artifact: None,
                    }))
                },
            )
            .expect("resume with replanning");

        assert!(resumed.resumed);
        assert_eq!(resumed.final_run_state, RunState::Idle);
        assert_eq!(resumed.step.status, StepStatus::Completed);
        assert_eq!(resumed.step.attempt, 2);
        assert_eq!(resumed.tool_activities.len(), 5);
        assert_eq!(
            resumed.tool_activities[0].tool_call.tool_name,
            "capture.start"
        );
        assert_eq!(
            resumed.tool_activities[0].tool_call.status,
            ToolCallStatus::Aborted
        );
        let executed = resumed
            .tool_activities
            .iter()
            .skip(1)
            .map(|activity| activity.tool_call.tool_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            executed,
            vec![
                "pcap.open",
                "dns.detect_anomalies",
                "report.generate",
                "ioc.export"
            ]
        );
        assert!(resumed.assistant_message.parts[0].content.contains("离线"));
        assert!(
            resumed
                .assistant_message
                .parts[0]
                .content
                .contains("pcap.open")
        );

        let session = runtime.sessions.get(&session_id).expect("session stored");
        assert_eq!(session.session.run_state, RunState::Idle);
        assert_eq!(session.steps.last().expect("last step").status, StepStatus::Completed);
    }

    #[test]
    fn streaming_llm_forwards_deltas_and_aggregates_tool_call_fragments() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
        let address = listener.local_addr().expect("fake provider address");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            // Round 1: streamed tool-call fragments; round 2 (after the tool
            // result is fed back) streams the final text answer.
            for round in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept request");
                let _ = read_http_body(&mut stream);
                let chunks: &[&str] = if round == 0 {
                    &[
                        r#"data: {"choices":[{"delta":{"role":"assistant","content":"Hel"}}]}"#,
                        r#"data: {"choices":[{"delta":{"content":"lo from"}}]}"#,
                        r#"data: {"choices":[{"delta":{"content":" stream"}}]}"#,
                        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"tc_1","function":{"name":"flow_l","arguments":"{\"li"}}]}}]}"#,
                        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"ist","arguments":"mit\":3}"}}]}}]}"#,
                        "data: [DONE]",
                    ]
                } else {
                    &[
                        r#"data: {"choices":[{"delta":{"role":"assistant","content":"Final "}}]}"#,
                        r#"data: {"choices":[{"delta":{"content":"answer."}}]}"#,
                        "data: [DONE]",
                    ]
                };
                let body = chunks
                    .iter()
                    .map(|chunk| format!("{chunk}\n\n"))
                    .collect::<String>();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("write response");
                stream.flush().expect("flush chunks");
            }
            ready_tx.send(()).expect("signal ready");
            let _ = finish_rx.recv();
        });

        let mut runtime = AgentRuntime::disabled();
        runtime.llm = Some(LlmConfig {
            api_base: format!("http://{address}/v1"),
            api_key: String::from("test-key"),
            model: String::from("test-model"),
            system_prompt: String::from(DEFAULT_SYSTEM_PROMPT),
            timeout_secs: 5,
            stream: true,
            thinking: false,
        });
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "flow_list",
                "description": "List flows",
                "parameters": { "type": "object" }
            }
        })];
        let mut deltas = Vec::new();
        let abort = AtomicBool::new(false);
        let turn = runtime
            .run_turn_with_tools_streaming(
                AgentAskInput {
                    session_id: None,
                    mode: AgentMode::Observe,
                    input: String::from("Stream please."),
                    context_summary: String::from("flows=0"),
                },
                &tools,
                &abort,
                &mut |delta: &str| deltas.push(delta.to_string()),
                |request| {
                    assert_eq!(request.tool_name, "flow.list");
                    assert_eq!(request.input, json!({ "limit": 3 }));
                    Ok(ToolOutcome::Completed(ToolResult {
                        title: String::from("Stored flows"),
                        summary: String::from("Found 0 stored flow records."),
                        structured: json!({ "total": 0 }),
                        artifacts: Vec::new(),
                        truncated: false,
                        raw_output_artifact: None,
                    }))
                },
            )
            .expect("streaming loop");
        finish_tx.send(()).expect("finish server");
        server.join().expect("fake provider server");

        assert_eq!(&deltas[..3], &["Hel", "lo from", " stream"]);
        assert!(deltas.contains(&"Final ".to_string()));
        assert_eq!(
            turn.assistant_message.parts[0].content,
            "Final answer."
        );
        assert_eq!(turn.tool_activities.len(), 1);
        assert_eq!(
            turn.tool_activities[0].tool_call.input,
            json!({ "limit": 3 }).to_string()
        );
    }

    #[test]
    fn streaming_llm_stops_early_when_abort_is_requested() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
        let address = listener.local_addr().expect("fake provider address");
        let (start_tx, start_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let _ = read_http_body(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .expect("write headers");
            let event = "data: {\"choices\":[{\"delta\":{\"content\":\"first chunk\"}}]}\n\n";
            write!(stream, "{:x}\r\n{}\r\n", event.len(), event).expect("write first chunk");
            stream.flush().expect("flush first chunk");
            start_tx.send(()).expect("signal first chunk");
            // Keep the connection open: the client should abort before any
            // second chunk arrives.
            let _ = finish_rx.recv();
        });

        let mut runtime = AgentRuntime::disabled();
        runtime.llm = Some(LlmConfig {
            api_base: format!("http://{address}/v1"),
            api_key: String::from("test-key"),
            model: String::from("test-model"),
            system_prompt: String::from(DEFAULT_SYSTEM_PROMPT),
            timeout_secs: 5,
            stream: true,
            thinking: false,
        });
        let abort = std::sync::Arc::new(AtomicBool::new(false));
        let abort_handle = abort.clone();
        let set_abort = thread::spawn(move || {
            start_rx.recv().expect("first chunk received");
            abort_handle.store(true, Ordering::Relaxed);
        });
        let result = runtime.run_turn_with_tools_streaming(
            AgentAskInput {
                session_id: None,
                mode: AgentMode::Observe,
                input: String::from("This will be aborted."),
                context_summary: String::from("flows=0"),
            },
            &[],
            abort.as_ref(),
            &mut |_delta: &str| {},
            |_request| unreachable!("no tool should execute"),
        );
        set_abort.join().expect("abort thread");
        finish_tx.send(()).expect("finish server");
        server.join().expect("fake provider server");

        let turn = result.expect("aborted turns settle as normal results");
        assert_eq!(turn.step.status, StepStatus::Aborted);
        assert_eq!(turn.final_run_state, RunState::Idle);
        assert_eq!(turn.stop_reason.as_deref(), Some("Agent turn aborted by the user."));
        assert!(
            turn.assistant_message.parts[0]
                .content
                .contains("aborted")
        );
    }

    #[test]
    fn repeated_tool_call_guard_stops_the_third_identical_call() {        let mut calls = HashMap::new();
        let input = json!({ "limit": 5 });
        assert!(!AgentRuntime::repeated_tool_call_exceeded(
            &mut calls,
            "flow.list",
            &input
        ));
        assert!(!AgentRuntime::repeated_tool_call_exceeded(
            &mut calls,
            "flow.list",
            &input
        ));
        assert!(AgentRuntime::repeated_tool_call_exceeded(
            &mut calls,
            "flow.list",
            &input
        ));
    }
}
