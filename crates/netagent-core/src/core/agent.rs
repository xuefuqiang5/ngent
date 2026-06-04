use std::collections::HashMap;
use std::time::Duration;

use netagent_models::{
    AgentMode, Message, MessagePart, MessagePartKind, MessageRole, RunState, Session, Step,
    StepStatus,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_MAX_STEPS: u32 = 8;
const DEFAULT_SYSTEM_PROMPT: &str = "You are NetAgent, a network investigation assistant. \
Answer concisely, stay grounded in the provided context, and do not invent packet evidence. \
If evidence is missing, say what is known and what is uncertain.";

#[derive(Debug, Clone)]
pub struct AgentTurn {
    pub session_created: bool,
    pub session_started: Session,
    pub session_finished: Session,
    pub user_message: Message,
    pub assistant_message: Message,
    pub step: Step,
    pub final_run_state: RunState,
    pub llm_used: bool,
    pub llm_model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AgentAskInput {
    pub session_id: Option<String>,
    pub mode: AgentMode,
    pub input: String,
    pub context_summary: String,
    pub capture_recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LlmStatus {
    pub enabled: bool,
    pub provider: String,
    pub model: Option<String>,
    pub api_base: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionRecord {
    session: Session,
    messages: Vec<Message>,
}

#[derive(Debug, Clone)]
struct LlmConfig {
    api_base: String,
    api_key: String,
    model: String,
    system_prompt: String,
    timeout_secs: u64,
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
                provider: String::from("mock_fallback"),
                model: None,
                api_base: None,
            },
        }
    }

    pub fn run_turn(&mut self, input: AgentAskInput) -> Result<AgentTurn, String> {
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
            .remove(&session_id)
            .unwrap_or_else(|| SessionRecord {
                session: Session {
                    id: session_id.clone(),
                    mode: input.mode,
                    run_state: RunState::Idle,
                    max_steps: DEFAULT_MAX_STEPS,
                },
                messages: Vec::new(),
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

        let step = Step {
            id: Self::next_id("step", &mut self.step_counter),
            session_id: session_id.clone(),
            status: StepStatus::Completed,
            attempt: 1,
        };

        let assistant_text = match &self.llm {
            Some(config) => self.complete_with_llm(
                config,
                &record.messages,
                &input.context_summary,
                input.capture_recommendation.as_deref(),
            )?,
            None => self.mock_response(
                &input.input,
                &input.context_summary,
                input.capture_recommendation.as_deref(),
            ),
        };

        let assistant_message = self.build_message(
            &session_id,
            MessageRole::Assistant,
            MessagePartKind::Text,
            assistant_text,
        );
        record.messages.push(assistant_message.clone());
        record.session.run_state = RunState::Idle;
        let session_finished = record.session.clone();
        self.sessions.insert(session_id, record);

        Ok(AgentTurn {
            session_created,
            session_started,
            session_finished,
            user_message,
            assistant_message,
            step,
            final_run_state: RunState::Idle,
            llm_used: self.llm.is_some(),
            llm_model: self.llm.as_ref().map(|config| config.model.clone()),
        })
    }

    pub fn build_agent_response(turn: &AgentTurn) -> Value {
        json!({
            "phase": "phase9",
            "session_created": turn.session_created,
            "session": turn.session_finished,
            "step": turn.step,
            "assistant_message": turn.assistant_message,
            "run_state": turn.final_run_state,
            "llm": {
                "used": turn.llm_used,
                "model": turn.llm_model,
            },
        })
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

    fn mock_response(
        &self,
        input: &str,
        context_summary: &str,
        capture_recommendation: Option<&str>,
    ) -> String {
        let mut response = format!(
            "LLM API is not configured yet, so this is a local fallback response.\n\nUser request: {input}\n\nCurrent NetAgent context:\n{context_summary}"
        );
        if let Some(recommendation) = capture_recommendation {
            response.push_str("\n\n");
            response.push_str(recommendation);
        }
        response
    }

    fn complete_with_llm(
        &self,
        config: &LlmConfig,
        messages: &[Message],
        context_summary: &str,
        capture_recommendation: Option<&str>,
    ) -> Result<String, String> {
        let mut provider_messages = Vec::new();
        provider_messages.push(ChatMessage {
            role: String::from("system"),
            content: config.system_prompt.clone(),
        });
        provider_messages.push(ChatMessage {
            role: String::from("system"),
            content: format!("Current NetAgent structured context:\n{context_summary}"),
        });
        if let Some(recommendation) = capture_recommendation {
            provider_messages.push(ChatMessage {
                role: String::from("system"),
                content: format!(
                    "Before answering, explain this proposed next step clearly and note that user approval is required before anything runs:\n{recommendation}"
                ),
            });
        }

        for message in messages
            .iter()
            .rev()
            .take(12)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            let role = match message.role {
                MessageRole::User => "user",
                MessageRole::Assistant => "assistant",
                MessageRole::Tool => continue,
            };
            let text = message
                .parts
                .iter()
                .filter(|part| matches!(part.kind, MessagePartKind::Text))
                .map(|part| part.content.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if text.trim().is_empty() {
                continue;
            }
            provider_messages.push(ChatMessage {
                role: role.to_string(),
                content: text,
            });
        }

        let request = ChatCompletionRequest {
            model: config.model.clone(),
            messages: provider_messages,
            temperature: 0.2,
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
            return Err(format!("llm request returned {status}: {body}"));
        }
        let payload: ChatCompletionResponse = response
            .json()
            .map_err(|error| format!("failed to parse llm response: {error}"))?;

        payload
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content.trim().to_string())
            .filter(|content| !content.is_empty())
            .ok_or_else(|| String::from("llm response did not contain assistant content"))
    }

    fn next_id(prefix: &str, counter: &mut u64) -> String {
        *counter += 1;
        format!("{prefix}_{counter:04}")
    }
}

impl LlmConfig {
    fn from_env() -> Option<Self> {
        let api_key = std::env::var("NETAGENT_LLM_API_KEY").ok()?;
        let model = std::env::var("NETAGENT_LLM_MODEL").ok()?;
        let api_base = std::env::var("NETAGENT_LLM_API_BASE")
            .unwrap_or_else(|_| String::from("https://api.openai.com/v1"));
        let system_prompt = std::env::var("NETAGENT_LLM_SYSTEM_PROMPT")
            .unwrap_or_else(|_| String::from(DEFAULT_SYSTEM_PROMPT));
        let timeout_secs = std::env::var("NETAGENT_LLM_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(5, 300);

        Some(Self {
            api_base,
            api_key,
            model,
            system_prompt,
            timeout_secs,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Debug, Clone, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
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
struct ChatAssistantMessage {
    content: String,
}
