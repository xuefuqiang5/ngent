#![allow(dead_code)]

mod analyzers;
mod api;
mod core;
mod reports;
mod runtime;
mod storage;
mod tools;

use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::analyzers::rules::{RuleManifest, load_rule_manifests, run_all_rules};
use crate::core::agent::{
    AgentAskInput, AgentPendingPermission, AgentResumeInput, AgentRuntime, AgentToolActivity,
    AgentToolExecutionRequest, AgentTurn, SessionRecord, ToolOutcome,
};
use crate::core::permissions::{PermissionManager, PermissionOutcome};
use crate::reports::markdown::{
    EvidenceBundleMetadata, build_evidence_bundle_metadata, build_markdown_report,
    collect_report_input,
};
use crate::runtime::tool_registry::{
    FirewallRuleProposal, ToolContext, ToolPermissionContext, ToolRegistry,
};
use crate::storage::artifact_store::ArtifactStore;
use crate::storage::sqlite::SqliteStore;
use crate::tools::tshark;
use netagent_models::{
    AgentMode, PermissionDecision, PermissionKind, PermissionMetadata, PermissionReply,
    PermissionReplyKind, PermissionRequest, RiskLevel, RunState, StepStatus, ToolCallStatus,
    ToolRef,
};
use netagent_models::{ArtifactKind, ArtifactRef, DnsEvent, Finding, Flow, ToolCall};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const JSON_RPC_VERSION: &str = "2.0";

#[derive(Debug, Serialize)]
struct RpcNotification<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug)]
struct CoreState {
    agent_runtime: AgentRuntime,
    permission_manager: PermissionManager,
    tool_registry: ToolRegistry,
    artifact_store: ArtifactStore,
    sqlite_store: SqliteStore,
    rule_manifests: Vec<RuleManifest>,
    capture_job: Option<CaptureJob>,
    pending_capture: Option<PendingCapture>,
    pending_respond: Option<PendingRespond>,
    agent_abort: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Abort signals forwarded by the stdin reader thread while a streaming
    /// agent turn is running. Polled inside the streaming delta callback.
    agent_abort_rx: Option<std::sync::mpsc::Receiver<()>>,
    permission_counter: u64,
    capture_counter: u64,
    tool_counter: u64,
    finding_counter: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingCapture {
    request_id: String,
    session_id: String,
    tool_call_id: String,
    interface: String,
    filter: String,
    duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRespond {
    request_id: String,
    session_id: String,
    tool_call_id: String,
    proposal: FirewallRuleProposal,
}

#[derive(Debug)]
struct CaptureJob {
    id: String,
    session_id: String,
    tool_call_id: String,
    request_id: String,
    interface: String,
    filter: String,
    duration_secs: u64,
    started_at: Instant,
    pcap_path: String,
    child: Child,
}

#[derive(Debug, Clone, Copy)]
struct CapturePermissionInput<'a> {
    session_id: &'a str,
    interface: &'a str,
    filter: &'a str,
    duration_secs: u64,
    reason: &'a str,
    message_id: &'a str,
    step_id: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct CaptureStartInput<'a> {
    session_id: &'a str,
    interface: &'a str,
    filter: &'a str,
    duration_secs: u64,
    approval_status: &'a str,
    tool_call_id: &'a str,
    request_id: &'a str,
}

#[derive(Debug, Serialize)]
struct IocExportDocument {
    generated_at: String,
    evidence_bundle: EvidenceBundleMetadata,
    findings: Vec<Finding>,
    flows: Vec<Flow>,
    dns_events: Vec<DnsEvent>,
    artifacts: Vec<ArtifactRef>,
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "netagent-core fatal error: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let db_path = resolve_database_path()?;
    let sqlite_store = SqliteStore::open(&db_path).map_err(io::Error::other)?;

    let mut state = CoreState {
        agent_runtime: AgentRuntime::from_env(),
        permission_manager: PermissionManager::default(),
        tool_registry: ToolRegistry,
        artifact_store: ArtifactStore::default(),
        sqlite_store,
        rule_manifests: Vec::new(),
        capture_job: None,
        pending_capture: None,
        pending_respond: None,
        agent_abort: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        agent_abort_rx: None,
        permission_counter: 0,
        capture_counter: 0,
        tool_counter: 0,
        finding_counter: 0,
    };
    match load_rule_manifests() {
        Ok(manifests) => state.rule_manifests = manifests,
        Err(error) => {
            return Err(io::Error::other(format!(
                "failed to load analyzer rule manifests: {error}"
            )));
        }
    }

    if let Err(error) = restore_core_counters(&mut state) {
        return Err(io::Error::other(error));
    }

    match state.sqlite_store.reconcile_interrupted_runtime() {
        Ok(summary) => {
            if summary.aborted_steps > 0
                || summary.aborted_tool_calls > 0
                || summary.errored_sessions > 0
                || summary.waiting_permission_sessions > 0
            {
                let _ = writeln!(
                    io::stderr(),
                    "netagent-core: reconciled interrupted state: {summary:?}"
                );
            }
        }
        Err(error) => {
            return Err(io::Error::other(error));
        }
    }

    // Restore persisted sessions and pending permission continuations so the UI can reconnect.
    match restore_agent_sessions(&mut state) {
        Ok(count) => {
            if count > 0 {
                let _ = writeln!(
                    io::stderr(),
                    "netagent-core: restored {count} session(s) from database"
                );
            }
        }
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "netagent-core: failed to restore sessions: {error}"
            );
        }
    }
    if let Err(error) = restore_permission_rules(&mut state) {
        return Err(io::Error::other(error));
    }
    match restore_pending_permissions(&mut state) {
        Ok(count) => {
            if count > 0 {
                let _ = writeln!(
                    io::stderr(),
                    "netagent-core: restored {count} pending permission request(s)"
                );
            }
        }
        Err(error) => {
            return Err(io::Error::other(error));
        }
    }

    // Shared stdout so the stdin reader thread can answer `agent.abort` while
    // the main thread is inside a streaming agent turn.
    let stdout = std::sync::Arc::new(std::sync::Mutex::new(io::stdout()));
    let mut writer = SharedStdout(stdout.clone());
    let (req_tx, req_rx) = std::sync::mpsc::channel::<String>();
    let (abort_tx, abort_rx) = std::sync::mpsc::channel::<()>();
    state.agent_abort_rx = Some(abort_rx);

    let stdin_stdout = stdout.clone();
    let stdin_thread = std::thread::spawn(move || {
        for line_result in io::stdin().lock().lines() {
            let Ok(line) = line_result else {
                break;
            };
            if line.trim().is_empty() {
                continue;
            }
            if line.contains("\"agent.abort\"") {
                // Answer abort requests immediately so a running streaming turn
                // can be interrupted; the turn loop notices via abort_rx.
                let id = serde_json::from_str::<RpcRequest>(&line)
                    .map(|request| request.id)
                    .unwrap_or(Value::Null);
                let mut out = stdin_stdout.lock().unwrap_or_else(|poison| poison.into_inner());
                let _ = serde_json::to_writer(
                    &mut *out,
                    &RpcResponse {
                        jsonrpc: JSON_RPC_VERSION,
                        id,
                        result: Some(json!({
                            "aborted": true,
                            "run_state": RunState::Canceling,
                            "message": "Abort accepted; the running agent turn will stop at the next streaming checkpoint."
                        })),
                        error: None,
                    },
                );
                let _ = writeln!(out);
                let _ = out.flush();
                let _ = abort_tx.send(());
                continue;
            }
            if req_tx.send(line).is_err() {
                break;
            }
        }
    });

    write_message(
        &mut writer,
        &RpcNotification {
            jsonrpc: JSON_RPC_VERSION,
            method: "event.core.ready",
            params: json!({
                "phase": "phase15",
                "protocol_version": JSON_RPC_VERSION,
                "message": "NetAgent core ready - Phase 15 streaming LLM with mid-turn cancel."
            }),
        },
    )?;

    for line in req_rx {
        let response = match serde_json::from_str::<RpcRequest>(&line) {
            Ok(request) => {
                reconcile_capture_state(&mut state, &mut writer)?;
                handle_request(request, &mut state, &mut writer)?
            }
            Err(error) => RpcResponse {
                jsonrpc: JSON_RPC_VERSION,
                id: Value::Null,
                result: None,
                error: Some(RpcError {
                    code: -32700,
                    message: format!("Parse error: {error}"),
                }),
            },
        };

        write_message(&mut writer, &response)?;
        // Drain any abort signals that arrived while handling the request so
        // the next agent turn starts with a clean flag.
        if let Some(abort_rx) = state.agent_abort_rx.as_ref() {
            while abort_rx.try_recv().is_ok() {}
        }
    }

    let _ = stdin_thread.join();
    Ok(())
}

/// A `Write` adapter over a shared stdout so the stdin reader thread and the
/// main thread can interleave responses without long-held locks.
#[derive(Clone)]
struct SharedStdout(std::sync::Arc<std::sync::Mutex<io::Stdout>>);

impl Write for SharedStdout {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut stdout = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        stdout.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stdout = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        stdout.flush()
    }
}

fn resolve_database_path() -> io::Result<PathBuf> {
    if let Ok(configured) = std::env::var("NETAGENT_DB_PATH") {
        let path = PathBuf::from(configured);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        return Ok(path);
    }

    let mut path = std::env::temp_dir();
    path.push("netagent-captures");
    std::fs::create_dir_all(&path)?;
    path.push("netagent.db");
    Ok(path)
}

fn handle_request<W: Write>(
    request: RpcRequest,
    state: &mut CoreState,
    writer: &mut W,
) -> io::Result<RpcResponse> {
    if request.jsonrpc != JSON_RPC_VERSION {
        return Ok(RpcResponse {
            jsonrpc: JSON_RPC_VERSION,
            id: request.id,
            result: None,
            error: Some(RpcError {
                code: -32600,
                message: String::from("Unsupported JSON-RPC version."),
            }),
        });
    }

    let result = match request.method.as_str() {
        "system.ping" => Ok(json!({
            "ok": true,
            "phase": "phase15",
            "message": "pong"
        })),
        "core.capabilities" => Ok(json!({
            "protocol_version": JSON_RPC_VERSION,
            "phase": "phase15",
            "methods": [
                "system.ping",
                "core.capabilities",
                "system.list_interfaces",
                "agent.ask",
                "agent.resume",
                "agent.abort",
                "session.list",
                "session.get",
                "message.list",
                "capture.start",
                "capture.status",
                "capture.stop",
                "permission.list_pending",
                "permission.reply",
                "tool.mock_large_output",
                "pcap.open",
                "pcap.summarize",
                "tshark.extract_flows",
                "tshark.extract_dns",
                "dns.detect_anomalies",
                "flow.list",
                "finding.list",
                "report.generate",
                "ioc.export"
            ],
            "events": [
                "event.core.ready",
                "session.created",
                "message.created",
                "message.part.created",
                "message.part.updated",
                "agent.step.started",
                "agent.reasoning.started",
                "agent.reasoning.delta",
                "agent.reasoning.ended",
                "agent.text.started",
                "agent.text.delta",
                "agent.text.ended",
                "agent.tool.called",
                "agent.tool.progress",
                "agent.tool.success",
                "agent.tool.failed",
                "agent.step.ended",
                "permission.asked",
                "permission.replied",
                "artifact.created",
                "finding.created",
                "capture.started",
                "capture.stopped",
                "pcap.created",
                "report.generated",
                "respond.proposal.created"
            ],
            "llm": state.agent_runtime.llm_status(),
            "agent_tools": state.tool_registry.agent_defs(),
            "rules": state.rule_manifests.clone(),
            "persistence": {
                "enabled": true,
                "backend": "sqlite",
                "session_snapshot": true,
                "pending_permission_restore": true,
                "agent_resume": true
            },
            "limits": {
                "high_frequency_packet_events": false,
                "max_steps": 8,
                "max_capture_duration_secs": 10
            }
        })),
        "system.list_interfaces" => Ok(json!({
            "interfaces": [
                {
                    "name": "mock0",
                    "label": "Mock Loopback",
                    "kind": "loopback",
                    "addresses": ["127.0.0.1"]
                },
                {
                    "name": "mock1",
                    "label": "Mock External",
                    "kind": "ethernet",
                    "addresses": ["10.0.0.10"]
                }
            ]
        })),
        "agent.ask" => {
            let input = request
                .params
                .get("input")
                .and_then(Value::as_str)
                .unwrap_or("Describe current network state.")
                .to_string();
            let session_id = request
                .params
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let context_summary = build_agent_context_summary(state);
            let capture_status = capture_status_snapshot(state);
            let tool_schemas = state.tool_registry.openai_tool_schemas();

            let (turn, streamed_text) = match run_agent_ask_turn(
                state,
                AgentAskInput {
                    session_id,
                    mode: AgentMode::Observe,
                    input,
                    context_summary,
                },
                &tool_schemas,
                &capture_status,
                writer,
            ) {
                Ok(turn) => turn,
                Err(message) => {
                    return Ok(error_response(
                        request.id,
                        RpcError {
                            code: -32010,
                            message,
                        },
                    ))
                }
            };

            if let Err(error) = persist_agent_turn(&state.sqlite_store, &turn) {
                return Ok(error_response(
                    request.id,
                    RpcError {
                        code: -32011,
                        message: format!("failed to persist agent turn: {error}"),
                    },
                ));
            }

            emit_agent_turn_events(writer, &turn, streamed_text)?;
            let mut result = AgentRuntime::build_agent_response(&turn);
            if let Some(pending) = &turn.pending_permission {
                match finalize_agent_pending_permission(state, writer, &turn.session_finished.id, pending) {
                    Ok(proposal) => {
                        result["session"]["run_state"] = json!(RunState::WaitingPermission);
                        result["run_state"] = json!(RunState::WaitingPermission);
                        result["capture_proposal"] = proposal;
                    }
                    Err(error) => return Ok(error_response(request.id, error)),
                }
            }
            Ok(result)
        }
        "agent.resume" => {
            let session_id = match required_string_param(&request.params, "session_id") {
                Ok(id) => id,
                Err(error) => return Ok(error_response(request.id, error)),
            };
            if let Some(job) = &state.capture_job {
                if job.session_id == session_id {
                    return Ok(RpcResponse {
                        jsonrpc: JSON_RPC_VERSION,
                        id: request.id,
                        result: Some(json!({
                            "status": "capture_running",
                            "session_id": session_id,
                            "message": "The approved capture is still running; resume once the pcap artifact is ready."
                        })),
                        error: None,
                    });
                }
            }
            let payload = match state.sqlite_store.load_agent_resume(session_id) {
                Ok(Some(payload)) => payload,
                Ok(None) => {
                    return Ok(error_response(
                        request.id,
                        RpcError {
                            code: -32013,
                            message: format!(
                                "no pending agent continuation for session {session_id}"
                            ),
                        },
                    ))
                }
                Err(message) => {
                    return Ok(error_response(
                        request.id,
                        RpcError {
                            code: -32011,
                            message,
                        },
                    ))
                }
            };

            let outcome_summary = build_resume_outcome_summary(&payload);
            let capture_status = capture_status_snapshot(state);
            let tool_schemas = state.tool_registry.openai_tool_schemas();
            let (turn, streamed_text) = match run_agent_resume_turn(
                state,
                AgentResumeInput {
                    session_id: session_id.to_string(),
                    mode: AgentMode::Observe,
                    context_summary: build_agent_context_summary(state),
                    outcome: payload,
                    outcome_summary,
                },
                &tool_schemas,
                &capture_status,
                writer,
            ) {
                Ok(turn) => turn,
                Err(message) => {
                    let _ = state.sqlite_store.delete_agent_resume(session_id);
                    return Ok(error_response(
                        request.id,
                        RpcError {
                            code: -32010,
                            message: format!("failed to resume agent turn: {message}"),
                        },
                    ));
                }
            };

            let _ = state.sqlite_store.delete_agent_resume(session_id);

            if let Err(error) = persist_agent_turn(&state.sqlite_store, &turn) {
                return Ok(error_response(
                    request.id,
                    RpcError {
                        code: -32011,
                        message: format!("failed to persist resumed agent turn: {error}"),
                    },
                ));
            }

            if let Err(error) = emit_resumed_turn_events(writer, &turn, streamed_text) {
                return Ok(error_response(
                    request.id,
                    RpcError {
                        code: -32001,
                        message: format!("failed to emit resumed turn events: {error}"),
                    },
                ));
            }
            let mut result = AgentRuntime::build_agent_response(&turn);
            if let Some(pending) = &turn.pending_permission {
                match finalize_agent_pending_permission(state, writer, session_id, pending) {
                    Ok(proposal) => {
                        result["session"]["run_state"] = json!(RunState::WaitingPermission);
                        result["run_state"] = json!(RunState::WaitingPermission);
                        result["capture_proposal"] = proposal;
                    }
                    Err(error) => return Ok(error_response(request.id, error)),
                }
            }
            Ok(result)
        }
        "agent.abort" => {
            state.agent_abort.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(json!({
                "aborted": true,
                "run_state": RunState::Canceling,
                "message": "Abort requested; the running agent turn will stop at the next streaming checkpoint."
            }))
        }
        "session.list" => handle_session_list(state),
        "session.get" => handle_session_get(state, &request.params),
        "message.list" => handle_message_list(state, &request.params),
        "capture.start" => handle_capture_start(state, writer, &request.params),
        "capture.status" => handle_capture_status(state),
        "capture.stop" => handle_capture_stop(state, writer),
        "permission.list_pending" => Ok(json!({
            "pending": state.permission_manager.list_pending()
        })),
        "permission.reply" => handle_permission_reply(state, writer, &request.params),
        "tool.mock_large_output" => handle_tool_mock_large_output(state, writer, &request.params),
        "pcap.open" => handle_pcap_open(state, writer, &request.params),
        "pcap.summarize" => handle_pcap_summarize(state, &request.params),
        "tshark.extract_flows" => handle_tshark_extract_flows(state, writer, &request.params),
        "tshark.extract_dns" => handle_tshark_extract_dns(state, writer, &request.params),
        "dns.detect_anomalies" => handle_dns_detect_anomalies(state, writer, &request.params),
        "flow.list" => handle_flow_list(state),
        "finding.list" => handle_finding_list(state),
        "report.generate" => handle_report_generate(state, writer, &request.params),
        "ioc.export" => handle_ioc_export(state, writer, &request.params),
        _ => Err(RpcError {
            code: -32601,
            message: format!("Method not found: {}", request.method),
        }),
    };

    Ok(match result {
        Ok(result) => RpcResponse {
            jsonrpc: JSON_RPC_VERSION,
            id: request.id,
            result: Some(result),
            error: None,
        },
        Err(error) => RpcResponse {
            jsonrpc: JSON_RPC_VERSION,
            id: request.id,
            result: None,
            error: Some(error),
        },
    })
}

fn error_response(id: Value, error: RpcError) -> RpcResponse {
    RpcResponse {
        jsonrpc: JSON_RPC_VERSION,
        id,
        result: None,
        error: Some(error),
    }
}

fn required_string_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: format!("{key} is required"),
        })
}

fn emit_agent_turn_events<W: Write>(
    writer: &mut W,
    turn: &AgentTurn,
    streamed_text: bool,
) -> io::Result<()> {
    if turn.session_created {
        emit_event(
            writer,
            "session.created",
            json!({ "session": turn.session_started }),
        )?;
    }
    emit_event(
        writer,
        "message.created",
        json!({ "message": turn.user_message }),
    )?;
    emit_event(
        writer,
        "agent.step.started",
        json!({
            "step": {
                "id": turn.step.id,
                "session_id": turn.step.session_id,
                "attempt": turn.step.attempt,
                "status": StepStatus::Running,
            }
        }),
    )?;
    emit_event(
        writer,
        "message.created",
        json!({ "message": turn.plan_message }),
    )?;
    emit_event(
        writer,
        "agent.reasoning.started",
        json!({
            "session_id": turn.session_started.id,
            "message_id": turn.plan_message.id,
            "part_id": turn.plan_message.parts[0].id,
            "run_state": RunState::Analyzing,
        }),
    )?;
    emit_event(
        writer,
        "agent.reasoning.delta",
        json!({
            "session_id": turn.session_started.id,
            "message_id": turn.plan_message.id,
            "part_id": turn.plan_message.parts[0].id,
            "summary": turn.goal_analysis,
            "run_state": RunState::Analyzing,
        }),
    )?;
    emit_event(
        writer,
        "agent.reasoning.ended",
        json!({
            "session_id": turn.session_started.id,
            "message_id": turn.plan_message.id,
            "part_id": turn.plan_message.parts[0].id,
            "goal_analysis": turn.goal_analysis,
            "run_state": RunState::Analyzing,
        }),
    )?;

    for activity in &turn.tool_activities {
        emit_activity_call_events(writer, turn, activity)?;
        emit_tool_domain_events(writer, activity)?;
    }

    if let Some(pending) = &turn.pending_permission {
        emit_event(
            writer,
            "message.created",
            json!({ "message": pending.call_message }),
        )?;
        emit_event(
            writer,
            "message.part.created",
            json!({
                "session_id": turn.session_started.id,
                "message_id": pending.call_message.id,
                "part": pending.call_part,
                "run_state": RunState::WaitingPermission,
            }),
        )?;
        emit_event(
            writer,
            "agent.tool.called",
            json!({
                "tool_call": pending.tool_call,
                "message_id": pending.call_message.id,
                "part_id": pending.call_part.id,
                "run_state": RunState::WaitingPermission,
            }),
        )?;
    } else if streamed_text {
        emit_event(
            writer,
            "message.created",
            json!({ "message": turn.assistant_message }),
        )?;
    } else {
        emit_event(
            writer,
            "message.created",
            json!({ "message": turn.assistant_message }),
        )?;
        emit_event(
            writer,
            "agent.text.started",
            json!({
                "session_id": turn.session_started.id,
                "message_id": turn.assistant_message.id,
                "part_id": turn.assistant_message.parts[0].id,
            }),
        )?;
        emit_event(
            writer,
            "agent.text.delta",
            json!({
                "session_id": turn.session_started.id,
                "message_id": turn.assistant_message.id,
                "part_id": turn.assistant_message.parts[0].id,
                "delta": turn.assistant_message.parts[0].content,
            }),
        )?;
        emit_event(
            writer,
            "agent.text.ended",
            json!({
                "session_id": turn.session_started.id,
                "message_id": turn.assistant_message.id,
                "part_id": turn.assistant_message.parts[0].id,
            }),
        )?;
    }
    emit_event(
        writer,
        "agent.step.ended",
        json!({
            "step": turn.step,
            "run_state": turn.final_run_state,
            "phase": "phase15",
            "llm": {
                "used": turn.llm_used,
                "model": turn.llm_model,
            }
        }),
    )
}

/// Emit the full lifecycle events for one completed tool activity.
fn emit_activity_call_events<W: Write>(
    writer: &mut W,
    turn: &AgentTurn,
    activity: &AgentToolActivity,
) -> io::Result<()> {
    let mut pending_call = activity.tool_call.clone();
    pending_call.status = ToolCallStatus::Pending;
    emit_event(
        writer,
        "message.created",
        json!({ "message": activity.call_message }),
    )?;
    emit_event(
        writer,
        "message.part.created",
        json!({
            "session_id": turn.session_started.id,
            "message_id": activity.call_message.id,
            "part": activity.call_message.parts[0],
            "run_state": RunState::RunningTool,
        }),
    )?;
    emit_event(
        writer,
        "agent.tool.called",
        json!({
            "tool_call": pending_call,
            "message_id": activity.call_message.id,
            "part_id": activity.call_message.parts[0].id,
            "run_state": RunState::RunningTool,
        }),
    )?;
    emit_event(
        writer,
        "agent.tool.progress",
        json!({
            "tool_call_id": activity.tool_call.id,
            "status": "running",
            "message": "Validated typed input and executed through Tool Runtime.",
            "run_state": RunState::RunningTool,
        }),
    )?;

    let (method, run_state) = if activity.tool_call.status == ToolCallStatus::Completed {
        ("agent.tool.success", RunState::Analyzing)
    } else {
        ("agent.tool.failed", RunState::Analyzing)
    };
    emit_event(
        writer,
        method,
        json!({
            "tool_call": activity.tool_call,
            "summary": activity.result.summary,
            "structured": activity.result.structured,
            "artifacts": activity.result.artifacts,
            "truncated": activity.result.truncated,
            "run_state": run_state,
        }),
    )?;
    emit_event(
        writer,
        "message.created",
        json!({ "message": activity.result_message }),
    )?;
    emit_event(
        writer,
        "message.part.created",
        json!({
            "session_id": turn.session_started.id,
            "message_id": activity.result_message.id,
            "part": activity.result_message.parts[0],
            "run_state": RunState::Analyzing,
        }),
    )?;
    emit_event(
        writer,
        "message.part.updated",
        json!({
            "session_id": turn.session_started.id,
            "message_id": activity.call_message.id,
            "part": activity.call_message.parts[0],
            "tool_call_status": activity.tool_call.status,
            "run_state": RunState::Analyzing,
        }),
    )
}

/// Emit the events for a resumed turn: the injected permission outcome, the
/// resolved capture call, any new tool calls the revised plan executed, and
/// the final answer (unless the loop paused on a new permission again).
fn emit_resumed_turn_events<W: Write>(
    writer: &mut W,
    turn: &AgentTurn,
    streamed_text: bool,
) -> io::Result<()> {
    emit_event(
        writer,
        "message.created",
        json!({ "message": turn.user_message }),
    )?;
    emit_event(
        writer,
        "message.created",
        json!({ "message": turn.plan_message }),
    )?;
    emit_event(
        writer,
        "agent.reasoning.started",
        json!({
            "session_id": turn.session_started.id,
            "message_id": turn.plan_message.id,
            "part_id": turn.plan_message.parts[0].id,
            "run_state": RunState::Analyzing,
        }),
    )?;
    emit_event(
        writer,
        "agent.reasoning.delta",
        json!({
            "session_id": turn.session_started.id,
            "message_id": turn.plan_message.id,
            "part_id": turn.plan_message.parts[0].id,
            "summary": turn.goal_analysis,
            "run_state": RunState::Analyzing,
        }),
    )?;
    emit_event(
        writer,
        "agent.reasoning.ended",
        json!({
            "session_id": turn.session_started.id,
            "message_id": turn.plan_message.id,
            "part_id": turn.plan_message.parts[0].id,
            "goal_analysis": turn.goal_analysis,
            "run_state": RunState::Analyzing,
        }),
    )?;

    for (index, activity) in turn.tool_activities.iter().enumerate() {
        if index == 0 && turn.resumed {
            let (method, run_state) = if activity.tool_call.status == ToolCallStatus::Completed {
                ("agent.tool.success", RunState::Analyzing)
            } else {
                ("agent.tool.failed", RunState::Analyzing)
            };
            emit_event(
                writer,
                method,
                json!({
                    "tool_call": activity.tool_call,
                    "summary": activity.result.summary,
                    "structured": activity.result.structured,
                    "artifacts": activity.result.artifacts,
                    "truncated": activity.result.truncated,
                    "run_state": run_state,
                }),
            )?;
            emit_event(
                writer,
                "message.created",
                json!({ "message": activity.result_message }),
            )?;
            emit_event(
                writer,
                "message.part.created",
                json!({
                    "session_id": turn.session_started.id,
                    "message_id": activity.result_message.id,
                    "part": activity.result_message.parts[0],
                    "run_state": RunState::Analyzing,
                }),
            )?;
        } else {
            emit_activity_call_events(writer, turn, activity)?;
            emit_tool_domain_events(writer, activity)?;
        }
    }

    if let Some(pending) = &turn.pending_permission {
        emit_event(
            writer,
            "message.created",
            json!({ "message": pending.call_message }),
        )?;
        emit_event(
            writer,
            "message.part.created",
            json!({
                "session_id": turn.session_started.id,
                "message_id": pending.call_message.id,
                "part": pending.call_part,
                "run_state": RunState::WaitingPermission,
            }),
        )?;
        emit_event(
            writer,
            "agent.tool.called",
            json!({
                "tool_call": pending.tool_call,
                "message_id": pending.call_message.id,
                "part_id": pending.call_part.id,
                "run_state": RunState::WaitingPermission,
            }),
        )?;
    } else if streamed_text {
        emit_event(
            writer,
            "message.created",
            json!({ "message": turn.assistant_message }),
        )?;
    } else {
        emit_event(
            writer,
            "message.created",
            json!({ "message": turn.assistant_message }),
        )?;
        emit_event(
            writer,
            "agent.text.started",
            json!({
                "session_id": turn.session_started.id,
                "message_id": turn.assistant_message.id,
                "part_id": turn.assistant_message.parts[0].id,
            }),
        )?;
        emit_event(
            writer,
            "agent.text.delta",
            json!({
                "session_id": turn.session_started.id,
                "message_id": turn.assistant_message.id,
                "part_id": turn.assistant_message.parts[0].id,
                "delta": turn.assistant_message.parts[0].content,
            }),
        )?;
        emit_event(
            writer,
            "agent.text.ended",
            json!({
                "session_id": turn.session_started.id,
                "message_id": turn.assistant_message.id,
                "part_id": turn.assistant_message.parts[0].id,
            }),
        )?;
    }
    emit_event(
        writer,
        "agent.step.ended",
        json!({
            "step": turn.step,
            "run_state": turn.final_run_state,
            "phase": "phase15",
            "llm": {
                "used": turn.llm_used,
                "model": turn.llm_model,
            }
        }),
    )
}

/// Emit bounded domain events for offline analysis tool results so the UI
/// alerts, pcap and report streams stay live. Only summaries and ArtifactRef
/// values are forwarded; raw packet or command output is never emitted.
fn emit_tool_domain_events<W: Write>(
    writer: &mut W,
    activity: &AgentToolActivity,
) -> io::Result<()> {
    let structured = &activity.result.structured;
    match activity.tool_call.tool_name.as_str() {
        "pcap.open" => {
            if let Some(artifact) = structured.get("artifact") {
                emit_event(writer, "pcap.created", json!({ "artifact": artifact }))?;
                emit_event(writer, "artifact.created", json!({ "artifact": artifact }))?;
            }
        }
        "tshark.extract_flows" => {
            emit_event(
                writer,
                "flow.created",
                json!({ "count": structured.get("flows_parsed") }),
            )?;
        }
        "tshark.extract_dns" => {
            emit_event(
                writer,
                "dns.observed",
                json!({ "count": structured.get("dns_parsed") }),
            )?;
        }
        "dns.detect_anomalies" => {
            if let Some(findings) = structured.get("findings").and_then(Value::as_array) {
                for finding in findings.iter().take(10) {
                    emit_event(
                        writer,
                        "finding.created",
                        json!({
                            "finding": {
                                "id": finding.get("id"),
                                "severity": finding.get("severity"),
                                "title": finding.get("title"),
                                "summary": finding.get("description"),
                                "evidence": finding.get("evidence"),
                                "rule_id": finding.pointer("/metadata/rule_id"),
                            }
                        }),
                    )?;
                }
            }
        }
        "report.generate" => {
            if let Some(artifact) = structured.get("artifact") {
                emit_event(writer, "artifact.created", json!({ "artifact": artifact }))?;
                emit_event(
                    writer,
                    "report.generated",
                    json!({
                        "artifact": artifact,
                        "metadata": structured.get("metadata"),
                    }),
                )?;
            }
        }
        "ioc.export" => {
            if let Some(artifact) = structured.get("artifact") {
                emit_event(writer, "artifact.created", json!({ "artifact": artifact }))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_tool_mock_large_output<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let query = params
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("Summarize mock flows.");
    let session_id = params
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("ses_tool_0001");
    let message_id = params
        .get("message_id")
        .and_then(Value::as_str)
        .unwrap_or("msg_tool_0001");
    let step_id = params
        .get("step_id")
        .and_then(Value::as_str)
        .unwrap_or("step_tool_0001");
    let call_id = next_counter_id("call", &mut state.tool_counter);
    let mut tool_call = ToolCall {
        id: call_id.clone(),
        session_id: session_id.to_string(),
        step_id: step_id.to_string(),
        tool_name: String::from("mock.large_output"),
        input: json!({ "query": query }).to_string(),
        status: ToolCallStatus::Pending,
    };
    state
        .sqlite_store
        .insert_tool_call(&tool_call)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;

    let context = ToolContext {
        session_id: session_id.to_string(),
        message_id: message_id.to_string(),
        part_id: params
            .get("part_id")
            .and_then(Value::as_str)
            .unwrap_or("part_tool_0001")
            .to_string(),
        call_id: call_id.clone(),
        agent: AgentMode::Observe,
        permission: ToolPermissionContext {
            required: false,
            decision: String::from("not_required"),
        },
        abort: false,
    };
    emit_event(
        writer,
        "agent.tool.called",
        json!({ "tool_call": tool_call }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit tool.called: {error}"),
    })?;

    tool_call.status = ToolCallStatus::Running;
    state
        .sqlite_store
        .insert_tool_call(&tool_call)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    let (tool_result, progress) =
        match state
            .tool_registry
            .run_mock_large_output(&context, query, &mut state.artifact_store)
        {
            Ok(result) => result,
            Err(message) => {
                let _ = state
                    .sqlite_store
                    .update_tool_call_status(&call_id, ToolCallStatus::Error);
                let _ = emit_event(
                    writer,
                    "agent.tool.failed",
                    json!({
                        "tool_call": {
                            "id": call_id,
                            "session_id": session_id,
                            "step_id": step_id,
                            "tool_name": "mock.large_output",
                            "status": ToolCallStatus::Error,
                        },
                        "message": message,
                    }),
                );
                return Err(RpcError {
                    code: -32001,
                    message,
                });
            }
        };

    for update in progress {
        emit_event(
            writer,
            "agent.tool.progress",
            json!({
                "tool_call_id": update.tool_call_id,
                "status": update.status,
                "message": update.message,
            }),
        )
        .map_err(|error| RpcError {
            code: -32001,
            message: format!("failed to emit tool progress: {error}"),
        })?;
    }

    if let Some(raw_output_artifact) = &tool_result.raw_output_artifact {
        emit_event(
            writer,
            "artifact.created",
            json!({ "artifact": raw_output_artifact }),
        )
        .map_err(|error| RpcError {
            code: -32001,
            message: format!("failed to emit artifact.created: {error}"),
        })?;
    }

    tool_call.status = ToolCallStatus::Completed;
    state
        .sqlite_store
        .insert_tool_call(&tool_call)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    emit_event(
        writer,
        "agent.tool.success",
        json!({
            "tool_call": tool_call,
            "summary": tool_result.summary,
            "artifacts": tool_result.artifacts,
        }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit tool.success: {error}"),
    })?;

    Ok(json!({ "tool_result": tool_result }))
}

fn emit_event<W: Write>(writer: &mut W, method: &str, params: Value) -> io::Result<()> {
    write_message(
        writer,
        &RpcNotification {
            jsonrpc: JSON_RPC_VERSION,
            method,
            params,
        },
    )
}

fn build_agent_context_summary(state: &CoreState) -> String {
    let flow_count = state.sqlite_store.flow_count().unwrap_or(0);
    let dns_count = state
        .sqlite_store
        .list_dns_events()
        .map(|items| items.len())
        .unwrap_or(0);
    let finding_count = state
        .sqlite_store
        .list_findings()
        .map(|items| items.len())
        .unwrap_or(0);
    let artifact_count = state.artifact_store.list_artifacts().len();
    let capture_status = match &state.capture_job {
        Some(job) => format!(
            "running capture {} on {} with filter {}",
            job.id, job.interface, job.filter
        ),
        None => String::from("no active live capture"),
    };

    format!(
        "flows={flow_count}\ndns_events={dns_count}\nfindings={finding_count}\nartifacts={artifact_count}\ncapture_status={capture_status}"
    )
}

/// Run one Agent turn (a fresh `agent.ask` or a permission-driven `agent.resume`)
/// with the Phase 15 typed tool executor and streaming deltas. The artifact
/// store and counters are taken out of `state` for the duration of the loop and
/// written back after.
fn run_agent_turn_with<W: Write, F>(
    state: &mut CoreState,
    tool_schemas: &[Value],
    capture_status: &Value,
    writer: &mut W,
    run: F,
) -> Result<(AgentTurn, bool), String>
where
    F: FnOnce(
        &mut AgentRuntime,
        &[Value],
        &std::sync::atomic::AtomicBool,
        &mut dyn FnMut(&str),
        &mut dyn FnMut(&AgentToolExecutionRequest) -> Result<ToolOutcome, String>,
    ) -> Result<AgentTurn, String>,
{
    let mut artifact_store = std::mem::take(&mut state.artifact_store);
    let tool_registry = &state.tool_registry;
    let sqlite_store = &state.sqlite_store;
    let mut finding_counter = state.finding_counter;
    let mut tool_id_counter = state.tool_counter;
    let mut permission_seq = 0_u64;
    let permission_seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    state.agent_abort.store(false, std::sync::atomic::Ordering::Relaxed);
    let abort = state.agent_abort.clone();
    let mut streamed_any = false;
    let mut streamed_text = false;

    let mut executor = |execution: &AgentToolExecutionRequest| {
        run_agent_tool(
            tool_registry,
            sqlite_store,
            &mut artifact_store,
            capture_status,
            &mut finding_counter,
            &mut tool_id_counter,
            &mut permission_seq,
            permission_seed,
            execution,
        )
    };
    let mut on_text_delta = |delta: &str| {
        if let Some(abort_rx) = state.agent_abort_rx.as_ref() {
            while abort_rx.try_recv().is_ok() {
                abort.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        streamed_any = true;
        streamed_text = true;
        let _ = emit_event(
            writer,
            "agent.text.delta",
            json!({
                "session_id": "streaming",
                "message_id": "streaming",
                "part_id": "streaming",
                "delta": delta,
                "run_state": RunState::Analyzing,
            }),
        );
    };

    let turn = run(
        &mut state.agent_runtime,
        tool_schemas,
        &abort,
        &mut on_text_delta,
        &mut executor,
    )?;
    state.artifact_store = artifact_store;
    state.finding_counter = finding_counter;
    state.tool_counter = tool_id_counter;
    Ok((turn, streamed_text))
}

fn run_agent_ask_turn<W: Write>(
    state: &mut CoreState,
    input: AgentAskInput,
    tool_schemas: &[Value],
    capture_status: &Value,
    writer: &mut W,
) -> Result<(AgentTurn, bool), String> {
    run_agent_turn_with(state, tool_schemas, capture_status, writer, |runtime, tools, abort, delta, executor| {
        runtime.run_turn_with_tools_streaming(input, tools, abort, delta, executor)
    })
}

fn run_agent_resume_turn<W: Write>(
    state: &mut CoreState,
    input: AgentResumeInput,
    tool_schemas: &[Value],
    capture_status: &Value,
    writer: &mut W,
) -> Result<(AgentTurn, bool), String> {
    run_agent_turn_with(state, tool_schemas, capture_status, writer, |runtime, tools, abort, delta, executor| {
        runtime.continue_turn_with_tools_streaming(input, tools, abort, delta, executor)
    })
}

fn run_agent_tool(
    tool_registry: &ToolRegistry,
    sqlite_store: &SqliteStore,
    artifact_store: &mut ArtifactStore,
    capture_status: &Value,
    finding_counter: &mut u64,
    tool_id_counter: &mut u64,
    permission_seq: &mut u64,
    permission_seed: u128,
    execution: &AgentToolExecutionRequest,
) -> Result<ToolOutcome, String> {
    let context = ToolContext {
        session_id: execution.session_id.clone(),
        message_id: execution.message_id.clone(),
        part_id: execution.part_id.clone(),
        call_id: execution.call_id.clone(),
        agent: execution.agent,
        permission: ToolPermissionContext {
            required: false,
            decision: String::from("not_required"),
        },
        abort: false,
    };
    match execution.tool_name.as_str() {
        "capture.start" => {
            let plan = tool_registry.validate_capture_input(&execution.input)?;
            *permission_seq += 1;
            let request_id = format!("per_agent_{permission_seed}_{permission_seq}");
            Ok(ToolOutcome::PermissionPending {
                request_id,
                summary: plan.reason.clone(),
                plan: json!({
                    "interface": plan.interface,
                    "filter": plan.filter,
                    "duration": plan.duration,
                    "reason": plan.reason,
                }),
            })
        }
        "respond.propose_firewall_rule" => {
            let proposal = tool_registry.validate_firewall_rule_input(&execution.input)?;
            *permission_seq += 1;
            let request_id = format!("per_agent_{permission_seed}_{permission_seq}");
            let summary = format!(
                "The agent proposes to block {target} (action={action}) based on stored evidence. This creates a review-only proposal; the firewall is never modified.",
                target = proposal.target,
                action = proposal.action,
            );
            Ok(ToolOutcome::PermissionPending {
                request_id,
                summary,
                plan: json!({
                    "finding_id": proposal.finding_id,
                    "target": proposal.target,
                    "port": proposal.port,
                    "protocol": proposal.protocol,
                    "action": proposal.action,
                    "reason": proposal.reason,
                    "kind": "firewall_rule_proposal",
                }),
            })
        }
        "pcap.open"
        | "tshark.extract_flows"
        | "tshark.extract_dns"
        | "dns.detect_anomalies"
        | "report.generate"
        | "ioc.export" => tool_registry
            .run_offline_tool(
                &context,
                &execution.tool_name,
                &execution.input,
                sqlite_store,
                artifact_store,
                finding_counter,
                tool_id_counter,
            )
            .map(ToolOutcome::Completed),
        _ => tool_registry
            .run_readonly_tool(
                &context,
                &execution.tool_name,
                &execution.input,
                sqlite_store,
                artifact_store,
                capture_status,
            )
            .map(ToolOutcome::Completed),
    }
}

/// Route a paused agent tool call to the right permission workflow:
/// `capture.start` and `respond.propose_firewall_rule` are the two
/// permission-gated agent tools in Phase 12/13.
fn finalize_agent_pending_permission<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    session_id: &str,
    pending: &AgentPendingPermission,
) -> Result<Value, RpcError> {
    match pending.tool_call.tool_name.as_str() {
        "respond.propose_firewall_rule" => {
            finalize_agent_respond_permission(state, writer, session_id, pending)
        }
        _ => finalize_agent_capture_permission(state, writer, session_id, pending),
    }
}

/// Turn a pending `respond.propose_firewall_rule` tool call into a high-risk
/// typed-confirmation permission request. Approval only creates a review
/// proposal artifact; nothing is executed against the firewall.
fn finalize_agent_respond_permission<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    session_id: &str,
    pending: &AgentPendingPermission,
) -> Result<Value, RpcError> {
    let plan = &pending.plan;
    let proposal = FirewallRuleProposal {
        finding_id: plan
            .get("finding_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.is_empty()),
        target: plan
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0")
            .to_string(),
        port: plan.get("port").and_then(Value::as_u64).map(|port| port as u16),
        protocol: plan
            .get("protocol")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.is_empty()),
        action: plan
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("block")
            .to_string(),
        reason: plan
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("No reason provided.")
            .to_string(),
    };

    state
        .sqlite_store
        .insert_tool_call(&pending.tool_call)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;

    let confirm_phrase = format!("BLOCK {}", proposal.target);
    let request = PermissionRequest {
        id: pending.request_id.clone(),
        session_id: session_id.to_string(),
        permission: PermissionKind::ModifyFirewall,
        patterns: vec![proposal.target.clone(), proposal.action.clone()],
        always: vec![
            format!("modify_firewall:{}:{}", proposal.target, proposal.action),
        ],
        risk: RiskLevel::High,
        metadata: PermissionMetadata {
            tool: String::from("respond.propose_firewall_rule"),
            command_preview: format!(
                "PREVIEW ONLY - pfctl rule would be: {action} from any to {target}{port} - NOT executed",
                action = proposal.action,
                target = proposal.target,
                port = proposal
                    .port
                    .map(|port| format!(" port {port}"))
                    .unwrap_or_default(),
            ),
            reason: pending.summary.clone(),
            confirm_phrase: Some(confirm_phrase.clone()),
        },
        tool: ToolRef {
            message_id: pending.call_message.id.clone(),
            call_id: pending.tool_call.id.clone(),
        },
        require_typed_confirmation: true,
    };

    let _ = emit_event(
        writer,
        "agent.tool.progress",
        json!({
            "tool_call_id": pending.tool_call.id,
            "status": "waiting_permission",
            "message": pending.summary,
        }),
    );

    // High-risk respond requests always need the modal + typed confirmation,
    // even when an always-rule exists for the pattern.
    let decision = state.permission_manager.ask(request.clone());
    if decision == PermissionDecision::AllowedAlways {
        state.permission_manager.restore_pending(request.clone());
    }

    let pending_respond = PendingRespond {
        request_id: request.id.clone(),
        session_id: session_id.to_string(),
        tool_call_id: pending.tool_call.id.clone(),
        proposal: proposal.clone(),
    };
    let continuation = serde_json::to_value(&pending_respond).map_err(|error| RpcError {
        code: -32011,
        message: format!("failed to encode pending respond: {error}"),
    })?;
    if let Err(message) =
        state
            .sqlite_store
            .save_pending_permission(&request, &continuation)
    {
        state.permission_manager.remove_pending(&request.id);
        let _ = state
            .sqlite_store
            .update_tool_call_status(&pending.tool_call.id, ToolCallStatus::Error);
        return Err(RpcError {
            code: -32011,
            message,
        });
    }
    state.pending_respond = Some(pending_respond);
    set_session_run_state(state, session_id, RunState::WaitingPermission)?;
    let _ = emit_event(writer, "permission.asked", json!({ "request": request }));

    Ok(json!({
        "status": "waiting_permission",
        "request_id": request.id,
        "require_typed_confirmation": true,
        "confirm_phrase": confirm_phrase,
        "proposal": proposal,
    }))
}

/// Turn a pending `capture.start` tool call into a real permission request.
/// The tool call already paused the Agent loop; this persists the request and
/// either shows the approval modal (pending) or starts the capture (always-rule).
fn finalize_agent_capture_permission<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    session_id: &str,
    pending: &AgentPendingPermission,
) -> Result<Value, RpcError> {
    let plan = &pending.plan;
    let interface = plan
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("mock1")
        .to_string();
    let filter = plan
        .get("filter")
        .and_then(Value::as_str)
        .unwrap_or("tcp or dns")
        .to_string();
    let duration = plan
        .get("duration")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 10);

    state
        .sqlite_store
        .insert_tool_call(&pending.tool_call)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;

    let request = PermissionRequest {
        id: pending.request_id.clone(),
        session_id: session_id.to_string(),
        permission: PermissionKind::CaptureLive,
        patterns: vec![interface.clone(), filter.clone()],
        always: vec![
            format!("capture_live:{interface}:*"),
            format!("capture_live:{filter}"),
        ],
        risk: RiskLevel::Medium,
        metadata: PermissionMetadata {
            tool: String::from("capture.start"),
            command_preview: format!(
                "tcpdump -i {interface} -nn -s 0 -w capture-{interface}.pcap {filter}"
            ),
            reason: pending.summary.clone(),
            confirm_phrase: None,
        },
        tool: ToolRef {
            message_id: pending.call_message.id.clone(),
            call_id: pending.tool_call.id.clone(),
        },
        require_typed_confirmation: false,
    };

    let _ = emit_event(
        writer,
        "agent.tool.progress",
        json!({
            "tool_call_id": pending.tool_call.id,
            "status": "waiting_permission",
            "message": pending.summary,
        }),
    );

    match state.permission_manager.ask(request.clone()) {
        PermissionDecision::Pending => {
            let pending_capture = PendingCapture {
                request_id: request.id.clone(),
                session_id: session_id.to_string(),
                tool_call_id: pending.tool_call.id.clone(),
                interface: interface.clone(),
                filter: filter.clone(),
                duration_secs: duration,
            };
            let continuation =
                serde_json::to_value(&pending_capture).map_err(|error| RpcError {
                    code: -32011,
                    message: format!("failed to encode pending capture: {error}"),
                })?;
            if let Err(message) =
                state
                    .sqlite_store
                    .save_pending_permission(&request, &continuation)
            {
                state.permission_manager.remove_pending(&request.id);
                let _ = state
                    .sqlite_store
                    .update_tool_call_status(&pending.tool_call.id, ToolCallStatus::Error);
                return Err(RpcError {
                    code: -32011,
                    message,
                });
            }
            state.pending_capture = Some(pending_capture);
            set_session_run_state(state, session_id, RunState::WaitingPermission)?;
            let _ = emit_event(writer, "permission.asked", json!({ "request": request }));
            Ok(json!({
                "status": "waiting_permission",
                "request_id": request.id,
                "capture": plan,
            }))
        }
        PermissionDecision::AllowedAlways => start_capture_job(
            state,
            writer,
            CaptureStartInput {
                session_id,
                interface: &interface,
                filter: &filter,
                duration_secs: duration,
                approval_status: "approved_always",
                tool_call_id: &pending.tool_call.id,
                request_id: &request.id,
            },
        ),
        _ => Err(RpcError {
            code: -32000,
            message: String::from("Unexpected permission state for capture.start"),
        }),
    }
}

fn build_resume_outcome_summary(payload: &Value) -> String {
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("rejected");
    match status {
        "approved" | "completed" => {
            if let Some(proposal) = payload.get("proposal") {
                let target = proposal
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let artifact_id = payload
                    .pointer("/artifact/id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                format!(
                    "Firewall rule proposal approved (preview only): block {target}. Proposal artifact {artifact_id} was created. The firewall was NOT modified."
                )
            } else {
                let artifact_id = payload
                    .pointer("/artifact/id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let pcap = payload
                    .pointer("/capture/pcap_path")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                format!(
                    "Live capture was approved and completed. PCAP artifact {artifact_id} is at {pcap}. Raw packets were not returned; use offline tools on that pcap."
                )
            }
        }
        "rejected" => {
            let feedback = payload
                .get("feedback")
                .and_then(Value::as_str)
                .unwrap_or("");
            if feedback.is_empty() {
                String::from("The action was rejected by the user. Revise the plan or use a different approach.")
            } else {
                format!("The action was rejected by the user. Feedback: {feedback}")
            }
        }
        _ => {
            let message = payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            format!("The action could not be completed: {message}. Fall back to a safer alternative.")
        }
    }
}

/// Load all persisted sessions (with their messages) from SQLite and restore them
/// into the agent runtime so conversation context survives restarts.
fn restore_agent_sessions(state: &mut CoreState) -> Result<usize, String> {
    let sessions = state.sqlite_store.list_sessions()?;
    if sessions.is_empty() {
        return Ok(0);
    }

    let mut records = Vec::with_capacity(sessions.len());
    for session in sessions {
        let messages = state.sqlite_store.load_messages(&session.id)?;
        let steps = state.sqlite_store.load_steps(&session.id)?;
        records.push(SessionRecord {
            session,
            messages,
            steps,
        });
    }

    let count = records.len();
    state.agent_runtime.restore_sessions(records);
    Ok(count)
}

fn restore_core_counters(state: &mut CoreState) -> Result<(), String> {
    let counters = state.sqlite_store.persistent_counters()?;
    state.permission_counter = counters.permission;
    state.capture_counter = counters.capture_or_call;
    state.tool_counter = counters.tool_data;
    state.finding_counter = counters.finding;
    Ok(())
}

fn restore_pending_permissions(state: &mut CoreState) -> Result<usize, String> {
    let pending = state.sqlite_store.list_pending_permissions()?;
    let count = pending.len();

    for stored in pending {
        state.permission_counter = state
            .permission_counter
            .max(id_suffix(&stored.request.id).unwrap_or(0));
        state.capture_counter = state
            .capture_counter
            .max(id_suffix(&stored.request.tool.call_id).unwrap_or(0));
        state
            .permission_manager
            .restore_pending(stored.request.clone());

        if state.pending_capture.is_none()
            && let Ok(capture) =
                serde_json::from_value::<PendingCapture>(stored.continuation.clone())
        {
            state.pending_capture = Some(capture);
            continue;
        }
        if state.pending_respond.is_none()
            && let Ok(respond) =
                serde_json::from_value::<PendingRespond>(stored.continuation.clone())
        {
            state.pending_respond = Some(respond);
        }
    }

    Ok(count)
}

fn restore_permission_rules(state: &mut CoreState) -> Result<(), String> {
    let rules = state.sqlite_store.list_permission_rules()?;
    state.permission_manager.persist_always_rule(&rules);
    Ok(())
}

fn id_suffix(id: &str) -> Option<u64> {
    id.rsplit('_').next()?.parse::<u64>().ok()
}

fn set_session_run_state(
    state: &mut CoreState,
    session_id: &str,
    run_state: RunState,
) -> Result<(), RpcError> {
    state
        .sqlite_store
        .update_session_run_state(session_id, run_state)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    state
        .agent_runtime
        .set_session_run_state(session_id, run_state);
    Ok(())
}

/// Persist the result of a single agent turn to SQLite.
fn persist_agent_turn(store: &SqliteStore, turn: &AgentTurn) -> Result<(), String> {
    let tool_calls = turn
        .tool_activities
        .iter()
        .map(|activity| activity.tool_call.clone())
        .collect::<Vec<_>>();
    store.save_agent_turn(
        &turn.session_finished,
        &turn.messages,
        &turn.step,
        &tool_calls,
    )
}

fn handle_session_list(state: &CoreState) -> Result<Value, RpcError> {
    let sessions = state
        .sqlite_store
        .list_sessions()
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    Ok(json!({
        "sessions": sessions
    }))
}

fn handle_session_get(state: &CoreState, params: &Value) -> Result<Value, RpcError> {
    let session_id = required_string_param(params, "session_id")?;
    let session = state
        .sqlite_store
        .load_session(session_id)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?
        .ok_or_else(|| RpcError {
            code: -32012,
            message: format!("session not found: {session_id}"),
        })?;
    let messages = state
        .sqlite_store
        .load_messages(session_id)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    let steps = state
        .sqlite_store
        .load_steps(session_id)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    let tool_calls = state
        .sqlite_store
        .load_tool_calls(session_id)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    let message_parts = messages
        .iter()
        .flat_map(|message| message.parts.iter().cloned())
        .collect::<Vec<_>>();
    let pending_permissions = state
        .sqlite_store
        .list_pending_permissions()
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?
        .into_iter()
        .filter(|pending| pending.request.session_id == session_id)
        .map(|pending| pending.request)
        .collect::<Vec<_>>();

    Ok(json!({
        "session": session,
        "messages": messages,
        "message_parts": message_parts,
        "steps": steps,
        "tool_calls": tool_calls,
        "pending_permissions": pending_permissions
    }))
}

fn handle_message_list(state: &CoreState, params: &Value) -> Result<Value, RpcError> {
    let session_id = required_string_param(params, "session_id")?;
    let messages = state
        .sqlite_store
        .load_messages(session_id)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    Ok(json!({
        "session_id": session_id,
        "messages": messages
    }))
}

fn handle_capture_start<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let interface = params
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("mock1");
    let filter = params
        .get("filter")
        .and_then(Value::as_str)
        .unwrap_or("tcp or dns");
    let duration = params.get("duration").and_then(Value::as_u64).unwrap_or(60);
    let session_id = params
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("ses_capture_0001");
    let duration = duration.clamp(1, 10);

    request_capture_permission(
        state,
        writer,
        CapturePermissionInput {
            session_id,
            interface,
            filter,
            duration_secs: duration,
            reason: &format!("Capture live packets from interface {interface}"),
            message_id: "msg_capture_0001",
            step_id: "step_capture_0001",
        },
    )
}

fn request_capture_permission<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    input: CapturePermissionInput<'_>,
) -> Result<Value, RpcError> {
    let CapturePermissionInput {
        session_id,
        interface,
        filter,
        duration_secs: duration,
        reason,
        message_id,
        step_id,
    } = input;
    if state.pending_capture.is_some() {
        return Err(RpcError {
            code: -32003,
            message: String::from("A capture permission request is already pending."),
        });
    }

    let call_id = next_counter_id("call", &mut state.capture_counter);
    let request = PermissionRequest {
        id: next_counter_id("per", &mut state.permission_counter),
        session_id: session_id.to_string(),
        permission: PermissionKind::CaptureLive,
        patterns: vec![interface.to_string(), filter.to_string()],
        always: vec![
            format!("capture_live:{interface}:*"),
            format!("capture_live:{filter}"),
        ],
        risk: RiskLevel::Medium,
        metadata: PermissionMetadata {
            tool: String::from("capture.start"),
            command_preview: format!(
                "mock tcpdump -i {interface} -nn -s 0 -w capture-{interface}.pcap {filter}"
            ),
            reason: reason.to_string(),
            confirm_phrase: None,
        },
        tool: ToolRef {
            message_id: message_id.to_string(),
            call_id: call_id.clone(),
        },
        require_typed_confirmation: false,
    };
    let tool_call = ToolCall {
        id: call_id.clone(),
        session_id: session_id.to_string(),
        step_id: step_id.to_string(),
        tool_name: String::from("capture.start"),
        input: json!({
            "interface": interface,
            "filter": filter,
            "duration": duration,
        })
        .to_string(),
        status: ToolCallStatus::Pending,
    };
    state
        .sqlite_store
        .insert_tool_call(&tool_call)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;

    match state.permission_manager.ask(request.clone()) {
        PermissionDecision::Pending => {
            let pending_capture = PendingCapture {
                request_id: request.id.clone(),
                session_id: session_id.to_string(),
                tool_call_id: call_id,
                interface: interface.to_string(),
                filter: filter.to_string(),
                duration_secs: duration,
            };
            let continuation =
                serde_json::to_value(&pending_capture).map_err(|error| RpcError {
                    code: -32011,
                    message: format!("failed to encode pending capture: {error}"),
                })?;
            if let Err(message) = state
                .sqlite_store
                .save_pending_permission(&request, &continuation)
            {
                state.permission_manager.remove_pending(&request.id);
                let _ = state
                    .sqlite_store
                    .update_tool_call_status(&request.tool.call_id, ToolCallStatus::Error);
                return Err(RpcError {
                    code: -32011,
                    message,
                });
            }
            state.pending_capture = Some(pending_capture);
            set_session_run_state(state, session_id, RunState::WaitingPermission)?;
            let _ = emit_event(
                writer,
                "agent.tool.called",
                json!({ "tool_call": tool_call }),
            );
            let _ = emit_event(writer, "permission.asked", json!({ "request": request }));
            Ok(json!({
                "status": "waiting_permission",
                "request_id": request.id,
                "capture": {
                    "interface": interface,
                    "filter": filter,
                    "duration": duration
                }
            }))
        }
        PermissionDecision::AllowedAlways => start_capture_job(
            state,
            writer,
            CaptureStartInput {
                session_id,
                interface,
                filter,
                duration_secs: duration,
                approval_status: "approved_always",
                tool_call_id: &request.tool.call_id,
                request_id: &request.id,
            },
        ),
        PermissionDecision::AllowedOnce | PermissionDecision::Rejected => Err(RpcError {
            code: -32000,
            message: String::from("Unexpected permission state for capture.start"),
        }),
    }
}

fn handle_permission_reply<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let request_id = params
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: String::from("request_id is required"),
        })?;
    let decision = parse_permission_reply_kind(params.get("decision")).ok_or_else(|| RpcError {
        code: -32602,
        message: String::from("decision must be one of once, always, reject, reject_with_feedback"),
    })?;
    let feedback = params
        .get("feedback")
        .and_then(Value::as_str)
        .map(str::to_string);
    let typed_confirmation = params
        .get("typed_confirmation")
        .and_then(Value::as_str)
        .map(str::to_string);

    let reply = PermissionReply {
        request_id: request_id.to_string(),
        decision,
        feedback,
        typed_confirmation,
    };
    let persisted_reply = reply.clone();

    let outcome = state
        .permission_manager
        .reply(reply)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: format!("pending request not found: {request_id}"),
        })?;

    if outcome.decision == PermissionDecision::Pending {
        // Typed confirmation failed: the request stays pending; surface the
        // validation message so the UI can re-prompt.
        return Err(RpcError {
            code: -32014,
            message: outcome.feedback.unwrap_or_else(|| {
                String::from("Typed confirmation was not accepted; request is still pending.")
            }),
        });
    }

    if let Err(message) = state.sqlite_store.resolve_permission(&persisted_reply) {
        state
            .permission_manager
            .restore_pending(outcome.request.clone());
        return Err(RpcError {
            code: -32011,
            message,
        });
    }

    let _ = emit_permission_replied(writer, &outcome);

    let is_approval = matches!(
        outcome.decision,
        PermissionDecision::AllowedOnce | PermissionDecision::AllowedAlways
    );
    let tool_call_id = outcome.request.tool.call_id.clone();
    let tool_session_id = outcome.request.session_id.clone();
    let tool_name = outcome.request.metadata.tool.clone();
    let result = match outcome.request.permission {
        PermissionKind::CaptureLive => {
            handle_capture_permission_outcome(state, writer, outcome)
        }
        PermissionKind::ModifyFirewall => {
            handle_respond_permission_outcome(state, writer, outcome)
        }
    };

    if result.is_err() && is_approval {
        let _ = state
            .sqlite_store
            .update_tool_call_status(&tool_call_id, ToolCallStatus::Error);
        let _ = set_session_run_state(state, &tool_session_id, RunState::Error);
        let _ = emit_event(
            writer,
            "agent.tool.failed",
            json!({
                "tool_call": {
                    "id": tool_call_id,
                    "session_id": tool_session_id,
                    "tool_name": tool_name,
                    "status": ToolCallStatus::Error,
                },
                "message": "Approved tool call failed to start."
            }),
        );
    }

    result
}

fn handle_capture_permission_outcome<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    outcome: PermissionOutcome,
) -> Result<Value, RpcError> {
    match outcome.decision {
        PermissionDecision::AllowedOnce => {
            start_capture_from_pending(state, writer, &outcome.request.id, "approved_once")
        }
        PermissionDecision::AllowedAlways => state
            .sqlite_store
            .save_permission_rules(&outcome.request.always)
            .map_err(|message| RpcError {
                code: -32011,
                message,
            })
            .and_then(|_| {
                start_capture_from_pending(state, writer, &outcome.request.id, "approved_always")
            }),
        PermissionDecision::Rejected => {
            state.pending_capture = None;
            state
                .sqlite_store
                .update_tool_call_status(&outcome.request.tool.call_id, ToolCallStatus::Aborted)
                .map_err(|message| RpcError {
                    code: -32011,
                    message,
                })?;
            set_session_run_state(state, &outcome.request.session_id, RunState::Idle)?;
            let _ = emit_event(
                writer,
                "agent.tool.failed",
                json!({
                    "tool_call": {
                        "id": outcome.request.tool.call_id,
                        "session_id": outcome.request.session_id,
                        "tool_name": outcome.request.metadata.tool,
                        "status": ToolCallStatus::Aborted,
                    },
                    "message": "Tool call was not executed because permission was rejected.",
                    "feedback": outcome.feedback,
                }),
            );
            let _ = state.sqlite_store.save_agent_resume(
                &outcome.request.session_id,
                &json!({
                    "status": "rejected",
                    "request_id": outcome.request.id,
                    "feedback": outcome.feedback,
                    "capture": null,
                }),
            );
            Ok(json!({
                "status": "rejected",
                "request_id": outcome.request.id,
                "feedback": outcome.feedback,
            }))
        }
        PermissionDecision::Pending => Err(RpcError {
            code: -32000,
            message: String::from("Unexpected pending outcome after permission.reply"),
        }),
    }
}

/// Respond (proposal/preview) outcome: approval creates a traceable proposal
/// artifact (never touching the firewall), rejection feeds the Agent loop.
fn handle_respond_permission_outcome<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    outcome: PermissionOutcome,
) -> Result<Value, RpcError> {
    match outcome.decision {
        PermissionDecision::AllowedOnce | PermissionDecision::AllowedAlways => {
            let pending = state
                .pending_respond
                .take()
                .filter(|pending| pending.request_id == outcome.request.id)
                .ok_or_else(|| RpcError {
                    code: -32602,
                    message: format!("pending respond continuation not found: {}", outcome.request.id),
                })?;
            let (artifact, proposal) = build_firewall_proposal_artifact(
                state,
                &pending.proposal,
            )
            .map_err(|message| RpcError {
                code: -32015,
                message,
            })?;
            state
                .sqlite_store
                .update_tool_call_status(&outcome.request.tool.call_id, ToolCallStatus::Completed)
                .map_err(|message| RpcError {
                    code: -32011,
                    message,
                })?;
            set_session_run_state(state, &outcome.request.session_id, RunState::Idle)?;

            let _ = emit_event(
                writer,
                "artifact.created",
                json!({ "artifact": artifact }),
            );
            let _ = emit_event(
                writer,
                "respond.proposal.created",
                json!({
                    "artifact": artifact,
                    "proposal": proposal,
                    "finding_id": pending.proposal.finding_id,
                    "status": "proposed",
                    "executed": false,
                }),
            );
            let _ = emit_event(
                writer,
                "agent.tool.success",
                json!({
                    "tool_call": {
                        "id": outcome.request.tool.call_id,
                        "session_id": outcome.request.session_id,
                        "tool_name": outcome.request.metadata.tool,
                        "status": ToolCallStatus::Completed,
                    },
                    "summary": "Firewall rule proposal created for review. NOT executed.",
                    "artifact": artifact,
                }),
            );
            let _ = state.sqlite_store.save_agent_resume(
                &outcome.request.session_id,
                &json!({
                    "status": "approved",
                    "request_id": outcome.request.id,
                    "proposal": proposal,
                    "artifact": artifact,
                    "executed": false,
                }),
            );
            Ok(json!({
                "status": "approved",
                "request_id": outcome.request.id,
                "proposal": proposal,
                "artifact": artifact,
                "executed": false,
            }))
        }
        PermissionDecision::Rejected => {
            state.pending_respond = None;
            state
                .sqlite_store
                .update_tool_call_status(&outcome.request.tool.call_id, ToolCallStatus::Aborted)
                .map_err(|message| RpcError {
                    code: -32011,
                    message,
                })?;
            set_session_run_state(state, &outcome.request.session_id, RunState::Idle)?;
            let _ = emit_event(
                writer,
                "agent.tool.failed",
                json!({
                    "tool_call": {
                        "id": outcome.request.tool.call_id,
                        "session_id": outcome.request.session_id,
                        "tool_name": outcome.request.metadata.tool,
                        "status": ToolCallStatus::Aborted,
                    },
                    "message": "Firewall rule proposal was rejected; nothing was executed.",
                    "feedback": outcome.feedback,
                }),
            );
            let _ = state.sqlite_store.save_agent_resume(
                &outcome.request.session_id,
                &json!({
                    "status": "rejected",
                    "request_id": outcome.request.id,
                    "feedback": outcome.feedback,
                    "proposal": null,
                }),
            );
            Ok(json!({
                "status": "rejected",
                "request_id": outcome.request.id,
                "feedback": outcome.feedback,
            }))
        }
        PermissionDecision::Pending => Err(RpcError {
            code: -32000,
            message: String::from("Unexpected pending outcome after permission.reply"),
        }),
    }
}

/// Build a traceable firewall-rule proposal artifact. The proposal references
/// the finding and its evidence; no firewall change is executed or staged.
fn build_firewall_proposal_artifact(
    state: &mut CoreState,
    proposal: &FirewallRuleProposal,
) -> Result<(ArtifactRef, Value), String> {
    let mut evidence_lines = Vec::new();
    let mut finding_title = String::from("(no finding linked)");
    let mut finding_ref = String::from("(none)");
    if let Some(finding_id) = &proposal.finding_id {
        finding_ref = finding_id.clone();
        if let Some(finding) = state
            .sqlite_store
            .load_finding_by_id(finding_id)
            .map_err(|message| format!("failed to load finding: {message}"))?
        {
            finding_title = finding.title.clone();
            for evidence in finding.evidence {
                evidence_lines.push(format!(
                    "- {} / {} / {}",
                    evidence.evidence_type, evidence.id, evidence.summary
                ));
            }
        }
    }
    for flow in state
        .sqlite_store
        .list_flows()
        .map_err(|message| format!("failed to list flows: {message}"))?
        .into_iter()
        .filter(|flow| flow.src_ip == proposal.target || flow.dst_ip == proposal.target)
        .take(5)
    {
        evidence_lines.push(format!(
            "- flow / {} / {}:{} -> {}:{} {}",
            flow.id, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
        ));
    }

    let target = &proposal.target;
    let port = proposal
        .port
        .map(|port| port.to_string())
        .unwrap_or_else(|| "any".to_string());
    let protocol = proposal.protocol.clone().unwrap_or_else(|| "any".to_string());
    let content = format!(
        "# Firewall Rule Proposal (preview only)\n\n\
         - Status: proposed (NOT executed)\n\
         - Action: {action}\n\
         - Target: {target}\n\
         - Port: {port}\n\
         - Protocol: {protocol}\n\
         - Finding: {finding_title}\n\
         - Finding id: {finding_ref}\n\
         - Reason: {reason}\n\n\
         ## Evidence refs\n{evidence}\n\n\
         ## Review checklist\n\
         - [ ] Confirm the target belongs to the suspicious entity\n\
         - [ ] Confirm the rule scope (port/protocol) matches the evidence\n\
         - [ ] Approve execution through a separate high-risk gate\n",
        action = proposal.action,
        reason = proposal.reason,
        evidence = if evidence_lines.is_empty() {
            "- no matching stored evidence".to_string()
        } else {
            evidence_lines.join("\n")
        },
    );
    let artifact = state
        .artifact_store
        .write_text_artifact(
            "firewall-proposal",
            "md",
            ArtifactKind::Proposal,
            "Firewall rule proposal (preview only)",
            &content,
        )
        .map_err(|message| format!("failed to write proposal artifact: {message}"))?;

    let value = json!({
        "action": proposal.action,
        "target": proposal.target,
        "port": port,
        "protocol": protocol,
        "finding_id": proposal.finding_id,
        "finding_title": finding_title,
        "reason": proposal.reason,
        "status": "proposed",
        "executed": false,
    });
    Ok((artifact, value))
}

fn handle_capture_status(state: &mut CoreState) -> Result<Value, RpcError> {
    Ok(capture_status_snapshot(state))
}

fn capture_status_snapshot(state: &CoreState) -> Value {
    match &state.capture_job {
        Some(job) => json!({
            "status": "running",
            "capture_id": job.id,
            "session_id": job.session_id,
            "interface": job.interface,
            "filter": job.filter,
            "duration_secs": job.duration_secs,
            "elapsed_secs": job.started_at.elapsed().as_secs(),
            "pcap_path": job.pcap_path,
        }),
        None => json!({
            "status": "idle"
        }),
    }
}

fn handle_capture_stop<W: Write>(state: &mut CoreState, writer: &mut W) -> Result<Value, RpcError> {
    if let Some(job) = state.capture_job.take() {
        let result =
            finalize_capture_job(state, writer, job, "stopped_by_user").map_err(|error| {
                RpcError {
                    code: -32002,
                    message: format!("failed to stop capture: {error}"),
                }
            })?;
        return Ok(result);
    }

    Ok(json!({
        "status": "idle",
        "message": "No active capture."
    }))
}

fn emit_permission_replied<W: Write>(
    writer: &mut W,
    outcome: &PermissionOutcome,
) -> io::Result<()> {
    emit_event(
        writer,
        "permission.replied",
        json!({
            "request_id": outcome.request.id,
            "session_id": outcome.request.session_id,
            "decision": outcome.decision,
            "feedback": outcome.feedback,
        }),
    )
}

fn parse_permission_reply_kind(value: Option<&Value>) -> Option<PermissionReplyKind> {
    match value.and_then(Value::as_str) {
        Some("once") => Some(PermissionReplyKind::Once),
        Some("always") => Some(PermissionReplyKind::Always),
        Some("reject") => Some(PermissionReplyKind::Reject),
        Some("reject_with_feedback") => Some(PermissionReplyKind::RejectWithFeedback),
        _ => None,
    }
}

fn start_capture_from_pending<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    request_id: &str,
    approval_status: &str,
) -> Result<Value, RpcError> {
    let pending = state
        .pending_capture
        .take()
        .filter(|capture| capture.request_id == request_id)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: format!("pending capture not found for request: {request_id}"),
        })?;

    start_capture_job(
        state,
        writer,
        CaptureStartInput {
            session_id: &pending.session_id,
            interface: &pending.interface,
            filter: &pending.filter,
            duration_secs: pending.duration_secs,
            approval_status,
            tool_call_id: &pending.tool_call_id,
            request_id,
        },
    )
}

fn start_capture_job<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    input: CaptureStartInput<'_>,
) -> Result<Value, RpcError> {
    let CaptureStartInput {
        session_id,
        interface,
        filter,
        duration_secs,
        approval_status,
        tool_call_id,
        request_id,
    } = input;
    if state.capture_job.is_some() {
        return Err(RpcError {
            code: -32003,
            message: String::from("Only one capture job is supported in Phase 6."),
        });
    }

    let capture_id = next_counter_id("cap", &mut state.capture_counter);
    let mut capture_dir = std::env::temp_dir();
    capture_dir.push("netagent-captures");
    std::fs::create_dir_all(&capture_dir).map_err(|error| RpcError {
        code: -32004,
        message: format!("failed to prepare capture directory: {error}"),
    })?;

    let pcap_path = capture_dir.join(format!("{capture_id}.pcap"));
    state
        .sqlite_store
        .update_tool_call_status(tool_call_id, ToolCallStatus::Running)
        .map_err(|message| RpcError {
            code: -32011,
            message,
        })?;
    let child = match spawn_tcpdump(interface, filter, &pcap_path) {
        Ok(child) => child,
        Err(error) => {
            let _ = state
                .sqlite_store
                .update_tool_call_status(tool_call_id, ToolCallStatus::Error);
            let _ = state.sqlite_store.save_agent_resume(
                session_id,
                &json!({
                    "status": "failed",
                    "request_id": request_id,
                    "message": error,
                    "capture": null,
                }),
            );
            return Err(RpcError {
                code: -32005,
                message: error,
            });
        }
    };

    emit_event(
        writer,
        "capture.started",
        json!({
            "capture_id": capture_id,
            "session_id": session_id,
            "interface": interface,
            "filter": filter,
            "duration_secs": duration_secs,
        }),
    )
    .map_err(|error| RpcError {
        code: -32006,
        message: format!("failed to emit capture.started: {error}"),
    })?;

    state.capture_job = Some(CaptureJob {
        id: capture_id.clone(),
        session_id: session_id.to_string(),
        tool_call_id: tool_call_id.to_string(),
        request_id: request_id.to_string(),
        interface: interface.to_string(),
        filter: filter.to_string(),
        duration_secs,
        started_at: Instant::now(),
        pcap_path: pcap_path.to_string_lossy().to_string(),
        child,
    });
    set_session_run_state(state, session_id, RunState::Capturing)?;

    emit_event(
        writer,
        "agent.tool.progress",
        json!({
            "tool_call_id": tool_call_id,
            "status": "running",
            "message": "Bounded live capture started after permission approval."
        }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit capture tool progress: {error}"),
    })?;

    Ok(json!({
        "status": approval_status,
        "capture_id": capture_id,
        "interface": interface,
        "filter": filter,
        "duration_secs": duration_secs,
        "pcap_path": pcap_path,
        "tool_call_id": tool_call_id,
    }))
}

fn spawn_tcpdump(interface: &str, filter: &str, pcap_path: &PathBuf) -> Result<Child, String> {
    let mut command = Command::new("/usr/sbin/tcpdump");
    command
        .arg("-i")
        .arg(interface)
        .arg("-nn")
        .arg("-s")
        .arg("0")
        .arg("-U")
        .arg("-w")
        .arg(pcap_path)
        .arg(filter)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn tcpdump: {error}"))?;

    std::thread::sleep(Duration::from_millis(150));
    if let Some(_status) = child
        .try_wait()
        .map_err(|error| format!("failed to inspect tcpdump status: {error}"))?
    {
        let mut stderr = String::new();
        if let Some(mut handle) = child.stderr.take() {
            let _ = handle.read_to_string(&mut stderr);
        }
        return Err(if stderr.trim().is_empty() {
            String::from("tcpdump exited immediately")
        } else {
            stderr.trim().to_string()
        });
    }

    Ok(child)
}

fn reconcile_capture_state<W: Write>(state: &mut CoreState, writer: &mut W) -> io::Result<()> {
    let should_finalize = match state.capture_job.as_mut() {
        Some(job) if job.started_at.elapsed() >= Duration::from_secs(job.duration_secs) => true,
        Some(job) => job.child.try_wait()?.is_some(),
        None => false,
    };

    if should_finalize && let Some(job) = state.capture_job.take() {
        let _ = finalize_capture_job(state, writer, job, "completed")?;
    }

    Ok(())
}

fn finalize_capture_job<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    mut job: CaptureJob,
    stop_reason: &str,
) -> io::Result<Value> {
    let _ = job.child.kill();
    let _ = job.child.wait();

    let note = format!(
        "Capture {} on {} with filter {}",
        job.id, job.interface, job.filter
    );
    let artifact = state.artifact_store.register_pcap(&job.pcap_path, &note);
    state
        .sqlite_store
        .update_tool_call_status(&job.tool_call_id, ToolCallStatus::Completed)
        .map_err(io::Error::other)?;
    set_session_run_state(state, &job.session_id, RunState::Idle)
        .map_err(|error| io::Error::other(error.message))?;
    let _ = state.sqlite_store.save_agent_resume(
        &job.session_id,
        &json!({
            "status": "approved",
            "request_id": job.request_id,
            "capture": {
                "capture_id": job.id,
                "interface": job.interface,
                "filter": job.filter,
                "duration_secs": job.duration_secs,
                "pcap_path": job.pcap_path,
            },
            "artifact": artifact,
        }),
    );

    emit_event(
        writer,
        "capture.stopped",
        json!({
            "capture_id": job.id,
            "session_id": job.session_id,
            "reason": stop_reason,
            "pcap_path": job.pcap_path,
        }),
    )?;
    emit_event(writer, "pcap.created", json!({ "artifact": artifact }))?;
    emit_event(writer, "artifact.created", json!({ "artifact": artifact }))?;
    emit_event(
        writer,
        "agent.tool.success",
        json!({
            "tool_call": {
                "id": job.tool_call_id,
                "session_id": job.session_id,
                "tool_name": "capture.start",
                "status": ToolCallStatus::Completed,
            },
            "summary": "Bounded capture completed; PCAP was stored as an artifact.",
            "artifact": artifact,
        }),
    )?;

    Ok(json!({
        "status": "stopped",
        "capture_id": job.id,
        "pcap_path": job.pcap_path,
        "artifact": artifact,
    }))
}

// ── Phase 7: pcap.open ──

fn handle_pcap_open<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: String::from("path is required"),
        })?;

    let pcap_path = std::path::Path::new(path);
    if !pcap_path.exists() {
        return Err(RpcError {
            code: -32602,
            message: format!("pcap file not found: {path}"),
        });
    }

    let mut flows = tshark::extract_flows(pcap_path).map_err(|message| RpcError {
        code: -32007,
        message: format!("failed to extract flows: {message}"),
    })?;
    let mut dns_events = tshark::extract_dns(pcap_path).map_err(|message| RpcError {
        code: -32007,
        message: format!("failed to extract DNS events: {message}"),
    })?;

    // Assign IDs
    for flow in &mut flows {
        flow.id = next_counter_id("flow", &mut state.tool_counter);
    }
    for event in &mut dns_events {
        event.id = next_counter_id("dns", &mut state.tool_counter);
    }

    let flow_count = flows.len();
    let dns_count = dns_events.len();

    let flow_inserted = state
        .sqlite_store
        .insert_flows(&flows)
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

    let dns_inserted = state
        .sqlite_store
        .insert_dns_events(&dns_events)
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

    let artifact = state
        .artifact_store
        .register_pcap(path, &format!("pcap opened from {path}"));
    let _ = emit_event(writer, "artifact.created", json!({ "artifact": artifact }));

    // Emit flow.created events (throttled: maximum 20)
    for flow in flows.iter().take(20) {
        let _ = emit_event(
            writer,
            "flow.created",
            json!({
                "flow": {
                    "id": flow.id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "bytes_out": flow.bytes_out,
                    "packets_out": flow.packets_out,
                }
            }),
        );
    }

    // Emit dns.observed events (throttled: maximum 20)
    for event in dns_events.iter().take(20) {
        let _ = emit_event(
            writer,
            "dns.observed",
            json!({
                "dns_event": {
                    "id": event.id,
                    "src_ip": event.src_ip,
                    "query_name": event.query_name,
                    "query_type": event.query_type,
                    "response_code": event.response_code,
                }
            }),
        );
    }

    Ok(json!({
        "status": "ok",
        "path": path,
        "artifact": artifact,
        "flows_parsed": flow_count,
        "flows_inserted": flow_inserted,
        "dns_parsed": dns_count,
        "dns_inserted": dns_inserted,
    }))
}

fn handle_pcap_summarize(_state: &CoreState, params: &Value) -> Result<Value, RpcError> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: String::from("path is required"),
        })?;

    let pcap_path = std::path::Path::new(path);
    let flows = tshark::extract_flows(pcap_path).map_err(|message| RpcError {
        code: -32007,
        message: format!("failed to extract flows: {message}"),
    })?;
    let dns_events = tshark::extract_dns(pcap_path).map_err(|message| RpcError {
        code: -32007,
        message: format!("failed to extract DNS events: {message}"),
    })?;

    // Compute protocol distribution
    use std::collections::HashMap;
    let mut proto_counts: HashMap<String, usize> = HashMap::new();
    for flow in &flows {
        *proto_counts.entry(flow.protocol.clone()).or_default() += 1;
    }

    let mut top_talkers: HashMap<String, usize> = HashMap::new();
    for flow in &flows {
        *top_talkers.entry(flow.src_ip.clone()).or_default() += 1;
    }
    let mut top: Vec<_> = top_talkers.into_iter().collect();
    top.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let top_ips: Vec<String> = top.into_iter().take(5).map(|(ip, _)| ip).collect();

    Ok(json!({
        "path": path,
        "total_flows": flows.len(),
        "total_dns_events": dns_events.len(),
        "protocol_distribution": proto_counts,
        "top_talkers": top_ips,
    }))
}

// ── Phase 7: tshark.extract_flows ──

fn handle_tshark_extract_flows<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: String::from("path is required"),
        })?;

    let pcap_path = std::path::Path::new(path);
    let mut flows = tshark::extract_flows(pcap_path).map_err(|e| RpcError {
        code: -32007,
        message: e,
    })?;

    for flow in &mut flows {
        flow.id = next_counter_id("flow", &mut state.tool_counter);
    }

    let inserted = state
        .sqlite_store
        .insert_flows(&flows)
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

    let _ = emit_event(
        writer,
        "flow.created",
        json!({ "count": flows.len(), "inserted": inserted }),
    );

    Ok(json!({
        "status": "ok",
        "flows_parsed": flows.len(),
        "flows_inserted": inserted,
        "flows": flows.iter().take(5).collect::<Vec<_>>(),
    }))
}

// ── Phase 7: tshark.extract_dns ──

fn handle_tshark_extract_dns<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: String::from("path is required"),
        })?;

    let pcap_path = std::path::Path::new(path);
    let mut dns_events = tshark::extract_dns(pcap_path).map_err(|e| RpcError {
        code: -32007,
        message: e,
    })?;

    for event in &mut dns_events {
        event.id = next_counter_id("dns", &mut state.tool_counter);
    }

    let inserted = state
        .sqlite_store
        .insert_dns_events(&dns_events)
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

    let _ = emit_event(
        writer,
        "dns.observed",
        json!({ "count": dns_events.len(), "inserted": inserted }),
    );

    Ok(json!({
        "status": "ok",
        "dns_parsed": dns_events.len(),
        "dns_inserted": inserted,
        "samples": dns_events.iter().take(5).collect::<Vec<_>>(),
    }))
}

// ── Phase 7: dns.detect_anomalies ──

fn handle_dns_detect_anomalies<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let mut manifests = load_rule_manifests().map_err(|message| RpcError {
        code: -32008,
        message: format!("failed to load rule manifests: {message}"),
    })?;
    if let Some(threshold) = params.get("threshold_ratio").and_then(Value::as_f64) {
        if let Some(spike) = manifests
            .iter_mut()
            .find(|manifest| manifest.id == "dns_nxdomain_spike")
        {
            spike
                .params
                .insert("threshold_ratio".to_string(), json!(threshold.clamp(0.0, 1.0)));
        }
    }
    if let Some(min) = params.get("min_queries").and_then(Value::as_u64) {
        if let Some(spike) = manifests
            .iter_mut()
            .find(|manifest| manifest.id == "dns_nxdomain_spike")
        {
            spike.params.insert("min_queries".to_string(), json!(min));
        }
    }

    let findings = run_all_rules(&manifests, &state.sqlite_store, &mut state.finding_counter)
        .map_err(|message| RpcError {
            code: -32008,
            message: format!("failed to run analyzer rules: {message}"),
        })?;

    for finding in &findings {
        let _ = emit_event(
            writer,
            "finding.created",
            json!({
                "finding": {
                    "id": finding.id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "summary": finding.description,
                    "evidence": finding.evidence,
                    "rule_id": finding.metadata.get("rule_id"),
                }
            }),
        );
    }

    Ok(json!({
        "status": "ok",
        "findings_count": findings.len(),
        "findings": findings,
    }))
}

// ── Phase 7: flow.list ──

fn handle_flow_list(state: &CoreState) -> Result<Value, RpcError> {
    let flows = state.sqlite_store.list_flows().map_err(|e| RpcError {
        code: -32007,
        message: e,
    })?;

    Ok(json!({
        "flows": flows,
        "total": flows.len(),
    }))
}

// ── Phase 7: finding.list ──

fn handle_finding_list(state: &CoreState) -> Result<Value, RpcError> {
    let findings = state.sqlite_store.list_findings().map_err(|e| RpcError {
        code: -32007,
        message: e,
    })?;

    Ok(json!({
        "findings": findings,
        "total": findings.len(),
    }))
}

// ── Phase 8: report.generate ──

fn handle_report_generate<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    params: &Value,
) -> Result<Value, RpcError> {
    let title = params
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("NetAgent Report");

    let input = collect_report_input(&state.sqlite_store, &state.artifact_store, title)
        .map_err(|message| RpcError {
            code: -32009,
            message,
        })?;
    let (content, metadata) = build_markdown_report(&input);
    let artifact = state
        .artifact_store
        .write_report("netagent-report", &content)
        .map_err(|message| RpcError {
            code: -32009,
            message,
        })?;

    emit_event(
        writer,
        "artifact.created",
        json!({ "artifact": artifact.clone() }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit artifact.created: {error}"),
    })?;
    emit_event(
        writer,
        "report.generated",
        json!({
            "artifact": artifact,
            "metadata": metadata,
        }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit report.generated: {error}"),
    })?;

    Ok(json!({
        "status": "ok",
        "summary": format!(
            "Report generated with {} findings, {} flows, and {} DNS events.",
            metadata.finding_count,
            metadata.flow_count,
            metadata.dns_event_count
        ),
        "artifact": artifact,
        "metadata": metadata,
        "preview": content.lines().take(12).collect::<Vec<_>>().join("\n"),
    }))
}

// ── Phase 8: ioc.export ──

fn handle_ioc_export<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    _params: &Value,
) -> Result<Value, RpcError> {
    let document = build_ioc_export_document(&state.sqlite_store, &state.artifact_store)?;
    let content = serde_json::to_string_pretty(&document).map_err(|error| RpcError {
        code: -32009,
        message: format!("failed to serialize IOC export: {error}"),
    })?;
    let artifact = state
        .artifact_store
        .write_ioc_export("netagent-iocs", &content)
        .map_err(|message| RpcError {
            code: -32009,
            message,
        })?;

    emit_event(
        writer,
        "artifact.created",
        json!({ "artifact": artifact.clone() }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit artifact.created: {error}"),
    })?;

    Ok(json!({
        "status": "ok",
        "summary": format!(
            "IOC export written with {} findings, {} flows, and {} DNS events.",
            document.findings.len(),
            document.flows.len(),
            document.dns_events.len()
        ),
        "artifact": artifact,
        "evidence_bundle": document.evidence_bundle.clone(),
        "counts": {
            "findings": document.findings.len(),
            "flows": document.flows.len(),
            "dns_events": document.dns_events.len(),
            "artifacts": document.artifacts.len(),
        }
    }))
}

fn build_ioc_export_document(
    store: &SqliteStore,
    artifact_store: &ArtifactStore,
) -> Result<IocExportDocument, RpcError> {
    let input = collect_report_input(store, artifact_store, "NetAgent IOC Export")
        .map_err(|message| RpcError {
            code: -32009,
            message,
        })?;
    let evidence_bundle = build_evidence_bundle_metadata(&input);

    Ok(IocExportDocument {
        generated_at: "2026-06-03T00:00:00Z".to_string(),
        evidence_bundle,
        findings: input.findings,
        flows: input.flows,
        dns_events: input.dns_events,
        artifacts: input.artifacts,
    })
}

fn next_counter_id(prefix: &str, counter: &mut u64) -> String {
    *counter += 1;
    format!("{prefix}_{counter:04}")
}

fn write_message<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, message).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::dns::detect_nxdomain_spike;
    use netagent_models::{ArtifactKind, DnsEvent, EvidenceRef};
    use std::process::Command;

    fn temp_db_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("netagent-test-{name}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn temp_pcap_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("netagent-test-{name}-{}.pcap", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn tshark_available() -> bool {
        Command::new("tshark").arg("-v").output().is_ok()
    }

    fn append_pcap_header(bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
    }

    fn append_pcap_packet(bytes: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        bytes.extend_from_slice(&ts_sec.to_le_bytes());
        bytes.extend_from_slice(&ts_usec.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(payload);
    }

    fn checksum16(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        if let Some(&byte) = chunks.remainder().first() {
            sum += u16::from_be_bytes([byte, 0]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn encode_qname(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn build_dns_payload(id: u16, flags: u16, qname: &str, answer_ip: Option<[u8; 4]>) -> Vec<u8> {
        let mut payload = Vec::new();
        let qname_bytes = encode_qname(qname);
        let answer_count = if answer_ip.is_some() { 1u16 } else { 0u16 };

        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&flags.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&answer_count.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&qname_bytes);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());

        if let Some(ip) = answer_ip {
            payload.extend_from_slice(&[0xc0, 0x0c]);
            payload.extend_from_slice(&1u16.to_be_bytes());
            payload.extend_from_slice(&1u16.to_be_bytes());
            payload.extend_from_slice(&60u32.to_be_bytes());
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&ip);
        }

        payload
    }

    fn build_udp_dns_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        dns_payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        let total_length = (20 + 8 + dns_payload.len()) as u16;
        let mut ipv4 = vec![0u8; 20];
        ipv4[0] = 0x45;
        ipv4[1] = 0;
        ipv4[2..4].copy_from_slice(&total_length.to_be_bytes());
        ipv4[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        ipv4[6..8].copy_from_slice(&0u16.to_be_bytes());
        ipv4[8] = 64;
        ipv4[9] = 17;
        ipv4[12..16].copy_from_slice(&src_ip);
        ipv4[16..20].copy_from_slice(&dst_ip);
        let ip_checksum = checksum16(&ipv4);
        ipv4[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        frame.extend_from_slice(&ipv4);

        let udp_length = (8 + dns_payload.len()) as u16;
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&udp_length.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(dns_payload);

        frame
    }

    fn write_test_dns_pcap(path: &PathBuf) {
        let mut bytes = Vec::new();
        append_pcap_header(&mut bytes);

        let nx_payload = build_dns_payload(0x1001, 0x8183, "missing.example", None);
        let ok_payload = build_dns_payload(0x1002, 0x8180, "ok.example", Some([93, 184, 216, 34]));

        let src_ip = [10, 0, 0, 8];
        let dst_ip = [1, 1, 1, 1];
        let nx_frame = build_udp_dns_frame(src_ip, dst_ip, 53000, 53, &nx_payload);
        let ok_frame = build_udp_dns_frame(src_ip, dst_ip, 53001, 53, &ok_payload);

        append_pcap_packet(&mut bytes, 1_717_777_800, 100_000, &nx_frame);
        append_pcap_packet(&mut bytes, 1_717_777_801, 200_000, &ok_frame);

        std::fs::write(path, bytes).expect("write test pcap");
    }

    fn test_core_state(db_path: &std::path::Path) -> CoreState {
        CoreState {
            agent_runtime: AgentRuntime::disabled(),
            permission_manager: PermissionManager::default(),
            tool_registry: ToolRegistry,
            artifact_store: ArtifactStore::default(),
            sqlite_store: SqliteStore::open(db_path).expect("open sqlite store"),
            rule_manifests: Vec::new(),
            capture_job: None,
            pending_capture: None,
            pending_respond: None,
            agent_abort: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            agent_abort_rx: None,
            permission_counter: 0,
            capture_counter: 0,
            tool_counter: 0,
            finding_counter: 0,
        }
    }

    fn rpc_request(id: u64, method: &str, params: Value) -> RpcRequest {
        RpcRequest {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id: json!(id),
            method: method.to_string(),
            params,
        }
    }

    fn call_rpc(
        state: &mut CoreState,
        id: u64,
        method: &str,
        params: Value,
    ) -> (Value, Vec<Value>) {
        let mut writer = Vec::new();
        let response = handle_request(rpc_request(id, method, params), state, &mut writer)
            .expect("handle rpc request");
        if let Some(error) = response.error {
            panic!("rpc {method} failed: {}", error.message);
        }

        let events = String::from_utf8(writer).expect("utf8 events");
        let events = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
            .collect::<Vec<_>>();

        (response.result.expect("rpc result"), events)
    }

    fn call_rpc_raw(
        state: &mut CoreState,
        id: u64,
        method: &str,
        params: Value,
    ) -> (RpcResponse, Vec<Value>) {
        let mut writer = Vec::new();
        let response = handle_request(rpc_request(id, method, params), state, &mut writer)
            .expect("handle rpc request");
        let events = String::from_utf8(writer).expect("utf8 events");
        let events = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
            .collect::<Vec<_>>();

        (response, events)
    }

    #[test]
    fn report_and_ioc_export_use_persisted_records() {
        let db_path = temp_db_path("phase8-report");
        let store = SqliteStore::open(&db_path).expect("open sqlite store");

        let flows = vec![Flow {
            id: "flow_0001".to_string(),
            start_time: "2026-06-03T10:00:00Z".to_string(),
            end_time: Some("2026-06-03T10:02:00Z".to_string()),
            src_ip: "10.0.0.8".to_string(),
            src_port: 53000,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 53,
            protocol: "udp".to_string(),
            service: "dns".to_string(),
            bytes_in: 140,
            bytes_out: 280,
            packets_in: 2,
            packets_out: 4,
            state: "closed".to_string(),
            metadata: json!({ "capture_id": "cap_0001" }),
        }];
        store.insert_flows(&flows).expect("insert flows");

        let dns_events = vec![
            DnsEvent {
                id: "dns_0001".to_string(),
                timestamp: "2026-06-03T10:00:30Z".to_string(),
                src_ip: "10.0.0.8".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                query_name: "missing.example".to_string(),
                query_type: "A".to_string(),
                response_code: "NXDOMAIN".to_string(),
                response_code_num: 3,
                answers: vec![],
            },
            DnsEvent {
                id: "dns_0002".to_string(),
                timestamp: "2026-06-03T10:01:00Z".to_string(),
                src_ip: "10.0.0.8".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                query_name: "ok.example".to_string(),
                query_type: "A".to_string(),
                response_code: "NOERROR".to_string(),
                response_code_num: 0,
                answers: vec!["93.184.216.34".to_string()],
            },
        ];
        store
            .insert_dns_events(&dns_events)
            .expect("insert dns events");

        let finding = Finding {
            id: "finding_0001".to_string(),
            created_at: "2026-06-03T10:03:00Z".to_string(),
            title: "NXDOMAIN spike detected for 10.0.0.8".to_string(),
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            category: "dns_anomaly".to_string(),
            description: "Host produced repeated NXDOMAIN responses.".to_string(),
            entities: vec!["10.0.0.8".to_string()],
            evidence: vec![EvidenceRef {
                evidence_type: "dns_event".to_string(),
                id: "dns_stats_10.0.0.8".to_string(),
                summary: "1 NXDOMAIN responses out of 2 total DNS queries (50.0% ratio)"
                    .to_string(),
            }],
            recommended_actions: vec!["Export evidence report".to_string()],
            metadata: json!({ "ratio": 0.5 }),
        };
        store.insert_finding(&finding).expect("insert finding");

        let mut artifact_store = ArtifactStore::default();
        artifact_store.register_pcap(
            "/tmp/netagent-test-phase8.pcap",
            "Capture cap_0001 on mock1 with filter dns",
        );

        let input =
            collect_report_input(&store, &artifact_store, "Stored Evidence Report").expect("input");
        let (report, metadata) = build_markdown_report(&input);
        let document = build_ioc_export_document(&store, &artifact_store).expect("ioc document");

        assert_eq!(metadata.finding_count, 1);
        assert_eq!(metadata.flow_count, 1);
        assert_eq!(metadata.dns_event_count, 2);
        assert_eq!(metadata.pcap_artifact_count, 1);
        assert_eq!(document.evidence_bundle.pcap_artifact_count, 1);
        assert_eq!(document.findings.len(), 1);
        assert_eq!(document.flows.len(), 1);
        assert_eq!(document.dns_events.len(), 2);
        assert!(matches!(document.artifacts[0].kind, ArtifactKind::Pcap));
        assert!(report.contains("Stored Evidence Report"));
        assert!(report.contains("NXDOMAIN spike detected for 10.0.0.8"));
        assert!(report.contains("10.0.0.8:53000 -> 1.1.1.1:53"));
        assert!(report.contains("/tmp/netagent-test-phase8.pcap"));
        assert!(report.contains("missing.example"));

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn report_and_ioc_export_use_real_parsed_pcap_data() {
        if !tshark_available() {
            return;
        }

        let db_path = temp_db_path("phase8-real-pcap");
        let pcap_path = temp_pcap_path("phase8-real-pcap");
        let store = SqliteStore::open(&db_path).expect("open sqlite store");
        write_test_dns_pcap(&pcap_path);

        let mut flows = tshark::extract_flows(&pcap_path).expect("extract flows");
        for (index, flow) in flows.iter_mut().enumerate() {
            flow.id = format!("flow_{index:04}");
        }
        store.insert_flows(&flows).expect("insert parsed flows");

        let mut dns_events = tshark::extract_dns(&pcap_path).expect("extract dns");
        for (index, event) in dns_events.iter_mut().enumerate() {
            event.id = format!("dns_{index:04}");
        }
        store
            .insert_dns_events(&dns_events)
            .expect("insert parsed dns events");

        let mut finding_counter = 0;
        let findings =
            detect_nxdomain_spike(&store, &mut finding_counter, 0.5, 2).expect("detect findings");

        let mut artifact_store = ArtifactStore::default();
        artifact_store.register_pcap(
            pcap_path.to_str().expect("pcap path"),
            "Capture cap_0001 on mock1 with filter dns",
        );

        let input = collect_report_input(&store, &artifact_store, "Real Parsed Evidence Report")
            .expect("input");
        let (report, metadata) = build_markdown_report(&input);
        let document = build_ioc_export_document(&store, &artifact_store).expect("ioc document");

        assert_eq!(flows.len(), 2);
        assert_eq!(dns_events.len(), 2);
        assert_eq!(findings.len(), 1);
        assert_eq!(metadata.finding_count, 1);
        assert_eq!(metadata.flow_count, 2);
        assert_eq!(metadata.dns_event_count, 2);
        assert_eq!(metadata.pcap_artifact_count, 1);
        assert_eq!(document.evidence_bundle.finding_count, 1);
        assert_eq!(document.evidence_bundle.dns_event_count, 2);
        assert!(report.contains("Real Parsed Evidence Report"));
        assert!(report.contains("missing.example"));
        assert!(report.contains("ok.example"));
        assert!(report.contains("10.0.0.8:53000 -> 1.1.1.1:53"));
        assert!(report.contains("10.0.0.8:53001 -> 1.1.1.1:53"));
        assert!(
            report.contains(pcap_path.to_str().expect("pcap path")),
            "report should reference generated pcap artifact"
        );
        assert_eq!(document.findings.len(), 1);
        assert_eq!(document.flows.len(), 2);
        assert_eq!(document.dns_events.len(), 2);

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(pcap_path);
    }

    #[test]
    fn report_and_ioc_export_work_through_rpc_after_pcap_open() {
        if !tshark_available() {
            return;
        }

        let db_path = temp_db_path("phase8-rpc");
        let pcap_path = temp_pcap_path("phase8-rpc");
        write_test_dns_pcap(&pcap_path);

        let mut state = test_core_state(&db_path);
        let pcap_path_str = pcap_path.to_str().expect("pcap path");

        let (open_result, open_events) =
            call_rpc(&mut state, 1, "pcap.open", json!({ "path": pcap_path_str }));
        assert_eq!(open_result["status"], "ok");
        assert_eq!(open_result["flows_inserted"], 2);
        assert_eq!(open_result["dns_inserted"], 2);
        assert!(
            open_events
                .iter()
                .any(|event| event["method"] == "artifact.created")
        );
        assert!(
            open_events
                .iter()
                .any(|event| event["method"] == "flow.created")
        );
        assert!(
            open_events
                .iter()
                .any(|event| event["method"] == "dns.observed")
        );

        let (finding_result, finding_events) = call_rpc(
            &mut state,
            2,
            "dns.detect_anomalies",
            json!({ "threshold_ratio": 0.5, "min_queries": 2 }),
        );
        assert_eq!(finding_result["status"], "ok");
        assert_eq!(finding_result["findings_count"], 1);
        assert!(
            finding_events
                .iter()
                .any(|event| event["method"] == "finding.created")
        );

        let (report_result, report_events) = call_rpc(
            &mut state,
            3,
            "report.generate",
            json!({ "title": "RPC Evidence Report" }),
        );
        assert_eq!(report_result["status"], "ok");
        assert_eq!(report_result["metadata"]["finding_count"], 1);
        assert_eq!(report_result["metadata"]["flow_count"], 2);
        assert_eq!(report_result["metadata"]["dns_event_count"], 2);
        assert_eq!(report_result["metadata"]["pcap_artifact_count"], 1);
        assert!(
            report_events
                .iter()
                .any(|event| event["method"] == "report.generated")
        );

        let report_path = report_result["artifact"]["path"]
            .as_str()
            .expect("report artifact path");
        let report = std::fs::read_to_string(report_path).expect("read report");
        assert!(report.contains("RPC Evidence Report"));
        assert!(report.contains("missing.example"));
        assert!(report.contains("ok.example"));
        assert!(report.contains("10.0.0.8:53000 -> 1.1.1.1:53"));
        assert!(report.contains(pcap_path_str));

        let (ioc_result, ioc_events) = call_rpc(&mut state, 4, "ioc.export", json!({}));
        assert_eq!(ioc_result["status"], "ok");
        assert_eq!(ioc_result["counts"]["findings"], 1);
        assert_eq!(ioc_result["counts"]["flows"], 2);
        assert_eq!(ioc_result["counts"]["dns_events"], 2);
        assert_eq!(ioc_result["evidence_bundle"]["finding_count"], 1);
        assert_eq!(ioc_result["evidence_bundle"]["flow_count"], 2);
        assert_eq!(ioc_result["evidence_bundle"]["dns_event_count"], 2);
        assert_eq!(ioc_result["evidence_bundle"]["pcap_artifact_count"], 1);
        assert!(
            ioc_events
                .iter()
                .any(|event| event["method"] == "artifact.created")
        );

        let ioc_path = ioc_result["artifact"]["path"]
            .as_str()
            .expect("ioc artifact path");
        let ioc_content = std::fs::read_to_string(ioc_path).expect("read ioc export");
        let ioc_json = serde_json::from_str::<Value>(&ioc_content).expect("ioc json");
        assert_eq!(ioc_json["evidence_bundle"]["finding_count"], 1);
        assert_eq!(ioc_json["evidence_bundle"]["flow_count"], 2);
        assert_eq!(ioc_json["evidence_bundle"]["dns_event_count"], 2);
        assert_eq!(ioc_json["evidence_bundle"]["pcap_artifact_count"], 1);

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(pcap_path);
        let _ = std::fs::remove_file(report_path);
        let _ = std::fs::remove_file(ioc_path);
    }

    #[test]
    fn pcap_open_reports_parse_errors_without_registering_artifact() {
        if !tshark_available() {
            return;
        }

        let db_path = temp_db_path("phase8-invalid-pcap");
        let pcap_path = temp_pcap_path("phase8-invalid-pcap");
        std::fs::write(&pcap_path, b"not a pcap").expect("write invalid pcap");

        let mut state = test_core_state(&db_path);
        let (response, events) = call_rpc_raw(
            &mut state,
            1,
            "pcap.open",
            json!({ "path": pcap_path.to_str().expect("pcap path") }),
        );

        let error = response.error.expect("pcap.open should fail");
        assert_eq!(error.code, -32007);
        assert!(
            error.message.contains("failed to extract flows"),
            "unexpected error: {}",
            error.message
        );
        assert!(response.result.is_none());
        assert!(events.is_empty());
        assert!(state.artifact_store.list_artifacts().is_empty());

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(pcap_path);
    }

    #[test]
    fn agent_ask_creates_session_and_reuses_it_when_session_id_is_provided() {
        let db_path = temp_db_path("phase9-agent-session");
        let mut state = test_core_state(&db_path);

        let (first, first_events) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "Summarize current state." }),
        );
        let session_id = first["session"]["id"]
            .as_str()
            .expect("session id")
            .to_string();
        assert_eq!(first["phase"], "phase15");
        assert_eq!(first["session_created"], true);
        assert_eq!(first["llm"]["used"], false);
        assert!(
            first_events
                .iter()
                .any(|event| event["method"] == "session.created")
        );

        let (second, second_events) = call_rpc(
            &mut state,
            2,
            "agent.ask",
            json!({
                "session_id": session_id,
                "input": "Continue the same conversation."
            }),
        );
        assert_eq!(second["session"]["id"], first["session"]["id"]);
        assert_eq!(second["session_created"], false);
        assert!(
            !second_events
                .iter()
                .any(|event| event["method"] == "session.created")
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn session_rpc_methods_read_persisted_agent_history() {
        let db_path = temp_db_path("phase10-session-rpc");
        let mut state = test_core_state(&db_path);

        let (turn, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "Summarize current state." }),
        );
        let session_id = turn["session"]["id"].as_str().expect("session id");

        let (sessions, _) = call_rpc(&mut state, 2, "session.list", json!({}));
        assert_eq!(sessions["sessions"].as_array().expect("sessions").len(), 1);
        assert_eq!(sessions["sessions"][0]["id"], session_id);

        let (messages, _) = call_rpc(
            &mut state,
            3,
            "message.list",
            json!({ "session_id": session_id }),
        );
        let message_list = messages["messages"].as_array().expect("messages");
        assert_eq!(message_list.len(), 11);
        assert_eq!(message_list[0]["role"], "user");
        assert_eq!(message_list.last().unwrap()["role"], "assistant");
        assert_eq!(
            message_list
                .iter()
                .filter(|message| message["role"] == "tool")
                .count(),
            4
        );

        let (session, _) = call_rpc(
            &mut state,
            4,
            "session.get",
            json!({ "session_id": session_id }),
        );
        assert_eq!(session["session"]["id"], session_id);
        assert_eq!(session["messages"].as_array().expect("messages").len(), 11);
        assert_eq!(session["tool_calls"].as_array().unwrap().len(), 4);
        assert_eq!(session["steps"].as_array().expect("steps").len(), 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn agent_ask_runs_and_persists_phase11_readonly_tool_loop() {
        let db_path = temp_db_path("phase11-readonly-tool-loop");
        let mut state = test_core_state(&db_path);

        let (turn, events) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "List stored flows and findings." }),
        );
        let tool_calls = turn["tool_calls"].as_array().expect("tool calls");
        assert_eq!(turn["phase"], "phase15");
        assert_eq!(turn["resumed"], false);
        assert_eq!(tool_calls.len(), 2);
        assert_eq!(tool_calls[0]["tool_name"], "flow.list");
        assert_eq!(tool_calls[1]["tool_name"], "finding.list");
        assert!(tool_calls.iter().all(|call| call["status"] == "completed"));
        assert_eq!(
            turn["goal_analysis"]["selected_tools"],
            json!(["flow.list", "finding.list"])
        );
        assert!(
            turn["assistant_message"]["parts"][0]["content"]
                .as_str()
                .unwrap()
                .contains("stored structured evidence")
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["method"] == "agent.tool.called")
                .count(),
            2
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "agent.reasoning.ended")
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["method"] == "agent.tool.success")
                .count(),
            2
        );

        let session_id = turn["session"]["id"].as_str().unwrap();
        let (snapshot, _) = call_rpc(
            &mut state,
            2,
            "session.get",
            json!({ "session_id": session_id }),
        );
        let parts = snapshot["message_parts"].as_array().unwrap();
        assert_eq!(
            parts
                .iter()
                .filter(|part| part["kind"] == "tool_call")
                .count(),
            2
        );
        assert_eq!(
            parts
                .iter()
                .filter(|part| part["kind"] == "reasoning")
                .count(),
            1
        );
        assert_eq!(
            parts
                .iter()
                .filter(|part| part["kind"] == "tool_result")
                .count(),
            2
        );
        assert_eq!(snapshot["tool_calls"].as_array().unwrap().len(), 2);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn restored_agent_runtime_continues_ids_without_collisions() {
        let db_path = temp_db_path("phase10-restore-counters");
        let mut state = test_core_state(&db_path);

        let (first, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "Start investigation." }),
        );
        let session_id = first["session"]["id"]
            .as_str()
            .expect("session id")
            .to_string();
        drop(state);

        let mut restored = test_core_state(&db_path);
        assert_eq!(restore_agent_sessions(&mut restored).expect("restore"), 1);

        let (second, _) = call_rpc(
            &mut restored,
            2,
            "agent.ask",
            json!({
                "session_id": session_id,
                "input": "Continue after restart."
            }),
        );
        assert_eq!(second["session_created"], false);
        assert_eq!(second["assistant_message"]["id"], "msg_0014");
        assert_eq!(second["assistant_message"]["parts"][0]["id"], "part_0014");
        assert_eq!(second["step"]["id"], "step_0002");

        let (messages, _) = call_rpc(
            &mut restored,
            3,
            "message.list",
            json!({ "session_id": session_id }),
        );
        assert_eq!(messages["messages"].as_array().expect("messages").len(), 14);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn pending_permission_and_tool_call_survive_restart_and_can_be_rejected() {
        let db_path = temp_db_path("phase10-pending-permission-restore");
        let mut state = test_core_state(&db_path);

        let (proposal, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "请抓包看看当前网络是否有异常流量" }),
        );
        let session_id = proposal["session"]["id"]
            .as_str()
            .expect("session id")
            .to_string();
        let request_id = proposal["capture_proposal"]["request_id"]
            .as_str()
            .expect("request id")
            .to_string();
        assert_eq!(proposal["run_state"], "waiting_permission");
        drop(state);

        let mut restored = test_core_state(&db_path);
        restored
            .sqlite_store
            .reconcile_interrupted_runtime()
            .expect("reconcile runtime");
        assert_eq!(restore_agent_sessions(&mut restored).expect("sessions"), 1);
        assert_eq!(
            restore_pending_permissions(&mut restored).expect("pending"),
            1
        );

        let (pending, _) = call_rpc(&mut restored, 2, "permission.list_pending", json!({}));
        assert_eq!(pending["pending"].as_array().expect("pending").len(), 1);
        assert_eq!(pending["pending"][0]["id"], request_id);

        let (snapshot, _) = call_rpc(
            &mut restored,
            3,
            "session.get",
            json!({ "session_id": session_id }),
        );
        assert_eq!(snapshot["session"]["run_state"], "waiting_permission");
        assert_eq!(snapshot["pending_permissions"].as_array().unwrap().len(), 1);
        let stored_calls = snapshot["tool_calls"].as_array().unwrap();
        assert_eq!(stored_calls.len(), 1);
        assert!(
            stored_calls.iter().any(|call| {
                call["tool_name"] == "capture.start"
                    && call["status"] == "waiting_permission"
            })
        );

        let (reply, events) = call_rpc(
            &mut restored,
            4,
            "permission.reply",
            json!({
                "request_id": request_id,
                "decision": "reject",
            }),
        );
        assert_eq!(reply["status"], "rejected");
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "agent.tool.failed")
        );

        let (settled, _) = call_rpc(
            &mut restored,
            5,
            "session.get",
            json!({ "session_id": session_id }),
        );
        assert_eq!(settled["session"]["run_state"], "idle");
        assert_eq!(settled["pending_permissions"].as_array().unwrap().len(), 0);
        assert!(
            settled["tool_calls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|call| {
                    call["tool_name"] == "capture.start" && call["status"] == "aborted"
                })
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn interrupted_steps_tools_and_sessions_are_reconciled_on_restart() {
        let db_path = temp_db_path("phase10-interrupted-recovery");
        let store = SqliteStore::open(&db_path).expect("open store");
        let session = netagent_models::Session {
            id: String::from("ses_0042"),
            mode: AgentMode::Observe,
            run_state: RunState::RunningTool,
            max_steps: 8,
        };
        store.save_session(&session).expect("save session");
        store
            .insert_step(&netagent_models::Step {
                id: String::from("step_0042"),
                session_id: session.id.clone(),
                status: StepStatus::Running,
                attempt: 1,
            })
            .expect("save step");
        store
            .insert_tool_call(&ToolCall {
                id: String::from("call_0042"),
                session_id: session.id.clone(),
                step_id: String::from("step_0042"),
                tool_name: String::from("flow.list"),
                input: String::from("{}"),
                status: ToolCallStatus::Running,
            })
            .expect("save tool call");

        let summary = store
            .reconcile_interrupted_runtime()
            .expect("reconcile runtime");
        assert_eq!(summary.aborted_steps, 1);
        assert_eq!(summary.aborted_tool_calls, 1);
        assert_eq!(summary.errored_sessions, 1);
        assert_eq!(
            store.load_session(&session.id).unwrap().unwrap().run_state,
            RunState::Error
        );
        assert_eq!(
            store.load_steps(&session.id).unwrap()[0].status,
            StepStatus::Aborted
        );
        assert_eq!(
            store.load_tool_calls(&session.id).unwrap()[0].status,
            ToolCallStatus::Aborted
        );

        drop(store);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn always_permission_rules_are_restored_from_sqlite() {
        let db_path = temp_db_path("phase10-permission-rules");
        let store = SqliteStore::open(&db_path).expect("open store");
        store
            .save_permission_rules(&[String::from("capture_live:mock1:*")])
            .expect("save permission rule");
        drop(store);

        let mut restored = test_core_state(&db_path);
        restore_permission_rules(&mut restored).expect("restore permission rules");
        assert!(
            restored
                .permission_manager
                .evaluate(PermissionKind::CaptureLive, &[String::from("mock1")],)
        );

        drop(restored);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn bounded_tool_result_and_completed_call_are_available_in_session_snapshot() {
        let db_path = temp_db_path("phase10-tool-snapshot");
        let mut state = test_core_state(&db_path);
        let (turn, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "Hello NetAgent." }),
        );
        let session_id = turn["session"]["id"].as_str().unwrap();
        let message_id = turn["assistant_message"]["id"].as_str().unwrap();
        let step_id = turn["step"]["id"].as_str().unwrap();

        let (tool, events) = call_rpc(
            &mut state,
            2,
            "tool.mock_large_output",
            json!({
                "session_id": session_id,
                "message_id": message_id,
                "step_id": step_id,
                "query": "Summarize mock flows without returning raw output."
            }),
        );
        assert_eq!(tool["tool_result"]["truncated"], true);
        assert!(tool["tool_result"]["raw_output_artifact"].is_object());
        let raw_output_path = tool["tool_result"]["raw_output_artifact"]["path"]
            .as_str()
            .expect("raw output artifact path")
            .to_string();
        assert!(std::path::Path::new(&raw_output_path).exists());
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "agent.tool.success")
        );

        let (snapshot, _) = call_rpc(
            &mut state,
            3,
            "session.get",
            json!({ "session_id": session_id }),
        );
        assert_eq!(snapshot["tool_calls"].as_array().unwrap().len(), 1);
        assert_eq!(snapshot["tool_calls"][0]["tool_name"], "mock.large_output");
        assert_eq!(snapshot["tool_calls"][0]["status"], "completed");
        assert_eq!(snapshot["message_parts"].as_array().unwrap().len(), 3);

        let raw = rusqlite::Connection::open(&db_path).expect("inspect sqlite");
        let message_part_count: usize = raw
            .query_row("SELECT COUNT(*) FROM message_parts", [], |row| row.get(0))
            .expect("count message parts");
        assert_eq!(message_part_count, 3);

        drop(raw);
        drop(state);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(raw_output_path);
    }

    #[test]
    fn agent_ask_requests_permission_when_live_capture_is_needed() {
        let db_path = temp_db_path("phase9-agent-capture-proposal");
        let mut state = test_core_state(&db_path);

        let (result, events) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "请抓包看看当前网络是否有异常流量" }),
        );

        assert_eq!(result["phase"], "phase15");
        assert_eq!(result["run_state"], "waiting_permission");
        assert_eq!(result["capture_proposal"]["status"], "waiting_permission");
        assert_eq!(result["capture_proposal"]["capture"]["duration"], 10);
        assert!(!result["permission_request_id"].as_str().unwrap().is_empty());
        assert_eq!(
            events
                .iter()
                .filter(|event| event["method"] == "permission.asked")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["method"] == "agent.tool.called")
                .count(),
            1
        );
        assert_eq!(state.permission_manager.list_pending().len(), 1);
        assert!(state.capture_job.is_none());

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn rejected_capture_permission_resumes_with_offline_pcap_analysis() {
        if !tshark_available() {
            return;
        }

        let db_path = temp_db_path("phase12-resume-replan");
        let pcap_path = temp_pcap_path("phase12-resume-replan");
        write_test_dns_pcap(&pcap_path);
        let pcap_path_str = pcap_path.to_str().expect("pcap path").to_string();
        let mut state = test_core_state(&db_path);

        let (proposal, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "请实时抓包分析当前网络是否存在 DNS 异常" }),
        );
        assert_eq!(proposal["run_state"], "waiting_permission");
        let session_id = proposal["session"]["id"]
            .as_str()
            .expect("session id")
            .to_string();
        let request_id = proposal["permission_request_id"]
            .as_str()
            .expect("request id")
            .to_string();

        let (reply, _) = call_rpc(
            &mut state,
            2,
            "permission.reply",
            json!({
                "request_id": request_id,
                "decision": "reject_with_feedback",
                "feedback": format!("不要实时抓包，请分析本地 pcap 文件 {pcap_path_str}"),
            }),
        );
        assert_eq!(reply["status"], "rejected");

        let (resumed, events) = call_rpc(
            &mut state,
            3,
            "agent.resume",
            json!({ "session_id": session_id }),
        );
        assert_eq!(resumed["resumed"], true);
        assert_eq!(resumed["run_state"], "idle");
        let tool_names = resumed["tool_calls"]
            .as_array()
            .expect("tool calls")
            .iter()
            .map(|call| call["tool_name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            tool_names,
            vec![
                "capture.start",
                "pcap.open",
                "dns.detect_anomalies",
                "report.generate",
                "ioc.export"
            ]
        );
        assert_eq!(resumed["tool_calls"][0]["status"], "aborted");
        assert!(
            resumed["tool_calls"]
                .as_array()
                .unwrap()
                .iter()
                .all(|call| call["tool_name"] != "capture.start"
                    || call["status"] == "aborted")
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "agent.tool.success")
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "finding.created")
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "pcap.created")
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "report.generated")
        );
        assert!(
            resumed["assistant_message"]["parts"][0]["content"]
                .as_str()
                .unwrap()
                .contains("离线")
        );

        let (snapshot, _) = call_rpc(
            &mut state,
            4,
            "session.get",
            json!({ "session_id": session_id }),
        );
        assert_eq!(snapshot["session"]["run_state"], "idle");
        assert_eq!(snapshot["tool_calls"].as_array().unwrap().len(), 5);
        assert_eq!(
            snapshot["steps"].as_array().unwrap()[0]["status"],
            "completed"
        );

        let (findings, _) = call_rpc(&mut state, 5, "finding.list", json!({}));
        assert_eq!(findings["total"], 1);
        assert_eq!(
            findings["findings"][0]["category"],
            "dns_anomaly"
        );

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(pcap_path);
    }

    #[test]
    fn approved_capture_permission_waits_for_completion_then_resumes() {
        let db_path = temp_db_path("phase12-resume-approved");
        let mut state = test_core_state(&db_path);

        let (proposal, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": "请抓包分析当前网络" }),
        );
        assert_eq!(proposal["run_state"], "waiting_permission");
        let session_id = proposal["session"]["id"]
            .as_str()
            .expect("session id")
            .to_string();
        let request_id = proposal["permission_request_id"]
            .as_str()
            .expect("request id")
            .to_string();

        let (reply, _) = call_rpc(
            &mut state,
            2,
            "permission.reply",
            json!({ "request_id": request_id, "decision": "reject" }),
        );
        assert_eq!(reply["status"], "rejected");

        let (resumed, events) = call_rpc(
            &mut state,
            3,
            "agent.resume",
            json!({ "session_id": session_id }),
        );
        assert_eq!(resumed["resumed"], true);
        assert_eq!(resumed["run_state"], "idle");
        assert_eq!(resumed["tool_calls"][0]["tool_name"], "capture.start");
        assert_eq!(resumed["tool_calls"][0]["status"], "aborted");
        assert!(
            resumed["assistant_message"]["parts"][0]["content"]
                .as_str()
                .unwrap()
                .contains("替代方案")
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "agent.tool.failed")
        );

        let (resume_again, _) = call_rpc_raw(
            &mut state,
            4,
            "agent.resume",
            json!({ "session_id": session_id }),
        );
        assert_eq!(
            resume_again.error.expect("no continuation error").code,
            -32013
        );
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn offline_pcap_plan_runs_through_agent_loop_directly() {
        if !tshark_available() {
            return;
        }

        let db_path = temp_db_path("phase12-offline-plan");
        let pcap_path = temp_pcap_path("phase12-offline-plan");
        write_test_dns_pcap(&pcap_path);
        let pcap_path_str = pcap_path.to_str().expect("pcap path").to_string();
        let mut state = test_core_state(&db_path);

        let (result, events) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": format!("请分析本地 pcap 文件 {pcap_path_str} 中的 DNS 异常并生成报告") }),
        );
        assert_eq!(result["run_state"], "idle");
        let tool_names = result["tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|call| call["tool_name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            tool_names,
            vec!["pcap.open", "dns.detect_anomalies", "report.generate", "ioc.export"]
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "finding.created")
        );
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "report.generated")
        );
        assert!(
            result["assistant_message"]["parts"][0]["content"]
                .as_str()
                .unwrap()
                .contains("dns_nxdomain_spike")
        );
        assert!(
            result["assistant_message"]["parts"][0]["content"]
                .as_str()
                .unwrap()
                .contains("1 finding(s)")
        );

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(pcap_path);
    }

    #[test]
    fn firewall_proposal_requires_typed_confirmation_and_stays_traceable() {
        if !tshark_available() {
            return;
        }

        let db_path = temp_db_path("phase13-firewall-proposal");
        let pcap_path = temp_pcap_path("phase13-firewall-proposal");
        write_test_dns_pcap(&pcap_path);
        let pcap_path_str = pcap_path.to_str().expect("pcap path").to_string();
        let mut state = test_core_state(&db_path);

        // Build evidence: offline analysis creates the NXDOMAIN finding.
        let (evidence, _) = call_rpc(
            &mut state,
            1,
            "agent.ask",
            json!({ "input": format!("请分析本地 pcap 文件 {pcap_path_str} 中的 DNS 异常") }),
        );
        let (findings, _) = call_rpc(&mut state, 2, "finding.list", json!({}));
        assert_eq!(findings["total"], 1);
        let finding_id = findings["findings"][0]["id"]
            .as_str()
            .expect("finding id")
            .to_string();

        // Agent proposes a firewall rule for the finding's entity.
        let (proposal, events) = call_rpc(
            &mut state,
            3,
            "agent.ask",
            json!({ "input": format!("请对 {finding_id} 的实体 10.0.0.8 提出防火墙封禁建议") }),
        );
        assert_eq!(proposal["run_state"], "waiting_permission");
        assert_eq!(proposal["capture_proposal"]["require_typed_confirmation"], true);
        let session_id = proposal["session"]["id"]
            .as_str()
            .expect("session id")
            .to_string();
        let request_id = proposal["permission_request_id"]
            .as_str()
            .expect("request id")
            .to_string();
        assert_ne!(session_id, evidence["session"]["id"].as_str().unwrap());
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "permission.asked")
        );
        let (pending, _) = call_rpc(&mut state, 4, "permission.list_pending", json!({}));
        assert_eq!(pending["pending"].as_array().unwrap().len(), 1);
        assert_eq!(pending["pending"][0]["permission"], "modify_firewall");
        assert_eq!(pending["pending"][0]["risk"], "high");
        assert_eq!(pending["pending"][0]["require_typed_confirmation"], true);
        assert_eq!(
            pending["pending"][0]["metadata"]["confirm_phrase"],
            "BLOCK 10.0.0.8"
        );
        assert!(
            pending["pending"][0]["metadata"]["command_preview"]
                .as_str()
                .unwrap()
                .contains("PREVIEW ONLY")
        );

        // Missing typed confirmation is rejected and the request stays pending.
        let (bad_reply, _) = call_rpc_raw(
            &mut state,
            5,
            "permission.reply",
            json!({ "request_id": request_id, "decision": "once" }),
        );
        assert_eq!(bad_reply.error.expect("error").code, -32014);
        let (still_pending, _) = call_rpc(&mut state, 6, "permission.list_pending", json!({}));
        assert_eq!(still_pending["pending"].as_array().unwrap().len(), 1);

        // Wrong phrase is also rejected.
        let (wrong_reply, _) = call_rpc_raw(
            &mut state,
            7,
            "permission.reply",
            json!({
                "request_id": request_id,
                "decision": "once",
                "typed_confirmation": "BLOCK 1.1.1.1"
            }),
        );
        assert_eq!(wrong_reply.error.expect("error").code, -32014);

        // Correct phrase approves; a proposal artifact is created, never executed.
        let (approved, approve_events) = call_rpc(
            &mut state,
            8,
            "permission.reply",
            json!({
                "request_id": request_id,
                "decision": "once",
                "typed_confirmation": "BLOCK 10.0.0.8"
            }),
        );
        assert_eq!(approved["status"], "approved");
        assert_eq!(approved["executed"], false);
        assert_eq!(approved["proposal"]["target"], "10.0.0.8");
        assert!(
            approve_events
                .iter()
                .any(|event| event["method"] == "respond.proposal.created")
        );
        assert!(
            approve_events
                .iter()
                .any(|event| event["method"] == "artifact.created")
        );

        let proposal_path = approved["artifact"]["path"].as_str().expect("proposal path");
        let proposal_content = std::fs::read_to_string(proposal_path).expect("read proposal");
        assert!(proposal_content.contains("NOT executed"));
        assert!(proposal_content.contains("10.0.0.8"));
        assert!(proposal_content.contains(finding_id.as_str()));
        assert!(proposal_content.contains("evidence"));

        // Resume: the agent finalizes with the proposal reference.
        let (resumed, _) = call_rpc(
            &mut state,
            9,
            "agent.resume",
            json!({ "session_id": session_id }),
        );        assert_eq!(resumed["run_state"], "idle");
        assert_eq!(
            resumed["tool_calls"].as_array().unwrap()[0]["tool_name"],
            "respond.propose_firewall_rule"
        );
        assert_eq!(
            resumed["tool_calls"].as_array().unwrap()[0]["status"],
            "completed"
        );

        // Nothing was executed against the system: no pfctl subprocess exists
        // in this test path and the proposal is the only record.
        assert!(state.capture_job.is_none());
        assert!(state.pending_respond.is_none());

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(pcap_path);
        let _ = std::fs::remove_file(proposal_path);
    }
}
