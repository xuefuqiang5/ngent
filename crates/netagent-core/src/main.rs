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

use crate::analyzers::dns::detect_nxdomain_spike;
use crate::core::agent::{AgentAskInput, AgentRuntime, AgentTurn, SessionRecord};
use crate::core::permissions::{PermissionManager, PermissionOutcome};
use crate::reports::markdown::{
    EvidenceBundleMetadata, MarkdownReportInput, build_evidence_bundle_metadata,
    build_markdown_report,
};
use crate::runtime::tool_registry::{ToolContext, ToolRegistry};
use crate::storage::artifact_store::ArtifactStore;
use crate::storage::sqlite::SqliteStore;
use crate::tools::tshark;
use netagent_models::{
    AgentMode, PermissionDecision, PermissionKind, PermissionMetadata, PermissionReply,
    PermissionReplyKind, PermissionRequest, RiskLevel, RunState, StepStatus, ToolCallStatus,
    ToolRef,
};
use netagent_models::{ArtifactRef, DnsEvent, Finding, Flow};
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
    capture_job: Option<CaptureJob>,
    pending_capture: Option<PendingCapture>,
    permission_counter: u64,
    capture_counter: u64,
    tool_counter: u64,
    finding_counter: u64,
}

#[derive(Debug)]
struct PendingCapture {
    request_id: String,
    session_id: String,
    interface: String,
    filter: String,
    duration_secs: u64,
}

#[derive(Debug)]
struct CaptureJob {
    id: String,
    session_id: String,
    interface: String,
    filter: String,
    duration_secs: u64,
    started_at: Instant,
    pcap_path: String,
    child: Child,
}

#[derive(Debug, Clone)]
struct AgentCapturePlan {
    interface: String,
    filter: String,
    duration_secs: u64,
    reason: String,
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
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    let mut db_path = std::env::temp_dir();
    db_path.push("netagent-captures");
    std::fs::create_dir_all(&db_path).ok();
    db_path.push("netagent.db");
    let sqlite_store =
        SqliteStore::open(&db_path).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut state = CoreState {
        agent_runtime: AgentRuntime::from_env(),
        permission_manager: PermissionManager::default(),
        tool_registry: ToolRegistry,
        artifact_store: ArtifactStore::default(),
        sqlite_store,
        capture_job: None,
        pending_capture: None,
        permission_counter: 0,
        capture_counter: 0,
        tool_counter: 0,
        finding_counter: 0,
    };

    // Restore persisted sessions from SQLite so conversation history survives restarts
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

    write_message(
        &mut stdout,
        &RpcNotification {
            jsonrpc: JSON_RPC_VERSION,
            method: "event.core.ready",
            params: json!({
                "phase": "phase10",
                "protocol_version": JSON_RPC_VERSION,
                "message": "NetAgent core ready - Phase 10 session persistence."
            }),
        },
    )?;

    for line_result in stdin.lock().lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RpcRequest>(&line) {
            Ok(request) => {
                reconcile_capture_state(&mut state, &mut stdout)?;
                handle_request(request, &mut state, &mut stdout)?
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

        write_message(&mut stdout, &response)?;
    }

    Ok(())
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
            "phase": "phase10",
            "message": "pong"
        })),
        "core.capabilities" => Ok(json!({
            "protocol_version": JSON_RPC_VERSION,
            "phase": "phase10",
            "methods": [
                "system.ping",
                "core.capabilities",
                "system.list_interfaces",
                "agent.ask",
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
                "agent.step.started",
                "agent.text.started",
                "agent.text.delta",
                "agent.text.ended",
                "agent.tool.called",
                "agent.tool.progress",
                "agent.tool.success",
                "agent.step.ended",
                "permission.asked",
                "permission.replied",
                "artifact.created",
                "finding.created",
                "capture.started",
                "capture.stopped",
                "pcap.created",
                "report.generated"
            ],
            "llm": state.agent_runtime.llm_status(),
            "limits": {
                "high_frequency_packet_events": false,
                "max_steps": 8
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
            let capture_plan = build_agent_capture_plan(state, &input);

            let turn = match state.agent_runtime.run_turn(AgentAskInput {
                session_id,
                mode: AgentMode::Observe,
                input,
                context_summary,
                capture_recommendation: capture_plan
                    .as_ref()
                    .map(agent_capture_recommendation_text),
            }) {
                Ok(turn) => {
                    // Persist the turn to SQLite
                    if let Err(error) = persist_agent_turn(&state.sqlite_store, &turn) {
                        let _ = writeln!(
                            io::stderr(),
                            "netagent-core: failed to persist agent turn: {error}"
                        );
                    }
                    turn
                }
                Err(message) => {
                    return Ok(error_response(
                        request.id,
                        RpcError {
                            code: -32010,
                            message,
                        },
                    ));
                }
            };

            emit_agent_turn_events(writer, &turn)?;
            let mut result = AgentRuntime::build_agent_response(&turn);
            if let Some(plan) = capture_plan {
                let proposal = match request_capture_permission(
                    state,
                    writer,
                    &turn.session_finished.id,
                    &plan.interface,
                    &plan.filter,
                    plan.duration_secs,
                    &plan.reason,
                    &turn.assistant_message.id,
                ) {
                    Ok(proposal) => proposal,
                    Err(error) => return Ok(error_response(request.id, error)),
                };
                result["capture_proposal"] = proposal;
            }
            Ok(result)
        }
        "agent.abort" => Ok(json!({
            "aborted": false,
            "run_state": RunState::Idle,
            "message": "No long-running agent step is active in Phase 10."
        })),
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

fn emit_agent_turn_events<W: Write>(writer: &mut W, turn: &AgentTurn) -> io::Result<()> {
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
        "message.created",
        json!({ "message": turn.assistant_message }),
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
    emit_event(
        writer,
        "agent.step.ended",
        json!({
            "step": turn.step,
            "run_state": turn.final_run_state,
            "phase": "phase10",
            "llm": {
                "used": turn.llm_used,
                "model": turn.llm_model,
            }
        }),
    )
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
    let call_id = next_counter_id("call", &mut state.tool_counter);

    let context = ToolContext {
        session_id: session_id.to_string(),
        message_id: message_id.to_string(),
        call_id: call_id.clone(),
        agent: AgentMode::Observe,
        abort: false,
    };
    let (tool_result, progress) =
        state
            .tool_registry
            .run_mock_large_output(&context, query, &mut state.artifact_store);

    emit_event(
        writer,
        "agent.tool.called",
        json!({
            "tool_call": {
                "id": call_id,
                "session_id": session_id,
                "step_id": "step_tool_0001",
                "tool_name": "mock.large_output",
                "input": query,
                "status": ToolCallStatus::Pending,
            }
        }),
    )
    .map_err(|error| RpcError {
        code: -32001,
        message: format!("failed to emit tool.called: {error}"),
    })?;

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

fn build_agent_capture_plan(state: &CoreState, input: &str) -> Option<AgentCapturePlan> {
    if state.capture_job.is_some() || state.pending_capture.is_some() {
        return None;
    }

    let lower = input.to_lowercase();
    if lower.contains("stop capture")
        || lower.contains("停止抓包")
        || lower.contains("不要抓包")
        || lower.contains("不用抓包")
    {
        return None;
    }

    let wants_live_evidence = lower.contains("抓包")
        || lower.contains("capture")
        || lower.contains("packet")
        || lower.contains("live")
        || lower.contains("实时")
        || lower.contains("当前网络")
        || lower.contains("现在网络")
        || lower.contains("流量")
        || lower.contains("可疑")
        || lower.contains("异常");

    if !wants_live_evidence {
        return None;
    }

    Some(AgentCapturePlan {
        interface: String::from("mock1"),
        filter: String::from("tcp or dns"),
        duration_secs: 10,
        reason: String::from(
            "The request needs fresh live network evidence. NetAgent proposes a short bounded capture before making stronger claims.",
        ),
    })
}

fn agent_capture_recommendation_text(plan: &AgentCapturePlan) -> String {
    format!(
        "I recommend requesting user approval for a bounded live capture: interface={}, filter={}, duration={}s. Reason: {}",
        plan.interface, plan.filter, plan.duration_secs, plan.reason
    )
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

/// Persist the result of a single agent turn to SQLite.
fn persist_agent_turn(store: &SqliteStore, turn: &AgentTurn) -> Result<(), String> {
    store.save_agent_turn(
        &turn.session_finished,
        &turn.user_message,
        &turn.assistant_message,
        &turn.step,
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

    Ok(json!({
        "session": session,
        "messages": messages,
        "steps": steps
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
        session_id,
        interface,
        filter,
        duration,
        &format!("Capture live packets from interface {interface}"),
        "msg_capture_0001",
    )
}

fn request_capture_permission<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    session_id: &str,
    interface: &str,
    filter: &str,
    duration: u64,
    reason: &str,
    message_id: &str,
) -> Result<Value, RpcError> {
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
        },
        tool: ToolRef {
            message_id: message_id.to_string(),
            call_id: next_counter_id("call", &mut state.capture_counter),
        },
    };

    match state.permission_manager.ask(request.clone()) {
        PermissionDecision::Pending => {
            state.pending_capture = Some(PendingCapture {
                request_id: request.id.clone(),
                session_id: session_id.to_string(),
                interface: interface.to_string(),
                filter: filter.to_string(),
                duration_secs: duration,
            });
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
            session_id,
            interface,
            filter,
            duration,
            "approved_always",
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

    let reply = PermissionReply {
        request_id: request_id.to_string(),
        decision,
        feedback,
    };

    let outcome = state
        .permission_manager
        .reply(reply)
        .ok_or_else(|| RpcError {
            code: -32602,
            message: format!("pending request not found: {request_id}"),
        })?;

    let _ = emit_permission_replied(writer, &outcome);

    match outcome.decision {
        PermissionDecision::AllowedOnce => {
            start_capture_from_pending(state, writer, &outcome.request.id, "approved_once")
        }
        PermissionDecision::AllowedAlways => {
            start_capture_from_pending(state, writer, &outcome.request.id, "approved_always")
        }
        PermissionDecision::Rejected => {
            state.pending_capture = None;
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

fn handle_capture_status(state: &mut CoreState) -> Result<Value, RpcError> {
    Ok(match &state.capture_job {
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
    })
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
        &pending.session_id,
        &pending.interface,
        &pending.filter,
        pending.duration_secs,
        approval_status,
    )
}

fn start_capture_job<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    session_id: &str,
    interface: &str,
    filter: &str,
    duration_secs: u64,
    approval_status: &str,
) -> Result<Value, RpcError> {
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
    let child = spawn_tcpdump(interface, filter, &pcap_path).map_err(|error| RpcError {
        code: -32005,
        message: error,
    })?;

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
        interface: interface.to_string(),
        filter: filter.to_string(),
        duration_secs,
        started_at: Instant::now(),
        pcap_path: pcap_path.to_string_lossy().to_string(),
        child,
    });

    Ok(json!({
        "status": approval_status,
        "capture_id": capture_id,
        "interface": interface,
        "filter": filter,
        "duration_secs": duration_secs,
        "pcap_path": pcap_path,
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

    if should_finalize {
        if let Some(job) = state.capture_job.take() {
            let _ = finalize_capture_job(state, writer, job, "completed")?;
        }
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
    let threshold_ratio = params
        .get("threshold_ratio")
        .and_then(Value::as_f64)
        .unwrap_or(0.3);
    let min_queries = params
        .get("min_queries")
        .and_then(Value::as_u64)
        .unwrap_or(5) as usize;

    let findings = detect_nxdomain_spike(
        &state.sqlite_store,
        &mut state.finding_counter,
        threshold_ratio,
        min_queries,
    )
    .map_err(|e| RpcError {
        code: -32008,
        message: e,
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

    let input = collect_report_input(&state.sqlite_store, &state.artifact_store, title)?;
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

fn list_flows_for_export(store: &SqliteStore) -> Result<Vec<Flow>, RpcError> {
    store.list_flows().map_err(|message| RpcError {
        code: -32007,
        message,
    })
}

fn list_dns_events_for_export(store: &SqliteStore) -> Result<Vec<DnsEvent>, RpcError> {
    store.list_dns_events().map_err(|message| RpcError {
        code: -32007,
        message,
    })
}

fn list_findings_for_export(store: &SqliteStore) -> Result<Vec<Finding>, RpcError> {
    store.list_findings().map_err(|message| RpcError {
        code: -32007,
        message,
    })
}

fn collect_report_input(
    store: &SqliteStore,
    artifact_store: &ArtifactStore,
    title: &str,
) -> Result<MarkdownReportInput, RpcError> {
    Ok(MarkdownReportInput {
        title: title.to_string(),
        findings: list_findings_for_export(store)?,
        flows: list_flows_for_export(store)?,
        dns_events: list_dns_events_for_export(store)?,
        artifacts: artifact_store.list_artifacts(),
    })
}

fn build_ioc_export_document(
    store: &SqliteStore,
    artifact_store: &ArtifactStore,
) -> Result<IocExportDocument, RpcError> {
    let input = collect_report_input(store, artifact_store, "NetAgent IOC Export")?;
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

    fn test_core_state(db_path: &PathBuf) -> CoreState {
        CoreState {
            agent_runtime: AgentRuntime::disabled(),
            permission_manager: PermissionManager::default(),
            tool_registry: ToolRegistry,
            artifact_store: ArtifactStore::default(),
            sqlite_store: SqliteStore::open(db_path).expect("open sqlite store"),
            capture_job: None,
            pending_capture: None,
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
        assert_eq!(first["phase"], "phase10");
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
        assert_eq!(message_list.len(), 2);
        assert_eq!(message_list[0]["role"], "user");
        assert_eq!(message_list[1]["role"], "assistant");

        let (session, _) = call_rpc(
            &mut state,
            4,
            "session.get",
            json!({ "session_id": session_id }),
        );
        assert_eq!(session["session"]["id"], session_id);
        assert_eq!(session["messages"].as_array().expect("messages").len(), 2);
        assert_eq!(session["steps"].as_array().expect("steps").len(), 1);

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
        assert_eq!(second["assistant_message"]["id"], "msg_0004");
        assert_eq!(second["assistant_message"]["parts"][0]["id"], "part_0004");
        assert_eq!(second["step"]["id"], "step_0002");

        let (messages, _) = call_rpc(
            &mut restored,
            3,
            "message.list",
            json!({ "session_id": session_id }),
        );
        assert_eq!(messages["messages"].as_array().expect("messages").len(), 4);

        let _ = std::fs::remove_file(db_path);
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

        assert_eq!(result["phase"], "phase10");
        assert_eq!(result["capture_proposal"]["status"], "waiting_permission");
        assert_eq!(result["capture_proposal"]["capture"]["duration"], 10);
        assert!(
            events
                .iter()
                .any(|event| event["method"] == "permission.asked")
        );
        assert_eq!(state.permission_manager.list_pending().len(), 1);
        assert!(state.capture_job.is_none());

        let _ = std::fs::remove_file(db_path);
    }
}
