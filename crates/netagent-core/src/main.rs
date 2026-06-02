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
use crate::core::agent::{MockAgentRun, MockAgentRuntime};
use crate::core::permissions::{PermissionManager, PermissionOutcome};
use crate::runtime::tool_registry::{ToolContext, ToolRegistry, ToolResult};
use crate::storage::artifact_store::ArtifactStore;
use crate::storage::sqlite::SqliteStore;
use crate::tools::tshark;
use netagent_models::{
    AgentMode, PermissionDecision, PermissionKind, PermissionMetadata, PermissionReply,
    PermissionReplyKind, PermissionRequest, RiskLevel, RunState, StepStatus, ToolCallStatus,
    ToolRef,
};
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
    agent_runtime: MockAgentRuntime,
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
        agent_runtime: MockAgentRuntime::default(),
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

    write_message(
        &mut stdout,
        &RpcNotification {
            jsonrpc: JSON_RPC_VERSION,
            method: "event.core.ready",
            params: json!({
                "phase": "phase7",
                "protocol_version": JSON_RPC_VERSION,
                "message": "NetAgent core ready — Phase 7 parsing and first finding."
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
            "phase": "phase7",
            "message": "pong"
        })),
        "core.capabilities" => Ok(json!({
            "protocol_version": JSON_RPC_VERSION,
            "phase": "phase7",
            "methods": [
                "system.ping",
                "core.capabilities",
                "system.list_interfaces",
                "agent.ask",
                "agent.abort",
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
                "finding.list"
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
                "pcap.created"
            ],
            "limits": {
                "high_frequency_packet_events": false,
                "max_steps": 4
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
                .unwrap_or("Describe current network state.");

            let run = state.agent_runtime.run_mock_turn(input);
            let tool_result = match execute_mock_large_output_tool(state, writer, &run, input) {
                Ok(result) => result,
                Err(error) => return Ok(error_response(request.id, error)),
            };
            emit_agent_run_events(writer, &run, &tool_result)?;

            Ok(MockAgentRuntime::build_agent_response_with_tool_result(
                &run,
                &tool_result,
            ))
        }
        "agent.abort" => Ok(json!({
            "aborted": false,
            "run_state": RunState::Idle,
            "message": "No long-running mock step is active in Phase 6."
        })),
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

fn emit_agent_run_events<W: Write>(
    writer: &mut W,
    run: &MockAgentRun,
    tool_result: &ToolResult,
) -> io::Result<()> {
    emit_event(
        writer,
        "session.created",
        json!({ "session": run.session_started }),
    )?;
    emit_event(
        writer,
        "message.created",
        json!({ "message": run.user_message }),
    )?;
    emit_event(
        writer,
        "message.created",
        json!({ "message": run.assistant_message }),
    )?;
    emit_event(
        writer,
        "agent.step.started",
        json!({
            "step": {
                "id": run.step.id,
                "session_id": run.step.session_id,
                "attempt": run.step.attempt,
                "status": StepStatus::Running,
            }
        }),
    )?;
    emit_event(
        writer,
        "agent.text.started",
        json!({
            "session_id": run.session_started.id,
            "message_id": run.assistant_message.id,
            "part_id": run.assistant_message.parts[0].id,
        }),
    )?;
    emit_event(
        writer,
        "agent.text.delta",
        json!({
            "session_id": run.session_started.id,
            "message_id": run.assistant_message.id,
            "part_id": run.assistant_message.parts[0].id,
            "delta": run.assistant_message.parts[0].content,
        }),
    )?;
    emit_event(
        writer,
        "agent.text.ended",
        json!({
            "session_id": run.session_started.id,
            "message_id": run.assistant_message.id,
            "part_id": run.assistant_message.parts[0].id,
        }),
    )?;
    emit_event(
        writer,
        "agent.tool.called",
        json!({
            "tool_call": {
                "id": run.tool_call.id,
                "session_id": run.tool_call.session_id,
                "step_id": run.tool_call.step_id,
                "tool_name": run.tool_call.tool_name,
                "input": run.tool_call.input,
                "status": ToolCallStatus::Pending,
            }
        }),
    )?;
    emit_event(
        writer,
        "agent.tool.success",
        json!({
            "tool_call": run.tool_call,
            "summary": tool_result.summary,
            "tool_result": tool_result,
        }),
    )?;
    emit_event(
        writer,
        "finding.created",
        json!({
            "id": "finding_mock_0001",
            "severity": "low",
            "title": "Large tool output truncated",
            "summary": "Assistant response uses artifact refs instead of raw tool output.",
            "evidence": tool_result.artifacts,
        }),
    )?;
    emit_event(
        writer,
        "agent.step.ended",
        json!({
            "step": run.step,
            "run_state": run.final_run_state,
            "phase": "phase4",
        }),
    )
}

fn execute_mock_large_output_tool<W: Write>(
    state: &mut CoreState,
    writer: &mut W,
    run: &MockAgentRun,
    query: &str,
) -> Result<ToolResult, RpcError> {
    let context = ToolContext {
        session_id: run.session_started.id.clone(),
        message_id: run.assistant_message.id.clone(),
        call_id: run.tool_call.id.clone(),
        agent: AgentMode::Observe,
        abort: false,
    };
    let (tool_result, progress) =
        state
            .tool_registry
            .run_mock_large_output(&context, query, &mut state.artifact_store);

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

    Ok(tool_result)
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
            reason: format!("Capture live packets from interface {interface}"),
        },
        tool: ToolRef {
            message_id: String::from("msg_capture_0001"),
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

    // Register pcap as an artifact
    let artifact = state
        .artifact_store
        .register_pcap(path, &format!("pcap opened from {path}"));
    let _ = emit_event(writer, "artifact.created", json!({ "artifact": artifact }));

    // Run tshark to extract flows
    let mut flows = tshark::extract_flows(pcap_path).unwrap_or_default();
    // Assign IDs
    for flow in &mut flows {
        flow.id = next_counter_id("flow", &mut state.tool_counter);
    }
    let flow_count = flows.len();
    let flow_inserted = state
        .sqlite_store
        .insert_flows(&flows)
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

    // Run tshark to extract DNS
    let mut dns_events = tshark::extract_dns(pcap_path).unwrap_or_default();
    for event in &mut dns_events {
        event.id = next_counter_id("dns", &mut state.tool_counter);
    }
    let dns_count = dns_events.len();
    let dns_inserted = state
        .sqlite_store
        .insert_dns_events(&dns_events)
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

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

fn handle_pcap_summarize(
    _state: &CoreState,
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
    let flows = tshark::extract_flows(pcap_path).unwrap_or_default();
    let dns_events = tshark::extract_dns(pcap_path).unwrap_or_default();

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
    let findings = state
        .sqlite_store
        .list_findings()
        .map_err(|e| RpcError {
            code: -32007,
            message: e,
        })?;

    Ok(json!({
        "findings": findings,
        "total": findings.len(),
    }))
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
