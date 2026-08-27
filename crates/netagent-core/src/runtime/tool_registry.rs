use netagent_models::{AgentMode, ArtifactRef};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::atomic::AtomicBool;

use crate::analyzers::rules::{load_rule_manifests, run_all_rules};
use crate::reports::markdown::{
    build_evidence_bundle_metadata, build_markdown_report, collect_report_input,
};
use crate::storage::artifact_store::ArtifactStore;
use crate::storage::sqlite::SqliteStore;
use crate::tools::{suricata, system_shell, tshark, zeek};

const DEFAULT_LIST_LIMIT: usize = 12;
const MAX_LIST_LIMIT: usize = 25;
const MAX_TOOL_ERROR_CHARS: usize = 500;
const DEFAULT_CAPTURE_DURATION: u64 = 10;
const MAX_CAPTURE_DURATION: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub id: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub permissions: Vec<String>,
    pub risk: String,
    pub timeout_ms: Option<u64>,
    pub truncate_at: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPermissionContext {
    pub required: bool,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContext {
    pub session_id: String,
    pub message_id: String,
    pub part_id: String,
    pub call_id: String,
    pub agent: AgentMode,
    pub permission: ToolPermissionContext,
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

impl ToolResult {
    pub fn bounded_error(tool_name: &str, message: &str) -> Self {
        let bounded = truncate_chars(message, MAX_TOOL_ERROR_CHARS);
        Self {
            title: format!("{tool_name} did not complete"),
            summary: bounded.clone(),
            structured: json!({
                "ok": false,
                "error": bounded,
            }),
            artifacts: Vec::new(),
            truncated: message.chars().count() > MAX_TOOL_ERROR_CHARS,
            raw_output_artifact: None,
        }
    }
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
        let mut tools = self.agent_defs();
        tools.push(ToolDef {
            id: String::from("mock.large_output"),
            description: String::from(
                "Produces large mock output and stores the raw body as an artifact.",
            ),
            input_schema: object_schema(
                json!({
                    "query": { "type": "string" }
                }),
                &["query"],
            ),
            output_schema: standard_output_schema(),
            permissions: Vec::new(),
            risk: String::from("low"),
            timeout_ms: Some(5_000),
            truncate_at: 120,
        });
        tools
    }

    /// Tools the Agent (LLM or deterministic planner) may call. The Phase 17
    /// set adds allowlisted read-only local inspection to the earlier analysis,
    /// capture, and response-planning tools. `capture.stop` and
    /// `mock.large_output` remain excluded.
    pub fn agent_defs(&self) -> Vec<ToolDef> {
        let mut tools = self.readonly_defs();
        tools.push(ToolDef {
            id: String::from("capture.start"),
            description: String::from(
                "Request a bounded live capture. This pauses for explicit user approval through the permission state machine; the investigation resumes with the resulting pcap artifact.",
            ),
            input_schema: capture_input_schema(),
            output_schema: standard_output_schema(),
            permissions: vec![String::from("capture_live")],
            risk: String::from("medium"),
            timeout_ms: Some(30_000),
            truncate_at: 4,
        });
        tools.extend(self.offline_defs());
        tools.push(ToolDef {
            id: String::from("respond.propose_firewall_rule"),
            description: String::from(
                "Propose a firewall block rule for a target found in stored evidence. This only creates a proposal artifact for review — it NEVER modifies the firewall. High-risk; the user must type an explicit confirmation phrase.",
            ),
            input_schema: firewall_rule_schema(),
            output_schema: standard_output_schema(),
            permissions: vec![String::from("modify_firewall")],
            risk: String::from("high"),
            timeout_ms: Some(5_000),
            truncate_at: 12,
        });
        tools
    }

    pub fn readonly_defs(&self) -> Vec<ToolDef> {
        vec![
            ToolDef {
                id: String::from("flow.list"),
                description: String::from(
                    "List a bounded number of flow records already stored by NetAgent. This does not capture live traffic.",
                ),
                input_schema: list_input_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(2_000),
                truncate_at: MAX_LIST_LIMIT,
            },
            ToolDef {
                id: String::from("finding.list"),
                description: String::from(
                    "List a bounded number of findings already stored by NetAgent.",
                ),
                input_schema: list_input_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(2_000),
                truncate_at: MAX_LIST_LIMIT,
            },
            ToolDef {
                id: String::from("capture.status"),
                description: String::from(
                    "Read the current capture status without starting, stopping, or changing a capture.",
                ),
                input_schema: object_schema(json!({}), &[]),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(1_000),
                truncate_at: 1,
            },
            ToolDef {
                id: String::from("system.shell"),
                description: String::from(
                    "Inspect missing local system facts through a read-only allowlist. Choose one operation: interfaces, routes, listeners, tool_versions, capture_preflight, or system_info. Core selects fixed executable paths and arguments; arbitrary commands, shell syntax, pipes, redirection, environment reads, and file changes are impossible. Use this before guessing local interfaces, capture readiness, routes, listeners, OS details, or installed network tools.",
                ),
                input_schema: system_shell_input_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(10_000),
                truncate_at: 36,
            },
            ToolDef {
                id: String::from("artifact.list"),
                description: String::from(
                    "List a bounded number of ArtifactRef records available in the current NetAgent process.",
                ),
                input_schema: list_input_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(1_000),
                truncate_at: MAX_LIST_LIMIT,
            },
            ToolDef {
                id: String::from("artifact.summary"),
                description: String::from(
                    "Return bounded metadata for one ArtifactRef. It never returns raw file contents.",
                ),
                input_schema: object_schema(
                    json!({
                        "artifact_id": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Artifact id returned by artifact.list"
                        }
                    }),
                    &["artifact_id"],
                ),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(1_000),
                truncate_at: 1,
            },
        ]
    }

    /// Bounded offline analysis tools (layer 2). All parse or summarize stored
    /// evidence; raw packet or command output never enters the model context.
    fn offline_defs(&self) -> Vec<ToolDef> {
        vec![
            ToolDef {
                id: String::from("pcap.open"),
                description: String::from(
                    "Parse a local pcap file with tshark, persist flows and DNS events, and register the pcap as an artifact. Returns bounded counts and an ArtifactRef.",
                ),
                input_schema: object_schema(
                    json!({
                        "path": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Path to a readable .pcap file"
                        }
                    }),
                    &["path"],
                ),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(30_000),
                truncate_at: 6,
            },
            ToolDef {
                id: String::from("tshark.extract_flows"),
                description: String::from(
                    "Extract flow records from a local pcap file and persist them. Returns a bounded sample.",
                ),
                input_schema: pcap_path_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(30_000),
                truncate_at: 8,
            },
            ToolDef {
                id: String::from("tshark.extract_dns"),
                description: String::from(
                    "Extract DNS events from a local pcap file and persist them. Returns a bounded sample.",
                ),
                input_schema: pcap_path_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(30_000),
                truncate_at: 8,
            },
            ToolDef {
                id: String::from("dns.detect_anomalies"),
                description: String::from(
                    "Run every enabled manifest analyzer rule (rules/builtin/*.yaml) over stored evidence and persist any findings. Returns bounded finding summaries.",
                ),
                input_schema: object_schema(
                    json!({
                        "threshold_ratio": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "NXDOMAIN ratio threshold for the spike rule"
                        },
                        "min_queries": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Minimum total DNS queries before a host is considered by the spike rule"
                        }
                    }),
                    &[],
                ),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(5_000),
                truncate_at: 12,
            },
            ToolDef {
                id: String::from("zeek.process_pcap"),
                description: String::from(
                    "Run Zeek (fixed arguments only) over a local pcap file, persist the parsed connection and DNS records, and store a bounded copy of the JSON logs as an artifact. If Zeek is not installed the result explains why and suggests the tshark fallback.",
                ),
                input_schema: pcap_path_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(70_000),
                truncate_at: 10,
            },
            ToolDef {
                id: String::from("suricata.process_pcap"),
                description: String::from(
                    "Run Suricata (fixed arguments only) over a local pcap file, persist parsed alert, connection, and DNS records, and store a bounded copy of eve.json as an artifact. If Suricata is not installed the result explains why and suggests the tshark fallback.",
                ),
                input_schema: pcap_path_schema(),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(70_000),
                truncate_at: 10,
            },
            ToolDef {
                id: String::from("report.generate"),
                description: String::from(
                    "Generate a Markdown evidence report from stored findings, flows, DNS events, and artifacts. Returns an ArtifactRef, not the full report.",
                ),
                input_schema: object_schema(
                    json!({
                        "title": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Report title"
                        }
                    }),
                    &["title"],
                ),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(10_000),
                truncate_at: 12,
            },
            ToolDef {
                id: String::from("ioc.export"),
                description: String::from(
                    "Export stored evidence as an IOC JSON document artifact. Returns an ArtifactRef.",
                ),
                input_schema: object_schema(json!({}), &[]),
                output_schema: standard_output_schema(),
                permissions: Vec::new(),
                risk: String::from("low"),
                timeout_ms: Some(10_000),
                truncate_at: 12,
            },
        ]
    }

    pub fn openai_tool_schemas(&self) -> Vec<Value> {
        self.agent_defs()
            .into_iter()
            .map(|tool| {
                let provider_name = tool.id.replace('.', "_");
                json!({
                    "type": "function",
                    "function": {
                        "name": provider_name,
                        "description": format!("NetAgent tool id: {}. {}", tool.id, tool.description),
                        "parameters": tool.input_schema,
                    }
                })
            })
            .collect()
    }

    pub fn run_readonly_tool(
        &self,
        context: &ToolContext,
        tool_name: &str,
        input: &Value,
        sqlite_store: &SqliteStore,
        artifact_store: &mut ArtifactStore,
        capture_status: &Value,
    ) -> Result<ToolResult, String> {
        validate_context(context)?;
        let object = validate_object_input(input)?;

        match tool_name {
            "flow.list" => {
                let limit = validate_list_input(object)?;
                let flows = sqlite_store.list_flows()?;
                let total = flows.len();
                let returned = flows.into_iter().take(limit).collect::<Vec<_>>();
                Ok(ToolResult {
                    title: String::from("Stored flows"),
                    summary: format!(
                        "Found {total} stored flow record(s); returned {} (limit {limit}).",
                        returned.len()
                    ),
                    structured: json!({
                        "total": total,
                        "returned": returned.len(),
                        "limit": limit,
                        "flows": returned,
                    }),
                    artifacts: Vec::new(),
                    truncated: total > limit,
                    raw_output_artifact: None,
                })
            }
            "finding.list" => {
                let limit = validate_list_input(object)?;
                let findings = sqlite_store.list_findings()?;
                let total = findings.len();
                let returned = findings.into_iter().take(limit).collect::<Vec<_>>();
                Ok(ToolResult {
                    title: String::from("Stored findings"),
                    summary: format!(
                        "Found {total} stored finding(s); returned {} (limit {limit}).",
                        returned.len()
                    ),
                    structured: json!({
                        "total": total,
                        "returned": returned.len(),
                        "limit": limit,
                        "findings": returned,
                    }),
                    artifacts: Vec::new(),
                    truncated: total > limit,
                    raw_output_artifact: None,
                })
            }
            "capture.status" => {
                reject_unknown_fields(object, &[])?;
                let status = capture_status
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                Ok(ToolResult {
                    title: String::from("Capture status"),
                    summary: format!(
                        "Capture status is {status}. No capture action was performed."
                    ),
                    structured: capture_status.clone(),
                    artifacts: Vec::new(),
                    truncated: false,
                    raw_output_artifact: None,
                })
            }
            "system.shell" => system_shell::run(object, artifact_store),
            "artifact.list" => {
                let limit = validate_list_input(object)?;
                let artifacts = artifact_store.list_artifacts();
                let total = artifacts.len();
                let returned = artifacts.into_iter().take(limit).collect::<Vec<_>>();
                Ok(ToolResult {
                    title: String::from("Available artifacts"),
                    summary: format!(
                        "Found {total} artifact reference(s); returned {} (limit {limit}).",
                        returned.len()
                    ),
                    structured: json!({
                        "total": total,
                        "returned": returned.len(),
                        "limit": limit,
                        "artifacts": returned,
                    }),
                    artifacts: returned,
                    truncated: total > limit,
                    raw_output_artifact: None,
                })
            }
            "artifact.summary" => {
                reject_unknown_fields(object, &["artifact_id"])?;
                let artifact_id = object
                    .get("artifact_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| String::from("artifact_id must be a non-empty string"))?;
                let artifact = artifact_store
                    .get_artifact(artifact_id)
                    .ok_or_else(|| format!("artifact not found: {artifact_id}"))?;
                Ok(ToolResult {
                    title: format!("Artifact {artifact_id}"),
                    summary: format!(
                        "Artifact {artifact_id} is a {:?} reference: {}. Raw file contents were not returned.",
                        artifact.kind, artifact.note
                    ),
                    structured: json!({
                        "artifact": artifact,
                        "raw_content_included": false,
                    }),
                    artifacts: vec![artifact.clone()],
                    truncated: false,
                    raw_output_artifact: None,
                })
            }
            _ => Err(format!(
                "tool is not registered in the Agent read-only allowlist: {tool_name}"
            )),
        }
    }

    /// Validate typed `capture.start` input without executing anything.
    /// The permission state machine decides whether a capture may actually run.
    pub fn validate_capture_input(&self, input: &Value) -> Result<CapturePlanIntent, String> {
        let object = validate_object_input(input)?;
        reject_unknown_fields(object, &["interface", "filter", "duration"])?;
        let interface = object
            .get("interface")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| String::from("interface must be a non-empty string"))?;
        let filter = object
            .get("filter")
            .and_then(Value::as_str)
            .unwrap_or("tcp or dns")
            .trim()
            .to_string();
        if filter.is_empty() {
            return Err(String::from("filter must be a non-empty string"));
        }
        let duration = match object.get("duration") {
            None => DEFAULT_CAPTURE_DURATION,
            Some(value) => {
                let duration = value
                    .as_u64()
                    .ok_or_else(|| String::from("duration must be an integer"))?;
                if !(1..=MAX_CAPTURE_DURATION).contains(&duration) {
                    return Err(format!(
                        "duration must be between 1 and {MAX_CAPTURE_DURATION} seconds, inclusive"
                    ));
                }
                duration
            }
        };
        let reason = format!(
            "The agent proposed a bounded live capture on {interface} with filter '{filter}' for {duration}s."
        );
        Ok(CapturePlanIntent {
            interface: interface.to_string(),
            filter,
            duration,
            reason,
        })
    }

    /// Execute the bounded offline analysis tools (layer 2). Raw file contents
    /// and tshark output never enter the model context; results are bounded
    /// summaries plus structured counts and ArtifactRef values.
    #[allow(clippy::too_many_arguments)]
    pub fn run_offline_tool(
        &self,
        context: &ToolContext,
        tool_name: &str,
        input: &Value,
        sqlite_store: &SqliteStore,
        artifact_store: &mut ArtifactStore,
        finding_counter: &mut u64,
        record_counter: &mut u64,
        abort: &AtomicBool,
    ) -> Result<ToolResult, String> {
        validate_context(context)?;
        let object = validate_object_input(input)?;

        match tool_name {
            "pcap.open" => {
                let path = required_path_field(object, "path")?;
                let parsed = parse_pcap_into_store(&path, sqlite_store, record_counter)?;
                let artifact = artifact_store.register_pcap(
                    &path,
                    &format!("pcap opened through the agent tool loop from {path}"),
                );
                Ok(ToolResult {
                    title: String::from("PCAP opened and parsed"),
                    summary: format!(
                        "Parsed {} flow(s) and {} DNS event(s) from {path}. Raw packets were not returned.",
                        parsed.flows, parsed.dns
                    ),
                    structured: json!({
                        "status": "ok",
                        "path": path,
                        "artifact": artifact,
                        "flows_parsed": parsed.flows,
                        "dns_parsed": parsed.dns,
                        "raw_packets_included": false,
                    }),
                    artifacts: vec![artifact.clone()],
                    truncated: false,
                    raw_output_artifact: None,
                })
            }
            "tshark.extract_flows" => {
                let path = required_path_field(object, "path")?;
                let flows = tshark::extract_flows(std::path::Path::new(&path))?;
                let samples = flows.iter().take(5).cloned().collect::<Vec<_>>();
                let inserted = insert_flows_with_ids(&flows, sqlite_store, record_counter)?;
                Ok(ToolResult {
                    title: String::from("Flows extracted"),
                    summary: format!(
                        "Extracted {} flow record(s) from {path}; {} inserted. Returning {}. Raw command output was not returned.",
                        flows.len(),
                        inserted,
                        samples.len()
                    ),
                    structured: json!({
                        "status": "ok",
                        "path": path,
                        "flows_parsed": flows.len(),
                        "flows_inserted": inserted,
                        "samples": samples,
                    }),
                    artifacts: Vec::new(),
                    truncated: flows.len() > samples.len(),
                    raw_output_artifact: None,
                })
            }
            "tshark.extract_dns" => {
                let path = required_path_field(object, "path")?;
                let dns_events = tshark::extract_dns(std::path::Path::new(&path))?;
                let samples = dns_events.iter().take(5).cloned().collect::<Vec<_>>();
                let inserted = insert_dns_with_ids(&dns_events, sqlite_store, record_counter)?;
                Ok(ToolResult {
                    title: String::from("DNS events extracted"),
                    summary: format!(
                        "Extracted {} DNS event(s) from {path}; {} inserted. Raw command output was not returned.",
                        dns_events.len(),
                        inserted
                    ),
                    structured: json!({
                        "status": "ok",
                        "path": path,
                        "dns_parsed": dns_events.len(),
                        "dns_inserted": inserted,
                        "samples": samples,
                    }),
                    artifacts: Vec::new(),
                    truncated: dns_events.len() > samples.len(),
                    raw_output_artifact: None,
                })
            }
            "zeek.process_pcap" => {
                let path = required_path_field(object, "path")?;
                let output =
                    zeek::process_pcap(std::path::Path::new(&path), artifact_store, abort)?;
                if !output.binary_available || output.exit_code != Some(0) {
                    return Ok(ToolResult {
                        title: String::from("Zeek processing did not run"),
                        summary: output.preview.clone(),
                        structured: json!({
                            "status": "unavailable",
                            "path": path,
                            "binary_available": output.binary_available,
                            "exit_code": output.exit_code,
                            "timed_out": output.timed_out,
                            "stderr_bounded": output.stderr,
                            "preview": output.preview,
                            "fallback": ["tshark.extract_flows", "tshark.extract_dns"],
                        }),
                        artifacts: Vec::new(),
                        truncated: false,
                        raw_output_artifact: None,
                    });
                }
                let flows = output.flows;
                let dns_events = output.dns_events;
                let flow_count = flows.len();
                let dns_count = dns_events.len();
                let flow_inserted = insert_flows_with_ids(&flows, sqlite_store, record_counter)?;
                let dns_inserted = insert_dns_with_ids(&dns_events, sqlite_store, record_counter)?;
                Ok(ToolResult {
                    title: String::from("Zeek logs processed"),
                    summary: format!(
                        "Zeek parsed {flow_count} connection(s) and {dns_count} DNS event(s) from {path}; inserted {flow_inserted} flow(s) and {dns_inserted} DNS event(s). Bounded JSON logs are stored as an artifact.",
                    ),
                    structured: json!({
                        "status": "ok",
                        "path": path,
                        "flows_parsed": flow_count,
                        "flows_inserted": flow_inserted,
                        "dns_parsed": dns_count,
                        "dns_inserted": dns_inserted,
                        "preview": output.preview,
                        "raw_logs_in_artifact": true,
                    }),
                    artifacts: output.log_artifact.iter().cloned().collect::<Vec<_>>(),
                    truncated: false,
                    raw_output_artifact: output.log_artifact,
                })
            }
            "suricata.process_pcap" => {
                let path = required_path_field(object, "path")?;
                let output =
                    suricata::process_pcap(std::path::Path::new(&path), artifact_store, abort)?;
                if !output.binary_available || output.exit_code != Some(0) {
                    return Ok(ToolResult {
                        title: String::from("Suricata processing did not run"),
                        summary: output.preview.clone(),
                        structured: json!({
                            "status": "unavailable",
                            "path": path,
                            "binary_available": output.binary_available,
                            "exit_code": output.exit_code,
                            "timed_out": output.timed_out,
                            "stderr_bounded": output.stderr,
                            "preview": output.preview,
                            "fallback": ["tshark.extract_flows", "tshark.extract_dns"],
                        }),
                        artifacts: Vec::new(),
                        truncated: false,
                        raw_output_artifact: None,
                    });
                }
                let mut alerts = output.alerts;
                let mut flows = output.flows;
                let mut dns_events = output.dns_events;
                let alert_count = alerts.len();
                let flow_count = flows.len();
                let dns_count = dns_events.len();
                for alert in &mut alerts {
                    *record_counter += 1;
                    alert.id = format!("alert_{record_counter:04}");
                }
                for flow in &mut flows {
                    *record_counter += 1;
                    flow.id = format!("flow_{record_counter:04}");
                }
                for event in &mut dns_events {
                    *record_counter += 1;
                    event.id = format!("dns_{record_counter:04}");
                }
                let alert_inserted = sqlite_store.insert_alerts(&alerts)?;
                let flow_inserted = sqlite_store.insert_flows(&flows)?;
                let dns_inserted = sqlite_store.insert_dns_events(&dns_events)?;
                Ok(ToolResult {
                    title: String::from("Suricata eve.json processed"),
                    summary: format!(
                        "Suricata parsed {alert_count} alert(s), {flow_count} connection(s), and {dns_count} DNS event(s) from {path}; inserted {alert_inserted}/{flow_inserted}/{dns_inserted}. Bounded eve.json is stored as an artifact.",
                    ),
                    structured: json!({
                        "status": "ok",
                        "path": path,
                        "alerts_parsed": alert_count,
                        "alerts_inserted": alert_inserted,
                        "flows_parsed": flow_count,
                        "flows_inserted": flow_inserted,
                        "dns_parsed": dns_count,
                        "dns_inserted": dns_inserted,
                        "preview": output.preview,
                        "raw_logs_in_artifact": true,
                    }),
                    artifacts: output.log_artifact.iter().cloned().collect::<Vec<_>>(),
                    truncated: false,
                    raw_output_artifact: output.log_artifact,
                })
            }
            "dns.detect_anomalies" => {
                reject_unknown_fields(object, &["threshold_ratio", "min_queries"])?;
                let threshold_ratio = object
                    .get("threshold_ratio")
                    .and_then(Value::as_f64)
                    .map(|value| value.clamp(0.0, 1.0));
                let min_queries = object.get("min_queries").and_then(Value::as_u64);
                let mut manifests = load_rule_manifests()?;
                if let Some(threshold) = threshold_ratio {
                    if let Some(spike) = manifests
                        .iter_mut()
                        .find(|manifest| manifest.id == "dns_nxdomain_spike")
                    {
                        spike
                            .params
                            .insert("threshold_ratio".to_string(), json!(threshold));
                    }
                }
                if let Some(min) = min_queries {
                    if let Some(spike) = manifests
                        .iter_mut()
                        .find(|manifest| manifest.id == "dns_nxdomain_spike")
                    {
                        spike.params.insert("min_queries".to_string(), json!(min));
                    }
                }
                let findings = run_all_rules(&manifests, sqlite_store, finding_counter)?;
                let rule_ids = manifests
                    .iter()
                    .map(|manifest| manifest.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(ToolResult {
                    title: String::from("DNS anomaly detection"),
                    summary: format!(
                        "Ran manifest rule(s) ({rule_ids}); detected {} finding(s).",
                        findings.len()
                    ),
                    structured: json!({
                        "status": "ok",
                        "rules_ran": manifests
                            .iter()
                            .map(|manifest| json!({
                                "id": manifest.id,
                                "name": manifest.name,
                                "severity": manifest.severity,
                            }))
                            .collect::<Vec<_>>(),
                        "findings_count": findings.len(),
                        "findings": findings,
                    }),
                    artifacts: Vec::new(),
                    truncated: false,
                    raw_output_artifact: None,
                })
            }
            "report.generate" => {
                reject_unknown_fields(object, &["title"])?;
                let title = object
                    .get("title")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("NetAgent Investigation Report");
                let input = collect_report_input(sqlite_store, artifact_store, title)?;
                let (content, metadata) = build_markdown_report(&input);
                let artifact = artifact_store.write_report("netagent-report", &content)?;
                Ok(ToolResult {
                    title: String::from("Evidence report generated"),
                    summary: format!(
                        "Report generated with {} findings, {} flows, and {} DNS events. Full report stored as an artifact.",
                        metadata.finding_count, metadata.flow_count, metadata.dns_event_count
                    ),
                    structured: json!({
                        "status": "ok",
                        "artifact": artifact,
                        "metadata": metadata,
                        "preview": content.lines().take(6).collect::<Vec<_>>().join("\n"),
                    }),
                    artifacts: vec![artifact.clone()],
                    truncated: true,
                    raw_output_artifact: None,
                })
            }
            "ioc.export" => {
                reject_unknown_fields(object, &[])?;
                let input =
                    collect_report_input(sqlite_store, artifact_store, "NetAgent IOC Export")?;
                let evidence_bundle = build_evidence_bundle_metadata(&input);
                let document = json!({
                    "evidence_bundle": evidence_bundle,
                    "findings": input.findings,
                    "flows": input.flows,
                    "dns_events": input.dns_events,
                    "artifacts": input.artifacts,
                });
                let content = serde_json::to_string_pretty(&document)
                    .map_err(|error| format!("failed to serialize IOC export: {error}"))?;
                let artifact = artifact_store.write_ioc_export("netagent-iocs", &content)?;
                Ok(ToolResult {
                    title: String::from("IOC export written"),
                    summary: format!(
                        "IOC export written with {} findings, {} flows, and {} DNS events. Full document stored as an artifact.",
                        evidence_bundle.finding_count,
                        evidence_bundle.flow_count,
                        evidence_bundle.dns_event_count
                    ),
                    structured: json!({
                        "status": "ok",
                        "artifact": artifact,
                        "evidence_bundle": evidence_bundle,
                        "counts": {
                            "findings": evidence_bundle.finding_count,
                            "flows": evidence_bundle.flow_count,
                            "dns_events": evidence_bundle.dns_event_count,
                        },
                    }),
                    artifacts: vec![artifact.clone()],
                    truncated: true,
                    raw_output_artifact: None,
                })
            }
            _ => Err(format!(
                "tool is not registered in the offline analysis allowlist: {tool_name}"
            )),
        }
    }

    /// Validate typed `respond.propose_firewall_rule` input without executing
    /// anything. Produces the proposal intent that the permission state
    /// machine turns into a high-risk typed-confirmation request.
    pub fn validate_firewall_rule_input(
        &self,
        input: &Value,
    ) -> Result<FirewallRuleProposal, String> {
        let object = validate_object_input(input)?;
        reject_unknown_fields(
            object,
            &[
                "finding_id",
                "target",
                "port",
                "protocol",
                "action",
                "reason",
            ],
        )?;
        let target = object
            .get("target")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| String::from("target must be a non-empty IP address or CIDR"))?
            .trim()
            .to_string();
        if !Self::looks_like_ip_or_cidr(&target) {
            return Err(format!(
                "target must be an IPv4/IPv6 address or CIDR, got: {target}"
            ));
        }
        let action = object
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("block")
            .trim()
            .to_string();
        if action != "block" {
            return Err(format!(
                "only action=block is supported in preview mode, got: {action}"
            ));
        }
        let port = object
            .get("port")
            .and_then(Value::as_u64)
            .map(|port| {
                if port == 0 || port > 65535 {
                    Err(String::from("port must be between 1 and 65535"))
                } else {
                    Ok(port as u16)
                }
            })
            .transpose()?;
        let protocol = object
            .get("protocol")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.is_empty());
        let reason = object
            .get("reason")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                String::from("reason must be a non-empty string describing the evidence")
            })?
            .trim()
            .to_string();
        let finding_id = object
            .get("finding_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.is_empty());

        Ok(FirewallRuleProposal {
            finding_id,
            target,
            port,
            protocol,
            action,
            reason,
        })
    }

    fn looks_like_ip_or_cidr(value: &str) -> bool {
        if let Some(cidr) = value.split_once('/') {
            let network = cidr.0;
            let prefix = cidr.1;
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            let max_prefix = if network.contains(':') { 128 } else { 32 };
            return prefix <= max_prefix && Self::looks_like_ip(network);
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
                octet.parse::<u8>().is_ok()
                    || octet.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
            })
    }

    pub fn run_mock_large_output(
        &self,
        context: &ToolContext,
        query: &str,
        artifact_store: &mut ArtifactStore,
    ) -> Result<(ToolResult, Vec<ToolProgressUpdate>), String> {
        validate_context(context)?;
        let tool_def = self
            .list_defs()
            .into_iter()
            .find(|tool| tool.id == "mock.large_output")
            .ok_or_else(|| String::from("mock.large_output definition is missing"))?;
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
        let artifact = artifact_store.write_raw_output(&tool_def.id, &raw_output)?;

        Ok((
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
        ))
    }
}

fn validate_context(context: &ToolContext) -> Result<(), String> {
    for (field, value) in [
        ("session_id", context.session_id.as_str()),
        ("message_id", context.message_id.as_str()),
        ("part_id", context.part_id.as_str()),
        ("call_id", context.call_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("tool context is missing {field}"));
        }
    }
    if context.abort {
        return Err(String::from("tool call was aborted before execution"));
    }
    if context.permission.required || context.permission.decision != "not_required" {
        return Err(String::from(
            "Agent tools require permission context decision=not_required (permission-gated tools resolve their own permission)",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturePlanIntent {
    pub interface: String,
    pub filter: String,
    pub duration: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleProposal {
    pub finding_id: Option<String>,
    pub target: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub action: String,
    pub reason: String,
}

fn required_path_field(object: &Map<String, Value>, field: &str) -> Result<String, String> {
    reject_unknown_fields(object, &[field])?;
    let path = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{field} must be a non-empty string"))?
        .to_string();
    let pcap_path = std::path::Path::new(&path);
    if !pcap_path.exists() {
        return Err(format!("pcap file not found: {path}"));
    }
    Ok(path)
}

struct ParsedPcapCounts {
    flows: usize,
    dns: usize,
}

fn parse_pcap_into_store(
    path: &str,
    store: &SqliteStore,
    record_counter: &mut u64,
) -> Result<ParsedPcapCounts, String> {
    let pcap_path = std::path::Path::new(path);
    let flows = tshark::extract_flows(pcap_path)
        .map_err(|message| format!("failed to extract flows from {path}: {message}"))?;
    let dns_events = tshark::extract_dns(pcap_path)
        .map_err(|message| format!("failed to extract DNS events from {path}: {message}"))?;
    let flow_count = flows.len();
    let dns_count = dns_events.len();
    insert_flows_with_ids(&flows, store, record_counter)?;
    insert_dns_with_ids(&dns_events, store, record_counter)?;
    Ok(ParsedPcapCounts {
        flows: flow_count,
        dns: dns_count,
    })
}

fn insert_flows_with_ids(
    flows: &[netagent_models::Flow],
    store: &SqliteStore,
    record_counter: &mut u64,
) -> Result<usize, String> {
    let mut owned = flows.to_vec();
    for flow in &mut owned {
        *record_counter += 1;
        flow.id = format!("flow_{record_counter:04}");
    }
    store.insert_flows(&owned)
}

fn insert_dns_with_ids(
    events: &[netagent_models::DnsEvent],
    store: &SqliteStore,
    record_counter: &mut u64,
) -> Result<usize, String> {
    let mut owned = events.to_vec();
    for event in &mut owned {
        *record_counter += 1;
        event.id = format!("dns_{record_counter:04}");
    }
    store.insert_dns_events(&owned)
}

fn validate_object_input(input: &Value) -> Result<&Map<String, Value>, String> {
    let object = input
        .as_object()
        .ok_or_else(|| String::from("tool input must be a JSON object"))?;
    if let Some(message) = object.get("__validation_error").and_then(Value::as_str) {
        return Err(message.to_string());
    }
    Ok(object)
}

fn validate_list_input(object: &Map<String, Value>) -> Result<usize, String> {
    reject_unknown_fields(object, &["limit"])?;
    match object.get("limit") {
        None => Ok(DEFAULT_LIST_LIMIT),
        Some(value) => {
            let limit = value
                .as_u64()
                .ok_or_else(|| String::from("limit must be an integer"))?
                as usize;
            if !(1..=MAX_LIST_LIMIT).contains(&limit) {
                return Err(format!(
                    "limit must be between 1 and {MAX_LIST_LIMIT}, inclusive"
                ));
            }
            Ok(limit)
        }
    }
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!("unknown input field: {field}"));
    }
    Ok(())
}

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn list_input_schema() -> Value {
    object_schema(
        json!({
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_LIST_LIMIT,
                "description": "Maximum number of records to return"
            }
        }),
        &[],
    )
}

fn capture_input_schema() -> Value {
    object_schema(
        json!({
            "interface": {
                "type": "string",
                "minLength": 1,
                "description": "Network interface to capture from"
            },
            "filter": {
                "type": "string",
                "minLength": 1,
                "description": "BPF capture filter, e.g. tcp or dns"
            },
            "duration": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_CAPTURE_DURATION,
                "description": "Bounded capture duration in seconds"
            }
        }),
        &["interface", "filter", "duration"],
    )
}

fn system_shell_input_schema() -> Value {
    object_schema(
        json!({
            "operation": {
                "type": "string",
                "enum": system_shell::OPERATIONS,
                "description": "Read-only inspection operation selected by the Agent"
            },
            "interface": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[A-Za-z0-9._:-]+$",
                "description": "Required only for capture_preflight; never evaluated as shell text"
            }
        }),
        &["operation"],
    )
}

fn pcap_path_schema() -> Value {
    object_schema(
        json!({
            "path": {
                "type": "string",
                "minLength": 1,
                "description": "Path to a readable .pcap file"
            }
        }),
        &["path"],
    )
}

fn firewall_rule_schema() -> Value {
    object_schema(
        json!({
            "finding_id": {
                "type": "string",
                "description": "Optional finding id this rule responds to, for traceability"
            },
            "target": {
                "type": "string",
                "minLength": 1,
                "description": "IPv4/IPv6 address or CIDR to block"
            },
            "port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535,
                "description": "Optional destination port"
            },
            "protocol": {
                "type": "string",
                "description": "Optional protocol, e.g. tcp or udp"
            },
            "action": {
                "type": "string",
                "enum": ["block"],
                "description": "Action; only block is supported in preview mode"
            },
            "reason": {
                "type": "string",
                "minLength": 1,
                "description": "Evidence-based justification for the rule"
            }
        }),
        &["target", "action", "reason"],
    )
}

fn standard_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "title": { "type": "string" },
            "summary": { "type": "string" },
            "structured": { "type": "object" },
            "artifacts": { "type": "array" },
            "truncated": { "type": "boolean" }
        }
    })
}

fn truncate_chars(value: &str, limit: usize) -> String {
    let mut characters = value.chars();
    let truncated = characters.by_ref().take(limit).collect::<String>();
    if characters.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_schemas_expose_agent_tools_but_not_capture_stop_or_mock() {
        let registry = ToolRegistry;
        let schemas = registry.openai_tool_schemas();
        let names = schemas
            .iter()
            .filter_map(|schema| schema.pointer("/function/name").and_then(Value::as_str))
            .collect::<Vec<_>>();

        assert_eq!(names.len(), 16);
        assert!(names.contains(&"flow_list"));
        assert!(names.contains(&"system_shell"));
        assert!(names.contains(&"artifact_summary"));
        assert!(names.contains(&"capture_start"));
        assert!(names.contains(&"pcap_open"));
        assert!(names.contains(&"dns_detect_anomalies"));
        assert!(names.contains(&"zeek_process_pcap"));
        assert!(names.contains(&"suricata_process_pcap"));
        assert!(names.contains(&"report_generate"));
        assert!(names.contains(&"ioc_export"));
        assert!(names.contains(&"respond_propose_firewall_rule"));
        assert!(!names.contains(&"capture_stop"));
        assert!(!names.contains(&"mock_large_output"));
        assert!(names.iter().all(|name| !name.contains('.')));
    }

    #[test]
    fn system_shell_schema_has_no_freeform_command_field() {
        let registry = ToolRegistry;
        let tool = registry
            .agent_defs()
            .into_iter()
            .find(|tool| tool.id == "system.shell")
            .expect("system.shell def");
        assert_eq!(tool.risk, "low");
        assert!(tool.permissions.is_empty());
        assert_eq!(tool.input_schema["additionalProperties"], false);
        assert!(tool.input_schema["properties"].get("command").is_none());
        assert!(tool.input_schema["properties"].get("args").is_none());
        assert_eq!(
            tool.input_schema["properties"]["operation"]["enum"]
                .as_array()
                .map(Vec::len),
            Some(system_shell::OPERATIONS.len())
        );
    }

    #[test]
    fn firewall_rule_def_declares_high_risk_modify_firewall_permission() {
        let registry = ToolRegistry;
        let rule = registry
            .agent_defs()
            .into_iter()
            .find(|tool| tool.id == "respond.propose_firewall_rule")
            .expect("firewall rule def");
        assert_eq!(rule.permissions, vec!["modify_firewall"]);
        assert_eq!(rule.risk, "high");
    }

    #[test]
    fn firewall_rule_input_validation_rejects_bad_targets_and_actions() {
        let registry = ToolRegistry;
        let valid = registry
            .validate_firewall_rule_input(&json!({
                "finding_id": "finding_0001",
                "target": "10.0.0.8",
                "port": 53,
                "protocol": "udp",
                "action": "block",
                "reason": "NXDOMAIN spike evidence points to this host.",
            }))
            .expect("valid rule");
        assert_eq!(valid.target, "10.0.0.8");
        assert_eq!(valid.port, Some(53));
        assert_eq!(valid.action, "block");

        assert!(
            registry
                .validate_firewall_rule_input(
                    &json!({ "target": "10.0.0.8", "action": "drop", "reason": "x" })
                )
                .is_err()
        );
        assert!(
            registry
                .validate_firewall_rule_input(
                    &json!({ "target": "not-an-ip", "action": "block", "reason": "x" })
                )
                .is_err()
        );
        assert!(
            registry
                .validate_firewall_rule_input(
                    &json!({ "target": "10.0.0.8/99", "action": "block", "reason": "x" })
                )
                .is_err()
        );
        assert!(
            registry
                .validate_firewall_rule_input(
                    &json!({ "target": "10.0.0.8", "action": "block", "reason": "" })
                )
                .is_err()
        );
        assert!(registry
            .validate_firewall_rule_input(&json!({ "target": "10.0.0.8", "action": "block", "reason": "x", "shell": "rm -rf /" }))
            .is_err());
    }

    #[test]
    fn capture_start_def_declares_capture_live_permission() {
        let registry = ToolRegistry;
        let capture = registry
            .agent_defs()
            .into_iter()
            .find(|tool| tool.id == "capture.start")
            .expect("capture.start def");
        assert_eq!(capture.permissions, vec!["capture_live"]);
        assert_eq!(capture.risk, "medium");
        let read_only = registry
            .agent_defs()
            .into_iter()
            .find(|tool| tool.id == "flow.list")
            .expect("flow.list def");
        assert!(read_only.permissions.is_empty());
    }

    #[test]
    fn capture_input_validation_bounds_duration_and_rejects_unknown_fields() {
        let registry = ToolRegistry;
        let plan = registry
            .validate_capture_input(&json!({
                "interface": "en0",
                "filter": "tcp or dns",
                "duration": 7
            }))
            .expect("valid capture input");
        assert_eq!(plan.interface, "en0");
        assert_eq!(plan.duration, 7);
        assert!(
            registry
                .validate_capture_input(&json!({ "interface": "en0", "duration": 60 }))
                .is_err()
        );
        assert!(
            registry
                .validate_capture_input(&json!({ "interface": "", "duration": 5 }))
                .is_err()
        );
        assert!(
            registry
                .validate_capture_input(&json!({ "interface": "en0", "shell": "ls" }))
                .is_err()
        );
        assert!(registry.validate_capture_input(&json!({})).is_err());
    }

    #[test]
    fn list_input_validation_rejects_unbounded_and_unknown_values() {
        assert_eq!(validate_list_input(json!({}).as_object().unwrap()), Ok(12));
        assert!(validate_list_input(json!({ "limit": 26 }).as_object().unwrap()).is_err());
        assert!(validate_list_input(json!({ "limit": "many" }).as_object().unwrap()).is_err());
        assert!(validate_list_input(json!({ "shell": "ls" }).as_object().unwrap()).is_err());
    }

    #[test]
    fn tool_context_requires_all_trace_identifiers() {
        let context = ToolContext {
            session_id: String::from("ses_0001"),
            message_id: String::from("msg_0001"),
            part_id: String::new(),
            call_id: String::from("call_0001"),
            agent: AgentMode::Observe,
            permission: ToolPermissionContext {
                required: false,
                decision: String::from("not_required"),
            },
            abort: false,
        };
        assert!(validate_context(&context).is_err());
    }
}
