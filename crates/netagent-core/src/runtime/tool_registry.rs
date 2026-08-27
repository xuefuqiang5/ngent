use netagent_models::{AgentMode, ArtifactRef};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::analyzers::dns::detect_nxdomain_spike;
use crate::reports::markdown::{
    build_evidence_bundle_metadata, build_markdown_report, collect_report_input,
};
use crate::storage::artifact_store::ArtifactStore;
use crate::storage::sqlite::SqliteStore;
use crate::tools::tshark;

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

    /// Tools the Agent (LLM or deterministic planner) may call. Phase 12 set:
    /// five read-only tools, `capture.start` (permission-gated), and bounded
    /// offline analysis/export tools. `capture.stop` and `mock.large_output`
    /// are deliberately excluded from the agent allowlist.
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
                    "Run the NXDOMAIN spike rule over stored DNS events and persist any findings. Returns bounded finding summaries.",
                ),
                input_schema: object_schema(
                    json!({
                        "threshold_ratio": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "NXDOMAIN ratio threshold for an anomaly"
                        },
                        "min_queries": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Minimum total DNS queries before a host is considered"
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
        artifact_store: &ArtifactStore,
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
                "tool is not registered in the Phase 11 read-only allowlist: {tool_name}"
            )),
        }
    }

    /// Validate typed `capture.start` input without executing anything.
    /// The permission state machine decides whether a capture may actually run.
    pub fn validate_capture_input(
        &self,
        input: &Value,
    ) -> Result<CapturePlanIntent, String> {
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
                let inserted =
                    insert_dns_with_ids(&dns_events, sqlite_store, record_counter)?;
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
            "dns.detect_anomalies" => {
                reject_unknown_fields(object, &["threshold_ratio", "min_queries"])?;
                let threshold_ratio = object
                    .get("threshold_ratio")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.3)
                    .clamp(0.0, 1.0);
                let min_queries = object
                    .get("min_queries")
                    .and_then(Value::as_u64)
                    .unwrap_or(5)
                    .clamp(1, 10_000) as usize;
                let findings = detect_nxdomain_spike(
                    sqlite_store,
                    finding_counter,
                    threshold_ratio,
                    min_queries,
                )?;
                Ok(ToolResult {
                    title: String::from("DNS anomaly detection"),
                    summary: format!(
                        "Detected {} finding(s) with NXDOMAIN ratio threshold {threshold_ratio} and min_queries {min_queries}.",
                        findings.len()
                    ),
                    structured: json!({
                        "status": "ok",
                        "threshold_ratio": threshold_ratio,
                        "min_queries": min_queries,
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
                        evidence_bundle.finding_count, evidence_bundle.flow_count, evidence_bundle.dns_event_count
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
            "Phase 12 agent tools require permission context decision=not_required (capture.start resolves its own permission)",
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
    let flows = tshark::extract_flows(pcap_path).map_err(|message| {
        format!("failed to extract flows from {path}: {message}")
    })?;
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
    fn openai_schemas_expose_phase12_agent_tools_but_not_capture_stop_or_mock() {
        let registry = ToolRegistry;
        let schemas = registry.openai_tool_schemas();
        let names = schemas
            .iter()
            .filter_map(|schema| schema.pointer("/function/name").and_then(Value::as_str))
            .collect::<Vec<_>>();

        assert_eq!(names.len(), 12);
        assert!(names.contains(&"flow_list"));
        assert!(names.contains(&"artifact_summary"));
        assert!(names.contains(&"capture_start"));
        assert!(names.contains(&"pcap_open"));
        assert!(names.contains(&"dns_detect_anomalies"));
        assert!(names.contains(&"report_generate"));
        assert!(names.contains(&"ioc_export"));
        assert!(!names.contains(&"capture_stop"));
        assert!(!names.contains(&"mock_large_output"));
        assert!(names.iter().all(|name| !name.contains('.')));
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
        assert!(registry
            .validate_capture_input(&json!({ "interface": "en0", "duration": 60 }))
            .is_err());
        assert!(registry
            .validate_capture_input(&json!({ "interface": "", "duration": 5 }))
            .is_err());
        assert!(registry
            .validate_capture_input(&json!({ "interface": "en0", "shell": "ls" }))
            .is_err());
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
