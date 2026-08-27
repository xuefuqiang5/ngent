use netagent_models::{ArtifactKind, ArtifactRef, DnsEvent, Finding, Flow};
use serde::Serialize;

use crate::storage::artifact_store::ArtifactStore;
use crate::storage::sqlite::SqliteStore;

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceBundleMetadata {
    pub finding_count: usize,
    pub flow_count: usize,
    pub dns_event_count: usize,
    pub artifact_count: usize,
    pub pcap_artifact_count: usize,
    pub evidence_ref_count: usize,
    pub time_window_start: Option<String>,
    pub time_window_end: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MarkdownReportInput {
    pub title: String,
    pub findings: Vec<Finding>,
    pub flows: Vec<Flow>,
    pub dns_events: Vec<DnsEvent>,
    pub artifacts: Vec<ArtifactRef>,
}

pub fn collect_report_input(
    store: &SqliteStore,
    artifact_store: &ArtifactStore,
    title: &str,
) -> Result<MarkdownReportInput, String> {
    Ok(MarkdownReportInput {
        title: title.to_string(),
        findings: store.list_findings()?,
        flows: store.list_flows()?,
        dns_events: store.list_dns_events()?,
        artifacts: artifact_store.list_artifacts(),
    })
}

pub fn build_markdown_report(input: &MarkdownReportInput) -> (String, EvidenceBundleMetadata) {
    let metadata = build_evidence_bundle_metadata(input);

    let mut lines = vec![
        format!("# {}", input.title),
        String::new(),
        "## Evidence Bundle".to_string(),
        format!("- Findings: {}", metadata.finding_count),
        format!("- Evidence refs: {}", metadata.evidence_ref_count),
        format!("- Flows: {}", metadata.flow_count),
        format!("- DNS events: {}", metadata.dns_event_count),
        format!("- Artifacts: {}", metadata.artifact_count),
        format!("- PCAP artifacts: {}", metadata.pcap_artifact_count),
        format!(
            "- Time window: {}",
            format_time_window(&metadata.time_window_start, &metadata.time_window_end)
        ),
        String::new(),
        "## Findings".to_string(),
    ];

    if input.findings.is_empty() {
        lines.push("- No findings available.".to_string());
    } else {
        for finding in &input.findings {
            lines.push(format!(
                "- {} [{}] {}",
                finding.id, finding.severity, finding.title
            ));
            lines.push(format!("  - Created: {}", finding.created_at));
            lines.push(format!("  - Category: {}", finding.category));
            lines.push(format!("  - Description: {}", finding.description));
            if !finding.entities.is_empty() {
                lines.push(format!("  - Entities: {}", finding.entities.join(", ")));
            }
            if !finding.evidence.is_empty() {
                lines.push("  - Evidence refs:".to_string());
                for evidence in &finding.evidence {
                    lines.push(format!(
                        "    - {} / {} / {}",
                        evidence.evidence_type, evidence.id, evidence.summary
                    ));
                }
            }
        }
    }

    lines.push(String::new());
    lines.push("## Source And Destination Summary".to_string());
    if input.flows.is_empty() {
        lines.push("- No flows available.".to_string());
    } else {
        for flow in input.flows.iter().take(10) {
            lines.push(format!(
                "- {}: {}:{} -> {}:{} protocol={} service={} start={} end={} bytes_in={} bytes_out={} packets_in={} packets_out={}",
                flow.id,
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
                empty_as_dash(&flow.service),
                flow.start_time,
                flow.end_time.as_deref().unwrap_or("-"),
                flow.bytes_in,
                flow.bytes_out,
                flow.packets_in,
                flow.packets_out
            ));
        }
    }

    lines.push(String::new());
    lines.push("## DNS Evidence Samples".to_string());
    if input.dns_events.is_empty() {
        lines.push("- No DNS events available.".to_string());
    } else {
        for event in input.dns_events.iter().take(10) {
            lines.push(format!(
                "- {} {} -> {} query={} type={} rcode={} answers={}",
                event.timestamp,
                event.src_ip,
                event.dst_ip,
                event.query_name,
                event.query_type,
                event.response_code,
                format_answers(&event.answers)
            ));
        }
    }

    lines.push(String::new());
    lines.push("## Artifacts".to_string());
    if input.artifacts.is_empty() {
        lines.push("- No artifacts referenced.".to_string());
    } else {
        for artifact in &input.artifacts {
            lines.push(format!(
                "- {} [{}] {} ({})",
                artifact.id,
                artifact.path,
                artifact.note,
                artifact.kind_label()
            ));
        }
    }

    (lines.join("\n"), metadata)
}

pub fn build_evidence_bundle_metadata(input: &MarkdownReportInput) -> EvidenceBundleMetadata {
    EvidenceBundleMetadata {
        finding_count: input.findings.len(),
        flow_count: input.flows.len(),
        dns_event_count: input.dns_events.len(),
        artifact_count: input.artifacts.len(),
        pcap_artifact_count: input
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == ArtifactKind::Pcap)
            .count(),
        evidence_ref_count: input
            .findings
            .iter()
            .map(|finding| finding.evidence.len())
            .sum(),
        time_window_start: earliest_time(input),
        time_window_end: latest_time(input),
    }
}

fn earliest_time(input: &MarkdownReportInput) -> Option<String> {
    input
        .flows
        .iter()
        .map(|flow| flow.start_time.as_str())
        .chain(
            input
                .dns_events
                .iter()
                .map(|event| event.timestamp.as_str()),
        )
        .chain(
            input
                .findings
                .iter()
                .map(|finding| finding.created_at.as_str()),
        )
        .filter(|value| !value.is_empty())
        .min()
        .map(str::to_string)
}

fn latest_time(input: &MarkdownReportInput) -> Option<String> {
    input
        .flows
        .iter()
        .flat_map(|flow| [Some(flow.start_time.as_str()), flow.end_time.as_deref()])
        .flatten()
        .chain(
            input
                .dns_events
                .iter()
                .map(|event| event.timestamp.as_str()),
        )
        .chain(
            input
                .findings
                .iter()
                .map(|finding| finding.created_at.as_str()),
        )
        .filter(|value| !value.is_empty())
        .max()
        .map(str::to_string)
}

fn format_time_window(start: &Option<String>, end: &Option<String>) -> String {
    match (start, end) {
        (Some(start), Some(end)) => format!("{start} to {end}"),
        (Some(start), None) => format!("{start} to unknown"),
        (None, Some(end)) => format!("unknown to {end}"),
        (None, None) => "unknown".to_string(),
    }
}

fn empty_as_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

fn format_answers(answers: &[String]) -> String {
    if answers.is_empty() {
        "-".to_string()
    } else {
        answers.join(", ")
    }
}

trait ArtifactLabelExt {
    fn kind_label(&self) -> &'static str;
}

impl ArtifactLabelExt for ArtifactRef {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            ArtifactKind::RawToolOutput => "raw_tool_output",
            ArtifactKind::Summary => "summary",
            ArtifactKind::Pcap => "pcap",
            ArtifactKind::Report => "report",
            ArtifactKind::IocExport => "ioc_export",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netagent_models::{EvidenceRef, Flow};
    use serde_json::json;

    #[test]
    fn report_includes_traceable_evidence_and_pcap_metadata() {
        let input = MarkdownReportInput {
            title: "Case Report".to_string(),
            findings: vec![Finding {
                id: "finding_1".to_string(),
                created_at: "2026-06-03T10:00:02Z".to_string(),
                title: "NXDOMAIN spike".to_string(),
                severity: "medium".to_string(),
                confidence: "medium".to_string(),
                category: "dns_anomaly".to_string(),
                description: "Host has elevated NXDOMAIN ratio.".to_string(),
                entities: vec!["10.0.0.8".to_string()],
                evidence: vec![EvidenceRef {
                    evidence_type: "dns_event".to_string(),
                    id: "dns_stats_10.0.0.8".to_string(),
                    summary: "7 NXDOMAIN responses".to_string(),
                }],
                recommended_actions: vec!["Review DNS queries".to_string()],
                metadata: json!({}),
            }],
            flows: vec![Flow {
                id: "flow_1".to_string(),
                start_time: "2026-06-03T10:00:00Z".to_string(),
                end_time: Some("2026-06-03T10:00:05Z".to_string()),
                src_ip: "10.0.0.8".to_string(),
                src_port: 53000,
                dst_ip: "1.1.1.1".to_string(),
                dst_port: 53,
                protocol: "udp".to_string(),
                service: "dns".to_string(),
                bytes_in: 120,
                bytes_out: 240,
                packets_in: 2,
                packets_out: 4,
                state: "closed".to_string(),
                metadata: json!({}),
            }],
            dns_events: vec![DnsEvent {
                id: "dns_1".to_string(),
                timestamp: "2026-06-03T10:00:01Z".to_string(),
                src_ip: "10.0.0.8".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                query_name: "missing.example".to_string(),
                query_type: "A".to_string(),
                response_code: "NXDOMAIN".to_string(),
                response_code_num: 3,
                answers: vec![],
            }],
            artifacts: vec![ArtifactRef {
                id: "artifact_1".to_string(),
                kind: ArtifactKind::Pcap,
                note: "Captured pcap".to_string(),
                path: "/tmp/case.pcap".to_string(),
            }],
        };

        let (report, metadata) = build_markdown_report(&input);

        assert_eq!(metadata.pcap_artifact_count, 1);
        assert_eq!(metadata.evidence_ref_count, 1);
        assert_eq!(
            metadata.time_window_start,
            Some("2026-06-03T10:00:00Z".to_string())
        );
        assert!(report.contains("## Evidence Bundle"));
        assert!(report.contains("dns_event / dns_stats_10.0.0.8 / 7 NXDOMAIN responses"));
        assert!(report.contains("10.0.0.8:53000 -> 1.1.1.1:53"));
        assert!(report.contains("/tmp/case.pcap"));
    }
}
