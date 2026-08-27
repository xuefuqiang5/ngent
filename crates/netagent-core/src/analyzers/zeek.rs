use netagent_models::{EvidenceRef, Finding};
use serde_json::json;
use std::collections::HashMap;

use crate::storage::sqlite::SqliteStore;

const MAX_EVIDENCE_REFS: usize = 5;

/// Detect a possible TCP SYN scan from Zeek connection records.
///
/// Zeek flows carry `metadata.source == "zeek"`. A host that opens many
/// incomplete TCP connections (`conn_state == "S0"`, i.e. SYN sent, no reply)
/// towards a large number of distinct targets is scored as a potential SYN
/// scan.
pub fn detect_syn_scan(
    store: &SqliteStore,
    finding_counter: &mut u64,
    min_targets: usize,
) -> Result<Vec<Finding>, String> {
    let flows = store.list_flows()?;
    let mut targets: HashMap<String, Vec<(String, u16, String)>> = HashMap::new();
    let mut by_host: HashMap<String, Vec<String>> = HashMap::new();

    for flow in flows {
        let is_zeek = flow.metadata.get("source").and_then(|value| value.as_str()) == Some("zeek");
        if !is_zeek {
            continue;
        }
        let is_tcp = flow.protocol == "tcp";
        let is_open_attempt = flow.state == "S0" || flow.state.starts_with("SYN");
        if !is_tcp || !is_open_attempt {
            continue;
        }
        if flow.src_ip.is_empty() || flow.dst_ip.is_empty() {
            continue;
        }
        let pair = (flow.dst_ip.clone(), flow.dst_port, flow.id.clone());
        let list = targets.entry(flow.src_ip.clone()).or_default();
        if !list
            .iter()
            .any(|(ip, port, _)| *ip == pair.0 && *port == pair.1)
        {
            list.push(pair);
        }
        by_host
            .entry(flow.src_ip.clone())
            .or_default()
            .push(flow.id.clone());
    }

    let mut findings = Vec::new();
    let mut hosts = targets
        .into_iter()
        .filter(|(_, list)| list.len() >= min_targets)
        .collect::<Vec<_>>();
    hosts.sort_by_key(|entry| std::cmp::Reverse(entry.1.len()));

    for (host, list) in hosts {
        *finding_counter += 1;
        let created_at = crate::analyzers::dns::current_time_iso();
        let evidence = list
            .iter()
            .take(MAX_EVIDENCE_REFS)
            .map(|(dst_ip, dst_port, flow_id)| EvidenceRef {
                evidence_type: String::from("zeek_flow"),
                id: flow_id.clone(),
                summary: format!("incomplete TCP attempt {host} -> {dst_ip}:{dst_port}"),
            })
            .collect::<Vec<_>>();
        let flow_ids = by_host.get(&host).cloned().unwrap_or_default();
        findings.push(Finding {
            id: format!("finding_{finding_counter:04}"),
            created_at,
            title: format!("possible TCP SYN scan from {host}"),
            severity: String::from("high"),
            confidence: String::from("medium"),
            category: String::from("scan_detection"),
            description: format!(
                "Zeek connection records show {host} opening {} incomplete TCP connection attempt(s) (conn_state S0/SYN) toward distinct targets. This matches the signature of a TCP SYN port scan.",
                list.len()
            ),
            entities: vec![host.clone()],
            evidence,
            recommended_actions: vec![
                String::from(
                    "Correlate the scanning host with DNS, flow, and alert evidence before any response.",
                ),
                String::from("Verify whether the host is an expected scanner or a compromised endpoint."),
            ],
            metadata: json!({
                "source": "zeek",
                "targets": list.len(),
                "host": host,
                "flow_ids": flow_ids.into_iter().take(10).collect::<Vec<_>>(),
            }),
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::SqliteStore;
    use netagent_models::Flow;

    fn temp_store(name: &str) -> SqliteStore {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netagent-zeek-analyzer-{name}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).expect("open store");
        store
    }

    fn zeek_flow(id: &str, src: &str, dst: &str, port: u16) -> Flow {
        Flow {
            id: id.to_string(),
            start_time: "2026-06-03T10:00:00Z".to_string(),
            end_time: None,
            src_ip: src.to_string(),
            src_port: 40000,
            dst_ip: dst.to_string(),
            dst_port: port,
            protocol: "tcp".to_string(),
            service: String::new(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 1,
            state: "S0".to_string(),
            metadata: json!({ "source": "zeek" }),
        }
    }

    #[test]
    fn detects_syn_scan_over_min_targets() {
        let store = temp_store("synscan");
        let mut flows = Vec::new();
        for port in [22, 80, 443, 3306, 6379, 8080] {
            flows.push(zeek_flow(
                &format!("zeek_flow_{port}"),
                "10.0.0.5",
                "192.168.1.10",
                port,
            ));
        }
        flows.push(zeek_flow(
            "zeek_flow_normal",
            "10.0.0.5",
            "192.168.1.10",
            53,
        ));
        // Non-zeek flows (tshark) must be ignored.
        flows.push(Flow {
            id: "tshark_flow_1".to_string(),
            start_time: "2026-06-03T10:00:00Z".to_string(),
            end_time: None,
            src_ip: "10.0.0.5".to_string(),
            src_port: 40000,
            dst_ip: "192.168.1.10".to_string(),
            dst_port: 22,
            protocol: "tcp".to_string(),
            service: String::new(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 1,
            state: "S0".to_string(),
            metadata: json!({}),
        });
        store.insert_flows(&flows).expect("insert flows");

        let mut counter = 0_u64;
        let findings = detect_syn_scan(&store, &mut counter, 5).expect("detect");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entities, vec!["10.0.0.5".to_string()]);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].evidence.len(), 5);
        assert_eq!(counter, 1);
        let _ = std::fs::remove_file(store_path("synscan"));
    }

    #[test]
    fn below_threshold_produces_no_findings() {
        let store = temp_store("under");
        let flows = vec![zeek_flow("z1", "10.0.0.6", "192.168.1.10", 22)];
        store.insert_flows(&flows).expect("insert flows");
        let mut counter = 0_u64;
        let findings = detect_syn_scan(&store, &mut counter, 5).expect("detect");
        assert!(findings.is_empty());
        let _ = std::fs::remove_file(store_path("under"));
    }

    fn store_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netagent-zeek-analyzer-{name}-{}.db",
            std::process::id()
        ));
        path
    }
}
