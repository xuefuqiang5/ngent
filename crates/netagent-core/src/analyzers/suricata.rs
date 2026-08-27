use netagent_models::{EvidenceRef, Finding};
use serde_json::json;
use std::collections::HashMap;

use crate::analyzers::dns::current_time_iso;
use crate::storage::sqlite::SqliteStore;

const MAX_EVIDENCE_REFS: usize = 5;

/// Turn persisted Suricata alerts into traceable findings.
///
/// Alerts are aggregated per distinct (signature, src_ip, dest_ip) tuple so a
/// repeated signature does not flood the finding stream. Each finding carries
/// the alert count, severity mapping, and evidence refs pointing at the
/// underlying alert rows.
pub fn ingest_alerts(
    store: &SqliteStore,
    finding_counter: &mut u64,
) -> Result<Vec<Finding>, String> {
    let alerts = store.list_alerts()?;
    if alerts.is_empty() {
        return Ok(Vec::new());
    }

    let mut groups: HashMap<(String, String, String), Vec<netagent_models::Alert>> = HashMap::new();
    for alert in alerts {
        groups
            .entry((
                alert.signature.clone(),
                alert.src_ip.clone(),
                alert.dest_ip.clone(),
            ))
            .or_default()
            .push(alert);
    }

    let mut findings = Vec::new();
    let mut ordered = groups.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.1.len()));

    for ((signature, src_ip, dest_ip), alerts) in ordered {
        *finding_counter += 1;
        let worst_severity = alerts.iter().map(|alert| alert.severity).min().unwrap_or(3);
        let severity = match worst_severity {
            0..=1 => "critical",
            2 => "high",
            _ => "medium",
        };
        let evidence = alerts
            .iter()
            .take(MAX_EVIDENCE_REFS)
            .map(|alert| EvidenceRef {
                evidence_type: String::from("suricata_alert"),
                id: alert.id.clone(),
                summary: format!(
                    "{} {} -> {}:{} (severity={})",
                    alert.signature, alert.src_ip, alert.dest_ip, alert.dest_port, alert.severity
                ),
            })
            .collect::<Vec<_>>();
        let mut entities = vec![src_ip.clone(), dest_ip.clone()];
        entities.retain(|entity| !entity.is_empty());
        entities.dedup();
        let total = alerts.len();
        let first = alerts[0].clone();
        findings.push(Finding {
            id: format!("finding_{finding_counter:04}"),
            created_at: current_time_iso(),
            title: format!("Suricata alert: {signature}"),
            severity: severity.to_string(),
            confidence: String::from("medium"),
            category: if first.category.is_empty() {
                String::from("sensor_alert")
            } else {
                first.category.clone()
            },
            description: format!(
                "Suricata raised {total} alert(s) for signature '{signature}' involving {src_ip} and {dest_ip}. The worst severity observed was level {}.",

                worst_severity
            ),
            entities,
            evidence,
            recommended_actions: vec![
                String::from(
                    "Correlate the alert with flow, DNS, and scan-detection evidence before responding.",
                ),
                String::from("Review the signature rule and its revision before proposing any action."),
            ],
            metadata: json!({
                "source": "suricata",
                "signature_id": first.signature_id,
                "signature": signature,
                "alert_count": total,
                "worst_severity": worst_severity,
                "alert_ids": alerts
                    .iter()
                    .take(10)
                    .map(|alert| alert.id.clone())
                    .collect::<Vec<_>>(),
            }),
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::SqliteStore;
    use netagent_models::Alert;

    fn temp_store(name: &str) -> SqliteStore {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netagent-suricata-analyzer-{name}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        SqliteStore::open(&path).expect("open store")
    }

    fn alert(id: &str, signature: &str, src: &str, dest: &str, severity: u32) -> Alert {
        Alert {
            id: id.to_string(),
            timestamp: "2026-06-03T10:00:00Z".to_string(),
            signature: signature.to_string(),
            signature_id: String::from("2000001"),
            severity,
            category: String::from("attempted-recon"),
            src_ip: src.to_string(),
            src_port: 40000,
            dest_ip: dest.to_string(),
            dest_port: 443,
            protocol: String::from("tcp"),
            metadata: json!({}),
        }
    }

    #[test]
    fn aggregates_alerts_by_signature_and_endpoints() {
        let store = temp_store("aggregate");
        store
            .insert_alerts(&[
                alert("a1", "ET SCAN SYN", "10.0.0.9", "192.168.1.1", 3),
                alert("a2", "ET SCAN SYN", "10.0.0.9", "192.168.1.1", 2),
                alert("a3", "ET SCAN SYN", "10.0.0.9", "192.168.1.2", 2),
                alert("a4", "ET DROP X", "10.0.0.9", "192.168.1.1", 3),
            ])
            .expect("insert alerts");

        let mut counter = 0_u64;
        let findings = ingest_alerts(&store, &mut counter).expect("ingest");
        assert_eq!(findings.len(), 3);
        let scan_pair = findings
            .iter()
            .find(|finding| finding.title.contains("ET SCAN SYN"))
            .expect("scan finding");
        assert_eq!(scan_pair.metadata["alert_count"], 2);
        assert_eq!(scan_pair.severity, "high");
        assert_eq!(scan_pair.evidence.len(), 2);
        assert_eq!(counter, 3);
        let _ = std::fs::remove_file(store_path("aggregate"));
    }

    #[test]
    fn empty_alerts_produce_no_findings() {
        let store = temp_store("empty");
        let mut counter = 0_u64;
        let findings = ingest_alerts(&store, &mut counter).expect("ingest");
        assert!(findings.is_empty());
        let _ = std::fs::remove_file(store_path("empty"));
    }

    fn store_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netagent-suricata-analyzer-{name}-{}.db",
            std::process::id()
        ));
        path
    }
}
