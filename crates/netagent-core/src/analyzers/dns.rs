use netagent_models::{EvidenceRef, Finding};

use crate::storage::sqlite::SqliteStore;

/// Run the NXDOMAIN spike detection rule against the current DNS events in the store.
///
/// Algorithm:
/// 1. Group DNS events by source IP.
/// 2. Calculate NXDOMAIN ratio per host.
/// 3. If ratio >= threshold, create a Finding.
pub fn detect_nxdomain_spike(
    store: &SqliteStore,
    finding_counter: &mut u64,
    threshold_ratio: f64,
    min_total_queries: usize,
) -> Result<Vec<Finding>, String> {
    let spikes = store.nxdomain_stats_by_host(threshold_ratio)?;

    let mut findings = Vec::new();
    for (host, total, nxdomain, ratio) in spikes {
        if total < min_total_queries {
            continue;
        }

        *finding_counter += 1;
        let finding_id = format!("finding_{:04}", finding_counter);
        let now = current_time_iso();

        let evidence = vec![EvidenceRef {
            evidence_type: "dns_event".to_string(),
            id: format!("dns_stats_{host}"),
            summary: format!(
                "{nxdomain} NXDOMAIN responses out of {total} total DNS queries ({:.1}% ratio)",
                ratio * 100.0
            ),
        }];

        let finding = Finding {
            id: finding_id,
            created_at: now,
            title: format!("NXDOMAIN spike detected for {host}"),
            severity: if ratio >= 0.5 { "high" } else { "medium" }.to_string(),
            confidence: if total >= 100 { "high" } else { "medium" }.to_string(),
            category: "dns_anomaly".to_string(),
            description: format!(
                "Host {host} produced {nxdomain} NXDOMAIN responses out of {total} DNS queries ({:.1}% ratio), exceeding the threshold of {:.0}%.",
                ratio * 100.0,
                threshold_ratio * 100.0
            ),
            entities: vec![host],
            evidence,
            recommended_actions: vec![
                "Investigate DNS query patterns for this host".to_string(),
                "Check for DGA-like domain names".to_string(),
                "Compare against host baseline".to_string(),
                "Export evidence report".to_string(),
            ],
            metadata: serde_json::json!({
                "nxdomain_count": nxdomain,
                "total_queries": total,
                "ratio": ratio,
                "threshold_ratio": threshold_ratio,
            }),
        };

        store.insert_finding(&finding)?;
        findings.push(finding);
    }

    Ok(findings)
}

/// Detect NXDOMAIN enumeration: a host that produced many distinct NXDOMAIN
/// query names in a short window. The fixture and real-world enumeration
/// traffic satisfy this pattern without external intelligence.
pub fn detect_nxdomain_enumeration(
    store: &SqliteStore,
    finding_counter: &mut u64,
    min_nxdomains: usize,
) -> Result<Vec<Finding>, String> {
    let hosts = store.nxdomain_qname_counts_by_host()?;

    let mut findings = Vec::new();
    for (host, distinct_names, total_nxdomain) in hosts {
        if distinct_names < min_nxdomains {
            continue;
        }

        *finding_counter += 1;
        let finding_id = format!("finding_{:04}", finding_counter);
        let now = current_time_iso();

        let evidence = vec![EvidenceRef {
            evidence_type: "dns_event".to_string(),
            id: format!("nxdomain_enum_{host}"),
            summary: format!(
                "{distinct_names} distinct NXDOMAIN query names out of {total_nxdomain} NXDOMAIN responses"
            ),
        }];

        let finding = Finding {
            id: finding_id,
            created_at: now,
            title: format!("NXDOMAIN enumeration pattern detected for {host}"),
            severity: "medium".to_string(),
            confidence: if total_nxdomain >= 50 {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            category: "dns_enumeration".to_string(),
            description: format!(
                "Host {host} queried {distinct_names} distinct names that returned NXDOMAIN (>= {min_nxdomains}), a pattern consistent with domain enumeration."
            ),
            entities: vec![host],
            evidence,
            recommended_actions: vec![
                "Inspect the queried names for DGA or typosquatting".to_string(),
                "Compare against host baseline".to_string(),
                "Check related connections to this host".to_string(),
            ],
            metadata: serde_json::json!({
                "distinct_nxdomain_names": distinct_names,
                "total_nxdomain_responses": total_nxdomain,
                "min_nxdomains": min_nxdomains,
            }),
        };

        store.insert_finding(&finding)?;
        findings.push(finding);
    }

    Ok(findings)
}

pub(crate) fn current_time_iso() -> String {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_secs_to_iso(now_secs as i64)
}

fn epoch_secs_to_iso(secs: i64) -> String {
    let d = secs / 86400;
    let s = secs % 86400;
    let (y, m, day) = days_to_date(d);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        day,
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

fn days_to_date(days: i64) -> (i64, u32, u32) {
    let mut d = days;
    let mut year: i64 = 1970;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if d < diy {
            break;
        }
        d -= diy;
        year += 1;
    }
    let month_lengths = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month: u32 = 1;
    for &mlen in &month_lengths {
        if d < mlen {
            break;
        }
        d -= mlen;
        month += 1;
    }
    (year, month, (d + 1) as u32)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
