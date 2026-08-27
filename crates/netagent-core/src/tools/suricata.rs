use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use netagent_models::{Alert, ArtifactRef, DnsEvent, Flow};
use serde_json::Value;

use crate::storage::artifact_store::ArtifactStore;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_EVE_FILE_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const MAX_MODEL_PREVIEW_CHARS: usize = 3_200;
const MAX_MODEL_PREVIEW_LINES: usize = 36;

const SURICATA_CANDIDATES: &[&str] = &[
    "/opt/homebrew/bin/suricata",
    "/usr/local/bin/suricata",
    "/usr/bin/suricata",
    "/bin/suricata",
];

/// Result of running Suricata over a pcap with fixed arguments.
#[derive(Debug)]
pub struct SuricataProcessOutput {
    pub binary_available: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stderr: String,
    pub alerts: Vec<Alert>,
    pub flows: Vec<Flow>,
    pub dns_events: Vec<DnsEvent>,
    /// Bounded copy of the produced eve.json stored as an artifact.
    pub log_artifact: Option<ArtifactRef>,
    /// Bounded preview for the model context.
    pub preview: String,
}

/// Run `suricata -r <pcap> -l <workdir>` with fixed arguments, parse the
/// produced eve.json lines, and store a bounded copy as an artifact. The
/// Agent cannot influence the command line; only the pcap path is
/// interpolated after validation. Missing binaries degrade gracefully.
pub fn process_pcap(
    pcap_path: &Path,
    artifact_store: &mut ArtifactStore,
    abort: &AtomicBool,
) -> Result<SuricataProcessOutput, String> {
    if abort.load(Ordering::Relaxed) {
        return Err(String::from("suricata processing aborted before execution"));
    }
    let Some(suricata) = SURICATA_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
    else {
        return Ok(SuricataProcessOutput {
            binary_available: false,
            exit_code: None,
            timed_out: false,
            stderr: format!(
                "suricata not found in fixed paths: {}",
                SURICATA_CANDIDATES.join(", ")
            ),
            alerts: Vec::new(),
            flows: Vec::new(),
            dns_events: Vec::new(),
            log_artifact: None,
            preview: String::from(
                "suricata is not installed at any allowlisted fixed path. Fall back to tshark.extract_flows / tshark.extract_dns on the pcap.",
            ),
        });
    };

    let work_dir = make_work_dir()?;
    let mut command = Command::new(&suricata);
    command
        .current_dir(&work_dir)
        .arg("-r")
        .arg(pcap_path)
        .arg("-l")
        .arg(&work_dir);
    // Fixed compile-time path to the demo local rules shipped with the repo.
    // Never user-controllable; absent on installs without the rules file.
    let demo_rules = {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../rules/suricata/demo_local.rules");
        path
    };
    if demo_rules.is_file() {
        command.arg("-S").arg(demo_rules);
    }
    let mut child = command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start suricata: {error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| String::from("suricata stderr pipe is unavailable"))?;
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));

    let (exit_code, timed_out, aborted) = wait_with_timeout(&mut child, PROCESS_TIMEOUT, abort)?;
    let (stderr, _) = stderr_reader
        .join()
        .map_err(|_| String::from("suricata stderr reader failed"))?;
    let stderr = String::from_utf8_lossy(&stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();

    if aborted {
        let _ = std::fs::remove_dir_all(&work_dir);
        return Err(String::from("suricata processing aborted by the user"));
    }

    let mut alerts = Vec::new();
    let mut flows = Vec::new();
    let mut dns_events = Vec::new();
    let mut raw_log = String::new();
    if exit_code == Some(0) && !timed_out {
        let eve_path = work_dir.join("eve.json");
        let contents = read_eve_file(&eve_path)?;
        if !contents.trim().is_empty() {
            let parsed = parse_eve_json_lines(&contents)?;
            alerts = parsed.0;
            flows = parsed.1;
            dns_events = parsed.2;
            raw_log = format!("\n== eve.json (bounded) ==\n{contents}");
        }
        let raw_log = raw_log.trim().to_string();
        let log_artifact = if raw_log.is_empty() {
            None
        } else {
            Some(artifact_store.write_raw_output("suricata.process_pcap", &raw_log)?)
        };
        let preview = build_preview(&alerts, &flows, &dns_events, &stderr);
        let _ = std::fs::remove_dir_all(&work_dir);
        return Ok(SuricataProcessOutput {
            binary_available: true,
            exit_code,
            timed_out: false,
            stderr,
            alerts,
            flows,
            dns_events,
            log_artifact,
            preview,
        });
    }

    let _ = std::fs::remove_dir_all(&work_dir);
    Ok(SuricataProcessOutput {
        binary_available: true,
        exit_code,
        timed_out,
        stderr,
        alerts,
        flows,
        dns_events,
        log_artifact: None,
        preview: format!(
            "suricata exited with code {exit_code:?} (timed_out={timed_out}). Bounded stderr was not returned; the RawToolOutput artifact was not produced because no eve.json was written. Fall back to tshark analysis."
        ),
    })
}

/// Parse JSON-lines `eve.json` into (alerts, flows, dns_events).
/// `event_type: alert` maps to Alert; `event_type: flow` maps to Flow;
/// `event_type: dns` maps to DnsEvent. All other event types are skipped.
pub fn parse_eve_json_lines(raw: &str) -> Result<(Vec<Alert>, Vec<Flow>, Vec<DnsEvent>), String> {
    let mut alerts = Vec::new();
    let mut flows = Vec::new();
    let mut dns_events = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Value::Object(record) = serde_json::from_str::<Value>(line)
            .map_err(|error| format!("invalid eve.json JSON line: {error}"))?
        else {
            continue;
        };
        match record.get("event_type").and_then(Value::as_str) {
            Some("alert") => {
                if let Some(alert) = parse_alert(&record) {
                    alerts.push(alert);
                }
            }
            Some("flow") => {
                if let Some(flow) = parse_flow(&record) {
                    flows.push(flow);
                }
            }
            Some("dns") => {
                if let Some(event) = parse_dns(&record) {
                    dns_events.push(event);
                }
            }
            _ => {}
        }
    }
    Ok((alerts, flows, dns_events))
}

fn parse_alert(record: &serde_json::Map<String, Value>) -> Option<Alert> {
    let alert = record.get("alert")?;
    let timestamp = record
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let signature = alert
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if signature.is_empty() {
        return None;
    }
    let signature_id = alert
        .get("signature_id")
        .and_then(Value::as_u64)
        .map(|id| id.to_string())
        .or_else(|| {
            alert
                .get("signature_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let severity = alert.get("severity").and_then(Value::as_u64).unwrap_or(0) as u32;
    let category = alert
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Some(Alert {
        id: String::new(),
        timestamp,
        signature,
        signature_id,
        severity,
        category,
        src_ip: record
            .get("src_ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        src_port: record.get("src_port").and_then(Value::as_u64).unwrap_or(0) as u16,
        dest_ip: record
            .get("dest_ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        dest_port: record.get("dest_port").and_then(Value::as_u64).unwrap_or(0) as u16,
        protocol: record
            .get("proto")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
            .to_lowercase(),
        metadata: serde_json::json!({
            "flow_id": record.get("flow_id").cloned().unwrap_or(Value::Null),
            "gid": alert.get("gid").cloned().unwrap_or(Value::Null),
            "rev": alert.get("rev").cloned().unwrap_or(Value::Null),
            "action": alert.get("action").cloned().unwrap_or(Value::Null),
            "source": "suricata",
        }),
    })
}

fn parse_flow(record: &serde_json::Map<String, Value>) -> Option<Flow> {
    let flow = record.get("flow")?;
    let timestamp = record
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let start_time = flow
        .get("start")
        .and_then(Value::as_str)
        .unwrap_or(&timestamp)
        .to_string();
    let end_time = flow.get("end").and_then(Value::as_str).map(str::to_string);
    let src_ip = record
        .get("src_ip")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dst_ip = record
        .get("dest_ip")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if src_ip.is_empty() && dst_ip.is_empty() {
        return None;
    }
    Some(Flow {
        id: String::new(),
        start_time,
        end_time,
        src_ip,
        src_port: record.get("src_port").and_then(Value::as_u64).unwrap_or(0) as u16,
        dst_ip,
        dst_port: record.get("dest_port").and_then(Value::as_u64).unwrap_or(0) as u16,
        protocol: record
            .get("proto")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
            .to_lowercase(),
        service: record
            .get("app_proto")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        bytes_in: flow
            .get("bytes_toclient")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        bytes_out: flow
            .get("bytes_toserver")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        packets_in: flow
            .get("pkts_toclient")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        packets_out: flow
            .get("pkts_toserver")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        state: flow
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        metadata: serde_json::json!({
            "source": "suricata",
            "flow_id": record.get("flow_id").cloned().unwrap_or(Value::Null),
            "reason": flow.get("reason").cloned().unwrap_or(Value::Null),
            "tx_count": flow.get("tx_cnt").cloned().unwrap_or(Value::Null),
            "alerted": flow.get("alerted").cloned().unwrap_or(Value::Null),
        }),
    })
}

fn parse_dns(record: &serde_json::Map<String, Value>) -> Option<DnsEvent> {
    let dns = record.get("dns")?;
    let timestamp = record
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let query_name = dns
        .pointer("/queries/0/rrname")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let query_type = dns
        .pointer("/queries/0/rrtype")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let response_code = dns
        .get("rcode")
        .and_then(Value::as_str)
        .unwrap_or("NOERROR")
        .to_string();
    let response_code_num = rcode_to_num(&response_code);
    let mut answers = Vec::new();
    if let Some(Value::Array(items)) = dns.get("answers") {
        for item in items {
            if let Some(data) = item.get("rdata").and_then(Value::as_str) {
                answers.push(data.to_string());
            }
        }
    }
    if answers.is_empty() {
        if let Some(Value::Array(items)) = dns.get("grouped").and_then(|grouped| grouped.get("A")) {
            for item in items {
                if let Some(data) = item.as_str() {
                    answers.push(data.to_string());
                }
            }
        }
    }
    Some(DnsEvent {
        id: String::new(),
        timestamp,
        src_ip: record
            .get("src_ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        dst_ip: record
            .get("dest_ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        query_name,
        query_type,
        response_code,
        response_code_num,
        answers,
    })
}

fn rcode_to_num(rcode: &str) -> u8 {
    match rcode.to_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        _ => 0,
    }
}

fn build_preview(
    alerts: &[Alert],
    flows: &[Flow],
    dns_events: &[DnsEvent],
    stderr: &str,
) -> String {
    let mut lines = vec![format!(
        "suricata parsed {} alert(s), {} connection(s), and {} DNS event(s).",
        alerts.len(),
        flows.len(),
        dns_events.len()
    )];
    for alert in alerts.iter().take(6) {
        lines.push(format!(
            "alert: {} {} {} -> {}:{} (severity={})",
            alert.signature,
            alert.protocol,
            alert.src_ip,
            alert.dest_ip,
            alert.dest_port,
            alert.severity
        ));
    }
    for flow in flows.iter().take(4) {
        lines.push(format!(
            "flow: {}:{} -> {}:{} {} {}",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol, flow.state
        ));
    }
    for event in dns_events.iter().take(4) {
        lines.push(format!(
            "dns: {} -> {} query={} type={} rcode={}",
            event.src_ip, event.dst_ip, event.query_name, event.query_type, event.response_code
        ));
    }
    if !stderr.trim().is_empty() {
        lines.push(format!("suricata stderr (bounded): {}", stderr.trim()));
    }
    let mut preview = String::new();
    for line in lines {
        if preview.chars().count() >= MAX_MODEL_PREVIEW_CHARS {
            break;
        }
        if !preview.is_empty() {
            preview.push('\n');
        }
        let remaining = MAX_MODEL_PREVIEW_CHARS.saturating_sub(preview.chars().count());
        preview.push_str(&line.chars().take(remaining).collect::<String>());
        if preview.lines().count() >= MAX_MODEL_PREVIEW_LINES {
            break;
        }
    }
    preview
}

fn make_work_dir() -> Result<PathBuf, String> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut path = std::env::temp_dir();
    path.push(format!("netagent-suricata-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("failed to create suricata work dir: {error}"))?;
    Ok(path)
}

fn read_eve_file(path: &Path) -> Result<String, String> {
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(String::new());
    };
    let mut buffer = [0_u8; 8 * 1024];
    let mut stored = Vec::new();
    loop {
        let Ok(count) = file.read(&mut buffer) else {
            break;
        };
        if count == 0 {
            break;
        }
        let remaining = MAX_EVE_FILE_BYTES.saturating_sub(stored.len());
        stored.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&stored).to_string())
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> (Vec<u8>, bool) {
    let mut stored = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let Ok(count) = reader.read(&mut buffer) else {
            break;
        };
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(stored.len());
        stored.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
        }
    }
    (stored, truncated)
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    abort: &AtomicBool,
) -> Result<(Option<i32>, bool, bool), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to poll process: {error}"))?
        {
            return Ok((status.code(), false, false));
        }
        if abort.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, false, true));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true, false));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../tests/fixtures/suricata_eve");
        path.push(name);
        path
    }

    #[test]
    fn parses_fixture_eve_into_alerts_flows_and_dns() {
        let raw = std::fs::read_to_string(fixture_path("eve.json")).expect("fixture eve.json");
        let (alerts, flows, dns_events) = parse_eve_json_lines(&raw).expect("parse eve.json");
        assert!(!alerts.is_empty());
        assert!(!flows.is_empty());
        assert!(!dns_events.is_empty());

        let alert = &alerts[0];
        assert!(!alert.signature.is_empty());
        assert!(!alert.signature_id.is_empty());
        assert!(alert.severity >= 1 && alert.severity <= 4);
        assert!(alert.src_port > 0 && alert.dest_port > 0);
        assert_eq!(alert.metadata["source"], "suricata");

        assert!(
            dns_events
                .iter()
                .any(|event| event.response_code == "NXDOMAIN")
        );
        assert!(dns_events.iter().any(|event| event.response_code_num == 3));
        assert!(
            flows
                .iter()
                .any(|flow| flow.metadata["source"] == "suricata")
        );
    }

    #[test]
    fn invalid_json_lines_are_rejected() {
        assert!(parse_eve_json_lines("not json\n").is_err());
    }

    #[test]
    fn unknown_event_types_are_skipped() {
        let (alerts, flows, dns_events) =
            parse_eve_json_lines("{\"event_type\":\"stats\",\"capture\":{\"kernel_packets\":1}}\n")
                .expect("parse stats line");
        assert!(alerts.is_empty() && flows.is_empty() && dns_events.is_empty());
    }

    #[test]
    fn empty_input_parses_to_empty() {
        let (alerts, flows, dns_events) = parse_eve_json_lines("").expect("parse empty");
        assert!(alerts.is_empty() && flows.is_empty() && dns_events.is_empty());
    }
}
