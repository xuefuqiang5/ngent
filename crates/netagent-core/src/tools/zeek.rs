use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use netagent_models::{ArtifactRef, DnsEvent, Flow};
use serde_json::Value;

use crate::storage::artifact_store::ArtifactStore;
use crate::tools::tshark;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_LOG_FILE_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const MAX_MODEL_PREVIEW_CHARS: usize = 3_200;
const MAX_MODEL_PREVIEW_LINES: usize = 36;

const ZEEK_CANDIDATES: &[&str] = &[
    "/opt/homebrew/bin/zeek",
    "/usr/local/bin/zeek",
    "/usr/bin/zeek",
    "/bin/zeek",
    "/opt/zeek/bin/zeek",
];

/// Result of running Zeek over a pcap with fixed arguments.
#[derive(Debug)]
pub struct ZeekProcessOutput {
    pub binary_available: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stderr: String,
    pub flows: Vec<Flow>,
    pub dns_events: Vec<DnsEvent>,
    /// Bounded copy of the produced conn.log/dns.log stored as an artifact.
    pub log_artifact: Option<ArtifactRef>,
    /// Bounded preview for the model context.
    pub preview: String,
}

/// Run `zeek -C -r <pcap>` with fixed arguments in a temporary directory,
/// parse the JSON conn.log/dns.log outputs, and store a bounded copy as an
/// artifact. The Agent cannot influence the command line; only the pcap path
/// is interpolated after validation. Missing binaries degrade gracefully.
pub fn process_pcap(
    pcap_path: &Path,
    artifact_store: &mut ArtifactStore,
    abort: &AtomicBool,
) -> Result<ZeekProcessOutput, String> {
    if abort.load(Ordering::Relaxed) {
        return Err(String::from("zeek processing aborted before execution"));
    }
    let Some(zeek) = ZEEK_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
    else {
        return Ok(ZeekProcessOutput {
            binary_available: false,
            exit_code: None,
            timed_out: false,
            stderr: format!(
                "zeek not found in fixed paths: {}",
                ZEEK_CANDIDATES.join(", ")
            ),
            flows: Vec::new(),
            dns_events: Vec::new(),
            log_artifact: None,
            preview: String::from(
                "zeek is not installed at any allowlisted fixed path. Fall back to tshark.extract_flows / tshark.extract_dns on the pcap.",
            ),
        });
    };

    let work_dir = make_work_dir()?;
    let mut child = Command::new(&zeek)
        .current_dir(&work_dir)
        .arg("-C")
        .arg("-r")
        .arg(pcap_path)
        .arg("-e")
        .arg("redef LogAscii::use_json=T;")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start zeek: {error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| String::from("zeek stderr pipe is unavailable"))?;
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));

    let (exit_code, timed_out, aborted) = wait_with_timeout(&mut child, PROCESS_TIMEOUT, abort)?;
    let (stderr, _) = stderr_reader
        .join()
        .map_err(|_| String::from("zeek stderr reader failed"))?;
    let stderr = String::from_utf8_lossy(&stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();

    if aborted {
        let _ = std::fs::remove_dir_all(&work_dir);
        return Err(String::from("zeek processing aborted by the user"));
    }

    let mut flows = Vec::new();
    let mut dns_events = Vec::new();
    let mut raw_log = String::new();
    if exit_code == Some(0) && !timed_out {
        let conn_raw = read_log_file(&work_dir.join("conn.log"))?;
        raw_log.push_str(&format!("\n== conn.log ==\n{conn_raw}"));
        let dns_raw = read_log_file(&work_dir.join("dns.log"))?;
        raw_log.push_str(&format!("\n== dns.log ==\n{dns_raw}"));
        flows = parse_conn_log(&conn_raw)
            .map_err(|message| format!("failed to parse zeek conn.log: {message}"))?;
        dns_events = parse_dns_log(&dns_raw)
            .map_err(|message| format!("failed to parse zeek dns.log: {message}"))?;
        let raw_log = raw_log.trim().to_string();
        let log_artifact = if raw_log.is_empty() {
            None
        } else {
            Some(artifact_store.write_raw_output("zeek.process_pcap", &raw_log)?)
        };
        let preview = build_preview(&flows, &dns_events, &stderr);
        let _ = std::fs::remove_dir_all(&work_dir);
        return Ok(ZeekProcessOutput {
            binary_available: true,
            exit_code,
            timed_out: false,
            stderr,
            flows,
            dns_events,
            log_artifact,
            preview,
        });
    }

    let _ = std::fs::remove_dir_all(&work_dir);
    Ok(ZeekProcessOutput {
        binary_available: true,
        exit_code,
        timed_out,
        stderr,
        flows,
        dns_events,
        log_artifact: None,
        preview: format!(
            "zeek exited with code {exit_code:?} (timed_out={timed_out}). Bounded stderr was not returned; the RawToolOutput artifact was not produced because no logs were written. Fall back to tshark analysis."
        ),
    })
}

/// Parse JSON-lines `conn.log` produced by `zeek -r` into Flow records.
/// Zeek connection semantics are preserved: `id.orig_h` is the connection
/// initiator and is stored as the flow source.
pub fn parse_conn_log(raw: &str) -> Result<Vec<Flow>, String> {
    let mut flows = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Value::Object(record) = serde_json::from_str::<Value>(line)
            .map_err(|error| format!("invalid conn.log JSON line: {error}"))?
        else {
            continue;
        };
        let get = |key: &str| {
            record
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let get_num = |key: &str| record.get(key).and_then(Value::as_u64).unwrap_or(0);
        let ts = record.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
        let start_time = tshark::format_epoch(ts);
        let src_ip = get("id.orig_h");
        let dst_ip = get("id.resp_h");
        if src_ip.is_empty() && dst_ip.is_empty() {
            continue;
        }
        let bytes_in = record
            .get("resp_ip_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let bytes_out = record
            .get("orig_ip_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let packets_in = record.get("resp_pkts").and_then(Value::as_u64).unwrap_or(0);
        let packets_out = record.get("orig_pkts").and_then(Value::as_u64).unwrap_or(0);
        flows.push(Flow {
            id: String::new(),
            start_time,
            end_time: None,
            src_ip,
            src_port: get_num("id.orig_p") as u16,
            dst_ip,
            dst_port: get_num("id.resp_p") as u16,
            protocol: get("proto").to_lowercase(),
            service: get("service"),
            bytes_in,
            bytes_out,
            packets_in,
            packets_out,
            state: get("conn_state"),
            metadata: serde_json::json!({
                "source": "zeek",
                "uid": get("uid"),
                "history": get("history"),
                "missed_bytes": record.get("missed_bytes").cloned().unwrap_or(Value::Null),
                "ip_proto": record.get("ip_proto").cloned().unwrap_or(Value::Null),
                "local_orig": record.get("local_orig").cloned().unwrap_or(Value::Null),
                "local_resp": record.get("local_resp").cloned().unwrap_or(Value::Null),
                "zeek_ts": ts,
            }),
        });
    }
    Ok(flows)
}

/// Parse JSON-lines `dns.log` produced by `zeek -r` into DnsEvent records.
/// Zeek orients DNS ids by query semantics: `id.orig_h` is the querying
/// client and is stored as the event source, `id.resp_h` as the DNS server.
pub fn parse_dns_log(raw: &str) -> Result<Vec<DnsEvent>, String> {
    let mut events = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Value::Object(record) = serde_json::from_str::<Value>(line)
            .map_err(|error| format!("invalid dns.log JSON line: {error}"))?
        else {
            continue;
        };
        let get = |key: &str| {
            record
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let query_name = record
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let query_type = record
            .get("qtype_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let src_ip = get("id.orig_h");
        if src_ip.is_empty() && query_name.is_empty() {
            continue;
        }
        let response_code = record
            .get("rcode_name")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_string();
        let response_code_num = record.get("rcode").and_then(Value::as_u64).unwrap_or(0) as u8;
        let answers = match record.get("answers") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Value::String(value) => Some(value.clone()),
                    Value::Object(object) => object
                        .get("data")
                        .or_else(|| object.get("str"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let ts = record.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
        events.push(DnsEvent {
            id: String::new(),
            timestamp: tshark::format_epoch(ts),
            src_ip,
            dst_ip: get("id.resp_h"),
            query_name,
            query_type,
            response_code,
            response_code_num,
            answers,
        });
    }
    Ok(events)
}

fn build_preview(flows: &[Flow], dns_events: &[DnsEvent], stderr: &str) -> String {
    let mut lines = vec![format!(
        "zeek parsed {} connection(s) and {} DNS event(s).",
        flows.len(),
        dns_events.len()
    )];
    for flow in flows.iter().take(6) {
        lines.push(format!(
            "conn: {}:{} -> {}:{} {} {}",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol, flow.state
        ));
    }
    for event in dns_events.iter().take(6) {
        lines.push(format!(
            "dns: {} -> {} query={} type={} rcode={}",
            event.src_ip, event.dst_ip, event.query_name, event.query_type, event.response_code
        ));
    }
    if !stderr.trim().is_empty() {
        lines.push(format!("zeek stderr (bounded): {}", stderr.trim()));
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
    path.push(format!("netagent-zeek-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("failed to create zeek work dir: {error}"))?;
    Ok(path)
}

fn read_log_file(path: &Path) -> Result<String, String> {
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
        let remaining = MAX_LOG_FILE_BYTES.saturating_sub(stored.len());
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
    use std::sync::Arc;

    fn fixture_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../tests/fixtures/zeek_logs");
        path.push(name);
        path
    }

    #[test]
    fn parses_fixture_conn_log_into_flows() {
        let raw = std::fs::read_to_string(fixture_path("conn.log")).expect("fixture conn.log");
        let flows = parse_conn_log(&raw).expect("parse conn.log");
        assert!(!flows.is_empty());
        let first = &flows[0];
        assert!(first.src_port > 0 || first.dst_port > 0);
        assert_eq!(first.metadata["source"], "zeek");
        let dns = flows
            .iter()
            .find(|flow| flow.service == "dns")
            .expect("a dns flow");
        assert!(!dns.start_time.is_empty());
        assert_eq!(dns.metadata["source"], "zeek");
    }

    #[test]
    fn wait_with_timeout_kills_child_when_aborted() {
        let mut child = Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("start sleep child");
        let abort = Arc::new(AtomicBool::new(false));
        let abort_handle = abort.clone();
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            abort_handle.store(true, Ordering::Relaxed);
        });

        let started = Instant::now();
        let (exit_code, timed_out, aborted) =
            wait_with_timeout(&mut child, Duration::from_secs(2), abort.as_ref())
                .expect("wait for abort");
        trigger.join().expect("abort trigger");

        assert!(aborted);
        assert!(!timed_out);
        assert_eq!(exit_code, None);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().expect("poll killed child").is_some());
    }

    #[test]
    fn parses_fixture_dns_log_into_dns_events() {
        let raw = std::fs::read_to_string(fixture_path("dns.log")).expect("fixture dns.log");
        let events = parse_dns_log(&raw).expect("parse dns.log");
        assert!(!events.is_empty());
        assert!(events.iter().any(|event| event.response_code == "NXDOMAIN"));
        assert!(events.iter().any(|event| event.response_code_num == 3));
        let with_answers = events
            .iter()
            .find(|event| !event.answers.is_empty())
            .expect("an event with answers");
        assert!(with_answers.answers.iter().all(|answer| !answer.is_empty()));
        assert!(events.iter().all(|event| !event.src_ip.is_empty()));
    }

    #[test]
    fn invalid_json_lines_are_rejected() {
        assert!(parse_conn_log("not json\n").is_err());
        assert!(parse_dns_log("{\"broken").is_err());
    }

    #[test]
    fn empty_and_blank_inputs_parse_to_empty() {
        assert!(parse_conn_log("").unwrap().is_empty());
        assert!(parse_dns_log("   \n\n").unwrap().is_empty());
    }
}
