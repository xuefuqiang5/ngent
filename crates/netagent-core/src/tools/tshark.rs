use std::path::Path;
use std::process::Command;

use netagent_models::{DnsEvent, Flow};
use serde_json::json;

/// Run `tshark` to extract 5-tuple flows from a pcap file.
///
/// Uses `tshark -r <path> -T fields` with a fixed field set.
/// Returns a list of Flow records.  Caller is responsible for assigning IDs.
pub fn extract_flows(pcap_path: &Path) -> Result<Vec<Flow>, String> {
    let output = run_tshark_fields(
        pcap_path,
        &[
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "ip.proto",
            "-e",
            "frame.len",
            "-e",
            "tcp.flags",
        ],
    )?;

    parse_flow_output(&output)
}

/// Run `tshark -r <path> -Y dns -T fields` to extract DNS events.
pub fn extract_dns(pcap_path: &Path) -> Result<Vec<DnsEvent>, String> {
    let output = run_tshark_fields(
        pcap_path,
        &[
            "-Y",
            "dns",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.qry.type",
            "-e",
            "dns.flags.rcode",
            "-e",
            "dns.resp.name",
        ],
    )?;

    parse_dns_output(&output)
}

fn run_tshark_fields(pcap_path: &Path, extra_args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("tshark");
    cmd.arg("-r")
        .arg(pcap_path)
        .arg("-T")
        .arg("fields")
        .arg("-E")
        .arg("separator=\t")
        .arg("-E")
        .arg("header=n")
        .arg("-E")
        .arg("occurrence=f");

    for arg in extra_args {
        cmd.arg(arg);
    }

    let output = cmd.output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "tshark is not installed or not on PATH".to_string()
        } else {
            format!("failed to run tshark: {e}")
        }
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tshark exited with error: {stderr}"));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("invalid tshark output encoding: {e}"))
}

/// Parse tab-separated tshark flow output into Flow records.
fn parse_flow_output(raw: &str) -> Result<Vec<Flow>, String> {
    let mut flows = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 7 {
            continue;
        }

        let epoch: f64 = fields[0].parse().unwrap_or(0.0);
        let start_time = format_epoch(epoch);
        let src_ip = fields[1].to_string();
        let dst_ip = fields[4].to_string();

        // Source port: try tcp first, then udp
        let src_port: u16 = fields[2]
            .parse()
            .or_else(|_| fields[3].parse())
            .unwrap_or(0);

        // Destination port
        let dst_port: u16 = fields[5]
            .parse()
            .or_else(|_| fields[6].parse())
            .unwrap_or(0);

        let proto_num: u8 = fields[7].parse().unwrap_or(0);
        let protocol = proto_to_name(proto_num);
        let service = port_to_service(dst_port, &protocol);

        let frame_len: u64 = fields[8].parse().unwrap_or(0);

        let flow = Flow {
            id: format!(
                "flow_{}_{}_{}_{}_{}",
                src_ip, src_port, dst_ip, dst_port, protocol
            ),
            start_time,
            end_time: None,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            service,
            bytes_in: 0,
            bytes_out: frame_len,
            packets_in: 0,
            packets_out: 1,
            state: String::new(),
            metadata: json!({
                "proto_num": proto_num,
                "tcp_flags": fields.get(9).unwrap_or(&"").to_string(),
                "frame_len": frame_len,
            }),
        };
        flows.push(flow);
    }

    // Merge flows with same 5-tuple
    merge_flows(&mut flows);
    Ok(flows)
}

fn merge_flows(flows: &mut Vec<Flow>) {
    use std::collections::HashMap;

    let mut map: HashMap<String, Flow> = HashMap::new();
    for flow in flows.drain(..) {
        let key = format!(
            "{}_{}_{}_{}_{}",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
        );
        if let Some(existing) = map.get_mut(&key) {
            existing.bytes_out += flow.bytes_out;
            existing.packets_out += flow.packets_out;
            if existing.end_time.as_deref().unwrap_or("") < flow.start_time.as_str() {
                existing.end_time = Some(flow.start_time.clone());
            }
        } else {
            map.insert(key, flow);
        }
    }
    *flows = map.into_values().collect();
    flows.sort_by(|a, b| a.start_time.cmp(&b.start_time));
}

fn parse_dns_output(raw: &str) -> Result<Vec<DnsEvent>, String> {
    let mut events = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 5 {
            continue;
        }

        let epoch: f64 = fields[0].parse().unwrap_or(0.0);
        let timestamp = format_epoch(epoch);
        let query_name = fields[3].to_string();
        let query_type = fields[4].to_string();

        // dns.flags.rcode is a decimal number in tshark field output
        let rcode_num: u8 = fields[5].parse().unwrap_or(0);
        let response_code = rcode_to_str(rcode_num);

        let resp_name = fields.get(6).unwrap_or(&"").to_string();
        let mut answers = Vec::new();
        if !resp_name.is_empty() {
            answers.push(resp_name);
        }

        events.push(DnsEvent {
            id: format!(
                "dns_{}_{}_{}_{}",
                fields[1], fields[2], query_name, timestamp
            ),
            timestamp,
            src_ip: fields[1].to_string(),
            dst_ip: fields[2].to_string(),
            query_name,
            query_type,
            response_code,
            response_code_num: rcode_num,
            answers,
        });
    }

    Ok(events)
}

fn format_epoch(epoch: f64) -> String {
    if epoch == 0.0 {
        return String::from("1970-01-01T00:00:00Z");
    }
    let secs = epoch as i64;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let nsecs = ((epoch - secs as f64) * 1_000_000_000.0) as u32;
    // Simple ISO 8601 formatting
    let dt_secs = secs % 86400;
    let days = secs / 86400;
    let hours = dt_secs / 3600;
    let mins = (dt_secs % 3600) / 60;
    let secs_rem = dt_secs % 60;
    // Days since epoch -> approximate date (good enough for Phase 7)
    // Use a simple calculation from 1970-01-01
    let (year, month, day) = days_since_epoch_to_date(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        year, month, day, hours, mins, secs_rem, nsecs
    )
}

fn days_since_epoch_to_date(days: i64) -> (i64, u32, u32) {
    let mut d = days;
    // Algorithm: start from 1970-01-01, count years, then months, then days
    let mut year: i64 = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
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
    let day = (d + 1) as u32;
    (year, month, day)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn proto_to_name(num: u8) -> String {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "unknown",
    }
    .to_string()
}

fn port_to_service(port: u16, protocol: &str) -> String {
    if protocol != "tcp" && protocol != "udp" {
        return String::new();
    }
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        993 => "imaps",
        995 => "pop3s",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        27017 => "mongodb",
        _ => "",
    }
    .to_string()
}

fn rcode_to_str(num: u8) -> String {
    match num {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_nxdomain() {
        let raw = "1712345678.123\t10.0.0.8\t8.8.8.8\tbad.example.com\tA\t3\t\n";
        let events = parse_dns_output(raw).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].response_code, "NXDOMAIN");
        assert_eq!(events[0].response_code_num, 3);
    }

    #[test]
    fn test_proto_to_name() {
        assert_eq!(proto_to_name(6), "tcp");
        assert_eq!(proto_to_name(17), "udp");
        assert_eq!(proto_to_name(1), "icmp");
    }
}
