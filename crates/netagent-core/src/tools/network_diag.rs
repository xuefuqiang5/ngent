use std::io::Read;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::runtime::tool_registry::ToolResult;
use crate::storage::artifact_store::ArtifactStore;

const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BYTES: usize = 64 * 1024;
const MAX_PREVIEW_CHARS: usize = 3_200;

pub const TOOL_IDS: [&str; 12] = [
    "network.ping",
    "network.dns_lookup",
    "network.tcp_connect",
    "network.http_probe",
    "network.tls_inspect",
    "network.traceroute",
    "system.processes",
    "system.connections",
    "system.dns_config",
    "system.proxy_config",
    "system.route_lookup",
    "system.port_owner",
];

pub fn run(
    tool: &str,
    input: &Map<String, Value>,
    artifacts: &mut ArtifactStore,
    abort: &AtomicBool,
) -> Result<ToolResult, String> {
    match tool {
        "network.tcp_connect" => tcp_connect(input, abort),
        "network.ping" => command_tool(tool, input, artifacts, ping_spec(input)?, abort),
        "network.dns_lookup" => command_tool(tool, input, artifacts, dns_spec(input)?, abort),
        "network.http_probe" => command_tool(tool, input, artifacts, http_spec(input)?, abort),
        "network.tls_inspect" => command_tool(tool, input, artifacts, tls_spec(input)?, abort),
        "network.traceroute" => {
            command_tool(tool, input, artifacts, traceroute_spec(input)?, abort)
        }
        "system.processes" => command_tool(tool, input, artifacts, processes_spec(input)?, abort),
        "system.connections" => {
            command_tool(tool, input, artifacts, connections_spec(input)?, abort)
        }
        "system.dns_config" => command_tool(tool, input, artifacts, dns_config_spec(input)?, abort),
        "system.proxy_config" => {
            command_tool(tool, input, artifacts, proxy_config_spec(input)?, abort)
        }
        "system.route_lookup" => {
            command_tool(tool, input, artifacts, route_lookup_spec(input)?, abort)
        }
        "system.port_owner" => command_tool(tool, input, artifacts, port_owner_spec(input)?, abort),
        _ => Err(format!("unsupported diagnostic tool: {tool}")),
    }
}

struct Spec {
    candidates: &'static [&'static str],
    args: Vec<String>,
}

fn command_tool(
    tool: &str,
    input: &Map<String, Value>,
    artifacts: &mut ArtifactStore,
    spec: Spec,
    abort: &AtomicBool,
) -> Result<ToolResult, String> {
    let executable = spec
        .candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| format!("no allowlisted executable is installed for {tool}"))?;
    let mut child = Command::new(&executable)
        .args(&spec.args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start {tool}: {error}"))?;
    let stdout = child.stdout.take().ok_or("diagnostic stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("diagnostic stderr unavailable")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + TIMEOUT;
    let (status, timed_out) = loop {
        if abort.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{tool} aborted by the user"));
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("failed to poll {tool}: {e}"))?
        {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (
                child
                    .wait()
                    .map_err(|e| format!("failed to stop {tool}: {e}"))?,
                true,
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stdout_truncated) = stdout_reader.join().map_err(|_| "stdout reader failed")?;
    let (stderr, stderr_truncated) = stderr_reader.join().map_err(|_| "stderr reader failed")?;
    let stdout = sanitize(&String::from_utf8_lossy(&stdout));
    let stderr = sanitize(&String::from_utf8_lossy(&stderr));
    let raw = format!(
        "tool={tool}\nexecutable={}\narguments={}\nexit_code={:?}\ntimed_out={timed_out}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}",
        executable.display(),
        spec.args.join(" "),
        status.code()
    );
    let artifact = artifacts.write_raw_output(tool, &raw)?;
    let preview = truncate(&if stdout.is_empty() {
        stderr.clone()
    } else {
        stdout.clone()
    });
    let ok = status.success() && !timed_out;
    Ok(ToolResult {
        title: tool.replace('.', " "),
        summary: format!(
            "{tool} completed: ok={ok}, timed_out={timed_out}. Raw output is stored as an artifact."
        ),
        structured: json!({
            "ok": ok,
            "timed_out": timed_out,
            "exit_code": status.code(),
            "target": input.get("target"),
            "preview": preview,
            "raw_output_in_artifact": true,
        }),
        artifacts: vec![artifact.clone()],
        truncated: stdout_truncated || stderr_truncated || raw.chars().count() > MAX_PREVIEW_CHARS,
        raw_output_artifact: Some(artifact),
    })
}

fn tcp_connect(input: &Map<String, Value>, abort: &AtomicBool) -> Result<ToolResult, String> {
    reject_unknown(input, &["target", "port", "timeout_ms"])?;
    let target = target(input)?;
    let port = input
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .ok_or("port must be an integer between 1 and 65535")? as u16;
    let timeout_ms = input
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(3_000)
        .clamp(100, 8_000);
    let addresses = (target.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve target: {e}"))?
        .collect::<Vec<_>>();
    let started = Instant::now();
    let mut last_error = String::new();
    for address in &addresses {
        if abort.load(Ordering::Relaxed) {
            return Err(String::from("network.tcp_connect aborted by the user"));
        }
        match TcpStream::connect_timeout(address, Duration::from_millis(timeout_ms)) {
            Ok(_) => {
                return Ok(ToolResult {
                    title: String::from("TCP connectivity"),
                    summary: format!(
                        "Connected to {target}:{port} in {} ms.",
                        started.elapsed().as_millis()
                    ),
                    structured: json!({"ok": true, "target": target, "port": port, "address": address, "latency_ms": started.elapsed().as_millis()}),
                    artifacts: Vec::new(),
                    truncated: false,
                    raw_output_artifact: None,
                });
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    Ok(ToolResult {
        title: String::from("TCP connectivity"),
        summary: format!("Could not connect to {target}:{port}: {last_error}"),
        structured: json!({"ok": false, "target": target, "port": port, "resolved_addresses": addresses, "error": last_error}),
        artifacts: Vec::new(),
        truncated: false,
        raw_output_artifact: None,
    })
}

fn ping_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["target", "count"])?;
    let count = input
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or(3)
        .clamp(1, 5);
    Ok(Spec {
        candidates: &["/sbin/ping", "/bin/ping", "/usr/bin/ping"],
        args: vec!["-c".into(), count.to_string(), target(input)?],
    })
}

fn dns_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["target", "record_type"])?;
    let record_type = input
        .get("record_type")
        .and_then(Value::as_str)
        .unwrap_or("A")
        .to_ascii_uppercase();
    if !["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR"].contains(&record_type.as_str()) {
        return Err("unsupported DNS record_type".into());
    }
    Ok(Spec {
        candidates: &["/usr/bin/dig", "/opt/homebrew/bin/dig", "/usr/bin/host"],
        args: vec!["+short".into(), target(input)?, record_type],
    })
}

fn http_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["url"])?;
    let url = input
        .get("url")
        .and_then(Value::as_str)
        .ok_or("url is required")?;
    if url.len() > 2048
        || !(url.starts_with("http://") || url.starts_with("https://"))
        || url.contains('@')
        || url.chars().any(char::is_whitespace)
    {
        return Err("url must be a bounded http(s) URL without credentials or whitespace".into());
    }
    Ok(Spec {
        candidates: &["/usr/bin/curl", "/opt/homebrew/bin/curl"],
        args: vec![
            "--head".into(),
            "--location".into(),
            "--max-time".into(),
            "8".into(),
            "--max-redirs".into(),
            "5".into(),
            "--silent".into(),
            "--show-error".into(),
            url.into(),
        ],
    })
}

fn tls_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["target", "port"])?;
    let target = target(input)?;
    let port = input.get("port").and_then(Value::as_u64).unwrap_or(443);
    if !(1..=65535).contains(&port) {
        return Err("port must be between 1 and 65535".into());
    }
    Ok(Spec {
        candidates: &["/usr/bin/openssl", "/opt/homebrew/bin/openssl"],
        args: vec![
            "s_client".into(),
            "-connect".into(),
            format!("{target}:{port}"),
            "-servername".into(),
            target,
            "-showcerts".into(),
        ],
    })
}

fn traceroute_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["target", "max_hops"])?;
    let hops = input
        .get("max_hops")
        .and_then(Value::as_u64)
        .unwrap_or(12)
        .clamp(1, 20);
    Ok(Spec {
        candidates: &[
            "/usr/sbin/traceroute",
            "/usr/bin/traceroute",
            "/bin/traceroute",
        ],
        args: vec![
            "-m".into(),
            hops.to_string(),
            "-w".into(),
            "1".into(),
            target(input)?,
        ],
    })
}

fn processes_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &[])?;
    Ok(Spec {
        candidates: &["/bin/ps", "/usr/bin/ps"],
        args: vec!["-axo".into(), "pid,ppid,user,%cpu,%mem,comm".into()],
    })
}
fn connections_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &[])?;
    Ok(Spec {
        candidates: &["/usr/sbin/lsof", "/usr/bin/lsof"],
        args: vec!["-nP".into(), "-i".into()],
    })
}
fn port_owner_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["port", "protocol"])?;
    let port = input
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .ok_or("port must be between 1 and 65535")?;
    let protocol = input
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("tcp")
        .to_ascii_uppercase();
    if !["TCP", "UDP"].contains(&protocol.as_str()) {
        return Err("protocol must be tcp or udp".into());
    }
    Ok(Spec {
        candidates: &["/usr/sbin/lsof", "/usr/bin/lsof"],
        args: vec!["-nP".into(), format!("-i{protocol}:{port}")],
    })
}

#[cfg(target_os = "macos")]
fn dns_config_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &[])?;
    Ok(Spec {
        candidates: &["/usr/sbin/scutil"],
        args: vec!["--dns".into()],
    })
}
#[cfg(target_os = "linux")]
fn dns_config_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &[])?;
    Ok(Spec {
        candidates: &["/usr/bin/resolvectl", "/bin/resolvectl"],
        args: vec!["status".into()],
    })
}

#[cfg(target_os = "macos")]
fn proxy_config_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &[])?;
    Ok(Spec {
        candidates: &["/usr/sbin/scutil"],
        args: vec!["--proxy".into()],
    })
}
#[cfg(target_os = "linux")]
fn proxy_config_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &[])?;
    Ok(Spec {
        candidates: &["/usr/bin/gsettings"],
        args: vec!["get".into(), "org.gnome.system.proxy".into(), "mode".into()],
    })
}

#[cfg(target_os = "macos")]
fn route_lookup_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["target"])?;
    Ok(Spec {
        candidates: &["/sbin/route"],
        args: vec!["-n".into(), "get".into(), target(input)?],
    })
}
#[cfg(target_os = "linux")]
fn route_lookup_spec(input: &Map<String, Value>) -> Result<Spec, String> {
    reject_unknown(input, &["target"])?;
    Ok(Spec {
        candidates: &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
        args: vec!["route".into(), "get".into(), target(input)?],
    })
}

fn target(input: &Map<String, Value>) -> Result<String, String> {
    let value = input
        .get("target")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or("target is required")?;
    if value.len() > 253
        || value.starts_with('-')
        || value
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-')))
    {
        return Err("target must be an IP address or DNS hostname".into());
    }
    if value.parse::<IpAddr>().is_err()
        && !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
    {
        return Err("target must be an IP address or DNS hostname".into());
    }
    Ok(value.to_string())
}

fn reject_unknown(input: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if let Some(field) = input.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unknown input field: {field}"));
    }
    Ok(())
}

fn read_bounded<R: Read>(mut reader: R) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    while let Ok(count) = reader.read(&mut buffer) {
        if count == 0 {
            break;
        }
        let remaining = MAX_BYTES.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
        }
    }
    (output, truncated)
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect()
}
fn truncate(value: &str) -> String {
    let mut chars = value.chars();
    let result = chars.by_ref().take(MAX_PREVIEW_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{result}…")
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_rejects_shell_syntax() {
        assert!(target(json!({"target":"google.com;id"}).as_object().unwrap()).is_err());
    }
    #[test]
    fn http_rejects_credentials() {
        assert!(
            http_spec(
                json!({"url":"https://user@example.com"})
                    .as_object()
                    .unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn tcp_port_is_bounded() {
        assert!(
            tcp_connect(
                json!({"target":"127.0.0.1","port":0}).as_object().unwrap(),
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
    #[test]
    fn tcp_connect_honors_abort_before_connecting() {
        assert!(
            tcp_connect(
                json!({"target":"127.0.0.1","port":443})
                    .as_object()
                    .unwrap(),
                &AtomicBool::new(true),
            )
            .expect_err("aborted diagnostic")
            .contains("aborted")
        );
    }
    #[test]
    fn tls_uses_macos_compatible_fixed_arguments() {
        let spec = tls_spec(
            json!({"target":"example.com","port":443})
                .as_object()
                .unwrap(),
        )
        .expect("valid TLS probe");
        assert!(spec.args.contains(&String::from("-showcerts")));
        assert!(!spec.args.contains(&String::from("-brief")));
    }
}
