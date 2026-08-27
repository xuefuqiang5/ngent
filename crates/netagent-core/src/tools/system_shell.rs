use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::runtime::tool_registry::ToolResult;
use crate::storage::artifact_store::ArtifactStore;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURED_STREAM_BYTES: usize = 64 * 1024;
const MAX_MODEL_PREVIEW_CHARS: usize = 3_200;
const MAX_MODEL_PREVIEW_LINES: usize = 36;
const MAX_INTERFACE_CHARS: usize = 64;

pub const OPERATIONS: [&str; 6] = [
    "interfaces",
    "routes",
    "listeners",
    "tool_versions",
    "capture_preflight",
    "system_info",
];

#[derive(Debug, Clone)]
struct CommandSpec {
    label: &'static str,
    candidates: &'static [&'static str],
    args: &'static [&'static str],
}

#[derive(Debug)]
struct CommandCapture {
    label: String,
    executable: Option<PathBuf>,
    args: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    unavailable: bool,
}

impl CommandCapture {
    fn success(&self) -> bool {
        !self.unavailable && !self.timed_out && self.exit_code == Some(0)
    }

    fn bounded_metadata(&self) -> Value {
        json!({
            "label": self.label,
            "executable": self.executable.as_ref().map(|path| path.to_string_lossy().to_string()),
            "arguments": self.args,
            "exit_code": self.exit_code,
            "success": self.success(),
            "timed_out": self.timed_out,
            "unavailable": self.unavailable,
            "stdout_truncated_in_artifact": self.stdout_truncated,
            "stderr_truncated_in_artifact": self.stderr_truncated,
        })
    }
}

/// Execute one of a small set of read-only local inspection operations.
///
/// This is deliberately not a general shell. The Agent chooses an operation,
/// while Core owns every executable path and argument. No input is evaluated
/// by a shell and the child process receives no inherited environment secrets.
pub fn run(
    input: &Map<String, Value>,
    artifact_store: &mut ArtifactStore,
) -> Result<ToolResult, String> {
    reject_unknown_fields(input, &["operation", "interface"])?;
    let operation = input
        .get("operation")
        .and_then(Value::as_str)
        .filter(|value| OPERATIONS.contains(value))
        .ok_or_else(|| format!("operation must be one of: {}", OPERATIONS.join(", ")))?;
    let requested_interface = input
        .get("interface")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if operation == "capture_preflight" && requested_interface.is_none() {
        return Err(String::from(
            "interface must be a non-empty string for capture_preflight",
        ));
    }
    if let Some(interface) = requested_interface {
        validate_interface(interface)?;
    }

    let specs = command_specs(operation)?;
    let captures = specs
        .into_iter()
        .map(run_command)
        .collect::<Result<Vec<_>, _>>()?;
    let raw_output = build_raw_output(operation, requested_interface, &captures);
    let artifact = artifact_store.write_raw_output("system.shell", &raw_output)?;
    let preview = build_preview(&captures);
    let interfaces = extract_interfaces(&captures);
    let capture_devices = extract_capture_devices(&captures);
    let any_success = captures.iter().any(CommandCapture::success);
    let all_success = captures.iter().all(CommandCapture::success);
    let truncated = raw_output.chars().count() > preview.chars().count()
        || captures
            .iter()
            .any(|capture| capture.stdout_truncated || capture.stderr_truncated);

    let (title, summary, operation_details) = match operation {
        "interfaces" => (
            String::from("Local network interfaces"),
            if interfaces.is_empty() {
                String::from(
                    "The interface inspection ran, but no interface names could be parsed. See the bounded preview or raw-output artifact.",
                )
            } else {
                format!(
                    "Discovered {} local interface(s): {}.",
                    interfaces.len(),
                    interfaces.join(", ")
                )
            },
            json!({ "interfaces": interfaces }),
        ),
        "routes" => (
            String::from("Local routing table"),
            status_summary("routing table", any_success),
            json!({}),
        ),
        "listeners" => (
            String::from("Local listening sockets"),
            status_summary("listening socket table", any_success),
            json!({}),
        ),
        "tool_versions" => {
            let available = captures
                .iter()
                .filter(|capture| capture.success())
                .map(|capture| capture.label.clone())
                .collect::<Vec<_>>();
            (
                String::from("Local network tool versions"),
                if available.is_empty() {
                    String::from("No allowlisted network tool returned version information.")
                } else {
                    format!("Available network tool(s): {}.", available.join(", "))
                },
                json!({ "available_tools": available }),
            )
        }
        "capture_preflight" => {
            let interface = requested_interface.expect("validated above");
            let interface_exists = interfaces.iter().any(|name| name == interface);
            let tcpdump_enumerated = captures
                .iter()
                .find(|capture| capture.label == "tcpdump-devices")
                .is_some_and(CommandCapture::success);
            let capture_device_visible = capture_devices.iter().any(|name| name == interface);
            let (capture_permission, permission_detail) = probe_capture_permission();
            let permission_status = match capture_permission {
                Some(true) => "available",
                Some(false) => "denied",
                None => "unverified",
            };
            let ready = interface_exists
                && tcpdump_enumerated
                && capture_device_visible
                && capture_permission == Some(true);
            (
                String::from("Capture preflight"),
                format!(
                    "Capture preflight for {interface}: interface_exists={interface_exists}, tcpdump_enumerated={tcpdump_enumerated}, capture_device_visible={capture_device_visible}, capture_permission={permission_status}, ready={ready}. No packets were captured.",
                ),
                json!({
                    "requested_interface": interface,
                    "interface_exists": interface_exists,
                    "tcpdump_enumerated": tcpdump_enumerated,
                    "capture_device_visible": capture_device_visible,
                    "capture_permission": permission_status,
                    "capture_permission_verified": capture_permission.is_some(),
                    "permission_detail": permission_detail,
                    "ready": ready,
                    "interfaces": interfaces,
                    "capture_devices": capture_devices,
                    "packets_captured": false,
                }),
            )
        }
        "system_info" => (
            String::from("Local system information"),
            status_summary("system information", any_success),
            json!({}),
        ),
        _ => unreachable!("operation was allowlisted"),
    };

    Ok(ToolResult {
        title,
        summary,
        structured: json!({
            "ok": all_success,
            "operation": operation,
            "details": operation_details,
            "commands": captures
                .iter()
                .map(CommandCapture::bounded_metadata)
                .collect::<Vec<_>>(),
            "preview": preview,
            "raw_output_in_artifact": true,
        }),
        artifacts: vec![artifact.clone()],
        truncated,
        raw_output_artifact: Some(artifact),
    })
}

fn command_specs(operation: &str) -> Result<Vec<CommandSpec>, String> {
    #[cfg(target_os = "macos")]
    let specs = match operation {
        "interfaces" => vec![CommandSpec {
            label: "interfaces",
            candidates: &["/sbin/ifconfig"],
            args: &["-a"],
        }],
        "routes" => vec![CommandSpec {
            label: "routes",
            candidates: &["/usr/sbin/netstat"],
            args: &["-rn"],
        }],
        "listeners" => vec![
            CommandSpec {
                label: "tcp-listeners",
                candidates: &["/usr/sbin/lsof"],
                args: &["-nP", "-iTCP", "-sTCP:LISTEN"],
            },
            CommandSpec {
                label: "udp-sockets",
                candidates: &["/usr/sbin/lsof"],
                args: &["-nP", "-iUDP"],
            },
        ],
        "tool_versions" => version_specs(),
        "capture_preflight" => vec![
            CommandSpec {
                label: "interfaces",
                candidates: &["/sbin/ifconfig"],
                args: &["-a"],
            },
            CommandSpec {
                label: "tcpdump-devices",
                candidates: &["/usr/sbin/tcpdump"],
                args: &["-D"],
            },
        ],
        "system_info" => vec![
            CommandSpec {
                label: "kernel",
                candidates: &["/usr/bin/uname"],
                args: &["-a"],
            },
            CommandSpec {
                label: "macos-version",
                candidates: &["/usr/bin/sw_vers"],
                args: &[],
            },
        ],
        _ => return Err(format!("unsupported operation on macOS: {operation}")),
    };

    #[cfg(target_os = "linux")]
    let specs = match operation {
        "interfaces" => vec![CommandSpec {
            label: "interfaces",
            candidates: &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
            args: &["-brief", "address", "show"],
        }],
        "routes" => vec![CommandSpec {
            label: "routes",
            candidates: &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
            args: &["route", "show", "table", "all"],
        }],
        "listeners" => vec![CommandSpec {
            label: "listeners",
            candidates: &["/usr/sbin/ss", "/sbin/ss", "/usr/bin/ss"],
            args: &["-lntu"],
        }],
        "tool_versions" => version_specs(),
        "capture_preflight" => vec![
            CommandSpec {
                label: "interfaces",
                candidates: &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
                args: &["-brief", "address", "show"],
            },
            CommandSpec {
                label: "tcpdump-devices",
                candidates: &["/usr/bin/tcpdump", "/usr/sbin/tcpdump", "/sbin/tcpdump"],
                args: &["-D"],
            },
        ],
        "system_info" => vec![CommandSpec {
            label: "kernel",
            candidates: &["/usr/bin/uname", "/bin/uname"],
            args: &["-a"],
        }],
        _ => return Err(format!("unsupported operation on Linux: {operation}")),
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let specs = {
        return Err(format!(
            "system.shell is not supported on this operating system: {operation}"
        ));
    };

    Ok(specs)
}

fn version_specs() -> Vec<CommandSpec> {
    vec![
        CommandSpec {
            label: "tcpdump",
            candidates: &["/usr/sbin/tcpdump", "/usr/bin/tcpdump", "/sbin/tcpdump"],
            args: &["--version"],
        },
        CommandSpec {
            label: "tshark",
            candidates: &[
                "/opt/homebrew/bin/tshark",
                "/usr/local/bin/tshark",
                "/usr/bin/tshark",
                "/usr/sbin/tshark",
            ],
            args: &["--version"],
        },
    ]
}

fn run_command(spec: CommandSpec) -> Result<CommandCapture, String> {
    let Some(executable) = spec
        .candidates
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
    else {
        return Ok(CommandCapture {
            label: spec.label.to_string(),
            executable: None,
            args: spec.args.iter().map(|value| (*value).to_string()).collect(),
            exit_code: None,
            timed_out: false,
            stdout: String::new(),
            stderr: format!(
                "allowlisted executable not found in fixed paths: {}",
                spec.candidates.join(", ")
            ),
            stdout_truncated: false,
            stderr_truncated: false,
            unavailable: true,
        });
    };

    let mut child = Command::new(&executable)
        .args(spec.args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", spec.label))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{} stdout pipe is unavailable", spec.label))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{} stderr pipe is unavailable", spec.label))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));

    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let (status, timed_out) = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to poll {}: {error}", spec.label))?
        {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child
                .wait()
                .map_err(|error| format!("failed to reap timed-out {}: {error}", spec.label))?;
            break (status, true);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| format!("{} stdout reader failed", spec.label))?;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| format!("{} stderr reader failed", spec.label))?;

    Ok(CommandCapture {
        label: spec.label.to_string(),
        executable: Some(executable),
        args: spec.args.iter().map(|value| (*value).to_string()).collect(),
        exit_code: status.code(),
        timed_out,
        stdout: sanitize_output(&String::from_utf8_lossy(&stdout)),
        stderr: sanitize_output(&String::from_utf8_lossy(&stderr)),
        stdout_truncated,
        stderr_truncated,
        unavailable: false,
    })
}

fn read_bounded<R: Read>(mut reader: R) -> (Vec<u8>, bool) {
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
        let remaining = MAX_CAPTURED_STREAM_BYTES.saturating_sub(stored.len());
        stored.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
        }
    }
    (stored, truncated)
}

fn build_raw_output(
    operation: &str,
    requested_interface: Option<&str>,
    captures: &[CommandCapture],
) -> String {
    let mut sections = vec![format!("operation={operation}")];
    if let Some(interface) = requested_interface {
        sections.push(format!("requested_interface={interface}"));
    }
    for capture in captures {
        let command = capture
            .executable
            .as_ref()
            .map(|path| {
                std::iter::once(path.to_string_lossy().to_string())
                    .chain(capture.args.iter().cloned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|| String::from("unavailable"));
        sections.push(format!(
            "\n== {} ==\ncommand={}\nexit_code={:?}\ntimed_out={}\nstdout_truncated={}\nstderr_truncated={}\n[stdout]\n{}\n[stderr]\n{}",
            capture.label,
            command,
            capture.exit_code,
            capture.timed_out,
            capture.stdout_truncated,
            capture.stderr_truncated,
            capture.stdout,
            capture.stderr,
        ));
    }
    sections.join("\n")
}

fn build_preview(captures: &[CommandCapture]) -> String {
    let mut preview = String::new();
    let mut lines = 0_usize;
    for capture in captures {
        for line in std::iter::once(format!("[{}]", capture.label)).chain(
            capture
                .stdout
                .lines()
                .chain(capture.stderr.lines())
                .filter(|line| !line.trim().is_empty())
                .map(str::to_string),
        ) {
            if lines >= MAX_MODEL_PREVIEW_LINES
                || preview.chars().count() >= MAX_MODEL_PREVIEW_CHARS
            {
                break;
            }
            let remaining = MAX_MODEL_PREVIEW_CHARS.saturating_sub(preview.chars().count());
            let bounded = line.chars().take(remaining).collect::<String>();
            if !preview.is_empty() {
                preview.push('\n');
            }
            preview.push_str(&bounded);
            lines += 1;
        }
    }
    preview
}

fn extract_interfaces(captures: &[CommandCapture]) -> Vec<String> {
    let mut interfaces = Vec::new();
    for capture in captures
        .iter()
        .filter(|capture| capture.label == "interfaces")
    {
        for line in capture.stdout.lines() {
            let name = if line.starts_with(char::is_whitespace) {
                None
            } else if let Some((name, remainder)) = line.split_once(':') {
                if remainder.contains("flags=") {
                    Some(name)
                } else {
                    line.split_whitespace().next()
                }
            } else {
                line.split_whitespace().next()
            };
            if let Some(name) = name
                .map(str::trim)
                .filter(|name| valid_interface_name(name))
            {
                if !interfaces.iter().any(|existing| existing == name) {
                    interfaces.push(name.to_string());
                }
            }
        }
    }
    interfaces
}

fn extract_capture_devices(captures: &[CommandCapture]) -> Vec<String> {
    let mut devices = Vec::new();
    for line in captures
        .iter()
        .filter(|capture| capture.label == "tcpdump-devices")
        .flat_map(|capture| capture.stdout.lines())
    {
        let Some((prefix, _)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = prefix
            .split_once('.')
            .map(|(_, name)| name)
            .unwrap_or(prefix)
            .trim_end_matches(':');
        if valid_interface_name(name) && !devices.iter().any(|existing| existing == name) {
            devices.push(name.to_string());
        }
    }
    devices
}

fn sanitize_output(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect()
}

#[cfg(target_os = "macos")]
fn probe_capture_permission() -> (Option<bool>, String) {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;

    let mut found_device = false;
    let mut last_error = None;
    for index in 0..32 {
        let path = PathBuf::from(format!("/dev/bpf{index}"));
        if !path.exists() {
            continue;
        }
        found_device = true;
        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => {
                drop(file);
                return (
                    Some(true),
                    format!(
                        "Opened {} read/write and closed it without binding an interface or capturing packets.",
                        path.display()
                    ),
                );
            }
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {
                return (
                    Some(false),
                    format!("Cannot open {} read/write: {error}", path.display()),
                );
            }
            Err(error) => last_error = Some(format!("{}: {error}", path.display())),
        }
    }
    if found_device {
        (
            Some(false),
            format!(
                "No available /dev/bpf device could be opened read/write: {}",
                last_error.unwrap_or_else(|| String::from("unknown error"))
            ),
        )
    } else {
        (
            Some(false),
            String::from("No /dev/bpf device is visible to this process."),
        )
    }
}

#[cfg(not(target_os = "macos"))]
fn probe_capture_permission() -> (Option<bool>, String) {
    (
        None,
        String::from(
            "Interface enumeration succeeded, but this platform adapter does not verify capture privileges without starting a capture.",
        ),
    )
}

fn validate_interface(value: &str) -> Result<(), String> {
    if valid_interface_name(value) {
        Ok(())
    } else {
        Err(String::from(
            "interface may contain only letters, digits, '.', '_', ':', and '-' and must be at most 64 characters",
        ))
    }
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_INTERFACE_CHARS
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if let Some(field) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unexpected field: {field}"));
    }
    Ok(())
}

fn status_summary(subject: &str, success: bool) -> String {
    if success {
        format!(
            "Read the local {subject}. A bounded preview is returned and bounded captured output is stored as an artifact."
        )
    } else {
        format!(
            "Could not read the local {subject}; the bounded error and raw-output artifact explain why."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_validation_rejects_shell_syntax() {
        assert!(validate_interface("en0").is_ok());
        assert!(validate_interface("eth0.100").is_ok());
        assert!(validate_interface("en0;whoami").is_err());
        assert!(validate_interface("$(whoami)").is_err());
        assert!(validate_interface("a/b").is_err());
    }

    #[test]
    fn unknown_fields_and_operations_are_rejected() {
        let mut store = ArtifactStore::default();
        assert!(
            run(
                json!({ "operation": "system_info", "command": "id" })
                    .as_object()
                    .unwrap(),
                &mut store,
            )
            .is_err()
        );
        assert!(
            run(
                json!({ "operation": "arbitrary" }).as_object().unwrap(),
                &mut store,
            )
            .is_err()
        );
        assert!(
            run(
                json!({ "operation": "capture_preflight" })
                    .as_object()
                    .unwrap(),
                &mut store,
            )
            .is_err()
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn system_info_returns_bounded_result_and_raw_artifact() {
        let mut store = ArtifactStore::default();
        let result = run(
            json!({ "operation": "system_info" }).as_object().unwrap(),
            &mut store,
        )
        .expect("system info inspection");
        assert_eq!(result.structured["operation"], "system_info");
        assert_eq!(result.structured["raw_output_in_artifact"], true);
        let artifact = result.raw_output_artifact.expect("raw output artifact");
        assert!(std::path::Path::new(&artifact.path).is_file());
    }
}
