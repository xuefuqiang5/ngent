# NetAgent

NetAgent is a permission-aware terminal agent for network investigation. The demo shows a complete investigate loop: the Agent plans, requests a live capture through the Permission State Machine, replans with offline pcap analysis when rejected with feedback, finds anomalies, and can propose a high-risk firewall response that requires typed confirmation and only ever produces a review artifact. Everything — plans, tool calls, results, permission decisions — is persisted in SQLite and survives Core/TUI restarts.

## Prerequisites

- Rust toolchain
- Bun
- `tshark` on `PATH` if you want to parse `.pcap` files
- System privileges for live capture if you plan to use `tcpdump`-backed capture flows

## Start the Rust core

Run the core process from the repository root:

```bash
cargo run -p netagent-core
```

To enable real LLM chat for `agent.ask`, export an OpenAI-compatible configuration before starting the core:

```bash
export NETAGENT_LLM_API_KEY="..."
export NETAGENT_LLM_API_BASE="https://api.openai.com/v1"
export NETAGENT_LLM_MODEL="gpt-4.1-mini"
```

LLM calls stream over SSE by default (`NETAGENT_LLM_STREAM=0` disables streaming): assistant text appears token-by-token in the TUI while tools still execute through the typed Tool Runtime. `agent.abort` (Ctrl+C-like, sent over stdio) cancels a running turn mid-stream; the turn settles as `aborted` instead of erroring.

The LLM settings are optional. When they are absent, the same typed Tool Runtime is driven by a deterministic local planner, so the complete demo works without an API key.

The Core reads `.env.local` and `.env` from the repository root itself. Both `./scripts/start_netagent_ui.sh` and a direct `bun run start` therefore load the configured model consistently. Set `NETAGENT_LLM_DISABLED=1` only when you explicitly want the offline planner.

Conversation state is stored in SQLite. Set an explicit path when you want an isolated demo database:

```bash
export NETAGENT_DB_PATH="/tmp/netagent-demo.db"
export NETAGENT_ARTIFACT_DIR="/tmp/netagent-demo-artifacts"
```

The core uses stdio JSON-RPC. You can verify that it starts correctly with:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"system.ping","params":{}}\n' | cargo run -q -p netagent-core
```

You can inspect the currently exposed methods with:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}\n' | cargo run -q -p netagent-core
```

## Start the OpenTUI app

Install UI dependencies once, then start the terminal app from the repository root:

```bash
cd ui/opentui-app && bun install && cd ../..
./scripts/start_netagent_ui.sh
```

The TUI starts and connects to the Rust Core itself; do not start a second Core process for this path. You can also start it directly from the UI directory:

```bash
bun run start
```

## Current agent tools

The model/local planner can call 14 typed tools. All are executed by the Rust Tool Runtime with full session/message/part/call context, and every result is a bounded summary plus structured output and `ArtifactRef` values — raw packet or command output never enters the model context:

- `flow.list` / `finding.list` — list up to 25 stored flows/findings.
- `capture.status` — inspect capture state without starting or stopping capture.
- `system.shell` — actively inspect missing local facts through six read-only operations: `interfaces`, `routes`, `listeners`, `tool_versions`, `capture_preflight`, and `system_info`. This is not a general shell: Core owns fixed executable paths/arguments, clears the child environment, enforces time/output bounds, and stores bounded captured output as an artifact. Command text, pipes, redirects, environment reads, arbitrary programs, and file changes are not accepted.
- `artifact.list` / `artifact.summary` — list/describe artifact references without raw contents.
- `capture.start` — request a bounded live capture. The Agent loop pauses and the Core raises a `PermissionRequest` (tool, risk, command preview, interface, filter, duration). `agent.resume` continues the loop after the user decides; rejection feedback makes the Agent replan (offline pcap analysis by default). `capture.stop` is deliberately not an agent tool.
- `pcap.open` / `tshark.extract_flows` / `tshark.extract_dns` — parse and persist offline pcap evidence.
- `dns.detect_anomalies` — NXDOMAIN spike rule over stored DNS events; creates `finding.created`.
- `report.generate` / `ioc.export` — Markdown evidence report and IOC JSON document artifacts.
- `respond.propose_firewall_rule` — high-risk proposal/preview only. The Agent pauses, the user must type an exact confirmation phrase (e.g. `BLOCK 10.0.0.8`) in the TUI, and approval creates a traceable proposal artifact (finding id + evidence refs, `executed=false`). The firewall is NEVER modified.

Detection rules are manifest-driven: every `*.yaml` under `rules/builtin/` is loaded at startup and dispatched by `dns.detect_anomalies`. Findings carry `rule_id` metadata, so adding a new detection rule is just a YAML file — no Core changes. See `core.capabilities.rules` for the loaded set.

The Core also exposes session recovery, capture RPCs, and a bounded mock-output RPC; inspect the exact RPC/event list with `core.capabilities`.

For every request, the Agent persists and displays a concise execution brief containing the objective, Observe-mode scope, candidate/selected tools, constraints, success criteria, and whether permission is required. This is a bounded plan summary, not hidden chain-of-thought.

## Demo flow

In the TUI:

1. Ask `目标：判断当前已经保存了哪些网络证据。请先分析目标并制定计划，再调用只读工具，最后区分已知项和未知项。`.
2. Watch the TUI show the configured model, the 12 available Agent tools, goal analysis, selected tools, bounded observations, and final answer.
3. Ask `请抓包看看当前网络是否有异常流量`. The agent calls `capture.start`, the Core raises a permission request, and the Approval Modal appears with the command preview.
4. Press `F` (reject with feedback) to watch the Agent replan with offline pcap analysis. Press `N` for a plain rejection. Press `Y`/`A` only when the host allows `tcpdump`.
5. Restart the TUI. The latest conversation, tool-call/result parts, and any still-pending approval are restored from SQLite.

For deterministic Core-only demos that require no API key and no live-capture privileges:

```bash
./scripts/demo_phase11.sh   # read-only tool loop + restart recovery
./scripts/demo_phase12.sh   # discover -> plan -> capture permission -> reject-with-feedback
                            # -> offline pcap analysis -> finding/report/IOC -> recovery
./scripts/demo_phase13.sh   # offline evidence -> high-risk firewall rule proposal with
                            # typed confirmation -> traceable proposal (never executed)
./scripts/demo_phase14.sh   # manifest-driven analyzer rules -> two attributed findings
                            # (NXDOMAIN spike + enumeration) from one fixture pcap
./scripts/demo_phase15.sh   # streaming SSE deltas + mid-turn cancel via a fake provider
```

The demo scripts generate their own DNS NXDOMAIN fixture pcap (via `cargo run --example gen_fixture`) inside an isolated temporary database/artifact directory.

## Useful startup checks

From the repository root:

```bash
cargo test --workspace
```

If you want to open a local `.pcap` after the core is running:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"pcap.open","params":{"path":"/absolute/path/to/file.pcap"}}\n' | cargo run -q -p netagent-core
```
