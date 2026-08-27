#!/usr/bin/env bash

set -euo pipefail

demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/netagent-phase12-demo.XXXXXX")"
trap 'rm -rf "$demo_dir"' EXIT

export NETAGENT_DB_PATH="$demo_dir/netagent-demo.db"
export NETAGENT_ARTIFACT_DIR="$demo_dir/artifacts"
unset NETAGENT_LLM_API_KEY NETAGENT_LLM_API_BASE NETAGENT_LLM_MODEL
export NETAGENT_LLM_DISABLED=1

fixture_pcap="$demo_dir/dns_nxdomain_spike.pcap"
cargo run -q -p netagent-core --example gen_fixture -- "$fixture_pcap" >/dev/null 2>&1

format_demo_output() {
  if ! command -v jq >/dev/null 2>&1; then
    cat
    return
  fi

  jq -r '
    if .method == "event.core.ready" then
      "[core] \(.params.message)"
    elif .method == "agent.reasoning.ended" then
      "[plan] \(.params.goal_analysis.selected_tools | join(", "))"
    elif .method == "agent.tool.called" then
      "[tool call] \(.params.tool_call.tool_name) \(.params.tool_call.input) [\(.params.tool_call.status)]"
    elif .method == "permission.asked" then
      "[permission] \(.params.request.metadata.tool) risk=\(.params.request.risk) request=\(.params.request.id)\n[preview] \(.params.request.metadata.command_preview)"
    elif .method == "agent.tool.success" then
      "[tool result] \(.params.tool_call.tool_name): \(.params.summary)"
    elif .method == "agent.tool.failed" then
      "[tool result] \(.params.tool_call.tool_name): \(.params.message // .params.summary // "failed")"
    elif .method == "finding.created" then
      "[finding] \(.params.finding.severity) \(.params.finding.title)"
    elif .method == "pcap.created" then
      "[pcap] artifact=\(.params.artifact.id)"
    elif .method == "report.generated" then
      "[report] artifact=\(.params.artifact.id)"
    elif .method == "artifact.created" then
      "[artifact] \(.params.artifact.id) kind=\(.params.artifact.kind)"
    elif .method == "capture.started" then
      "[capture] started \(.params.interface) filter=\(.params.filter) duration=\(.params.duration_secs)s"
    elif .id == 1 then
      "[capabilities] phase=\(.result.phase), tools=\(.result.agent_tools | map(.id) | join(", "))"
    elif .id == 2 then
      "[agent.ask] run_state=\(.result.run_state) request=\(.result.permission_request_id // "-")"
    elif .id == 3 then
      "[permission.reply] status=\(.result.status) feedback=\(.result.feedback // "-")"
    elif .id == 4 then
      "[agent.resume] run_state=\(.result.run_state) resumed=\(.result.resumed)\n[final answer]\n\(.result.assistant_message.parts[0].content)"
    elif .id == 5 or .id == 6 then
      "[snapshot] session=\(.result.session.id), messages=\(.result.messages | length), tool_calls=\(.result.tool_calls | length), state=\(.result.session.run_state)"
    elif .id == 7 then
      "[agent.ask(offline)] run_state=\(.result.run_state)\n[final answer]\n\(.result.assistant_message.parts[0].content)"
    else empty end
  '
}

echo "======================================================"
echo "NetAgent Phase 12 demo"
echo "discover -> analyze -> typed tools -> solve"
echo "======================================================"
echo

echo "--- Step 1: user asks for live capture; agent plans and pauses for permission"
phase1_out="$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"agent.ask","params":{"input":"请实时抓包分析当前网络是否存在 DNS 异常"}}' |
  cargo run -q -p netagent-core 2>/dev/null)"
printf '%s\n' "$phase1_out" | format_demo_output

request_id="$(printf '%s\n' "$phase1_out" | jq -r 'select(.id == 2) | .result.permission_request_id')"
session_id="$(printf '%s\n' "$phase1_out" | jq -r 'select(.id == 2) | .result.session.id')"

echo
echo "--- Step 2: user rejects live capture with feedback; agent must replan"
phase2_out="$(printf '%s\n%s\n%s\n' \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"permission.reply\",\"params\":{\"request_id\":\"$request_id\",\"decision\":\"reject_with_feedback\",\"feedback\":\"不要实时抓包，请分析本地 pcap 文件 $fixture_pcap\"}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"agent.resume\",\"params\":{\"session_id\":\"$session_id\"}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"session.get\",\"params\":{\"session_id\":\"$session_id\"}}" |
  cargo run -q -p netagent-core 2>/dev/null)"
printf '%s\n' "$phase2_out" | format_demo_output

echo
echo "--- Step 3: restart recovery - the full investigation survives a Core restart"
printf '{"jsonrpc":"2.0","id":6,"method":"session.get","params":{"session_id":"%s"}}\n' "$session_id" |
  cargo run -q -p netagent-core 2>/dev/null | format_demo_output

echo
echo "--- Step 4: direct offline request (no permission needed) - discover -> analyze -> solve"
printf '{"jsonrpc":"2.0","id":7,"method":"agent.ask","params":{"input":"请分析本地 pcap 文件 %s 中的 DNS 异常并生成报告"}}\n' "$fixture_pcap" |
  cargo run -q -p netagent-core 2>/dev/null | format_demo_output

echo
echo "Done. Evidence artifacts were written under NETAGENT_ARTIFACT_DIR."
