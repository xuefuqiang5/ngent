#!/usr/bin/env bash

set -euo pipefail

demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/netagent-phase13-demo.XXXXXX")"
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
    elif .method == "finding.created" then
      "[finding] \(.params.finding.severity) \(.params.finding.title)"
    elif .method == "agent.reasoning.ended" then
      "[plan] \(.params.goal_analysis.selected_tools | join(", "))"
    elif .method == "agent.tool.called" then
      "[tool call] \(.params.tool_call.tool_name) \(.params.tool_call.input) [\(.params.tool_call.status)]"
    elif .method == "permission.asked" then
      "[permission] \(.params.request.metadata.tool) risk=\(.params.request.risk) typed_confirmation=\(.params.request.require_typed_confirmation)\n[phrase] \(.params.request.metadata.confirm_phrase)\n[preview] \(.params.request.metadata.command_preview)"
    elif .method == "agent.tool.success" then
      "[tool result] \(.params.tool_call.tool_name): \(.params.summary)"
    elif .method == "agent.tool.failed" then
      "[tool result] \(.params.tool_call.tool_name): \(.params.message // .params.summary // "failed")"
    elif .method == "respond.proposal.created" then
      "[proposal] \(.params.artifact.id) target=\(.params.proposal.target) executed=\(.params.executed) finding=\(.params.finding_id // "-")"
    elif .method == "artifact.created" then
      "[artifact] \(.params.artifact.id) kind=\(.params.artifact.kind)"
    elif .id == 1 then
      "[capabilities] phase=\(.result.phase), tools=\(.result.agent_tools | map(.id) | join(", "))"
    elif .id == 2 then
      "[agent.ask(evidence)] run_state=\(.result.run_state)"
    elif .id == 3 then
      "[agent.ask(respond)] run_state=\(.result.run_state) request=\(.result.permission_request_id // "-")"
    elif .id == 4 then
      "[permission.reply] status=\(.result.status // "error") executed=\(.result.executed // false)"
    elif .id == 5 then
      "[agent.resume] run_state=\(.result.run_state) resumed=\(.result.resumed)\n[final answer]\n\(.result.assistant_message.parts[0].content)"
    elif .id == 6 or .id == 7 then
      "[snapshot] session=\(.result.session.id), tool_calls=\(.result.tool_calls | length), state=\(.result.session.run_state)"
    else empty end
  '
}

echo "======================================================"
echo "NetAgent Phase 13 demo"
echo "advanced analysis -> high-risk respond proposal (preview only)"
echo "======================================================"
echo

echo "--- Step 1: offline evidence -> NXDOMAIN finding"
phase1_out="$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"agent.ask\",\"params\":{\"input\":\"请分析本地 pcap 文件 $fixture_pcap 中的 DNS 异常\"}}" |
  cargo run -q -p netagent-core 2>/dev/null)"
printf '%s\n' "$phase1_out" | format_demo_output

finding_id="$(printf '%s\n' "$phase1_out" | jq -r 'select(.id == 2) | .result.goal_analysis.selected_tools[0] // "finding_0001"' | sed 's/.*//' )"
finding_id="$(cargo run -q -p netagent-core 2>/dev/null <<'EOF' | jq -r 'select(.id == 1) | .result.findings[0].id'
{"jsonrpc":"2.0","id":1,"method":"finding.list","params":{}}
EOF
)"

echo
echo "--- Step 2: agent proposes a firewall rule for the finding entity (high risk, typed confirmation)"
phase2_out="$(printf '%s\n%s\n' \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"agent.ask\",\"params\":{\"input\":\"请对 $finding_id 的实体 10.0.0.8 提出防火墙封禁建议\"}}" |
  cargo run -q -p netagent-core 2>/dev/null)"
printf '%s\n' "$phase2_out" | format_demo_output

request_id="$(printf '%s\n' "$phase2_out" | jq -r 'select(.id == 3) | .result.permission_request_id')"
session_id="$(printf '%s\n' "$phase2_out" | jq -r 'select(.id == 3) | .result.session.id')"

echo
echo "--- Step 3: wrong typed confirmation is rejected; the request stays pending"
printf '{"jsonrpc":"2.0","id":4,"method":"permission.reply","params":{"request_id":"%s","decision":"once","typed_confirmation":"BLOCK 1.1.1.1"}}\n' "$request_id" |
  cargo run -q -p netagent-core 2>/dev/null |
  jq -r 'if .id == 4 then "[permission.reply] ERROR \(.error.code): \(.error.message)" else empty end'

echo
echo "--- Step 4: correct typed confirmation -> proposal artifact (NOT executed)"
phase4_out="$(printf '%s\n%s\n%s\n' \
  "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"permission.reply\",\"params\":{\"request_id\":\"$request_id\",\"decision\":\"once\",\"typed_confirmation\":\"BLOCK 10.0.0.8\"}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"agent.resume\",\"params\":{\"session_id\":\"$session_id\"}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"session.get\",\"params\":{\"session_id\":\"$session_id\"}}" |
  cargo run -q -p netagent-core 2>/dev/null)"
printf '%s\n' "$phase4_out" | format_demo_output

proposal_path="$(printf '%s\n' "$phase4_out" | jq -r 'select(.id == 4) | .result.artifact.path')"
echo
echo "--- Proposal artifact (traceable to finding + evidence)"
if [[ -f "$proposal_path" ]]; then
  cat "$proposal_path"
else
  echo "(proposal artifact not readable at $proposal_path)"
fi

echo
echo "--- Step 5: restart recovery - the proposal decision survives a Core restart"
printf '{"jsonrpc":"2.0","id":7,"method":"session.get","params":{"session_id":"%s"}}\n' "$session_id" |
  cargo run -q -p netagent-core 2>/dev/null | format_demo_output

echo
echo "Done. The firewall was NEVER modified; only a review proposal artifact was created."
