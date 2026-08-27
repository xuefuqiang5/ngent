#!/usr/bin/env bash

set -euo pipefail

demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/netagent-phase14-demo.XXXXXX")"
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
      "[finding] \(.params.finding.severity) \(.params.finding.title) [rule=\(.params.finding.rule_id // "-")]"
    elif .method == "agent.tool.success" then
      "[tool result] \(.params.tool_call.tool_name): \(.params.summary)"
    elif .id == 1 then
      "[capabilities] phase=\(.result.phase)\n[rules] \(.result.rules | map("\(.id) [\(.severity), enabled=\(.enabled)]: \(.description)") | join("\n"))"
    elif .id == 2 then
      "[agent.ask] run_state=\(.result.run_state)\n[final answer]\n\(.result.assistant_message.parts[0].content)"
    elif .id == 3 then
      "[finding.list] total=\(.result.total)\n\(.result.findings | map("- \(.id) [\(.severity)] \(.title) rule=\(.metadata.rule_id // "-")") | join("\n"))"
    else empty end
  '
}

echo "======================================================"
echo "NetAgent Phase 14 demo"
echo "manifest-driven analyzer rules (rules/builtin/*.yaml)"
echo "======================================================"
echo

echo "--- Step 1: capabilities expose loaded rule manifests (no code change needed for new rules)"
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"agent.ask\",\"params\":{\"input\":\"请分析本地 pcap 文件 $fixture_pcap 中的 DNS 异常\"}}" \
  '{"jsonrpc":"2.0","id":3,"method":"finding.list","params":{}}' |
  cargo run -q -p netagent-core 2>/dev/null | format_demo_output

echo
echo "Done. Both findings carry rule_id metadata and were produced by manifest-driven analyzers."
