#!/usr/bin/env bash

set -euo pipefail

demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/netagent-phase11-demo.XXXXXX")"
trap 'rm -rf "$demo_dir"' EXIT

export NETAGENT_DB_PATH="$demo_dir/netagent-demo.db"
export NETAGENT_ARTIFACT_DIR="$demo_dir/artifacts"
unset NETAGENT_LLM_API_KEY NETAGENT_LLM_API_BASE NETAGENT_LLM_MODEL
export NETAGENT_LLM_DISABLED=1

format_demo_output() {
  if ! command -v jq >/dev/null 2>&1; then
    cat
    return
  fi

  jq -r '
    if .method == "event.core.ready" then
      "[core] \(.params.message)"
    elif .method == "agent.reasoning.ended" then
      "[goal] \(.params.goal_analysis.objective)\n[plan] \(.params.goal_analysis.selected_tools | join(", "))"
    elif .method == "agent.tool.called" then
      "[tool call] \(.params.tool_call.tool_name) \(.params.tool_call.input)"
    elif .method == "agent.tool.success" then
      "[tool result] \(.params.tool_call.tool_name): \(.params.summary)"
    elif .id == 1 then
      "[capabilities] phase=\(.result.phase), tools=\(.result.agent_tools | map(.id) | join(", "))"
    elif .id == 2 then
      "[setup] \(.result.summary) artifact=\(.result.artifact.id)"
    elif .id == 3 then
      "[final answer]\n\(.result.assistant_message.parts[0].content)"
    elif .id == 4 or .id == 5 then
      "[snapshot] session=\(.result.session.id), messages=\(.result.messages | length), tool_calls=\(.result.tool_calls | length), state=\(.result.session.run_state)"
    else empty end
  '
}

echo "NetAgent Phase 11 demo"
echo "requirement -> five read-only tools -> bounded results -> final answer"
{
cargo run -q -p netagent-core <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}
{"jsonrpc":"2.0","id":2,"method":"report.generate","params":{"title":"NetAgent Demo Evidence Report"}}
{"jsonrpc":"2.0","id":3,"method":"agent.ask","params":{"input":"请分析已有 flow 和 finding，读取抓包状态，并列出和总结 artifact_0001，最后说明已知项与证据边界。"}}
{"jsonrpc":"2.0","id":4,"method":"session.get","params":{"session_id":"ses_0001"}}
EOF
} | format_demo_output

echo
echo "Restart recovery demo"
{
cargo run -q -p netagent-core <<'EOF'
{"jsonrpc":"2.0","id":5,"method":"session.get","params":{"session_id":"ses_0001"}}
EOF
} | format_demo_output
