#!/usr/bin/env bash

set -euo pipefail

demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/netagent-phase15-demo.XXXXXX")"
trap 'rm -rf "$demo_dir"' EXIT

export NETAGENT_DB_PATH="$demo_dir/netagent-demo.db"
export NETAGENT_ARTIFACT_DIR="$demo_dir/artifacts"

provider_port=8799
while lsof -iTCP:$provider_port -sTCP:LISTEN >/dev/null 2>&1; do
  provider_port=$((provider_port + 1))
done

python3 scripts/fake_llm_sse.py "$provider_port" 2>/dev/null &
provider_pid=$!
trap 'kill $provider_pid 2>/dev/null || true; rm -rf "$demo_dir"' EXIT
sleep 0.5

export NETAGENT_LLM_API_KEY="demo-key"
export NETAGENT_LLM_API_BASE="http://127.0.0.1:$provider_port/v1"
export NETAGENT_LLM_MODEL="fake-sse-model"
export NETAGENT_LLM_TIMEOUT_SECS="30"

format_demo_output() {
  if ! command -v jq >/dev/null 2>&1; then
    cat
    return
  fi

  jq -r '
    if .method == "event.core.ready" then
      "[core] \(.params.message)"
    elif .method == "agent.text.delta" then
      "[delta] \(.params.delta)"
    elif .method == "agent.text.ended" then
      "[text ended]"
    elif .method == "agent.step.ended" then
      "[step ended] run_state=\(.params.run_state) stop_reason=\(.params.step.status)"
    elif .id == 1 then
      "[agent.ask] run_state=\(.result.run_state // "error") stop_reason=\(.result.safety.stop_reason // "-")"
    elif .id == 999 then
      "[agent.abort] \(.result.message)"
    else empty end
  '
}

echo "======================================================"
echo "NetAgent Phase 15 demo"
echo "streaming LLM deltas + mid-turn cancel (agent.abort)"
echo "======================================================"
echo

echo "--- Part 1: streaming deltas arrive in real time"
{
  printf '{"jsonrpc":"2.0","id":1,"method":"agent.ask","params":{"input":"请分析当前已有证据并总结"}}\n'
  sleep 12
} | cargo run -q -p netagent-core 2>/dev/null | format_demo_output

echo
echo "--- Part 2: agent.abort interrupts the running turn mid-stream"
{
  printf '{"jsonrpc":"2.0","id":1,"method":"agent.ask","params":{"input":"请分析当前已有证据并总结"}}\n'
  sleep 1.8
  printf '{"jsonrpc":"2.0","id":999,"method":"agent.abort","params":{}}\n'
  sleep 6
} | cargo run -q -p netagent-core 2>/dev/null | format_demo_output

echo
echo "Done. Part 2 shows the turn stopping after the first few deltas."
