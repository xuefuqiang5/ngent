#!/usr/bin/env bash

set -euo pipefail

demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/netagent-demo.XXXXXX")"
trap 'rm -rf "$demo_dir"' EXIT

export NETAGENT_DB_PATH="$demo_dir/netagent-demo.db"
export NETAGENT_ARTIFACT_DIR="$demo_dir/artifacts"
unset NETAGENT_LLM_API_KEY NETAGENT_LLM_API_BASE NETAGENT_LLM_MODEL
export NETAGENT_LLM_DISABLED=1

echo "NetAgent demo: analysis -> bounded tool call -> result snapshot"
cargo run -q -p netagent-core <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"agent.ask","params":{"input":"Analyze the currently available network evidence and state what is known versus uncertain."}}
{"jsonrpc":"2.0","id":2,"method":"tool.mock_large_output","params":{"session_id":"ses_0001","message_id":"msg_0002","step_id":"step_0001","query":"Summarize the available flow evidence without returning raw output."}}
{"jsonrpc":"2.0","id":3,"method":"session.get","params":{"session_id":"ses_0001"}}
EOF

echo
echo "NetAgent demo: restart -> restored session snapshot"
cargo run -q -p netagent-core <<'EOF'
{"jsonrpc":"2.0","id":4,"method":"session.get","params":{"session_id":"ses_0001"}}
EOF
