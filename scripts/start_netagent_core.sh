#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/scripts/load_netagent_env.sh"

cd "$ROOT_DIR"

if [[ -z "${NETAGENT_LLM_API_KEY:-}" || -z "${NETAGENT_LLM_MODEL:-}" ]]; then
  echo "LLM is not configured; starting the deterministic Phase 11 demo planner." >&2
fi

exec cargo run -p netagent-core
