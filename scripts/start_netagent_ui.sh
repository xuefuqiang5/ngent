#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_DIR="$ROOT_DIR/ui/opentui-app"

source "$ROOT_DIR/scripts/load_netagent_env.sh"

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is not installed or not on PATH." >&2
  exit 1
fi

if [[ -z "${NETAGENT_LLM_API_KEY:-}" || -z "${NETAGENT_LLM_MODEL:-}" ]]; then
  echo "LLM is not configured; starting the deterministic Phase 11 demo planner." >&2
fi

cd "$UI_DIR"
exec bun run dev
