#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/scripts/load_netagent_env.sh"

cd "$ROOT_DIR"

if [[ -z "${NETAGENT_LLM_API_KEY:-}" ]]; then
  echo "NETAGENT_LLM_API_KEY is not set." >&2
  exit 1
fi

if [[ -z "${NETAGENT_LLM_API_BASE:-}" ]]; then
  echo "NETAGENT_LLM_API_BASE is not set." >&2
  exit 1
fi

if [[ -z "${NETAGENT_LLM_MODEL:-}" ]]; then
  echo "NETAGENT_LLM_MODEL is not set." >&2
  exit 1
fi

exec cargo run -p netagent-core
