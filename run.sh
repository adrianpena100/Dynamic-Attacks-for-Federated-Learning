#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$ROOT_DIR/../myenv/bin/python"

# Silence Ray's recurring FutureWarning about accelerator env vars.
export RAY_ACCEL_ENV_VAR_OVERRIDE_ON_ZERO="${RAY_ACCEL_ENV_VAR_OVERRIDE_ON_ZERO:-0}"

# Preserve per-client metric logs (Ray log dedup breaks per-client time series).
export RAY_DEDUP_LOGS="${RAY_DEDUP_LOGS:-0}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Error: expected venv python at: $PYTHON_BIN" >&2
  echo "Either create the venv at ../myenv or run: python scripts/run_simulation_and_log.py" >&2
  exit 1
fi


# --- Run simulation and capture output directory ---
RUN_OUTPUT_DIR=""
if [[ "$#" -eq 0 ]]; then
  # Default run: use only pyproject.toml config.
  # This keeps "./run.sh" as the simplest entrypoint; override via args if needed.
  RUN_OUTPUT_DIR=$("$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py" \
    --project-root "$ROOT_DIR" --print-log-dir)
else
  # Passthrough mode (keeps backwards compatibility).
  RUN_OUTPUT_DIR=$("$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py" \
    --project-root "$ROOT_DIR" --print-log-dir "$@")
fi

# If the simulation script does not print the log dir, fallback to latest log dir
if [[ ! -d "$RUN_OUTPUT_DIR" ]]; then
  RUN_OUTPUT_DIR=$(ls -td "$ROOT_DIR"/logs/*__*__*__* 2>/dev/null | head -n1)
fi

if [[ -d "$RUN_OUTPUT_DIR" ]]; then
  # Run LLM analysis for this run directory using the script's current CLI.
  "$PYTHON_BIN" "$ROOT_DIR/scripts/llm_sweep_analysis.py" --sweeps-root "$RUN_OUTPUT_DIR" --call-api
  echo "LLM analysis written inside: $RUN_OUTPUT_DIR"
else
  echo "Warning: Could not determine run output directory for LLM analysis." >&2
fi
