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

if [[ "$#" -eq 0 ]]; then
  # Default run: use only pyproject.toml config.
  # This keeps "./run.sh" as the simplest entrypoint; override via args if needed.
  exec "$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py" \
    --project-root "$ROOT_DIR"
else
  # Passthrough mode (keeps backwards compatibility).
  exec "$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py" \
    --project-root "$ROOT_DIR" \
    "$@"
fi
