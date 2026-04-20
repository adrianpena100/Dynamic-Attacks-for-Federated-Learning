#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$ROOT_DIR/../myenv/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Error: expected venv python at: $PYTHON_BIN" >&2
  exit 1
fi

NAME="thesis_sweep"
DATASET=""
PARTITIONER=""
DIRICHLET_ALPHA=""
FEDERATION=""
STRATEGY=""
STRATEGIES="bulyan,multikrum,fedtrimmedavg"
SWEEPS_FILE="$ROOT_DIR/docs/thesis_sweeps.conf"
REPEATS=1
SEEDS=""
FROM_LABEL=""
STAMP_OVERRIDE=""
EXTRA_CONFIG=""
ROUND_TIMEOUT=120
INIT_TIMEOUT=600
MAX_RETRIES=2
AUTO_LLM_SWEEP_ANALYSIS=0
LLM_ANALYSIS_MODEL=""

csv_escape() {
  local v="$1"
  v="${v//\"/\"\"}"
  printf '"%s"' "$v"
}

normalize_strategy() {
  local raw="$1"
  local lower
  lower="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    trimmed|trimmedmean|trimmed_mean|trimmed-mean)
      printf 'fedtrimmedavg'
      ;;
    median|fedmedian|fed-median|fed_median)
      printf 'fedmedian'
      ;;
    fltrust|fl-trust|fl_trust)
      printf 'fltrust'
      ;;
    *)
      printf '%s' "$lower"
      ;;
  esac
}

usage() {
  cat <<EOF
Usage: ./run_thesis_sweep.sh [--name NAME] [--dataset DATASET] [--partitioner NAME] [--dirichlet-alpha VAL] [--federation NAME] [--strategy NAME] [--strategies CSV] [--sweeps-file PATH] [--repeats N] [--seeds CSV] [--from-label LABEL] [--stamp YYYY-mm-dd_HH-MM-SS] [--extra-config 'key=val ...'] [--round-timeout SECS] [--init-timeout SECS] [--max-retries N] [--llm-analysis] [--llm-model NAME]

Runs thesis sweeps sequentially across one or more strategies.

Defaults:
  --strategies bulyan,multikrum,fedtrimmedavg
  --sweeps-file docs/thesis_sweeps.conf
  --repeats 1

Examples:
  ./run_thesis_sweep.sh --name thesis_balanced --repeats 3
  ./run_thesis_sweep.sh --name thesis_balanced --repeats 3 --seeds "1337,2027,4242"
  ./run_thesis_sweep.sh --name thesis_balanced_resume --strategy bulyan --from-label S05_A_adaptive_churn05
  ./run_thesis_sweep.sh --name thesis_full --stamp 2026-03-05_15-38-03
  ./run_thesis_sweep.sh --name thesis_full --llm-analysis --llm-model claude-opus-4-6
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      NAME="$2"
      shift 2
      ;;
    --dataset)
      DATASET="$2"
      shift 2
      ;;
    --partitioner)
      PARTITIONER="$2"
      shift 2
      ;;
    --dirichlet-alpha)
      DIRICHLET_ALPHA="$2"
      shift 2
      ;;
    --federation)
      FEDERATION="$2"
      shift 2
      ;;
    --strategy)
      STRATEGY="$2"
      shift 2
      ;;
    --strategies)
      STRATEGIES="$2"
      shift 2
      ;;
    --sweeps-file)
      SWEEPS_FILE="$2"
      shift 2
      ;;
    --repeats)
      REPEATS="$2"
      shift 2
      ;;
    --seeds)
      SEEDS="$2"
      shift 2
      ;;
    --from-label)
      FROM_LABEL="$2"
      shift 2
      ;;
    --stamp)
      STAMP_OVERRIDE="$2"
      shift 2
      ;;
    --extra-config)
      EXTRA_CONFIG="$2"
      shift 2
      ;;
    --round-timeout)
      ROUND_TIMEOUT="$2"
      shift 2
      ;;
    --init-timeout)
      INIT_TIMEOUT="$2"
      shift 2
      ;;
    --max-retries)
      MAX_RETRIES="$2"
      shift 2
      ;;
    --llm-analysis)
      AUTO_LLM_SWEEP_ANALYSIS=1
      shift 1
      ;;
    --llm-model)
      LLM_ANALYSIS_MODEL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! [[ "$REPEATS" =~ ^[0-9]+$ ]] || [[ "$REPEATS" -lt 1 ]]; then
  echo "Error: --repeats must be an integer >= 1" >&2
  exit 1
fi

if [[ -n "$STAMP_OVERRIDE" ]]; then
  STAMP="$STAMP_OVERRIDE"
else
  STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
fi

if [[ ! -f "$SWEEPS_FILE" ]]; then
  echo "Error: sweeps file not found: $SWEEPS_FILE" >&2
  exit 1
fi

declare -a SWEEPS=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  SWEEPS+=("$line")
done < "$SWEEPS_FILE"

if [[ "${#SWEEPS[@]}" -eq 0 ]]; then
  echo "Error: no sweep entries found in $SWEEPS_FILE" >&2
  exit 1
fi

if [[ -n "$FROM_LABEL" ]]; then
  from_label_found=0
  for entry in "${SWEEPS[@]}"; do
    IFS="|" read -r label _ <<<"$entry"
    if [[ "$label" == "$FROM_LABEL" ]]; then
      from_label_found=1
      break
    fi
  done
  if [[ "$from_label_found" -ne 1 ]]; then
    echo "Error: --from-label '$FROM_LABEL' not found in $SWEEPS_FILE" >&2
    exit 1
  fi
fi

# Order by label bucket prefix (S00, S05, S10, …) then alphabetically within bucket.
# This keeps BL_clean baselines (window 31|31) grouped with their bucket-mates
# instead of being pushed to the end by numeric start-round sort.
declare -a SWEEPS_SORTED=()
while IFS= read -r sorted_line; do
  SWEEPS_SORTED+=("$sorted_line")
done < <(printf '%s\n' "${SWEEPS[@]}" | sort -t'|' -k1,1)
SWEEPS=("${SWEEPS_SORTED[@]}")

declare -a RUN_STRATEGIES=()
if [[ -n "$STRATEGY" ]]; then
  RUN_STRATEGIES=("$(normalize_strategy "$STRATEGY")")
else
  IFS="," read -r -a raw_strategies <<<"$STRATEGIES"
  for s in "${raw_strategies[@]}"; do
    s_trimmed="$(echo "$s" | sed 's/^ *//; s/ *$//')"
    [[ -z "$s_trimmed" ]] && continue
    RUN_STRATEGIES+=("$(normalize_strategy "$s_trimmed")")
  done
fi

if [[ "${#RUN_STRATEGIES[@]}" -eq 0 ]]; then
  echo "Error: no strategies selected." >&2
  exit 1
fi

# --- Pre-flight checks ---
echo "Pre-flight: verifying dataset and metrics pipeline..."
preflight_dataset="${DATASET:-ylecun/mnist}"
"$PYTHON_BIN" -c "
from pytorchexample.task import get_dataset_spec, create_model
spec = get_dataset_spec('${preflight_dataset}')
assert spec.modality == 'vision', f'Expected vision modality, got {spec.modality}'
model = create_model('${preflight_dataset}')
print(f'Dataset: {spec.dataset} | classes={spec.num_classes} | channels={spec.input_channels} | label_key={spec.label_key}')
print(f'Model: in_ch={model.conv1.in_channels} out_classes={model.fc3.out_features}')
print('Pre-flight OK')
" || { echo "Pre-flight FAILED: dataset/model check failed" >&2; exit 1; }
echo ""

declare -a STRATEGY_SWEEP_ROOTS=()
declare -a SEED_LIST=()
if [[ -n "$SEEDS" ]]; then
  IFS="," read -r -a raw_seeds <<<"$SEEDS"
  for s in "${raw_seeds[@]}"; do
    s_trimmed="$(echo "$s" | sed 's/^ *//; s/ *$//')"
    [[ -z "$s_trimmed" ]] && continue
    if ! [[ "$s_trimmed" =~ ^-?[0-9]+$ ]]; then
      echo "Error: invalid seed '$s_trimmed' in --seeds" >&2
      exit 1
    fi
    SEED_LIST+=("$s_trimmed")
  done
fi

pick_seed() {
  local rep_idx="$1"
  if [[ "${#SEED_LIST[@]}" -gt 0 ]]; then
    local pos=$(( (rep_idx - 1) % ${#SEED_LIST[@]} ))
    printf '%s' "${SEED_LIST[$pos]}"
  else
    # Default deterministic seeds for repeatability across configs.
    printf '%s' $((1337 + (rep_idx - 1) * 101))
  fi
}

for strategy_name in "${RUN_STRATEGIES[@]}"; do
  SWEEP_ROOT="$ROOT_DIR/logs/sweeps/${strategy_name}_${NAME}__${STAMP}"
  STRATEGY_SWEEP_ROOTS+=("$SWEEP_ROOT")
  mkdir -p "$SWEEP_ROOT"

  settings_csv="$SWEEP_ROOT/sweep_settings.csv"
  if [[ ! -f "$settings_csv" ]]; then
    echo "label,base_label,repeat_index,seed,run_folder,attack_window_start,attack_window_end,ramp_end,attack_mode,selection_mode,churn_fraction,layering_mode,layered_k,layered_attacks,layer_multipliers" > "$settings_csv"
  fi

  COMPLETED_KEYS_STR=$'\n'
  if [[ -s "$settings_csv" ]]; then
    while IFS=, read -r c_label _c_base c_rep _rest; do
      [[ -z "$c_label" ]] && continue
      [[ "$c_label" == "label" ]] && continue
      c_label="${c_label#\"}"
      c_label="${c_label%\"}"
      c_rep="${c_rep#\"}"
      c_rep="${c_rep%\"}"
      [[ -z "$c_label" ]] && continue
      [[ -z "$c_rep" ]] && continue
      COMPLETED_KEYS_STR+="${c_label}|${c_rep}"$'\n'
    done < "$settings_csv"
  fi

  echo "=== Strategy: ${strategy_name} ==="
  start_emitting=1
  # Only apply --from-label for the first strategy; subsequent strategies
  # rely on the skip-completed logic and should start from the beginning.
  if [[ -n "$FROM_LABEL" && "$strategy_name" == "${RUN_STRATEGIES[0]}" ]]; then
    start_emitting=0
    echo "Resuming from label: $FROM_LABEL"
  fi

  for entry in "${SWEEPS[@]}"; do
    IFS="|" read -r label start_round end_round ramp_end attack_mode selection_mode churn_fraction layering_mode layered_k layered_attacks layer_mult <<<"$entry"

    if [[ "$start_emitting" -ne 1 ]]; then
      if [[ "$label" == "$FROM_LABEL" ]]; then
        start_emitting=1
      else
        continue
      fi
    fi

    run_config="attack-window-start-round=${start_round} attack-window-end-round=${end_round} "
    run_config+="attack-intensity-ramp-start-round=${start_round} "
    run_config+="attack-intensity-ramp-multiplier-end=${ramp_end} "
    run_config+="attack-mode=\"${attack_mode}\" "
    run_config+="attack-selection-mode=\"${selection_mode}\" "
    run_config+="attack-churn-fraction=${churn_fraction} "
    run_config+="attack-churn-min-replace=2 attack-cooldown-rounds=2"

    if [[ -n "${layering_mode}" && "${layering_mode}" != "single" ]]; then
      run_config+=" attack-layering-mode=\"${layering_mode}\""
    fi
    if [[ -n "${layered_k}" ]]; then
      run_config+=" attack-layered-k=${layered_k}"
    fi
    if [[ -n "${layered_attacks}" ]]; then
      run_config+=" attack-layered-attacks=\"${layered_attacks}\""
    fi
    if [[ -n "${layer_mult}" ]]; then
      IFS="," read -r -a mult_pairs <<<"${layer_mult}"
      for pair in "${mult_pairs[@]}"; do
        key="${pair%%=*}"
        val="${pair##*=}"
        if [[ -n "$key" && -n "$val" ]]; then
          key_dash="${key//_/-}"
          run_config+=" attack-layer-intensity-${key_dash}=${val}"
        fi
      done
    fi

    if [[ -n "$DATASET" ]]; then
      run_config+=" dataset=\"${DATASET}\""
    fi
    if [[ -n "$PARTITIONER" ]]; then
      run_config+=" partitioner=${PARTITIONER}"
    fi
    if [[ -n "$DIRICHLET_ALPHA" ]]; then
      run_config+=" dirichlet-alpha=${DIRICHLET_ALPHA}"
    fi
    if [[ -n "$EXTRA_CONFIG" ]]; then
      run_config+=" ${EXTRA_CONFIG}"
    fi

    run_config+=" strategy=\"${strategy_name}\""

    if [[ "${strategy_name}" == "bulyan" ]]; then
      # Bulyan requires at least (4f + 3) total updates; with 100 clients, f must be <= 24.
      run_config+=" num-malicious-nodes=24"
      run_config+=" attack-malicious-fraction=0.24 attack-malicious-fraction-mode=\"fixed\""
    fi

    if [[ "${strategy_name}" == "fedtrimmedavg" ]]; then
      # Trimmed mean cuts beta from each tail; keep f <= beta for within-bound runs.
      run_config+=" trimmed-beta=0.24"
      run_config+=" attack-malicious-fraction=0.24 attack-malicious-fraction-mode=\"fixed\""
    fi

    if [[ "${strategy_name}" == "fedmedian" ]]; then
      # Coordinate-wise median; tolerates < 50% Byzantine in theory.
      run_config+=" attack-malicious-fraction=0.25 attack-malicious-fraction-mode=\"fixed\""
    fi

    if [[ "${strategy_name}" == "fltrust" ]]; then
      # Trust-score aggregation; no hard f-bound but keep 25% for comparison.
      # Root: 62×30=1860 stratified samples (30/class).
      # max-train-examples=1860 caps client local data to match server root
      # size, keeping client/server gradient step counts comparable (~58 each).
      # Without this cap, FEMNIST clients do ~204 steps vs server's 58,
      # causing cosine-similarity trust scores to collapse.
      run_config+=" fltrust-root-size=1860 fltrust-root-batch-size=32 fltrust-server-lr=0.1"
      run_config+=" max-train-examples=1860"
      run_config+=" attack-malicious-fraction=0.25 attack-malicious-fraction-mode=\"fixed\""
    fi

    for ((rep=1; rep<=REPEATS; rep++)); do
      seed_value="$(pick_seed "$rep")"
      # attack-seed is supported in run-config; plain seed is not a top-level override key.
      run_config_rep="$run_config attack-seed=${seed_value}"

      label_eff="$label"
      if [[ "$REPEATS" -gt 1 ]]; then
        label_eff="${label}__rep$(printf '%02d' "$rep")"
      fi

      completed_key="${label_eff}|${rep}"
      if [[ "$COMPLETED_KEYS_STR" == *$'\n'"$completed_key"$'\n'* ]]; then
        echo "Skipping completed: ${label_eff} (${strategy_name})"
        continue
      fi

      echo "=== ${label_eff} (${strategy_name}) ==="

      tmp_log="$(mktemp)"
      run_ok=0
      for ((attempt=1; attempt<=MAX_RETRIES+1; attempt++)); do
        if [[ "$attempt" -gt 1 ]]; then
          echo "Retry $((attempt-1))/${MAX_RETRIES} for ${label_eff} (${strategy_name})"
        fi
        > "$tmp_log"  # truncate

        # Launch the run in the background, filter PID lines, write to log file
        run_cmd=("$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py"
          --project-root "$ROOT_DIR")
        [[ -n "$FEDERATION" ]] && run_cmd+=(--federation "$FEDERATION")
        run_cmd+=(--run-config "$run_config_rep")

        set +e
        "${run_cmd[@]}" > "$tmp_log" 2>&1 &
        run_pid=$!

        # Stream output to terminal in real time
        tail -f "$tmp_log" 2>/dev/null &
        tail_pid=$!

        # Watchdog: monitor round progress
        last_round=""
        last_progress=$(date +%s)
        init_phase=1
        timed_out=0
        while kill -0 "$run_pid" 2>/dev/null; do
          sleep 10
          cur_round=$(grep -oE '\[ROUND +[0-9]+' "$tmp_log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$' || echo "")
          now=$(date +%s)
          if [[ -n "$cur_round" && "$cur_round" != "$last_round" ]]; then
            last_round="$cur_round"
            last_progress=$now
            init_phase=0
          fi
          if [[ "$init_phase" -eq 1 ]]; then
            effective_timeout=$INIT_TIMEOUT
          else
            effective_timeout=$ROUND_TIMEOUT
          fi
          if (( now - last_progress > effective_timeout )); then
            echo "" >&2
            if [[ "$init_phase" -eq 1 ]]; then
              echo "WARNING: Initialization exceeded ${INIT_TIMEOUT}s, killing run..." >&2
            else
              echo "WARNING: No round progress for ${ROUND_TIMEOUT}s (stuck at round ${last_round:-0}), killing run..." >&2
            fi
            kill "$run_pid" 2>/dev/null || true
            timed_out=1
            break
          fi
        done
        wait "$run_pid" 2>/dev/null || true
        kill "$tail_pid" 2>/dev/null || true
        wait "$tail_pid" 2>/dev/null || true
        set -e

        if [[ "$timed_out" -eq 1 ]]; then
          # Clean up any partial run dir
          partial_dir="$(grep -E "^Run folder: " "$tmp_log" | tail -n 1 | sed 's/^Run folder: //' || true)"
          if [[ -n "$partial_dir" && -d "$partial_dir" ]]; then
            rm -rf "$partial_dir"
          fi
          continue
        fi
        run_ok=1
        break
      done
      if [[ "$run_ok" -ne 1 ]]; then
        echo "ERROR: ${label_eff} failed after $((MAX_RETRIES+1)) attempts, skipping." >&2
        rm -f "$tmp_log"
        continue
      fi

      run_dir="$(grep -E "^Run folder: " "$tmp_log" | tail -n 1 | sed 's/^Run folder: //')"
      rm -f "$tmp_log"

      if [[ -n "$run_dir" && -d "$run_dir" ]]; then
        new_dir="$SWEEP_ROOT/${label_eff}__$(basename "$run_dir")"
        mv "$run_dir" "$new_dir"
        echo "Moved run to $new_dir"
        metrics_probe="$new_dir/metrics/evaluate_server__accuracy.csv"
        if [[ ! -s "$metrics_probe" ]]; then
          echo "Error: run produced no metrics at $metrics_probe" >&2
          echo "Aborting sweep early due to failed run: $label_eff ($strategy_name)" >&2
          exit 1
        fi
        echo "$(csv_escape "$label_eff"),$(csv_escape "$label"),$(csv_escape "$rep"),$(csv_escape "$seed_value"),$(csv_escape "$(basename "$new_dir")"),$(csv_escape "$start_round"),$(csv_escape "$end_round"),$(csv_escape "$ramp_end"),$(csv_escape "$attack_mode"),$(csv_escape "$selection_mode"),$(csv_escape "$churn_fraction"),$(csv_escape "$layering_mode"),$(csv_escape "$layered_k"),$(csv_escape "$layered_attacks"),$(csv_escape "$layer_mult")" >> "$settings_csv"
        COMPLETED_KEYS_STR+="$completed_key"$'\n'
      else
        echo "Warning: could not resolve run folder for ${label_eff}." >&2
      fi
    done
  done

  "$PYTHON_BIN" "$ROOT_DIR/scripts/generate_sweep_summary.py" \
    --sweep-root "$SWEEP_ROOT" \
    --settings-csv "$settings_csv" \
    --output "$SWEEP_ROOT/sweep_summary.txt"
  echo "Generated summary: $SWEEP_ROOT/sweep_summary.txt"

  if [[ "$AUTO_LLM_SWEEP_ANALYSIS" -eq 1 ]]; then
    echo "Running LLM CSV analysis for: $SWEEP_ROOT"
    llm_cmd=(
      "$PYTHON_BIN" "$ROOT_DIR/scripts/llm_sweep_analysis.py"
      --project-root "$ROOT_DIR"
      --sweeps-root "$SWEEP_ROOT"
      --skip-global
    )
    if [[ -n "$LLM_ANALYSIS_MODEL" ]]; then
      llm_cmd+=(--model "$LLM_ANALYSIS_MODEL")
    fi

    if ! "${llm_cmd[@]}"; then
      echo "Warning: LLM analysis failed for $SWEEP_ROOT (continuing)." >&2
    fi
  fi
done

echo "Completed sweeps:"
for root in "${STRATEGY_SWEEP_ROOTS[@]}"; do
  echo "  - $root"
done
