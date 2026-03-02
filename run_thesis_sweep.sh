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

usage() {
  cat <<EOF
Usage: ./run_thesis_sweep.sh [--name NAME] [--dataset DATASET] [--partitioner NAME] [--dirichlet-alpha VAL] [--federation NAME] [--strategy NAME]

Runs a focused sweep to test defense robustness within fixed malicious fraction.
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

STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
SWEEP_ROOT="$ROOT_DIR/logs/sweeps/${NAME}__${STAMP}"
mkdir -p "$SWEEP_ROOT"

# Each entry: label|start_round|end_round|ramp_end|attack_mode|selection_mode|churn_fraction|layering_mode|layered_k|layered_attacks|layer_multipliers
SWEEPS=(
  "A_start15_ramp3_adaptive_churn05|15|30|3.0|adaptive|churn|0.5|single|||"
  "B_start15_ramp3_weighted_churn05|15|30|3.0|weighted_random|churn|0.5|single|||"
  "C_start05_ramp3_adaptive_churn05|5|30|3.0|adaptive|churn|0.5|single|||"
  "D_start10_ramp45_adaptive_churn05|10|30|4.5|adaptive|churn|0.5|single|||"
  "E_start10_ramp3_adaptive_churn00|10|30|3.0|adaptive|churn|0.0|single|||"
  "F_start10_ramp3_adaptive_churn08|10|30|3.0|adaptive|churn|0.8|single|||"
  "G_start10_end20_adaptive_churn05|10|20|3.0|adaptive|churn|0.5|single|||"
  "H_start10_ramp3_sticky|10|30|3.0|adaptive|sticky|0.0|single|||"
  "I_start10_ramp3_perround|10|30|3.0|adaptive|per_round_random|0.0|single|||"
  "J_start10_ramp3_stack_fixed|10|30|3.0|adaptive|churn|0.5|fixed|3|mean_shift,sign_flip,backdoor|mean_shift=2.5,sign_flip=1.5,backdoor=1.2"
  "K_start10_ramp3_stack_samplek|10|30|3.0|adaptive|churn|0.5|sample_k|3|gaussian_noise,sign_flip,alie,mean_shift,backdoor|mean_shift=2.0,alie=1.5"
  "L_start15_ramp3_stack_fixed|15|30|3.0|adaptive|churn|0.5|fixed|3|mean_shift,backdoor,alie|mean_shift=2.0,backdoor=1.3,alie=1.5"
  "M_start10_ramp2_adaptive_churn05|10|30|2.0|adaptive|churn|0.5|single|||"
  "N_start10_ramp35_adaptive_churn05|10|30|3.5|adaptive|churn|0.5|single|||"
)

settings_csv="$SWEEP_ROOT/sweep_settings.csv"
echo "label,run_folder,attack_window_start,attack_window_end,ramp_end,attack_mode,selection_mode,churn_fraction,layering_mode,layered_k,layered_attacks,layer_multipliers" > "$settings_csv"

for entry in "${SWEEPS[@]}"; do
  IFS="|" read -r label start_round end_round ramp_end attack_mode selection_mode churn_fraction layering_mode layered_k layered_attacks layer_mult <<<"$entry"

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
    run_config+=" dataset=${DATASET}"
  fi
  if [[ -n "$PARTITIONER" ]]; then
    run_config+=" partitioner=${PARTITIONER}"
  fi
  if [[ -n "$DIRICHLET_ALPHA" ]]; then
    run_config+=" dirichlet-alpha=${DIRICHLET_ALPHA}"
  fi
  if [[ -n "$STRATEGY" ]]; then
    run_config+=" strategy=\"${STRATEGY}\""
  fi

  if [[ "${STRATEGY}" == "bulyan" ]]; then
    # Bulyan requires at least (4f + 3) total updates; with 100 clients, f must be <= 24.
    run_config+=" num-malicious-nodes=24"
    run_config+=" attack-malicious-fraction=0.24 attack-malicious-fraction-mode=\"fixed\""
  fi

  if [[ "${STRATEGY}" == "fedtrimmedavg" ]]; then
    # Trimmed mean cuts beta from each tail; keep f <= beta for within-bound runs.
    run_config+=" trimmed-beta=0.24"
    run_config+=" attack-malicious-fraction=0.24 attack-malicious-fraction-mode=\"fixed\""
  fi

  echo "=== ${label} ==="

  tmp_log="$(mktemp)"
  if [[ -n "$FEDERATION" ]]; then
    "$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py" \
      --project-root "$ROOT_DIR" \
      --federation "$FEDERATION" \
      --run-config "$run_config" | tee "$tmp_log"
  else
    "$PYTHON_BIN" "$ROOT_DIR/scripts/run_simulation_and_log.py" \
      --project-root "$ROOT_DIR" \
      --run-config "$run_config" | tee "$tmp_log"
  fi

  run_dir="$(grep -E "^Run folder: " "$tmp_log" | tail -n 1 | sed 's/^Run folder: //')"
  rm -f "$tmp_log"

  if [[ -n "$run_dir" && -d "$run_dir" ]]; then
    new_dir="$SWEEP_ROOT/${label}__$(basename "$run_dir")"
    mv "$run_dir" "$new_dir"
    echo "Moved run to $new_dir"
    echo "${label},$(basename "$new_dir"),${start_round},${end_round},${ramp_end},${attack_mode},${selection_mode},${churn_fraction},${layering_mode},${layered_k},${layered_attacks},${layer_mult}" >> "$settings_csv"
  else
    echo "Warning: could not resolve run folder for ${label}." >&2
  fi
done

echo "Sweep folder: $SWEEP_ROOT"
