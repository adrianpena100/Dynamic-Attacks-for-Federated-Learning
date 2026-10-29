#!/bin/bash
# Submits one Slurm job per strategy per seed (24 jobs total, 8 strategies × 3 seeds).
# Each job runs 10 scenarios × 50 rounds for one seed — fits within the 36h cluster limit.
# Run this from ~/dynamic_fl on the HPC.
# Usage: bash slurm/submit_all.sh

cd ~/dynamic_fl
mkdir -p slurm/logs

STRATEGIES=(
  bulyan
  multikrum
  fedtrimmedavg
  fedmedian
  fltrust
  foolsgold
  flram
  mab-rfl
)

SEEDS=(1337 42 2024)

for strategy in "${STRATEGIES[@]}"; do
  for seed in "${SEEDS[@]}"; do
    job_id=$(sbatch --export=ALL,STRATEGY="$strategy",SEED="$seed" \
      --job-name="fl_${strategy}_s${seed}" \
      slurm/run_strategy.sh | awk '{print $NF}')
    echo "Submitted $strategy seed=$seed → job $job_id"
  done
done

echo ""
echo "All 24 jobs submitted (8 strategies × 3 seeds). Check status with:"
echo "  squeue -u $USER"
echo ""
echo "Logs will appear in slurm/logs/"
