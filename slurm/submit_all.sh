#!/bin/bash
# Submits one Slurm job per defense strategy — all run in parallel.
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

for strategy in "${STRATEGIES[@]}"; do
  job_id=$(sbatch --export=ALL,STRATEGY="$strategy" \
    --job-name="fl_${strategy}" \
    slurm/run_strategy.sh | awk '{print $NF}')
  echo "Submitted $strategy → job $job_id"
done

echo ""
echo "All jobs submitted. Check status with:"
echo "  squeue -u $USER"
echo ""
echo "Logs will appear in slurm/logs/"
