#!/bin/bash
#SBATCH --job-name=fl_${STRATEGY}
#SBATCH --output=slurm/logs/%x_%j.out
#SBATCH --error=slurm/logs/%x_%j.err
#SBATCH -N 1
#SBATCH -p kimq
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=16
#SBATCH --mem=48G
#SBATCH --time=10:00:00

echo "=== Job started: $(date) ==="
echo "Strategy: $STRATEGY"
echo "Node: $HOSTNAME"
echo "CUDA: $CUDA_VISIBLE_DEVICES"

cd ~/dynamic_fl
source ~/dynamic_fl_env/bin/activate

# Load .env variables
set -a
source .env
set +a

echo "=== Running sweep for $STRATEGY ==="
./run_thesis_sweep.sh \
  --name fixed_vs_mab_full \
  --dataset "flwrlabs/femnist" \
  --dirichlet-alpha 0.5 \
  --sweeps-file docs/fixed_vs_mab_sweep.conf \
  --strategies "$STRATEGY" \
  --repeats 1 \
  --seeds "1337,42,2024" \
  --trust-level full \
  --extra-config "num-server-rounds=100"

echo "=== Job finished: $(date) ==="
