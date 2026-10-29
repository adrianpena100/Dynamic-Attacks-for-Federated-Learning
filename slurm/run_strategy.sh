#!/bin/bash
#SBATCH --job-name=fl_strategy
#SBATCH --output=slurm/logs/%x_%j.out
#SBATCH --error=slurm/logs/%x_%j.err
#SBATCH -N 1
#SBATCH -p gpua30q
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=16
#SBATCH --mem=48G
#SBATCH --time=1-10:00:00

echo "=== Job started: $(date) ==="
echo "Strategy: $STRATEGY"
echo "Node: $HOSTNAME"
echo "CUDA: $CUDA_VISIBLE_DEVICES"

module load cuda/12.3

cd ~/dynamic_fl
export LD_LIBRARY_PATH=$HOME/python3.10/lib:$LD_LIBRARY_PATH
export PYTHONPATH=$HOME/dynamic_fl:$PYTHONPATH
source ~/dynamic_fl_env/bin/activate

# Load .env variables
set -a
source .env
set +a

echo "=== Running sweep for $STRATEGY seed=$SEED ==="
./run_thesis_sweep.sh \
  --name fixed_vs_mab_full \
  --dataset "flwrlabs/femnist" \
  --dirichlet-alpha 0.5 \
  --sweeps-file docs/fixed_vs_mab_sweep.conf \
  --strategies "$STRATEGY" \
  --repeats 1 \
  --seeds "$SEED" \
  --trust-level full \
  --extra-config "num-server-rounds=50"

echo "=== Job finished: $(date) ==="
