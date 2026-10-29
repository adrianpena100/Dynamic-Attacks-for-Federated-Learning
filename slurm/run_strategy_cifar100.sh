#!/bin/bash
#SBATCH --job-name=fl_cifar100
#SBATCH --output=slurm/logs/%x_%j.out
#SBATCH --error=slurm/logs/%x_%j.err
#SBATCH -N 1
#SBATCH -p gpul40q
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=16
#SBATCH --mem=48G
#SBATCH --time=2-00:00:00

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

echo "=== Running CIFAR-100 sweep for $STRATEGY seed=$SEED ==="
./run_thesis_sweep.sh \
  --name fixed_vs_mab_cifar100 \
  --dataset "uoft-cs/cifar100" \
  --dirichlet-alpha 1.0 \
  --federation local-simulation-gpu \
  --sweeps-file docs/fixed_vs_mab_sweep.conf \
  --strategies "$STRATEGY" \
  --repeats 1 \
  --seeds "$SEED" \
  --trust-level full \
  --extra-config "num-server-rounds=100 local-epochs=3 learning-rate=0.05" \
  --log-base "logs/sweeps/sep21sweeps"

echo "=== Job finished: $(date) ==="
