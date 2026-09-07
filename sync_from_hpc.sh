#!/bin/bash
# Pulls sweep logs from Cradle HPC to local machine.
# Run this from your local Mac (VPN must be active first).
# Usage: ./sync_from_hpc.sh

HPC_USER="adrianpena05"
HPC_HOST="login.cradle.utrgv.edu"
HPC_PROJECT="~/dynamic_fl"
LOCAL_PROJECT="$(dirname "$(realpath "$0")")"

echo "Syncing logs from HPC → local..."
rsync -avz --progress \
  "${HPC_USER}@${HPC_HOST}:${HPC_PROJECT}/logs/sweeps/" \
  "${LOCAL_PROJECT}/logs/sweeps/"

echo ""
echo "Done. To generate the comparison report:"
echo "  python scripts/fixed_vs_mab_comparison.py \"logs/sweeps/*fixed_vs_mab_full*\" \\"
echo "    --out docs/reports/fixed_vs_mab_full.html && open docs/reports/fixed_vs_mab_full.html"
