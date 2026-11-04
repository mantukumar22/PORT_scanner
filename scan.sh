#!/usr/bin/env bash
# Run the scanner and keep a copy of the output with the date in the filename.
# Usage: ./scan.sh <target> [--ports 22,80,443] [--timeout 2] [--log]
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results

stamp=$(date +%F_%H%M%S)
out="results/run_${stamp}.txt"

# -u: unbuffered, so the confirmation prompt shows up right away
set +e
python3 -u scanner.py "$@" 2>&1 | tee "$out"
status=${PIPESTATUS[0]}
set -e

echo "Wrapper output saved to $out (exit code $status)"
exit "$status"
