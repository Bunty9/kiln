#!/bin/sh
# Pull the "BENCH <name> <ms>" lines of bench-ci's docker jobs out of each attempt's log.
# usage: bench-lines.sh OWNER/REPO RUN_ID  > docker.csv
set -eu
repo=$1 run=$2
n=$(gh api "repos/$repo/actions/runs/$run" --jq .run_attempt)
echo "run_id,attempt,job,measure,ms"
for a in $(seq 1 "$n"); do
  gh run view "$run" -R "$repo" --attempt "$a" --log |
    awk -F'\t' -v r="$run" -v a="$a" '$3 ~ / BENCH / { split($3, f, " "); print r "," a "," $1 "," f[3] "," f[4] }'
done
