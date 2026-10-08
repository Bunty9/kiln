#!/bin/sh
# Re-run every job of a workflow run until it has N attempts, one at a time.
# usage: rerun.sh OWNER/REPO RUN_ID N
set -eu
repo=$1 run=$2 n=$3
while :; do
  gh run watch "$run" -R "$repo" --exit-status >/dev/null 2>&1 || true
  att=$(gh api "repos/$repo/actions/runs/$run" --jq .run_attempt)
  echo "attempt $att done"
  [ "$att" -ge "$n" ] && exit 0
  gh run rerun "$run" -R "$repo"
  sleep 10
done
