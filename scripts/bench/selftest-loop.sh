#!/bin/sh
# Dispatch selftest.yml N times, one at a time, waiting PAUSE seconds after each
# finishes (so a warm pool can refill). Prints the run ids.
# usage: selftest-loop.sh OWNER/REPO N [PAUSE]
set -eu
repo=$1 n=$2 pause=${3:-30}
for i in $(seq 1 "$n"); do
  before=$(gh run list -R "$repo" -w selftest.yml -L 1 --json databaseId --jq '.[0].databaseId // 0')
  gh workflow run selftest.yml --ref main -R "$repo"
  run=$before
  while [ "$run" = "$before" ]; do
    sleep 3
    run=$(gh run list -R "$repo" -w selftest.yml -L 1 --json databaseId --jq '.[0].databaseId // 0')
  done
  gh run watch "$run" -R "$repo" >/dev/null 2>&1 || true
  echo "$run"
  sleep "$pause"
done
