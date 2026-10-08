#!/usr/bin/env python3
"""Dump GitHub Actions job timings as CSV (needs an authenticated `gh`).

usage: jobs.py OWNER/REPO RUN_ID[:ATTEMPT] ...      (all attempts if ATTEMPT omitted)

One row per job: queue_s = created_at -> started_at (time until a runner took it;
on kiln without a warm VM this includes booting the VM), run_s = started_at ->
completed_at, plus every step's duration in seconds as step:<name>.
"""
import csv, json, subprocess, sys
from datetime import datetime


def gh(path):
    return json.loads(subprocess.check_output(["gh", "api", path]))


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def secs(a, b):
    return round((ts(b) - ts(a)).total_seconds()) if a and b else ""


def main():
    repo, specs = sys.argv[1], sys.argv[2:]
    rows = []
    for spec in specs:
        run_id, _, att = spec.partition(":")
        run = gh(f"repos/{repo}/actions/runs/{run_id}")
        attempts = [int(att)] if att else range(1, run["run_attempt"] + 1)
        for a in attempts:
            for j in gh(f"repos/{repo}/actions/runs/{run_id}/attempts/{a}/jobs?per_page=100")["jobs"]:
                row = {
                    "run_id": run_id, "attempt": a, "workflow": run["name"], "event": run["event"],
                    "branch": run["head_branch"], "job": j["name"], "runner": j.get("runner_name") or "",
                    "labels": " ".join(j["labels"]), "conclusion": j["conclusion"], "created_at": j["created_at"],
                    "queue_s": secs(j["created_at"], j["started_at"]),
                    "run_s": secs(j["started_at"], j["completed_at"]),
                }
                for s in j.get("steps", []):
                    row["step:" + s["name"]] = secs(s.get("started_at"), s.get("completed_at"))
                rows.append(row)
    cols = list(dict.fromkeys(k for r in rows for k in r))
    w = csv.DictWriter(sys.stdout, cols)
    w.writeheader()
    w.writerows(rows)


if __name__ == "__main__":
    main()
