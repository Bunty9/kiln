#!/usr/bin/env python3
"""kiln's VM records (GET /api/state) as CSV.

usage: curl -s -H "x-kiln-key: $KEY" http://127.0.0.1:7878/api/state | vms.py [OWNER/REPO] > vms.csv

boot_s = online_at - started (VM created -> runner "Listening for Jobs"),
pickup_s = busy_since - queued_at (job queued -> runner busy with it),
vm_ready_before_job = 1 when the VM was started before the job was queued (warm pool).
Repos other than OWNER/REPO are written as "other" so private names stay out.
"""
import csv, json, sys

keep = sys.argv[1] if len(sys.argv) > 1 else None
cols = ["id", "repo", "job", "warm", "cpus", "mem_mb", "egress", "state", "result",
        "queued_at", "started", "online_at", "busy_since", "done_at", "boot_s", "pickup_s", "vm_ready_before_job", "job_url"]
w = csv.DictWriter(sys.stdout, cols, extrasaction="ignore")
w.writeheader()
for v in sorted(json.load(sys.stdin)["vms"], key=lambda v: v["started"]):
    r = dict(v)
    other = keep and v["repo"] != keep
    if other:
        r.update(repo="other", job="", job_url="")
    r["boot_s"] = v["online_at"] - v["started"] if v.get("online_at") and v.get("started") else ""
    r["pickup_s"] = v["busy_since"] - v["queued_at"] if v.get("busy_since") and v.get("queued_at") else ""
    # The record's `warm` flag is false once a warm VM takes a job; a VM that
    # existed before the job was queued is the reliable sign it was pre-booted.
    r["vm_ready_before_job"] = int(bool(v.get("queued_at")) and v["started"] < v["queued_at"]) if v.get("queued_at") else ""
    w.writerow(r)
