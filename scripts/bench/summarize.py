#!/usr/bin/env python3
"""Median / p95 / min / max of one numeric CSV column, grouped by other columns.

usage: summarize.py FILE.csv VALUE_COLUMN GROUP_COLUMN [GROUP_COLUMN ...]
p95 is linear interpolation between closest ranks (numpy's default); with
fewer than 20 samples it is close to the maximum, read it that way.
"""
import csv, statistics, sys


def pct(v, p):
    v = sorted(v)
    k = (len(v) - 1) * p
    f = int(k)
    c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


def main():
    path, col, *by = sys.argv[1:]
    groups = {}
    for r in csv.DictReader(open(path)):
        if r.get(col, "") != "" and r.get("conclusion", "success") == "success":
            groups.setdefault(tuple(r[b] for b in by), []).append(float(r[col]))
    print("| " + " | ".join(by) + " | n | median | p95 | min | max |")
    print("|" + "---|" * (len(by) + 5))
    for k, v in sorted(groups.items()):
        cells = [f"{x:g}" for x in (statistics.median(v), round(pct(v, 0.95), 1), min(v), max(v))]
        print("| " + " | ".join(k) + f" | {len(v)} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    assert pct([1, 2, 3, 4, 5], 0.5) == 3 and pct([0, 10], 0.95) == 9.5
    main()
