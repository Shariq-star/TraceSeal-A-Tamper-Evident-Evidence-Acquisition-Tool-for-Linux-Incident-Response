#!/usr/bin/env python3
"""
compare_runs.py: compares two TraceSeal case folders, for example one collected
with sudo and one without, and prints a table you can paste into your report.

    python3 compare_runs.py <root_case_folder> <non_root_case_folder>

Only the items that differ are listed in detail. No evidence is modified.
"""

import json
import os
import sys


def load(case):
    with open(os.path.join(case, "manifest.json"), encoding="utf-8") as f:
        return json.load(f)


def describe(a):
    if a is None:
        return "missing from manifest"
    if a["status"] == "skipped":
        return "skipped (" + a.get("reason", "no reason") + ")"
    if a.get("exit_code") not in (None, 0):
        return f"collected, but exit code {a['exit_code']}"
    return "collected"


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    a_dir, b_dir = sys.argv[1], sys.argv[2]
    ma, mb = load(a_dir), load(b_dir)
    A = {x["source"]: x for x in ma["artifacts"]}
    B = {x["source"]: x for x in mb["artifacts"]}

    def counts(m):
        arts = m["artifacts"]
        ok = sum(1 for x in arts if x["status"] == "collected" and x.get("exit_code") in (None, 0))
        err = sum(1 for x in arts if x["status"] == "collected" and x.get("exit_code") not in (None, 0))
        skip = sum(1 for x in arts if x["status"] == "skipped")
        return ok, err, skip, len(arts)

    ca, cb = counts(ma), counts(mb)
    label_a = "Root (sudo)" if ma.get("run_as_root") else "Not root"
    label_b = "Root (sudo)" if mb.get("run_as_root") else "Not root"

    print(f"TraceSeal comparison on {mb.get('hostname')}\n")
    print(f"| Measure | {label_a} | {label_b} |")
    print("|---|---|---|")
    print(f"| Collected cleanly | {ca[0]} of {ca[3]} | {cb[0]} of {cb[3]} |")
    print(f"| Collected, but the command reported an error | {ca[1]} | {cb[1]} |")
    print(f"| Skipped | {ca[2]} | {cb[2]} |")
    print()
    print(f"| Item | {label_a} | {label_b} |")
    print("|---|---|---|")
    differences = 0
    for src in list(A) + [x for x in B if x not in A]:
        da, db = describe(A.get(src)), describe(B.get(src))
        if da != db:
            differences += 1
            print(f"| {src} | {da} | {db} |")
    if not differences:
        print("| (no differences) | | |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
