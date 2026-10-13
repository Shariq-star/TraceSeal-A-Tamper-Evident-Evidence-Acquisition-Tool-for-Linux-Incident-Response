#!/usr/bin/env python3
"""
footprint_test.py: measures how running TraceSeal changes the system it runs on.

It takes a snapshot BEFORE the collection, runs TraceSeal, takes a snapshot
AFTER, and reports what changed. Run it from the same folder as traceseal.py:
    sudo python3 footprint_test.py

What it measures:
  - atime / mtime / ctime of every file TraceSeal collects (os.stat does not
    change atime, so the snapshots themselves do not disturb these values)
  - number of processes, journal lines, free memory and disk usage
  - whether the CONTENT of the source files is unchanged (compared with the
    hash TraceSeal recorded before copying)

Important: the measurement is not perfectly clean either. The snapshot commands
and sudo also leave traces, which is the same point the report makes about
live collection in general.
"""

import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import traceseal as ts  # noqa: E402


def count_lines(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return len(r.stdout.splitlines())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def mem_available_kb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def snapshot(paths, disk_path):
    snap = {"time_utc": ts.utc_now(), "files": {}}
    for p in paths:
        try:
            st = os.stat(p)
            snap["files"][p] = {"atime": st.st_atime_ns, "mtime": st.st_mtime_ns, "ctime": st.st_ctime_ns}
        except OSError:
            snap["files"][p] = None
    snap["process_count"] = count_lines(["ps", "-e", "--no-headers"])
    snap["journal_lines"] = count_lines(["journalctl", "-q", "--no-pager", "-b"])
    snap["mem_available_kb"] = mem_available_kb()
    snap["disk_used_bytes"] = shutil.disk_usage(disk_path).used
    return snap


def delta(before, after):
    if before is None or after is None:
        return "n/a"
    return f"{after - before:+d}"


def main():
    if os.geteuid() != 0:
        print("WARNING: run with sudo for a realistic measurement.\n")

    out_dir = tempfile.mkdtemp(prefix="traceseal_footprint_")
    paths = ts.files_to_collect()

    before = snapshot(paths, out_dir)
    result = subprocess.run(
        [sys.executable, os.path.join(HERE, "traceseal.py"), "collect",
         "--case-id", "FOOTPRINT", "--output", out_dir],
        capture_output=True, text=True)
    after = snapshot(paths, out_dir)

    if result.returncode != 0:
        print("TraceSeal failed:\n", result.stderr)
        return 1

    case = glob.glob(os.path.join(out_dir, "FOOTPRINT_*"))[0]
    with open(os.path.join(case, ts.MANIFEST_NAME), encoding="utf-8") as f:
        manifest = json.load(f)
    recorded = {a["source"]: a.get("sha256_source_before_copy")
                for a in manifest["artifacts"] if a["type"] == "file"}
    collected_bytes = sum(a.get("size", 0) for a in manifest["artifacts"] if a["status"] == "collected")

    lines = [f"TraceSeal footprint test on {socket.gethostname()}", ""]
    lines += ["| Source file | atime | mtime | ctime | Content unchanged |", "|---|---|---|---|---|"]
    for p in paths:
        b, a = before["files"][p], after["files"][p]
        if b is None or a is None:
            lines.append(f"| {p} | not present | | | |")
            continue
        flags = ["CHANGED" if b[k] != a[k] else "same" for k in ("atime", "mtime", "ctime")]
        try:
            same = ts.sha256_file(p) == recorded.get(p)
            content = "yes" if same else "NO"
        except OSError:
            content = "n/a"
        lines.append(f"| {p} | {flags[0]} | {flags[1]} | {flags[2]} | {content} |")

    lines += [
        "",
        "| System measure | Before | After | Change |",
        "|---|---|---|---|",
        f"| Running processes | {before['process_count']} | {after['process_count']} | "
        f"{delta(before['process_count'], after['process_count'])} |",
        f"| Journal lines (this boot) | {before['journal_lines']} | {after['journal_lines']} | "
        f"{delta(before['journal_lines'], after['journal_lines'])} |",
        f"| Available memory (kB) | {before['mem_available_kb']} | {after['mem_available_kb']} | "
        f"{delta(before['mem_available_kb'], after['mem_available_kb'])} |",
        f"| Disk used (bytes) | {before['disk_used_bytes']} | {after['disk_used_bytes']} | "
        f"{delta(before['disk_used_bytes'], after['disk_used_bytes'])} |",
        "",
        f"Evidence written by TraceSeal: {collected_bytes} bytes in "
        f"{sum(1 for a in manifest['artifacts'] if a['status'] == 'collected')} artifacts.",
        f"Collection window (UTC): {manifest['started_utc']} to {manifest['finished_utc']}.",
        "",
        "How to read this: mtime and file content should never change (TraceSeal only reads the",
        "sources). atime and ctime may change depending on the mount options. Journal, process",
        "and memory changes are the footprint of running the tool (and of sudo and the snapshot",
        "commands themselves).",
    ]
    report = "\n".join(lines)
    print(report)

    host = socket.gethostname()
    out_file = os.path.join(os.getcwd(), f"footprint_results_{host}.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\nSaved: {out_file}")
    shutil.rmtree(out_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
