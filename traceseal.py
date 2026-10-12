#!/usr/bin/env python3
"""
TraceSeal v0.1 (Week 2): evidence collector for Linux.

What it does (in this order, following the order of volatility):
  1. Runs volatile-data commands (time, network, processes, users)
  2. Runs log commands (journalctl, dmesg)
  3. Copies a small list of files, hashing each file before and after the copy
  4. Writes manifest.json with a SHA-256 hash and UTC timestamp for every artifact

Use only on systems you own or are authorized to examine.
Usage:  sudo python3 traceseal.py collect --case-id CASE001 --output ./cases
"""

import argparse
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone

VERSION = "0.1"

# (name, command). Order matters: most volatile first.
VOLATILE_COMMANDS = [
    ("date_utc",      ["date", "-u"]),
    ("uptime",        ["uptime"]),
    ("uname",         ["uname", "-a"]),
    ("arp_neighbors", ["ip", "neigh"]),
    ("ip_addr",       ["ip", "addr"]),
    ("ip_route",      ["ip", "route"]),
    ("sockets",       ["ss", "-tulpan"]),
    ("processes",     ["ps", "-eo", "pid,ppid,user,lstart,cmd"]),
    ("who",           ["who"]),
    ("w",             ["w"]),
    ("last_logins",   ["last", "-n", "50"]),
    ("mounts",        ["mount"]),
    ("kernel_modules", ["lsmod"]),
]

LOG_COMMANDS = [
    ("journal_last_500", ["journalctl", "--no-pager", "-n", "500"]),
    ("dmesg",            ["dmesg"]),
]

# Files to copy. Missing files are recorded as "skipped", not as errors.
FILES_TO_COLLECT = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/os-release",
    "/var/log/auth.log",   # may not exist on newer Kali (uses journald)
]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path, chunk_size=65536):
    """Hash a file in chunks so large files do not fill memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def real_user_home():
    """Home directory of the user who ran sudo (not root's)."""
    name = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    try:
        return pwd.getpwnam(name).pw_dir
    except KeyError:
        return os.path.expanduser("~")


def collect_commands(commands, kind, case_dir, subdir, artifacts):
    out_dir = os.path.join(case_dir, subdir)
    os.makedirs(out_dir, exist_ok=True)
    for name, cmd in commands:
        entry = {
            "id": len(artifacts) + 1,
            "type": kind,
            "source": " ".join(cmd),
            "collected_utc": utc_now(),
        }
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            rel_path = os.path.join(subdir, name + ".txt")
            full_path = os.path.join(case_dir, rel_path)
            with open(full_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(result.stdout)
            entry.update({
                "status": "collected",
                "file": rel_path,
                "exit_code": result.returncode,
                "size": os.path.getsize(full_path),
                "sha256": sha256_file(full_path),
            })
            if result.stderr.strip():
                entry["stderr"] = result.stderr.strip()[:300]
        except FileNotFoundError:
            entry.update({"status": "skipped", "reason": "command not found"})
        except subprocess.TimeoutExpired:
            entry.update({"status": "skipped", "reason": "timeout (30s)"})
        artifacts.append(entry)
        print(f"  [{entry['status']:9}] {entry['source']}")


def collect_files(paths, case_dir, artifacts):
    for src in paths:
        entry = {
            "id": len(artifacts) + 1,
            "type": "file",
            "source": src,
            "collected_utc": utc_now(),
        }
        try:
            hash_before = sha256_file(src)
            rel_path = os.path.join("files", src.lstrip("/"))
            dst = os.path.join(case_dir, rel_path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)  # copy2 keeps original timestamps
            hash_after = sha256_file(dst)
            entry.update({
                "status": "collected",
                "file": rel_path,
                "size": os.path.getsize(dst),
                "sha256": hash_after,
                "sha256_source_before_copy": hash_before,
                "copy_verified": hash_before == hash_after,
            })
        except FileNotFoundError:
            entry.update({"status": "skipped", "reason": "file not found"})
        except PermissionError:
            entry.update({"status": "skipped", "reason": "permission denied"})
        artifacts.append(entry)
        print(f"  [{entry['status']:9}] {src}")


def run_collect(case_id, output):
    if os.geteuid() != 0:
        print("WARNING: not running as root. Some data will be incomplete or skipped.\n")

    started = utc_now()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case_dir = os.path.join(output, f"{case_id}_{stamp}")
    os.makedirs(case_dir, exist_ok=False)  # never overwrite an old case

    artifacts = []

    print("[1/3] Volatile data")
    collect_commands(VOLATILE_COMMANDS, "volatile", case_dir, "volatile", artifacts)

    print("[2/3] Logs")
    collect_commands(LOG_COMMANDS, "log", case_dir, "logs", artifacts)

    print("[3/3] Files")
    files = FILES_TO_COLLECT + [os.path.join(real_user_home(), ".bash_history")]
    collect_files(files, case_dir, artifacts)

    manifest = {
        "tool": "TraceSeal",
        "version": VERSION,
        "case_id": case_id,
        "hostname": socket.gethostname(),
        "collected_by_uid": os.getuid(),
        "started_utc": started,
        "finished_utc": utc_now(),
        "artifacts": artifacts,
    }
    manifest_path = os.path.join(case_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    collected = sum(1 for a in artifacts if a["status"] == "collected")
    print(f"\nDone. {collected}/{len(artifacts)} artifacts collected.")
    print(f"Case folder : {case_dir}")
    print(f"Manifest    : {manifest_path}")
    print(f"Manifest SHA-256: {sha256_file(manifest_path)}")


def main():
    parser = argparse.ArgumentParser(prog="traceseal", description="TraceSeal evidence collector")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect", help="collect evidence from this host")
    c.add_argument("--case-id", required=True, help="case identifier, e.g. CASE001")
    c.add_argument("--output", default="./cases", help="folder where case folders are created")
    args = parser.parse_args()

    if args.command == "collect":
        run_collect(args.case_id, args.output)


if __name__ == "__main__":
    sys.exit(main())

