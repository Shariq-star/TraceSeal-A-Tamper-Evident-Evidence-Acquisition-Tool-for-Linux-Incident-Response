#!/usr/bin/env python3
"""
TraceSeal v0.2 (Week 3): evidence collector with a tamper-evident custody log.

collect : gathers evidence in order of volatility (volatile data, logs, files),
          writes manifest.json and a hash-chained custody_log.jsonl
verify  : re-checks a case folder and reports modified, missing or added
          evidence, a broken custody log, or a modified manifest

Every custody log entry stores the hash of the previous entry, so changing,
removing or reordering an entry breaks the chain. The last entry (CASE_END)
seals the SHA-256 of manifest.json.

Optional hardening:
  --key-file    chain hashes become HMAC-SHA256, so the chain cannot be
                recomputed without the key
  --expect-head verify compares the chain head with a value you stored
                somewhere else (for example in an email)

Use only on systems you own or are authorized to examine.

  sudo python3 traceseal.py collect --case-id CASE001 --output ./cases
  python3 traceseal.py verify --case ./cases/CASE001_<timestamp>
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import pwd
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone

VERSION = "0.2"
GENESIS_HASH = "0" * 64
LOG_NAME = "custody_log.jsonl"
MANIFEST_NAME = "manifest.json"

# (name, command). Order matters: most volatile first.
VOLATILE_COMMANDS = [
    ("date_utc",       ["date", "-u"]),
    ("uptime",         ["uptime"]),
    ("uname",          ["uname", "-a"]),
    ("arp_neighbors",  ["ip", "neigh"]),
    ("ip_addr",        ["ip", "addr"]),
    ("ip_route",       ["ip", "route"]),
    ("sockets",        ["ss", "-tulpan"]),
    ("processes",      ["ps", "-eo", "pid,ppid,user,lstart,cmd"]),
    ("who",            ["who"]),
    ("w",              ["w"]),
    ("login_sessions", ["loginctl", "list-sessions", "--no-pager"]),
    ("last_logins",    ["last", "-n", "50"]),
    ("mounts",         ["mount"]),
    ("kernel_modules", ["lsmod"]),
]

LOG_COMMANDS = [
    ("journal_last_500", ["journalctl", "--no-pager", "-n", "500"]),
    ("dmesg",            ["dmesg"]),
]

SYSTEM_FILES = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/os-release",
    "/var/log/auth.log",   # not present on systems that only use journald
]


# ---------------------------------------------------------------- helpers

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


def safe_sha256(path):
    """Return (hash, None), or (None, error text) if the file cannot be read."""
    try:
        return sha256_file(path), None
    except OSError as e:
        return None, e.strerror or str(e)


def real_user_home():
    """Home directory of the user who ran sudo (not root's)."""
    name = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    try:
        return pwd.getpwnam(name).pw_dir
    except KeyError:
        return os.path.expanduser("~")


def files_to_collect():
    home = real_user_home()
    return SYSTEM_FILES + [
        os.path.join(home, ".bash_history"),
        os.path.join(home, ".zsh_history"),
    ]


def load_key(path):
    if not path:
        return None
    with open(path, "rb") as f:
        key = f.read().strip()
    if not key:
        sys.exit("error: key file is empty")
    return key


# ------------------------------------------------------- custody log chain

def canonical(obj):
    """Stable JSON bytes, so the same entry always produces the same hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def chain_hash(entry_without_hash, key=None):
    data = canonical(entry_without_hash)
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def actor_info():
    return {
        "user": pwd.getpwuid(os.geteuid()).pw_name,
        "sudo_user": os.environ.get("SUDO_USER"),
        "uid": os.geteuid(),
        "hostname": socket.gethostname(),
    }


class CustodyLog:
    """Append-only log. Each entry contains the hash of the previous entry."""

    def __init__(self, path, key=None):
        self.path = path
        self.key = key
        self.seq = 0
        self.prev_hash = GENESIS_HASH
        self.actor = actor_info()

    def append(self, event, details):
        entry = {
            "seq": self.seq,
            "timestamp_utc": utc_now(),
            "event": event,
            "actor": self.actor,
            "details": details,
            "prev_hash": self.prev_hash,
        }
        entry["entry_hash"] = chain_hash(entry, self.key)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self.prev_hash = entry["entry_hash"]
        self.seq += 1


def log_artifact(log, entry):
    keys = ("id", "type", "source", "status", "file", "sha256", "reason")
    log.append("ARTIFACT", {k: entry.get(k) for k in keys})


# -------------------------------------------------------------- collection

def collect_commands(commands, kind, case_dir, subdir, artifacts, log):
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
        log_artifact(log, entry)
        print(f"  [{entry['status']:9}] {entry['source']}")


def collect_files(paths, case_dir, artifacts, log):
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
        log_artifact(log, entry)
        print(f"  [{entry['status']:9}] {src}")


def run_collect(case_id, output, key_file):
    if os.geteuid() != 0:
        print("WARNING: not running as root. Some data will be incomplete or skipped.\n")

    key = load_key(key_file)
    started = utc_now()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case_dir = os.path.join(output, f"{case_id}_{stamp}")
    os.makedirs(case_dir, exist_ok=False)  # never overwrite an old case

    log = CustodyLog(os.path.join(case_dir, LOG_NAME), key)
    log.append("CASE_START", {
        "case_id": case_id,
        "tool_version": VERSION,
        "tool_pid": os.getpid(),
        "keyed": bool(key),
        "platform": platform.platform(),
    })

    artifacts = []
    print("[1/3] Volatile data")
    collect_commands(VOLATILE_COMMANDS, "volatile", case_dir, "volatile", artifacts, log)
    print("[2/3] Logs")
    collect_commands(LOG_COMMANDS, "log", case_dir, "logs", artifacts, log)
    print("[3/3] Files")
    collect_files(files_to_collect(), case_dir, artifacts, log)

    manifest = {
        "tool": "TraceSeal",
        "version": VERSION,
        "case_id": case_id,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "tool_pid": os.getpid(),
        "collected_by_uid": os.getuid(),
        "started_utc": started,
        "finished_utc": utc_now(),
        "artifacts": artifacts,
    }
    manifest_path = os.path.join(case_dir, MANIFEST_NAME)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    manifest_sha = sha256_file(manifest_path)
    collected = sum(1 for a in artifacts if a["status"] == "collected")
    log.append("CASE_END", {
        "manifest_sha256": manifest_sha,
        "artifact_count": len(artifacts),
        "collected_count": collected,
    })

    print(f"\nDone. {collected}/{len(artifacts)} artifacts collected.")
    print(f"Case folder : {case_dir}")
    print(f"Manifest SHA-256 : {manifest_sha}")
    print(f"Custody log      : {log.seq} entries" + (" (HMAC keyed)" if key else ""))
    print(f"Chain head       : {log.prev_hash}")
    print("Store the chain head somewhere separate (for example in an email)."
          " verify --expect-head can check it later.")
    return 0


# ------------------------------------------------------------ verification

def verify_case(case_dir, key=None, expect_head=None):
    """Return (findings, chain_head, stats). findings is a list of (code, message)."""
    findings = []

    def bad(code, msg):
        findings.append((code, msg))

    stats = {"log_entries": 0, "artifacts_checked": 0}
    manifest_path = os.path.join(case_dir, MANIFEST_NAME)
    log_path = os.path.join(case_dir, LOG_NAME)

    # load manifest
    manifest = None
    if not os.path.isfile(manifest_path):
        bad("MANIFEST_MISSING", "manifest.json is missing")
    else:
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
        except (ValueError, OSError) as e:
            bad("MANIFEST_UNREADABLE", f"manifest.json cannot be read ({e})")

    # load custody log
    entries = []
    if not os.path.isfile(log_path):
        bad("LOG_MISSING", f"{LOG_NAME} is missing")
    else:
        try:
            with open(log_path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except ValueError:
                        bad("LOG_UNREADABLE", f"log line {n} is not valid JSON")
            if not entries:
                bad("LOG_EMPTY", "custody log has no entries")
        except OSError as e:
            bad("LOG_UNREADABLE", f"{LOG_NAME} cannot be read ({e.strerror}); try running verify with sudo")
    stats["log_entries"] = len(entries)

    # check the hash chain
    head = None
    if entries:
        start_details = entries[0].get("details") if isinstance(entries[0].get("details"), dict) else {}
        if start_details.get("keyed") and not key:
            bad("KEY_REQUIRED", "this log is HMAC keyed; supply --key-file to verify the chain")
        else:
            prev = GENESIS_HASH
            for i, e in enumerate(entries):
                if e.get("seq") != i:
                    bad("CHAIN_BREAK", f"entry {i}: sequence number is {e.get('seq')}, expected {i} "
                                       "(an entry was removed or reordered)")
                    break
                if e.get("prev_hash") != prev:
                    bad("CHAIN_BREAK", f"entry {i}: prev_hash does not match the previous entry")
                    break
                body = {k: v for k, v in e.items() if k != "entry_hash"}
                if chain_hash(body, key) != e.get("entry_hash"):
                    bad("CHAIN_BREAK", f"entry {i}: content was changed (entry hash mismatch)")
                    break
                prev = e["entry_hash"]
            else:
                head = prev

        if entries[-1].get("event") != "CASE_END":
            bad("LOG_INCOMPLETE", "log does not end with CASE_END (truncated or interrupted)")

    # compare chain head with an externally stored value
    if expect_head and head is not None and head != expect_head:
        bad("HEAD_MISMATCH", "chain head differs from the value you stored separately")

    # manifest seal
    case_end = entries[-1] if entries and entries[-1].get("event") == "CASE_END" else None
    if case_end and os.path.isfile(manifest_path):
        sealed = (case_end.get("details") or {}).get("manifest_sha256")
        actual, err = safe_sha256(manifest_path)
        if err:
            bad("MANIFEST_UNREADABLE", f"manifest.json cannot be hashed ({err}); try running verify with sudo")
        elif sealed != actual:
            bad("MANIFEST_MODIFIED", "manifest.json does not match the hash sealed in the custody log")

    # artifacts
    if manifest:
        log_artifacts = {}
        for e in entries:
            if e.get("event") == "ARTIFACT" and isinstance(e.get("details"), dict):
                log_artifacts[e["details"].get("id")] = e["details"]

        listed = set()
        for a in manifest.get("artifacts", []):
            if a.get("status") != "collected":
                continue
            stats["artifacts_checked"] += 1
            rel = a.get("file", "")
            listed.add(os.path.normpath(rel))
            full = os.path.join(case_dir, rel)
            try:
                actual = sha256_file(full)
            except FileNotFoundError:
                bad("FILE_MISSING", f"artifact {a.get('id')}: {rel} is missing")
            except OSError as e:
                bad("FILE_UNREADABLE", f"artifact {a.get('id')}: {rel} cannot be read ({e.strerror}); "
                                       "try running verify with sudo")
            else:
                if actual != a.get("sha256"):
                    bad("FILE_MODIFIED", f"artifact {a.get('id')}: {rel} does not match its recorded SHA-256")
            la = log_artifacts.get(a.get("id"))
            if la is None:
                bad("LOG_MISMATCH", f"artifact {a.get('id')}: no matching custody log entry")
            elif la.get("sha256") != a.get("sha256"):
                bad("LOG_MISMATCH", f"artifact {a.get('id')}: hash differs between manifest and custody log")

        allowed = listed | {MANIFEST_NAME, LOG_NAME}
        for root, _, files in os.walk(case_dir):
            for fn in files:
                rel = os.path.normpath(os.path.relpath(os.path.join(root, fn), case_dir))
                if rel not in allowed:
                    bad("FILE_ADDED", f"{rel} is in the case folder but not in the manifest")

    return findings, head, stats


def run_verify(case_dir, key_file, expect_head):
    if not os.path.isdir(case_dir):
        print(f"error: case folder not found: {case_dir}")
        return 2
    key = load_key(key_file)
    findings, head, stats = verify_case(case_dir, key, expect_head)

    print(f"Verifying {case_dir}")
    print(f"  custody log entries : {stats['log_entries']}")
    print(f"  artifacts checked   : {stats['artifacts_checked']}")
    if head:
        print(f"  chain head          : {head}")
    print()
    for code, msg in findings:
        print(f"  [FAIL] {code}: {msg}")
    if any(code.endswith("UNREADABLE") for code, _ in findings):
        print("\nHint: evidence collected with sudo is owned by root. Run verify with sudo too.")
    if findings:
        print(f"\nRESULT: FAIL ({len(findings)} finding(s))")
        return 1
    print("RESULT: PASS (no tampering detected)")
    return 0


# --------------------------------------------------------------------- CLI

def main():
    parser = argparse.ArgumentParser(prog="traceseal", description="TraceSeal evidence collector and verifier")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="collect evidence from this host")
    c.add_argument("--case-id", required=True, help="case identifier, e.g. CASE001")
    c.add_argument("--output", default="./cases", help="folder where case folders are created")
    c.add_argument("--key-file", help="secret key file; makes the custody chain HMAC keyed")

    v = sub.add_parser("verify", help="verify a collected case folder")
    v.add_argument("--case", required=True, help="path to a case folder")
    v.add_argument("--key-file", help="key file used at collection time (if the case was keyed)")
    v.add_argument("--expect-head", help="chain head hash you stored separately")

    args = parser.parse_args()
    if args.command == "collect":
        return run_collect(args.case_id, args.output, args.key_file)
    return run_verify(args.case, args.key_file, args.expect_head)


if __name__ == "__main__":
    sys.exit(main())
