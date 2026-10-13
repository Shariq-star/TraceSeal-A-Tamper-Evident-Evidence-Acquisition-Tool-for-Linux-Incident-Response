#!/usr/bin/env python3
"""
tamper_tests.py: runs TraceSeal against a set of tampering scenarios and
prints a results table you can paste into your report.

Run it from the same folder as traceseal.py, ideally with sudo:
    sudo python3 tamper_tests.py
It never touches your real cases: everything happens in a temporary folder.
"""

import glob
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import traceseal as ts  # noqa: E402


def collect_case(workdir, case_id, key_file=None):
    cmd = [sys.executable, os.path.join(HERE, "traceseal.py"), "collect",
           "--case-id", case_id, "--output", workdir]
    if key_file:
        cmd += ["--key-file", key_file]
    subprocess.run(cmd, capture_output=True, text=True, check=True)
    return glob.glob(os.path.join(workdir, case_id + "_*"))[0]


def load_manifest(case):
    with open(os.path.join(case, ts.MANIFEST_NAME), encoding="utf-8") as f:
        return json.load(f)


def first_volatile_file(case):
    for a in load_manifest(case)["artifacts"]:
        if a["status"] == "collected" and a["type"] == "volatile":
            return a["file"]
    raise RuntimeError("no volatile artifact found")


def read_log(case):
    with open(os.path.join(case, ts.LOG_NAME), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_log(case, entries):
    with open(os.path.join(case, ts.LOG_NAME), "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, sort_keys=True) + "\n")


# ------------------------------------------------------------ tamper actions

def t_modify_file(case):
    with open(os.path.join(case, first_volatile_file(case)), "a") as f:
        f.write("X")


def t_delete_file(case):
    os.remove(os.path.join(case, first_volatile_file(case)))


def t_add_file(case):
    with open(os.path.join(case, "volatile", "planted_evidence.txt"), "w") as f:
        f.write("planted")


def t_edit_log_entry(case):
    entries = read_log(case)
    entries[3]["details"]["source"] = "edited command"
    write_log(case, entries)


def t_delete_log_entry(case):
    entries = read_log(case)
    del entries[3]
    write_log(case, entries)


def t_truncate_log(case):
    entries = read_log(case)
    write_log(case, entries[:-1])


def t_edit_manifest(case):
    path = os.path.join(case, ts.MANIFEST_NAME)
    m = load_manifest(case)
    m["hostname"] = "someone-else"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)


def t_forge_chain(case):
    """Attacker edits a file and rewrites manifest, log entries and chain
    consistently, WITHOUT knowing any secret key."""
    rel = first_volatile_file(case)
    full = os.path.join(case, rel)
    with open(full, "a") as f:
        f.write("\nforged line")
    new_sha = ts.sha256_file(full)
    new_size = os.path.getsize(full)

    mpath = os.path.join(case, ts.MANIFEST_NAME)
    m = load_manifest(case)
    art_id = None
    for a in m["artifacts"]:
        if a.get("file") == rel:
            a["sha256"], a["size"] = new_sha, new_size
            art_id = a["id"]
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
    new_manifest_sha = ts.sha256_file(mpath)

    entries = read_log(case)
    for e in entries:
        if e["event"] == "ARTIFACT" and e["details"]["id"] == art_id:
            e["details"]["sha256"] = new_sha
        if e["event"] == "CASE_END":
            e["details"]["manifest_sha256"] = new_manifest_sha
    prev = ts.GENESIS_HASH
    for e in entries:
        e["prev_hash"] = prev
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        e["entry_hash"] = ts.chain_hash(body, None)  # attacker has no key
        prev = e["entry_hash"]
    write_log(case, entries)


# ------------------------------------------------------------------ runner

def main():
    workdir = tempfile.mkdtemp(prefix="traceseal_tests_")
    keyfile = os.path.join(workdir, "test.key")
    with open(keyfile, "wb") as f:
        f.write(b"correct-horse-battery-staple")

    print("Collecting a plain case and a keyed case (a few seconds)...")
    plain = collect_case(workdir, "PLAIN")
    keyed = collect_case(workdir, "KEYED", keyfile)
    plain_head = ts.verify_case(plain)[1]
    key = ts.load_key(keyfile)

    # (id, description, case, action, expected, verify kwargs)
    tests = [
        ("T1", "Clean case, no changes", plain, None, "PASS", {}),
        ("T2", "Modify a collected file", plain, t_modify_file, "FILE_MODIFIED", {}),
        ("T3", "Delete a collected file", plain, t_delete_file, "FILE_MISSING", {}),
        ("T4", "Add a file to the case folder", plain, t_add_file, "FILE_ADDED", {}),
        ("T5", "Edit a custody log entry", plain, t_edit_log_entry, "CHAIN_BREAK", {}),
        ("T6", "Delete a custody log entry", plain, t_delete_log_entry, "CHAIN_BREAK", {}),
        ("T7", "Edit manifest.json", plain, t_edit_manifest, "MANIFEST_MODIFIED", {}),
        ("T8", "Delete the last log entry (CASE_END)", plain, t_truncate_log, "LOG_INCOMPLETE", {}),
        ("T9a", "Forge file + manifest + whole chain (plain chain, no anchor)",
         plain, t_forge_chain, "PASS", {}),
        ("T9b", "Same forgery, verified against the stored chain head",
         plain, t_forge_chain, "HEAD_MISMATCH", {"expect_head": plain_head}),
        ("T9c", "Same forgery on an HMAC keyed case (attacker has no key)",
         keyed, t_forge_chain, "CHAIN_BREAK", {"key": key}),
    ]

    rows, all_ok = [], True
    for tid, desc, case, action, expected, kwargs in tests:
        work = os.path.join(workdir, "work_" + tid)
        shutil.copytree(case, work)
        if action:
            action(work)
        kw = dict(kwargs)
        if case == keyed and "key" not in kw:
            kw["key"] = key
        findings, _, _ = ts.verify_case(work, **kw)
        codes = sorted({c for c, _ in findings})
        detected = bool(findings)
        got = ", ".join(codes) if codes else "PASS"
        ok = (expected == "PASS" and not detected) or (expected != "PASS" and expected in codes)
        all_ok = all_ok and ok
        status = "OK" if ok else "UNEXPECTED"
        if tid == "T9a" and ok:
            status = "OK (known limitation)"
        rows.append((tid, desc, expected, got, status))

    host = socket.gethostname()
    lines = [
        f"TraceSeal tamper tests on {host} ({platform.platform()})",
        "",
        "| Test | Tamper action | Expected | Result | Status |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    lines += [
        "",
        "Note: T9a is expected to pass. A plain hash chain cannot stop an attacker who rewrites",
        "everything consistently; T9b (stored chain head) and T9c (HMAC key) are the defences.",
    ]
    report = "\n".join(lines)
    print("\n" + report)

    out_file = os.path.join(os.getcwd(), f"tamper_results_{host}.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\nSaved: {out_file}")

    shutil.rmtree(workdir, ignore_errors=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
