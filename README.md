# TraceSeal

**A Tamper-Evident Evidence Acquisition Tool for Linux Incident Response**

Built for the CyberFox Society Cybersecurity R&D Internship (October 2026). Current version: 0.3.

## Problem
During incident response, evidence is often collected by hand and in no fixed order. Volatile data (running processes, network connections) is easy to lose, and once evidence is copied there is usually nothing to prove it was not changed later. Many existing tools only run on Windows, need a license or a larger setup, or focus on collecting files without a tamper-evident record of custody.

TraceSeal is a small command-line tool for Linux. It collects evidence in order of volatility, hashes every artifact, records who owned each file, keeps a hash-chained chain-of-custody log, and can verify a case folder later to detect tampering.

## Existing tools reviewed
| Tool | Limitation for this project (from public documentation) |
|---|---|
| KAPE | Windows only, not open source, registration and licensing requirements |
| CyLR | Documentation describes NTFS hosts; no tamper-evident custody log found in the documentation |
| Velociraptor | Full platform with server/client setup and its own query language (VQL) |

## Features
- **Collection in order of volatility:** date and uptime, ARP neighbours, IP addresses and routes, sockets, processes, logged-in users, login sessions, mounts and kernel modules, then `journalctl` and `dmesg`, then selected files (`/etc/passwd`, `/etc/hosts`, `/etc/crontab`, `/etc/os-release`, `/var/log/auth.log`, and the user's bash and zsh history)
- **SHA-256 hashing** of every artifact (read in chunks); files are hashed before and after copying
- **manifest.json** with a hash and UTC timestamp for every artifact, and a reason for anything skipped
- **Ownership metadata:** for every collected file the manifest records the original owner, group, mode and the access, modification and change times, read before the file is opened. `--preserve-owner` (root only) also gives the copy the original owner and group
- **Hash-chained custody log** (`custody_log.jsonl`): every entry contains the hash of the previous entry, and the last entry seals the SHA-256 of the manifest
- **`verify` command** that detects modified, missing and added files, a broken or truncated log, and an edited manifest
- **Key management:** `--key-file` makes the chain HMAC-SHA256 keyed, `keygen` creates a 256-bit key with mode 600, and warnings appear for keys that are too short, readable by other users, or inside the output folder (see [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md))
- **Chain head check:** `--expect-head` compares the chain head with a value stored outside the case folder
- **Runs without root:** missing commands, commands that cannot be run and unreadable files are skipped and recorded, and commands that exit with an error are listed at the end of the run

## Requirements
- Linux and Python 3 (standard library only, no extra packages)
- `sudo` for complete collection. Cases collected with sudo are owned by root, so `verify` on them also needs `sudo`

## Usage
```bash
git clone https://github.com/Shariq-star/TraceSeal-A-Tamper-Evident-Evidence-Acquisition-Tool-for-Linux-Incident-Response TraceSeal
cd TraceSeal

# collect
sudo python3 traceseal.py collect --case-id CASE001 --output ./cases

# verify
sudo python3 traceseal.py verify --case ./cases/CASE001_<timestamp>

# collect without root (into a folder you own)
python3 traceseal.py collect --case-id CASE001 --output ./cases_nonroot

# keep the original owner and group on the copies (root only)
sudo python3 traceseal.py collect --case-id CASE001 --output ./cases --preserve-owner

# keyed chain
python3 traceseal.py keygen --out ~/keys/traceseal.key
sudo python3 traceseal.py collect --case-id CASE001 --output ./cases --key-file ~/keys/traceseal.key
sudo python3 traceseal.py verify --case ./cases/CASE001_<timestamp> --key-file ~/keys/traceseal.key

# compare with a chain head you stored separately
sudo python3 traceseal.py verify --case ./cases/CASE001_<timestamp> --expect-head <chain_head>
```
Each run creates a new case folder and never overwrites an old one:
```
cases/CASE001_<timestamp>/
├── volatile/          command output (processes, network, users, ...)
├── logs/              journalctl and dmesg output
├── files/             copied system files
├── manifest.json      artifacts with SHA-256, UTC timestamps and source metadata
└── custody_log.jsonl  hash-chained custody log
```
The chain head printed at the end of `collect` should be stored somewhere separate (for example in an email). Keep key files out of the repository. If a case folder name matches more than one folder, use the full folder name.

## What verify reports
`CHAIN_BREAK`, `FILE_MODIFIED`, `FILE_MISSING`, `FILE_ADDED`, `MANIFEST_MODIFIED`, `LOG_INCOMPLETE`, `LOG_MISMATCH`, `FILE_UNREADABLE`, `KEY_REQUIRED`, `HEAD_MISMATCH`. The result is `PASS` only when nothing is found.

## Testing
- `tamper_tests.py` runs 12 tamper scenarios on a copy of a fresh case: clean case, modified file, deleted file, added file, edited log entry, deleted log entry, edited manifest, truncated log, edited ownership record, and a full chain rewrite (plain chain, with a stored chain head, and with an HMAC key)
- `footprint_test.py` takes a snapshot before and after a collection and reports which file times, processes, journal lines, memory and disk use changed
- `compare_runs.py` compares two case folders, for example a root run and a non-root run

Results (see `tamper_results_*.md` and `footprint_results_*.md`):

| Check | Kali Linux | Ubuntu Server 26.04 LTS |
|---|---|---|
| Tamper tests | 12 of 12 as expected | 12 of 12 as expected |
| Artifacts collected as root | 21 of 23 | 21 of 23 |
| Artifacts collected without root | 21 of 23 | 20 of 23 (`dmesg` exited with an error) |
| `verify` on the non-root case | PASS | PASS |
| Source files after collection | content, mtime and ctime unchanged | content, mtime and ctime unchanged |
| Access time after collection | changed for `auth.log` only | changed for `auth.log` only |

A plain hash chain cannot stop someone who rewrites every hash (test T9a passes by design). The stored chain head (T9b) and the HMAC key (T9c) are the defences.

## Limitations
- By default the copies are owned by root. `--preserve-owner` gives them the original owner, which lets that account change its copy (`verify` would still detect it)
- A plain hash chain needs the chain head or the HMAC key to be kept outside the case folder
- Tested on two virtual machines (Kali Linux and Ubuntu Server 26.04 LTS)
- The footprint measurement is coarse and its own commands leave traces
- Linux only, no memory acquisition, no GUI

## Roadmap
- [x] Week 1: Problem definition, research, design
- [x] Week 2: Core collector and manifest generation
- [x] Week 3: Custody log, verify command, tamper tests, footprint test, second environment
- [x] Week 4: Ownership metadata, testing without root, key management, final validation and documentation

## Legal and Ethical Notice
Use this tool only on systems you own or have explicit authorization to examine. All testing for this project was done in personal VM labs.

## Author
Shariq
