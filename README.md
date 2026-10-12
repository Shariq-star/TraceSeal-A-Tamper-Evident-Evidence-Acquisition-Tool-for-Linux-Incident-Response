# TraceSeal

**A Tamper-Evident Evidence Acquisition Tool for Linux Incident Response**

> Status: Work in progress. Built for the CyberFox Society Cybersecurity R&D Internship (October 2026).

## Problem
During incident response, evidence is often collected by hand and in no fixed order. Volatile data (running processes, network connections) is easy to lose, and once evidence is copied there is usually nothing to prove it was not changed later. Many existing tools only run on Windows, need a license or a larger setup, or focus on collecting files without a tamper-evident record of custody.

TraceSeal aims to be a small command-line tool for Linux that collects evidence in order of volatility, hashes every artifact, and (in progress) keeps a hash-chained chain-of-custody log that can be verified later.

## Existing tools reviewed
| Tool | Limitation for this project (from public documentation) |
|---|---|
| KAPE | Windows only, not open source, registration and licensing requirements |
| CyLR | Documentation describes NTFS hosts; no tamper-evident custody log found in the documentation |
| Velociraptor | Full platform with server/client setup and its own query language (VQL) |

## Current features (Week 2)
- Collects volatile data first: date/uptime, ARP neighbors, IP addresses and routes, sockets, processes, logged-in users, recent logins, mounts, kernel modules
- Collects logs from `journalctl` and `dmesg`
- Copies a small list of system files (for example `/etc/passwd`, `/etc/hosts`) and the user's `.bash_history`
- Hashes each copied file before and after copying and records whether the copy matched
- Records a SHA-256 hash, size and UTC timestamp for every artifact in `manifest.json`
- Skips missing commands or files without crashing and records the reason in the manifest

## Planned
- Hash-chained chain-of-custody log (each entry contains the hash of the previous entry)
- `verify` mode to detect modified, deleted or added evidence and broken log entries
- Summary report

## Requirements
- Linux (developed and tested on Kali Linux in a VM)
- Python 3, standard library only (no extra packages)
- Root privileges (`sudo`) for complete collection

## Usage
```bash
git clone <this-repository-url> TraceSeal
cd TraceSeal
sudo python3 traceseal.py collect --case-id CASE001 --output ./cases
```

Each run creates a new case folder. Existing cases are never overwritten.

```
cases/CASE001_<timestamp>/
├── volatile/        command output (processes, network, users, ...)
├── logs/            journalctl and dmesg output
├── files/           copied system files
└── manifest.json    list of all artifacts with SHA-256 and UTC timestamps
```

Example manifest entry:
```json
{
  "id": 1,
  "type": "volatile",
  "source": "date -u",
  "collected_utc": "2026-10-13T10:34:59Z",
  "status": "collected",
  "file": "volatile/date_utc.txt",
  "exit_code": 0,
  "size": 29,
  "sha256": "..."
}
```

## Limitations
- The manifest is hashed but not yet tamper-evident; the custody log and verify mode are planned for Week 3
- Some data is incomplete or skipped when not run as root
- Linux only, no memory acquisition, no GUI

## Roadmap
- [x] Week 1: Problem definition, research, design
- [x] Week 2: Core collector and manifest generation
- [ ] Week 3: Hash-chained custody log, verify mode, testing
- [ ] Week 4: Final testing, documentation, report

## Legal and Ethical Notice
Use this tool only on systems you own or have explicit authorization to examine. All testing for this project is done in a personal VM lab.

## Author
Shariq
