TraceSeal footprint test on kali

| Source file | atime | mtime | ctime | Content unchanged |
|---|---|---|---|---|
| /etc/passwd | same | same | same | yes |
| /etc/hosts | same | same | same | yes |
| /etc/crontab | same | same | same | yes |
| /etc/os-release | same | same | same | yes |
| /var/log/auth.log | not present | | | |
| /home/shariq/.bash_history | not present | | | |
| /home/shariq/.zsh_history | same | same | same | yes |

| System measure | Before | After | Change |
|---|---|---|---|
| Running processes | 179 | 179 | +0 |
| Journal lines (this boot) | 4136 | 4136 | +0 |
| Available memory (kB) | 3414552 | 3405932 | -8620 |
| Disk used (bytes) | 8192 | 335872 | +327680 |

Evidence written by TraceSeal: 241124 bytes in 20 artifacts.
Collection window (UTC): 2026-10-13T12:04:48Z to 2026-10-13T12:04:48Z.

How to read this: mtime and file content should never change (TraceSeal only reads the
sources). atime and ctime may change depending on the mount options. Journal, process
and memory changes are the footprint of running the tool (and of sudo and the snapshot
commands themselves).
