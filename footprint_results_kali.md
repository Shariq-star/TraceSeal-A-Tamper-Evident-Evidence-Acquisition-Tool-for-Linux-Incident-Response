TraceSeal footprint test on kali

| Source file | atime | mtime | ctime | Content unchanged |
|---|---|---|---|---|
| /etc/passwd | same | same | same | yes |
| /etc/hosts | same | same | same | yes |
| /etc/crontab | same | same | same | yes |
| /etc/os-release | same | same | same | yes |
| /var/log/auth.log | CHANGED | same | same | yes |
| /home/shariq/.bash_history | not present | | | |
| /home/shariq/.zsh_history | same | same | same | yes |

| System measure | Before | After | Change |
|---|---|---|---|
| Running processes | 185 | 185 | +0 |
| Journal lines (this boot) | 2592 | 2592 | +0 |
| Available memory (kB) | 3308324 | 3307064 | -1260 |
| Disk used (bytes) | 32768 | 413696 | +380928 |

Evidence written by TraceSeal: 283778 bytes in 21 artifacts.
Collection window (UTC): 2026-10-30T18:24:48Z to 2026-10-30T18:24:49Z.

How to read this: mtime and file content should never change (TraceSeal only reads the
sources). atime and ctime may change depending on the mount options. Journal, process
and memory changes are the footprint of running the tool (and of sudo and the snapshot
commands themselves).
