TraceSeal tamper tests on kali (Linux-7.0.12+kali-amd64-x86_64-with-glibc2.42)

| Test | Tamper action | Expected | Result | Status |
|---|---|---|---|---|
| T1 | Clean case, no changes | PASS | PASS | OK |
| T2 | Modify a collected file | FILE_MODIFIED | FILE_MODIFIED | OK |
| T3 | Delete a collected file | FILE_MISSING | FILE_MISSING | OK |
| T4 | Add a file to the case folder | FILE_ADDED | FILE_ADDED | OK |
| T5 | Edit a custody log entry | CHAIN_BREAK | CHAIN_BREAK | OK |
| T6 | Delete a custody log entry | CHAIN_BREAK | CHAIN_BREAK, LOG_MISMATCH | OK |
| T7 | Edit manifest.json | MANIFEST_MODIFIED | MANIFEST_MODIFIED | OK |
| T8 | Delete the last log entry (CASE_END) | LOG_INCOMPLETE | LOG_INCOMPLETE | OK |
| T8b | Edit the recorded owner of a file in the manifest | MANIFEST_MODIFIED | MANIFEST_MODIFIED | OK |
| T9a | Forge file + manifest + whole chain (plain chain, no anchor) | PASS | PASS | OK (known limitation) |
| T9b | Same forgery, verified against the stored chain head | HEAD_MISMATCH | HEAD_MISMATCH | OK |
| T9c | Same forgery on an HMAC keyed case (attacker has no key) | CHAIN_BREAK | CHAIN_BREAK | OK |

Note: T9a is expected to pass. A plain hash chain cannot stop an attacker who rewrites
everything consistently; T9b (stored chain head) and T9c (HMAC key) are the defences.
