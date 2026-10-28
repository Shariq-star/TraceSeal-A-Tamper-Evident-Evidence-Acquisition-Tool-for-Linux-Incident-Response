# Key Management for TraceSeal

TraceSeal can protect the custody log with a secret key (`--key-file`). The chain hashes then become
HMAC-SHA256, so nobody can recompute a valid chain after tampering unless they have the key
(this is test T9c). A plain chain without a key can be rewritten by someone who recomputes every hash
(test T9a), so for evidence that matters, use a key and also store the chain head separately.

## 1. Create the key
```bash
python3 traceseal.py keygen --out ~/keys/case001.key
```
- 256 bits from Python's `secrets` module, written to a file readable only by its owner (mode 600)
- Refuses to overwrite an existing file unless `--force` is given
- The key is never printed on screen
- Do not invent a key by hand. TraceSeal warns if a key is shorter than 16 bytes.

## 2. Store the key
- Keep it **outside the case folder and outside the Git repository**. `*.key` is in `.gitignore`, and
  TraceSeal warns if the key file is inside the evidence output folder.
- Keep the file at mode 600. TraceSeal warns if other users can read it (`chmod 600 <file>`).
- Keep one backup, stored **separately** from the evidence (for example an encrypted drive).

## 3. Use the key
```bash
sudo python3 traceseal.py collect --case-id CASE001 --output ./cases --key-file ~/keys/case001.key
sudo python3 traceseal.py verify --case ./cases/CASE001_<timestamp> --key-file ~/keys/case001.key
```
TraceSeal only accepts the **path** of a key file, never the key itself on the command line,
because command lines end up in shell history and in the process list.

## 4. Share the key
- The person who verifies needs the key file. Send it through a secure channel (in person, or an
  encrypted message), never by plain email or chat.
- The **chain head** is not secret. It can be emailed or written down, and `verify --expect-head`
  checks it without needing the key.

## 5. One key per case
Use a separate key for each case or investigation. If one key leaks, only that case is affected.

## 6. If the key is lost
The keyed chain can no longer be verified. The collected files can still be checked by hand against
the hashes in the manifest, but the custody log cannot be trusted without the key. Keep a backup.

## 7. If the key may have leaked
- Assume the custody chain of cases made with that key could be forged by someone who held the key.
- Rely on the separately stored chain heads (`--expect-head`), which do not depend on the key.
- If the evidence can be collected again, do so with a new key. Use new keys for all new cases.
- Write the incident down in the case notes.

## 8. Limits
- The key protects against someone who does **not** have it. Anyone who can read the key file can
  forge the chain, so do not keep the key on the machine being investigated.
- Run `verify` on a separate, trusted machine when possible.
- TraceSeal is tamper-evident, not tamper-proof: it shows that evidence changed, it does not stop the change.
