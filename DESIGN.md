# local-ai: Architecture & Design Note

## 1. Overview

local-ai ingests workstation events, encrypts the raw event, classifies it locally, redacts credential and identity values, extracts a structured memory from the redacted text, and indexes that memory for search. Every processing or query step receives a routing verdict (`local_ai`, `cloud_ai`, `blocked`) before any payload could be serialized.

Pipeline: ingest gate → vault (encrypted) → classify → redact → injection check → route → extract → memory store (FTS5) → search → route again.

## 2. Data separation & isolation

- Two SQLite files with different trust levels:
  - `vault.db`: raw events, AES-256-GCM encrypted, never read by the memory layer.
  - `memory.db`: redacted, structured memories plus the FTS5 index.
- One-way boundary: `Pipeline.process()` is the only code that sees raw text and memory fields together. The extractor receives redacted text only, so `memory.db` cannot contain a raw credential even if extraction rules are wrong.
- Why: raw logs are untrusted (attacker-controllable, may contain injected instructions) and high-value (keys, health data). Memories are the useful, low-risk product. Separate files give separate blast radii, separate deletion and retention policies, and let us later encrypt each with a different key.
- Labels are sticky: tiers detected on the raw event are stored with the memory and inherited by every later routing decision.

## 3. Storage rationale

SQLite fits a local CLI or daemon: no server process, a single file per store, ACID transactions, WAL for concurrent reads, indexed time-range queries for deletion, and FTS5 with BM25 for search, all in Python's standard library.

- Raw schema keeps `event_ts` and `ingested_at` in clear text (indexed) so range deletes need no decryption; app, source and content are encrypted together.
- Event IDs are a keyed HMAC: de-duplication without a content hash an attacker could confirm guesses against.
- Search: FTS5 BM25 with Porter stemming. Milliseconds on tens of thousands of rows and a few MB of RAM, no model download. Semantic search (a small local embedding model) is a later upgrade, fused with BM25, once CPU and disk budgets are measured.

## 4. Local encryption & key custody

- Raw events: AES-256-GCM (`cryptography` library), random 96-bit nonce per record, event ID as associated data so ciphertexts cannot be swapped between rows.
- Master key: 32 random bytes in the OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service) via `keyring`. HKDF derives separate encryption and ID keys. Plaintext or null keyring backends are refused.
- Headless or CI: `LOCAL_AI_MASTER_KEY` (base64) injected from a secret manager. Environment variables are readable by same-user processes (`/proc/<pid>/environ`), so this is a fallback, not the default.
- If no secure source exists the program stops; it never writes a key file beside the data.
- Files: data dir `0700`, files `0600`, umask `077` so SQLite's `-wal`/`-shm` files match. Windows relies on the per-user profile ACL.

OS limitations (stated honestly):

- Any process running as the same user can usually read the same keyring item: Windows Credential Manager has no per-app isolation; an unlocked Linux Secret Service collection serves any session process; macOS Keychain ACLs are per-binary, and the binary here is the Python interpreter.
- So encryption protects against other OS users, stolen disks and backups, and copied files. It does not protect against malware running as the same user, which could also keylog or read process memory. Full-disk encryption (FileVault, BitLocker, LUKS) is the recommended baseline.
- `memory.db` is not encrypted in this prototype because FTS5 needs plaintext tokens; it holds only redacted text. Production path: SQLCipher with a second keyring key.

## 5. Data lifecycle & deletion

- Targeted: `local-ai forget --last 2h` (or `--since`/`--until`, by event or ingest time). The vault's time index yields event IDs; memories and their FTS rows are deleted first, then raw rows. Derived data never outlives its source.
- Remnants: `secure_delete` zeroes freed pages; FTS `optimize` rewrites index segments; `wal_checkpoint(TRUNCATE)` empties the WAL.
- Full wipe: `local-ai wipe` deletes the keyring key first (crypto-shredding), then the data directory. On SSDs and copy-on-write filesystems (APFS, btrfs), overwritten blocks may survive, which is why raw data is encrypted: without the key it is noise.
- Next step: per-day data keys (`key_version` column) so a range delete can also crypto-shred that range; a `retention_days` setting run on a schedule.

## 6. Routing

Order: credential tripwire → caller preference → `cloud_ai_enabled` → per-tier consent → injection quarantine → `cloud_ai`. The router re-scans the exact payload and unions the result with stored labels. Only `egress.build_cloud_request()` may serialize a cloud body, and it re-verifies the verdict, a SHA-256 of the routed payload, and a final scan. Unlabelled content defaults to personal. Missing consent keys default to false.

## 7. Known limitations

- Regex rules miss novel secret formats (next: entropy scoring) and produce some false positives (accepted: false positives cost privacy nothing).
- Extractive summaries are simple; a local LLM extractor can implement the same `Extractor` protocol behind the same redaction and injection checks.
- No real cloud client: the verdict and egress gate are implemented and tested.
