# local-ai

A privacy-first local memory CLI: ingest workstation events, keep raw data encrypted, extract redacted memories, search them, and get an explicit local/cloud/blocked routing verdict for every action. Python 3.10+, two dependencies (`cryptography`, `keyring`).

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e .
local-ai init                        # creates data dir, master key (OS keyring), settings
chmod 600 settings.example.json      # macOS/Linux: settings writable by others are refused
local-ai ingest mock_events.json --settings settings.example.json
local-ai search "Stripe pricing" --settings settings.example.json --reveal
```

No OS keyring (headless Linux, CI, containers)? Provide the key from a secret manager:

```bash
export LOCAL_AI_MASTER_KEY="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
```

## All commands

| Command | What it does |
|---|---|
| `local-ai init` | Create data dir (`0700`), master key, default settings (cloud off) |
| `local-ai ingest FILE` | Validate, capture-filter, encrypt, classify, redact, route, extract |
| `local-ai search "QUERY" [--reveal] [--prefer cloud]` | BM25 search + routing verdict for answering |
| `local-ai inspect ID [--reveal]` | One memory with its classification explanation |
| `local-ai route --memory ID` / `--stdin` | Routing verdict for a memory or for piped text |
| `local-ai forget --last 2h` / `--since T [--until T] [--by ingested]` | Targeted deletion from both stores |
| `local-ai wipe [--yes]` | Destroy the key (crypto-shred), delete all data |
| `local-ai stats` | Counts by tier, no content |

Add `--json` to any command for machine-readable output. Use `--home DIR` or `LOCAL_AI_HOME` to choose the data directory.

## Demo script

```bash
S="--settings settings.example.json"
local-ai ingest mock_events.json $S          # 7 received, 6 stored, 1 dropped (1Password)
local-ai ingest mock_events.json $S          # 6 duplicates: idempotent
local-ai search "Stripe pricing" $S          # secret memory hidden; verdict local_ai
local-ai search "CORS fetch" $S              # public memory; verdict cloud_ai
local-ai search "CORS fetch" $S --prefer local
echo "my key is sk_test_localaidemokey01" | local-ai route --stdin $S
local-ai search "patient" $S --prefer cloud  # blocked: personal data, cloud demanded
local-ai forget --since 2026-05-19T10:00:00Z --until 2026-05-19T11:00:00Z
local-ai stats
```

Recorded on macOS (Python 3.12), 12 Oct 2026. Flags go on the subcommand (`local-ai ingest FILE --settings ...`), not before it.

```
$ local-ai ingest mock_events.json --settings settings.example.json
received 7 | stored 6 | duplicates 0 | dropped by capture policy 1 | invalid 0
  df1bd093  transcript       secret       extract -> local_ai
  279c5d0e  note             confidential extract -> local_ai
  ebd70c21  browser_metadata personal     extract -> local_ai
  988b7d94  shell_history    secret       extract -> local_ai
  93a6436f  note             public       extract -> local_ai  flags=prompt_injection_suspected
  8bda0f7f  browser_metadata public       extract -> cloud_ai

$ local-ai ingest mock_events.json --settings settings.example.json
received 7 | stored 0 | duplicates 6 | dropped by capture policy 1 | invalid 0

$ local-ai search "Stripe pricing" --settings settings.example.json
1. [secret] 2026-05-19T10:30:00Z  ...  [hidden: secret memory; add --reveal to show]
   route: local_ai  (cloud not permitted for: secret, confidential)

$ local-ai search "CORS fetch" --settings settings.example.json
1. [public] ... Read the MDN documentation on the Fetch API and CORS preflight requests.
   route: cloud_ai

$ echo "my key is sk_test_localaidemokey01" | local-ai route --stdin --settings settings.example.json
{"route": "local_ai", "effective_sensitivity": "secret", ...}  # key redacted before routing

$ local-ai search "patient" --settings settings.example.json --prefer cloud
{"route": "blocked", "reason": "cloud was requested but is not permitted for: personal, confidential"}

$ local-ai forget --since 2026-05-19T10:00:00Z --until 2026-05-19T11:00:00Z
forgot 1 memories and 1 raw events

$ local-ai stats
{"raw_events": 5, "memories_by_tier": {"confidential": 1, "personal": 1, "public": 2, "secret": 1}}
```

Event IDs and scores change per install (keyed HMAC + BM25). Counts and routes should match.

Expected ingest verdicts with `settings.example.json`:

| Event | Tier | Extract route | Why |
|---|---|---|---|
| Slack, Stripe key | secret | `local_ai` | Key redacted; credential context remains, secret consent is false |
| Obsidian, Q2 roadmap | confidential | `local_ai` | Confidential consent is false |
| Chrome, patient portal | personal (+ confidential) | `local_ai` | Record ID redacted; health context remains |
| zsh, AWS export | secret | `local_ai` | Value redacted from the memory, original encrypted in the vault |
| 1Password clipboard | (dropped) | none | Denylisted app; never stored |
| Obsidian, injection note | public, flagged | `local_ai` | Quarantined from cloud |
| Firefox, MDN page | public | `cloud_ai` | Only tier present is public and cloud is enabled |

## Tests

```bash
python -m unittest discover -s tests -v
```

## Documents

- [DESIGN.md](DESIGN.md): data separation, storage, encryption and key custody, deletion
- [THREAT_MODEL.md](THREAT_MODEL.md): five threats with risks and mitigations
- [Architecture.md](Architecture.md): short data-flow overview
