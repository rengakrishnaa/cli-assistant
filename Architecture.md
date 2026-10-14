# Architecture

local-ai is a privacy-first local memory CLI. Raw workstation events are untrusted: they are gated, encrypted in `vault.db`, classified locally, redacted, then turned into searchable memories in `memory.db`. Only redacted text ever leaves the vault layer.

```
ingest gate → vault (AES-256-GCM) → classify → redact
    → injection check → route → extract → memory.db (FTS5)
    → search → route again
```

Three trust zones:

1. **Untrusted input** — clipboard, shell, browser, chat. Validated in `ingest.py`; denylisted/concealed items never hit disk.
2. **Encrypted raw store** — `vault.db` only. Key in the OS keyring (or `LOCAL_AI_MASTER_KEY`). Memory code cannot read it.
3. **Derived memory** — redacted fields + BM25 index. Router + `egress.py` are the only path a payload could take toward a cloud model.

Fail closed: unmatched text is `personal`; missing consent is no; no secure key store stops the process.

See [DESIGN.md](DESIGN.md) for data separation, storage, encryption, deletion and routing, and [THREAT_MODEL.md](THREAT_MODEL.md) for the five threats this design answers.
