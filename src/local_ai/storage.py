"""SQLite persistence: two files, two trust levels, one deletion story.

vault.db   raw events, AES-GCM encrypted; timestamps in clear for range deletes
memory.db  redacted structured memories + FTS5 index; never holds raw text
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Iterable, Iterator

from .config import restrict_file
from .crypto import Cipher
from .models import Memory, RawEvent, Sensitivity

VAULT_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    id           TEXT PRIMARY KEY,      -- keyed HMAC of the event: idempotent re-ingest
    event_type   TEXT NOT NULL,
    event_ts     INTEGER NOT NULL,      -- unix seconds UTC, clear text: deletes need no key
    ingested_at  INTEGER NOT NULL,
    key_version  INTEGER NOT NULL,      -- room for key rotation or per-period keys
    nonce        BLOB NOT NULL,
    ciphertext   BLOB NOT NULL          -- AES-GCM of app, source and content
);
CREATE INDEX IF NOT EXISTS idx_raw_event_ts ON raw_events(event_ts);
CREATE INDEX IF NOT EXISTS idx_raw_ingested_at ON raw_events(ingested_at);
"""

MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id               TEXT PRIMARY KEY,
    event_id         TEXT NOT NULL UNIQUE,  -- logical link to vault.db (no cross-file FK)
    event_ts         INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    sensitivity      TEXT NOT NULL
                     CHECK (sensitivity IN ('public', 'confidential', 'personal', 'secret')),
    tiers_json       TEXT NOT NULL,
    flags_json       TEXT NOT NULL,
    people_json      TEXT NOT NULL,
    projects_json    TEXT NOT NULL,
    topics_json      TEXT NOT NULL,
    summary          TEXT NOT NULL,         -- redacted before it reaches this table
    explanation_json TEXT NOT NULL,         -- rule names and reasons, never matched text
    extractor        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mem_event_ts ON memories(event_ts);
CREATE INDEX IF NOT EXISTS idx_mem_sensitivity ON memories(sensitivity);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    memory_id UNINDEXED, summary, people, projects, topics,
    tokenize = 'porter unicode61'
)"""

_MEMORY_ID = re.compile(r"[0-9a-f]{6,32}")


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    restrict_file(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA secure_delete=ON")  # overwrite freed pages with zeros
    return conn


def _purge_remnants(conn: sqlite3.Connection) -> None:
    """Move the WAL into the main file and truncate it so deleted rows do not linger."""
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _chunks(items: Iterable[str], size: int = 500) -> Iterator[list[str]]:
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _marks(n: int) -> str:
    return ",".join("?" * n)


class VaultStore:
    def __init__(self, path: Path, cipher: Cipher):
        self.conn = _connect(path)
        self.conn.executescript(VAULT_SCHEMA)
        self.cipher = cipher

    def put(self, event: RawEvent) -> bool:
        """Returns False when the event is already stored."""
        blob = json.dumps({"app": event.app, "source": event.source, "content": event.content})
        nonce, ciphertext = self.cipher.encrypt(blob.encode("utf-8"), aad=event.id.encode())
        with self.conn:
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO raw_events "
                "(id, event_type, event_ts, ingested_at, key_version, nonce, ciphertext) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event.id, event.type, event.event_ts, int(time.time()),
                 self.cipher.key_version, nonce, ciphertext),
            )
        return cursor.rowcount == 1

    def get(self, event_id: str) -> RawEvent | None:
        row = self.conn.execute("SELECT * FROM raw_events WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            return None
        data = json.loads(self.cipher.decrypt(row["nonce"], row["ciphertext"], aad=row["id"].encode()))
        return RawEvent(row["id"], row["event_type"], data["app"], data["source"],
                        data["content"], row["event_ts"])

    def ids_in_range(self, start: int, end: int, column: str = "event_ts") -> list[str]:
        if column not in ("event_ts", "ingested_at"):
            raise ValueError("unknown time column")
        sql = f"SELECT id FROM raw_events WHERE {column} BETWEEN ? AND ?"
        return [row[0] for row in self.conn.execute(sql, (start, end))]

    def delete_ids(self, ids: Iterable[str]) -> int:
        removed = 0
        with self.conn:
            for chunk in _chunks(ids):
                sql = f"DELETE FROM raw_events WHERE id IN ({_marks(len(chunk))})"
                removed += self.conn.execute(sql, chunk).rowcount
        _purge_remnants(self.conn)
        return removed

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]

    def close(self) -> None:
        self.conn.close()


class MemoryStore:
    def __init__(self, path: Path):
        self.conn = _connect(path)
        self.conn.executescript(MEMORY_SCHEMA)
        try:
            self.conn.execute(FTS_SCHEMA)
            self.has_fts = True
        except sqlite3.OperationalError:  # SQLite built without FTS5
            self.has_fts = False

    def put(self, m: Memory) -> None:
        with self.conn:  # row and index entry commit together
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO memories (id, event_id, event_ts, created_at, sensitivity, "
                "tiers_json, flags_json, people_json, projects_json, topics_json, summary, "
                "explanation_json, extractor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (m.id, m.event_id, m.event_ts, m.created_at, m.sensitivity.label,
                 json.dumps([t.label for t in m.tiers]), json.dumps(m.flags), json.dumps(m.people),
                 json.dumps(m.projects), json.dumps(m.topics), m.summary,
                 json.dumps(m.explanation), m.extractor),
            )
            if cursor.rowcount == 1 and self.has_fts:
                self.conn.execute(
                    "INSERT INTO memory_fts (memory_id, summary, people, projects, topics) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (m.id, m.summary, " ".join(m.people), " ".join(m.projects), " ".join(m.topics)),
                )

    def get(self, memory_id: str) -> Memory | None:
        if not _MEMORY_ID.fullmatch(memory_id):
            raise LookupError("memory id must be 6 to 32 hex characters")
        rows = self.conn.execute(
            "SELECT * FROM memories WHERE id LIKE ? LIMIT 2", (memory_id + "%",)).fetchall()
        if len(rows) > 1:
            raise LookupError("memory id prefix is ambiguous; use more characters")
        return _to_memory(rows[0]) if rows else None

    def search(self, query: str, limit: int = 5) -> list[tuple[Memory, float]]:
        terms = re.findall(r"\w+", query.lower())[:16]
        if not terms:
            return []
        if self.has_fts:
            match = " OR ".join(f'"{t}"' for t in terms)  # quoted: no FTS syntax injection
            rows = self.conn.execute(
                "SELECT m.*, -bm25(memory_fts, 0.0, 1.0, 2.0, 3.0, 2.0) AS score "
                "FROM memory_fts JOIN memories AS m ON m.id = memory_fts.memory_id "
                "WHERE memory_fts MATCH ? ORDER BY score DESC LIMIT ?",
                (match, limit),
            ).fetchall()
            return [(_to_memory(r), float(r["score"])) for r in rows]
        scored = []  # fallback: naive term counting
        for r in self.conn.execute("SELECT * FROM memories"):
            haystack = " ".join((r["summary"], r["people_json"],
                                 r["projects_json"], r["topics_json"])).lower()
            score = sum(haystack.count(t) for t in terms)
            if score:
                scored.append((_to_memory(r), float(score)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:limit]

    def delete_by_event_ids(self, event_ids: Iterable[str]) -> int:
        removed = 0
        with self.conn:
            for chunk in _chunks(event_ids):
                marks = _marks(len(chunk))
                ids = [r[0] for r in self.conn.execute(
                    f"SELECT id FROM memories WHERE event_id IN ({marks})", chunk)]
                if self.has_fts and ids:
                    self.conn.execute(
                        f"DELETE FROM memory_fts WHERE memory_id IN ({_marks(len(ids))})", ids)
                removed += self.conn.execute(
                    f"DELETE FROM memories WHERE event_id IN ({marks})", chunk).rowcount
        if removed and self.has_fts:
            with self.conn:  # rewrite index segments without deleted terms
                self.conn.execute("INSERT INTO memory_fts(memory_fts) VALUES ('optimize')")
        _purge_remnants(self.conn)
        return removed

    def count_by_tier(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT sensitivity, COUNT(*) FROM memories GROUP BY sensitivity")
        return {row[0]: row[1] for row in rows}

    def close(self) -> None:
        self.conn.close()


def _to_memory(row: sqlite3.Row) -> Memory:
    return Memory(
        id=row["id"],
        event_id=row["event_id"],
        event_ts=row["event_ts"],
        created_at=row["created_at"],
        people=tuple(json.loads(row["people_json"])),
        projects=tuple(json.loads(row["projects_json"])),
        topics=tuple(json.loads(row["topics_json"])),
        summary=row["summary"],
        sensitivity=Sensitivity.parse(row["sensitivity"]),
        tiers=tuple(Sensitivity.parse(t) for t in json.loads(row["tiers_json"])),
        flags=tuple(json.loads(row["flags_json"])),
        explanation=json.loads(row["explanation_json"]),
        extractor=row["extractor"],
    )
