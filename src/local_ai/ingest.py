"""Untrusted input boundary: validate, normalize and apply capture policy BEFORE storage."""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import Settings
from .models import RawEvent

EVENT_TYPES = frozenset({"transcript", "note", "browser_metadata", "shell_history", "clipboard"})
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_CONTENT_CHARS = 20_000
# ASCII control chars (except tab/newline), zero-width chars and bidi overrides
_INVISIBLE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)


class EventFileError(Exception):
    """The whole file is unusable."""


class EventError(ValueError):
    """One event is invalid. Messages never include field values."""


def load_event_file(path: Path) -> list:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EventFileError("event file is larger than 10 MB")
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise EventFileError(f"file not found: {path.name}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventFileError(f"cannot parse {path.name} as UTF-8 JSON ({type(exc).__name__})") from None
    if not isinstance(data, list):
        raise EventFileError("event file must contain a JSON array")
    return data


def _clean(text: str) -> str:
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


def _parse_timestamp(value: str) -> int:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EventError("timestamp is not ISO-8601") from None
    if moment.tzinfo is None:
        raise EventError("timestamp must include a timezone")
    return int(moment.timestamp())


def parse_event(item: object, make_id: Callable[..., str]) -> RawEvent:
    if not isinstance(item, dict):
        raise EventError("event is not a JSON object")
    event_type = item.get("type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise EventError("unsupported event type")
    for name in ("app", "source", "content", "timestamp"):
        value = item.get(name)
        if not isinstance(value, str) or not value.strip():
            raise EventError(f"field '{name}' must be a non-empty string")
    content = _clean(item["content"])
    if len(content) > MAX_CONTENT_CHARS:
        raise EventError("content exceeds 20,000 characters")
    app, source = _clean(item["app"])[:100], _clean(item["source"])[:200]
    event_ts = _parse_timestamp(item["timestamp"])
    return RawEvent(
        id=make_id(event_type, app, source, str(event_ts), content),
        type=event_type,
        app=app,
        source=source,
        content=content,
        event_ts=event_ts,
        concealed=item.get("concealed") is True,
    )


def capture_allowed(event: RawEvent, settings: Settings) -> tuple[bool, str]:
    """Runs BEFORE storage: a dropped event leaves no trace but a counter."""
    if event.concealed:
        return False, "source marked the item as concealed"
    if event.app.casefold() in {app.casefold() for app in settings.capture_denylist_apps}:
        return False, "app is on the capture denylist"
    if event.type == "shell_history" and event.content.startswith(" "):
        return False, "shell command starts with a space (ignorespace convention)"
    return True, ""
