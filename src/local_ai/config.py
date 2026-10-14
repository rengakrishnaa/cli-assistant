"""Filesystem locations and user policy. Every failure here fails closed."""

from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "local-ai"
DEFAULT_DENYLIST = ("1Password", "Bitwarden", "KeePassXC", "LastPass", "Keychain Access")
CONSENT_KEYS = (
    "cloud_ai_enabled",
    "send_personal_data_to_cloud",
    "send_confidential_data_to_cloud",
    "send_secret_data_to_cloud",
)


class SettingsError(Exception):
    """Settings are unreadable or unsafe. The CLI refuses to run."""


@dataclass(frozen=True)
class Settings:
    cloud_ai_enabled: bool = False
    send_personal_data_to_cloud: bool = False
    send_confidential_data_to_cloud: bool = False
    send_secret_data_to_cloud: bool = False
    capture_denylist_apps: tuple[str, ...] = DEFAULT_DENYLIST
    source_path: str = "<built-in defaults: cloud disabled>"


@dataclass(frozen=True)
class Paths:
    root: Path

    @property
    def vault_db(self) -> Path:
        return self.root / "vault.db"

    @property
    def memory_db(self) -> Path:
        return self.root / "memory.db"

    @property
    def settings(self) -> Path:
        return self.root / "settings.json"


def data_dir() -> Path:
    """Per-user, per-OS data directory. Override with LOCAL_AI_HOME."""
    override = os.environ.get("LOCAL_AI_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / APP_NAME


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)  # owner only; on Windows the per-user profile ACL applies
    return path


def restrict_file(path: Path) -> None:
    if os.name == "posix" and path.exists():
        os.chmod(path, 0o600)


def load_settings(path: Path | None) -> Settings:
    if path is None or not path.exists():
        return Settings()
    if os.name == "posix" and path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SettingsError(f"{path} is writable by other users; run: chmod 600 {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SettingsError(f"cannot read {path.name} ({type(exc).__name__})") from None
    if not isinstance(data, dict):
        raise SettingsError("settings must be a JSON object")
    values = {}
    for key in CONSENT_KEYS:
        value = data.get(key, False)  # missing consent = no consent
        if not isinstance(value, bool):
            raise SettingsError(f"'{key}' must be true or false")
        values[key] = value
    denylist = data.get("capture_denylist_apps", list(DEFAULT_DENYLIST))
    if not isinstance(denylist, list) or not all(isinstance(a, str) for a in denylist):
        raise SettingsError("'capture_denylist_apps' must be a list of app names")
    return Settings(**values, capture_denylist_apps=tuple(denylist), source_path=str(path))


def write_default_settings(path: Path) -> bool:
    if path.exists():
        return False
    defaults = {key: False for key in CONSENT_KEYS}
    defaults["capture_denylist_apps"] = list(DEFAULT_DENYLIST)
    path.write_text(json.dumps(defaults, indent=2) + "\n", encoding="utf-8")
    restrict_file(path)
    return True
