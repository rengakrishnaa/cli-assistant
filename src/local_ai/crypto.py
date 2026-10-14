"""Key custody and authenticated encryption for the raw-event vault.

Custody order:
  1. LOCAL_AI_MASTER_KEY env var (base64, 32 bytes): CI, containers, headless Linux.
  2. The OS keyring: macOS Keychain, Windows Credential Manager, Linux Secret Service.
No usable source -> KeyUnavailable. Never a key file beside the data.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SERVICE = "local-ai"
KEY_NAME = "master-key-v1"
ENV_VAR = "LOCAL_AI_MASTER_KEY"
KEY_VERSION = 1


class KeyUnavailable(Exception):
    """No trustworthy key source. The CLI stops instead of storing plaintext."""


def _decode(value: str) -> bytes:
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except ValueError:
        raise KeyUnavailable("master key is not valid base64") from None
    if len(key) != 32:
        raise KeyUnavailable("master key must decode to exactly 32 bytes")
    return key


def _secure_keyring():
    try:
        import keyring
    except ImportError:
        raise KeyUnavailable(f"'keyring' is not installed; set {ENV_VAR} instead") from None
    backend = keyring.get_keyring()
    module, name = type(backend).__module__, type(backend).__name__
    if module.startswith(("keyring.backends.fail", "keyring.backends.null")) or "Plaintext" in name:
        raise KeyUnavailable(
            f"no secure OS keyring available ({name}); set {ENV_VAR} from a secret manager"
        )
    return keyring


class KeyManager:
    def load(self) -> bytes:
        env_value = os.environ.get(ENV_VAR)
        if env_value:
            return _decode(env_value)
        keyring = _secure_keyring()
        try:
            stored = keyring.get_password(SERVICE, KEY_NAME)
        except Exception as exc:  # backend errors, e.g. a locked keychain
            raise KeyUnavailable(f"OS keyring read failed ({type(exc).__name__})") from None
        if not stored:
            raise KeyUnavailable("no master key yet; run `local-ai init`")
        return _decode(stored)

    def create(self) -> str:
        if os.environ.get(ENV_VAR):
            self.load()  # validates the format
            return f"environment variable {ENV_VAR} (managed outside local-ai)"
        keyring = _secure_keyring()
        try:
            if keyring.get_password(SERVICE, KEY_NAME):
                return "OS keyring (existing key kept)"
            keyring.set_password(SERVICE, KEY_NAME, base64.b64encode(os.urandom(32)).decode())
        except Exception as exc:
            raise KeyUnavailable(
                f"OS keyring write failed ({type(exc).__name__}); set {ENV_VAR}"
            ) from None
        return "OS keyring"

    def destroy(self) -> str:
        """Crypto-shredding: without the key, every vault ciphertext is unreadable."""
        if os.environ.get(ENV_VAR):
            return f"key lives in {ENV_VAR}; delete it from your secret manager"
        try:
            _secure_keyring().delete_password(SERVICE, KEY_NAME)
        except Exception as exc:
            return f"no key deleted ({type(exc).__name__})"
        return "key deleted from OS keyring"


class Cipher:
    """AES-256-GCM with HKDF-separated subkeys: one to encrypt, one to derive event IDs."""

    def __init__(self, master_key: bytes):
        self.key_version = KEY_VERSION
        self._aead = AESGCM(self._derive(master_key, b"local-ai/vault/v1"))
        self._id_key = self._derive(master_key, b"local-ai/event-id/v1")

    @staticmethod
    def _derive(master: bytes, label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(master)

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)  # random 96-bit nonce per record
        return nonce, self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self._aead.decrypt(nonce, ciphertext, aad)  # raises InvalidTag if tampered

    def event_id(self, *parts: str) -> str:
        """Keyed hash: stable for de-duplication, reveals nothing without the key."""
        message = "\x1f".join(parts).encode("utf-8")
        return hmac.new(self._id_key, message, hashlib.sha256).hexdigest()[:32]
