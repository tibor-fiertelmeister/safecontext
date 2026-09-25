"""Local pseudonym mapping management."""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path


class MappingVault:
    """Stores reversible pseudonym mappings locally.

    The MVP stores mappings as JSON. Encryption at rest is planned but is not
    implemented in v0.1.
    """

    def __init__(self, salt: str | None = None) -> None:
        self.salt = salt or secrets.token_hex(16)
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}

    def pseudonym_for(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        if key in self.forward:
            return self.forward[key]

        digest = hashlib.sha256(f"{self.salt}:{key}".encode()).hexdigest()[:8].upper()
        token = f"{kind}_{digest}"
        self.forward[key] = token
        self.reverse[token] = value
        return token

    def save(self, path: Path) -> None:
        payload = {
            "version": 1,
            "salt": self.salt,
            "mapping": self.reverse,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "MappingVault":
        payload = json.loads(path.read_text(encoding="utf-8"))
        vault = cls(salt=payload["salt"])
        vault.reverse = dict(payload["mapping"])
        vault.forward = {
            f"{token.split('_', 1)[0]}:{value}": token
            for token, value in vault.reverse.items()
        }
        return vault
