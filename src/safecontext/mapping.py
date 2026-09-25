"""Local pseudonym mapping management."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

from .policy import DetectionPolicy


def policy_fingerprint(policy: DetectionPolicy | None) -> str:
    rules = {
        "identifiers": [
            {"name": rule.name, "fields": list(rule.fields), "action": rule.action}
            for rule in (policy.identifiers if policy else ())
        ],
        "secrets": [
            {"name": rule.name, "fields": list(rule.fields), "action": rule.action}
            for rule in (policy.secrets if policy else ())
        ],
    }
    return hashlib.sha256(
        json.dumps(rules, sort_keys=True).encode("utf-8")
    ).hexdigest()


class MappingVault:
    """Stores reversible pseudonym mappings locally.

    The MVP stores mappings as JSON. Encryption at rest is planned but is not
    implemented in v0.1.
    """

    def __init__(self, salt: str | None = None) -> None:
        self.salt = salt or secrets.token_hex(16)
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.policy_fingerprint = policy_fingerprint(None)

    def bind_policy(self, policy: DetectionPolicy | None) -> None:
        fingerprint = policy_fingerprint(policy)
        if self.reverse and self.policy_fingerprint != fingerprint:
            raise ValueError("Cannot reuse a mapping with a different policy.")
        self.policy_fingerprint = fingerprint

    def pseudonym_for(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        if key in self.forward:
            return self.forward[key]

        counter = 0
        while True:
            digest = hashlib.sha256(
                f"{self.salt}:{key}:{counter}".encode()
            ).hexdigest()[:8].upper()
            token = f"{kind}_{digest}"
            if token not in self.reverse or self.reverse[token] == value:
                break
            counter += 1
        self.forward[key] = token
        self.reverse[token] = value
        return token

    def save(self, path: Path) -> None:
        payload = {
            "version": 1,
            "salt": self.salt,
            "mapping": self.reverse,
            "policy_fingerprint": self.policy_fingerprint,
        }
        # Create privately before publishing the path, even with a permissive umask.
        temporary_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent,
                prefix=f".{path.name}.", delete=False,
            ) as handle:
                temporary_name = handle.name
                os.chmod(temporary_name, 0o600)
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)

    @classmethod
    def load(cls, path: Path) -> "MappingVault":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("version") != 1 or not isinstance(payload.get("mapping"), dict):
            raise ValueError("Invalid SafeContext mapping file.")
        vault = cls(salt=payload["salt"])
        vault.policy_fingerprint = payload.get(
            "policy_fingerprint", policy_fingerprint(None)
        )
        vault.reverse = dict(payload["mapping"])
        vault.forward = {
            f"{token.rsplit('_', 1)[0]}:{value}": token
            for token, value in vault.reverse.items()
        }
        return vault
