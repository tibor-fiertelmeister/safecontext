"""Core protect and restore operations."""

from __future__ import annotations

import re
from pathlib import Path

from .detectors import detect_entities
from .mapping import MappingVault


# These are reversible identifiers. Secrets are never placed in the vault.
PSEUDONYM_KINDS = (
    "EMAIL",
    "IP",
    "HOST",
    "CUSTOMER_ID",
    "USER_ID",
    "ACCOUNT_ID",
    "TENANT_ID",
    "SESSION_ID",
)

TOKEN_PATTERN = re.compile(
    rf"\b(?:{'|'.join(PSEUDONYM_KINDS)})_[A-F0-9]{{8}}\b"
)


def protect_text(text: str, vault: MappingVault) -> str:
    """Protect sensitive text according to each detector's requested action.

    Reversible identifiers are pseudonymized into the local mapping vault.
    Secrets are irreversibly replaced with [SECRET_REDACTED].
    """
    protected = text
    detections = detect_entities(text)

    # Replace from the end so the original character offsets stay valid.
    for detection in reversed(detections):
        if detection.action == "REDACT":
            replacement = "[SECRET_REDACTED]"
        elif detection.action == "PSEUDONYMIZE":
            replacement = vault.pseudonym_for(detection.kind, detection.value)
        else:
            # Fail closed for an unknown detector action.
            replacement = "[SENSITIVE_REDACTED]"

        protected = (
            protected[: detection.start]
            + replacement
            + protected[detection.end :]
        )

    return protected


def restore_text(text: str, vault: MappingVault) -> str:
    """Restore reversible SafeContext pseudonyms from the local mapping."""

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        return vault.reverse.get(token, token)

    return TOKEN_PATTERN.sub(replace, text)


def protect_file(input_path: Path, output_path: Path, mapping_path: Path) -> None:
    vault = MappingVault()
    raw = input_path.read_text(encoding="utf-8")
    protected = protect_text(raw, vault)
    output_path.write_text(protected, encoding="utf-8")
    vault.save(mapping_path)


def restore_file(input_path: Path, output_path: Path, mapping_path: Path) -> None:
    vault = MappingVault.load(mapping_path)
    protected = input_path.read_text(encoding="utf-8")
    restored = restore_text(protected, vault)
    output_path.write_text(restored, encoding="utf-8")
