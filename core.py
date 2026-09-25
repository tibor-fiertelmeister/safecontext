"""Core protect and restore operations."""

from __future__ import annotations

import re
from pathlib import Path

from .detectors import detect_entities, redact_secrets
from .mapping import MappingVault


TOKEN_PATTERN = re.compile(r"\b(?:EMAIL|IP|HOST)_[A-F0-9]{8}\b")


def protect_text(text: str, vault: MappingVault) -> str:
    """Redact secrets, then pseudonymize reversible identifiers."""
    protected = redact_secrets(text)
    detections = detect_entities(protected)

    for detection in reversed(detections):
        token = vault.pseudonym_for(detection.kind, detection.value)
        protected = protected[:detection.start] + token + protected[detection.end:]

    return protected


def restore_text(text: str, vault: MappingVault) -> str:
    """Restore exact SafeContext pseudonyms from the local mapping."""
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
