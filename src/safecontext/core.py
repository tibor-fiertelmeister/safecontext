"""Core protect and restore operations."""

from __future__ import annotations

import re
from pathlib import Path

from .detectors import detect_entities, redact_secrets
from .mapping import MappingVault
from .policy import DetectionPolicy


TOKEN_PATTERN = re.compile(r"\b[A-Z][A-Z0-9_]*_[A-F0-9]{8}\b")


def protect_text(
    text: str,
    vault: MappingVault,
    policy: DetectionPolicy | None = None,
) -> str:
    """Redact known secrets and pseudonymize detected identifiers."""
    vault.bind_policy(policy)
    protected = redact_secrets(text, policy)
    detections = [
        item for item in detect_entities(protected, policy)
        if item.action == "PSEUDONYMIZE"
    ]
    occupied: list[tuple[int, int]] = []
    for item in reversed(detections):
        if any(item.start < end and item.end > start for start, end in occupied):
            continue
        token = vault.pseudonym_for(item.kind, item.value)
        protected = protected[:item.start] + token + protected[item.end:]
        occupied.append((item.start, item.end))
    return protected


def restore_text(text: str, vault: MappingVault) -> str:
    """Restore only exact pseudonyms present in the local mapping."""
    return TOKEN_PATTERN.sub(
        lambda match: vault.reverse.get(match.group(), match.group()), text
    )


def protect_file(
    input_path: Path,
    output_path: Path,
    mapping_path: Path,
    policy: DetectionPolicy | None = None,
) -> None:
    from .validate import validate_text

    paths = {path.resolve() for path in (input_path, output_path, mapping_path)}
    if len(paths) != 3:
        raise ValueError("Input, protected output and mapping must be separate files.")
    vault = MappingVault()
    raw = input_path.read_text(encoding="utf-8")
    protected = protect_text(raw, vault, policy=policy)
    if not validate_text(protected, policy=policy, vault=vault).safe:
        raise ValueError("Privacy validation failed; protected output was not written.")
    vault.save(mapping_path)
    output_path.write_text(protected, encoding="utf-8")


def restore_file(input_path: Path, output_path: Path, mapping_path: Path) -> None:
    vault = MappingVault.load(mapping_path)
    protected = input_path.read_text(encoding="utf-8")
    restored = restore_text(protected, vault)
    output_path.write_text(restored, encoding="utf-8")
