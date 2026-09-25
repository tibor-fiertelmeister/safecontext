"""Core protect and restore operations."""

from __future__ import annotations

import re
from pathlib import Path

from .detectors import detect_entities, redact_secrets
from .mapping import MappingVault
from .policy import DetectionPolicy, build_context_pattern, build_secret_pattern


TOKEN_PATTERN = re.compile(r"\b[A-Z][A-Z0-9_]*_[A-F0-9]{8}\b")


def _redact_policy_secrets(
    text: str,
    policy: DetectionPolicy | None,
) -> str:
    """Redact secrets defined by a custom policy."""

    if policy is None:
        return text

    result = text

    for rule in policy.secrets:
        pattern = build_secret_pattern(rule.fields)

        def replace(match: re.Match[str]) -> str:
            full = match.group(0)
            value_start = match.start(2) - match.start()
            return full[:value_start] + "[SECRET_REDACTED]"

        result = pattern.sub(replace, result)

    return result


def _detect_policy_identifiers(
    text: str,
    policy: DetectionPolicy | None,
) -> list[tuple[str, str, int, int]]:
    """Detect custom identifiers defined by a policy."""

    if policy is None:
        return []

    detections: list[tuple[str, str, int, int]] = []

    for rule in policy.identifiers:
        pattern = build_context_pattern(rule.fields)

        for match in pattern.finditer(text):
            start, end = match.span(1)
            detections.append((rule.name, match.group(1), start, end))

    return sorted(detections, key=lambda item: item[2])


def protect_text(
    text: str,
    vault: MappingVault,
    policy: DetectionPolicy | None = None,
) -> str:
    """Redact secrets and pseudonymize sensitive identifiers."""

    protected = redact_secrets(text)
    protected = _redact_policy_secrets(protected, policy)

    replacements: list[tuple[str, str, int, int]] = []

    for detection in detect_entities(protected):
        if detection.action != "PSEUDONYMIZE":
            continue
        replacements.append(
            (
                detection.kind,
                detection.value,
                detection.start,
                detection.end,
            )
        )

    replacements.extend(_detect_policy_identifiers(protected, policy))
    replacements.sort(key=lambda item: item[2], reverse=True)

    occupied: list[tuple[int, int]] = []

    for kind, value, start, end in replacements:
        if any(
            start < existing_end and end > existing_start
            for existing_start, existing_end in occupied
        ):
            continue

        token = vault.pseudonym_for(kind, value)
        protected = protected[:start] + token + protected[end:]
        occupied.append((start, end))

    return protected


def restore_text(text: str, vault: MappingVault) -> str:
    """Restore exact SafeContext pseudonyms from the local mapping."""

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        return vault.reverse.get(token, token)

    return TOKEN_PATTERN.sub(replace, text)


def protect_file(
    input_path: Path,
    output_path: Path,
    mapping_path: Path,
    policy: DetectionPolicy | None = None,
) -> None:
    vault = MappingVault()
    raw = input_path.read_text(encoding="utf-8")
    protected = protect_text(raw, vault, policy=policy)
    output_path.write_text(protected, encoding="utf-8")
    vault.save(mapping_path)


def restore_file(
    input_path: Path,
    output_path: Path,
    mapping_path: Path,
) -> None:
    vault = MappingVault.load(mapping_path)
    protected = input_path.read_text(encoding="utf-8")
    restored = restore_text(protected, vault)
    output_path.write_text(restored, encoding="utf-8")
