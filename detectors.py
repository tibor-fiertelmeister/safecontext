"""Deterministic detectors used by SafeContext."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    kind: str
    value: str
    start: int
    end: int


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("HOST", re.compile(
        r"\b(?=[A-Za-z0-9.-]*[A-Za-z])(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+(?:internal|local|lan|corp|example)\b",
        re.IGNORECASE,
    )),
)

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+"),
)


def detect_entities(text: str) -> list[Detection]:
    """Detect identifiers that should be reversibly pseudonymized."""
    detections: list[Detection] = []
    occupied: list[tuple[int, int]] = []

    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            if any(span[0] < end and span[1] > start for start, end in occupied):
                continue
            detections.append(Detection(kind, match.group(0), span[0], span[1]))
            occupied.append(span)

    return sorted(detections, key=lambda item: item.start)


def redact_secrets(text: str) -> str:
    """Irreversibly remove secret values while retaining useful context."""
    result = text
    for pattern in SECRET_PATTERNS:
        if "Authorization" in pattern.pattern:
            result = pattern.sub("Authorization: Bearer [SECRET_REDACTED]", result)
        else:
            result = pattern.sub(
                lambda match: f"{match.group(1)}=[SECRET_REDACTED]",
                result,
            )
    return result
