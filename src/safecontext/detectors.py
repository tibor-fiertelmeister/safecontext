"""Deterministic detectors used by the SafeContext MVP."""

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
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "IP",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
    ),
    (
        "HOST",
        re.compile(
            r"\b(?=[A-Za-z0-9.-]*[A-Za-z])"
            r"(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+"
            r"(?:internal|local|lan|corp|example)\b",
            re.IGNORECASE,
        ),
    ),
)

# Deliberately conservative MVP patterns. More formats will be added with tests.
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b(password|passwd|pwd|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token)\s*[:=]\s*([^\s,;]+)"
    ),
    re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+"),
)


def detect_entities(text: str) -> list[Detection]:
    detections: list[Detection] = []
    occupied: list[tuple[int, int]] = []

    # Email before hostname so the domain inside an email is not separately replaced.
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            if any(span[0] < end and span[1] > start for start, end in occupied):
                continue
            detections.append(Detection(kind, match.group(0), span[0], span[1]))
            occupied.append(span)

    return sorted(detections, key=lambda item: item.start)


def redact_secrets(text: str) -> str:
    result = text
    for pattern in SECRET_PATTERNS:
        if "Authorization" in pattern.pattern:
            result = pattern.sub("Authorization: [SECRET_REDACTED]", result)
        else:
            result = pattern.sub(
                lambda m: f"{m.group(1)}=[SECRET_REDACTED]", result
            )
    return result
