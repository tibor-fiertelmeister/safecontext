"""Deterministic privacy detectors used by SafeContext."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    """A sensitive entity detected in text."""

    kind: str
    value: str
    start: int
    end: int
    confidence: str = "HIGH"
    action: str = "PSEUDONYMIZE"


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

CONTEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "CUSTOMER_ID",
        re.compile(
            r"(?i)\b(?:customer[_-]?id|customer[_-]?number|cust[_-]?id)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._-]+)[\"']?"
        ),
    ),
    (
        "USER_ID",
        re.compile(
            r"(?i)\b(?:user[_-]?id|userid)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._-]+)[\"']?"
        ),
    ),
    (
        "ACCOUNT_ID",
        re.compile(
            r"(?i)\b(?:account[_-]?id|account[_-]?number)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._-]+)[\"']?"
        ),
    ),
    (
        "TENANT_ID",
        re.compile(
            r"(?i)\b(?:tenant[_-]?id|tenantid)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._-]+)[\"']?"
        ),
    ),
    (
        "SESSION_ID",
        re.compile(
            r"(?i)\b(?:session[_-]?id|sessionid)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._-]+)[\"']?"
        ),
    ),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "SECRET",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret)"
            r"\s*[:=]\s*[\"']?([^\s,;\"']+)[\"']?"
        ),
    ),
    (
        "API_KEY",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|x-api-key)"
            r"\s*[:=]\s*[\"']?([^\s,;\"']+)[\"']?"
        ),
    ),
    (
        "ACCESS_TOKEN",
        re.compile(
            r"(?i)\b(?:access[_-]?token|refresh[_-]?token|token)"
            r"\s*[:=]\s*[\"']?([^\s,;\"']+)[\"']?"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(
            r"(?i)\bAuthorization\s*:\s*Bearer\s+"
            r"([A-Za-z0-9._~+/=-]+)"
        ),
    ),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\b"
        ),
    ),
)


def _overlaps(
    span: tuple[int, int],
    occupied: list[tuple[int, int]],
) -> bool:
    return any(
        span[0] < end and span[1] > start
        for start, end in occupied
    )


def detect_entities(text: str) -> list[Detection]:
    """Detect sensitive entities without modifying the input."""

    detections: list[Detection] = []
    occupied: list[tuple[int, int]] = []

    # Secrets have highest priority.
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if match.lastindex:
                start, end = match.span(1)
                value = match.group(1)
            else:
                start, end = match.span()
                value = match.group(0)

            span = (start, end)
            if _overlaps(span, occupied):
                continue

            detections.append(
                Detection(
                    kind=kind,
                    value=value,
                    start=start,
                    end=end,
                    confidence="HIGH",
                    action="REDACT",
                )
            )
            occupied.append(span)

    # Strong structured identifiers.
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            if _overlaps(span, occupied):
                continue

            detections.append(
                Detection(
                    kind=kind,
                    value=match.group(0),
                    start=span[0],
                    end=span[1],
                    confidence="HIGH",
                    action="PSEUDONYMIZE",
                )
            )
            occupied.append(span)

    # Context-derived identifiers.
    for kind, pattern in CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span(1)
            span = (start, end)
            if _overlaps(span, occupied):
                continue

            detections.append(
                Detection(
                    kind=kind,
                    value=match.group(1),
                    start=start,
                    end=end,
                    confidence="HIGH",
                    action="PSEUDONYMIZE",
                )
            )
            occupied.append(span)

    return sorted(detections, key=lambda item: item.start)


def redact_secrets(text: str) -> str:
    """Redact secrets while preserving useful surrounding context.

    This helper remains public for inspection/unit tests. protect_text uses
    detect_entities directly so every sensitive value is transformed exactly
    once according to its action.
    """
    result = text
    detections = [
        detection
        for detection in detect_entities(text)
        if detection.action == "REDACT"
    ]

    for detection in reversed(detections):
        result = (
            result[: detection.start]
            + "[SECRET_REDACTED]"
            + result[detection.end :]
        )

    return result
