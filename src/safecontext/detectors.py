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


# ---------------------------------------------------------------------------
# Structured identifiers
# ---------------------------------------------------------------------------

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "EMAIL",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
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


# ---------------------------------------------------------------------------
# Context-aware identifiers
#
# These values may not be sensitive by format alone. Their surrounding field
# name provides the context required to classify them.
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Secrets
#
# Secrets are intentionally REDACTED rather than pseudonymized.
# They should never be recoverable from LLM-visible content.
# ---------------------------------------------------------------------------

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
    """Return True when a span overlaps an existing detection."""

    return any(
        span[0] < end and span[1] > start
        for start, end in occupied
    )


def detect_entities(text: str) -> list[Detection]:
    """Detect sensitive entities without modifying the input."""

    detections: list[Detection] = []
    occupied: list[tuple[int, int]] = []

    # ------------------------------------------------------------------
    # Secrets first.
    #
    # They have the highest priority because a token may contain strings
    # that would otherwise look like another identifier.
    # ------------------------------------------------------------------

    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):

            # Most secret patterns capture only the secret value.
            # JWT matches the entire value.
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

    # ------------------------------------------------------------------
    # Strong structured identifiers
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Context-derived identifiers
    # ------------------------------------------------------------------

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

    return sorted(
        detections,
        key=lambda item: item.start,
    )


def redact_secrets(text: str) -> str:
    """Redact detected secrets while preserving useful surrounding context."""

    result = text

    # Authorization headers need special handling.
    result = re.sub(
        r"(?i)\bAuthorization\s*:\s*Bearer\s+"
        r"[A-Za-z0-9._~+/=-]+",
        "Authorization: Bearer [SECRET_REDACTED]",
        result,
    )

    # Generic key/value secrets.
    result = re.sub(
        r"(?i)\b(password|passwd|pwd|secret|"
        r"api[_-]?key|apikey|x-api-key|"
        r"access[_-]?token|refresh[_-]?token|token)"
        r"\s*([:=])\s*[\"']?[^\s,;\"']+[\"']?",
        lambda m: (
            f"{m.group(1)}{m.group(2)}[SECRET_REDACTED]"
        ),
        result,
    )

    # Standalone JWTs.
    result = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\b",
        "[SECRET_REDACTED]",
        result,
    )

    return result
