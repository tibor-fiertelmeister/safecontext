"""Deterministic privacy detectors used by SafeContext."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .policy import DetectionPolicy


@dataclass(frozen=True)
class Detection:
    kind: str
    value: str
    start: int
    end: int
    confidence: str = "HIGH"
    action: str = "PSEUDONYMIZE"


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("HOST", re.compile(
        r"\b(?=[A-Za-z0-9.-]*[A-Za-z])"
        r"(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+"
        r"(?:internal|local|lan|corp|example)\b", re.IGNORECASE)),
)


def _field_pattern(fields: tuple[str, ...], value_pattern: str) -> re.Pattern[str]:
    field_expr = "|".join(re.escape(field) for field in fields)
    return re.compile(rf"(?i)\b(?:{field_expr})['\"]?\s*[:=]\s*{value_pattern}")


def _secret_pattern(fields: tuple[str, ...]) -> re.Pattern[str]:
    # Full quoted values can contain spaces; bare values stop at separators.
    return _field_pattern(
        fields,
        r'''(?:"(?P<double>(?:\\.|[^"\\])*)"|'(?P<single>(?:\\.|[^'\\])*)'|(?P<bare>[^\s,;"']+)|(?P<open_double>"[^\r\n]*)|(?P<open_single>'[^\r\n]*))''',
    )


CONTEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CUSTOMER_ID", _field_pattern(("customer_id", "customer_number", "cust_id"), r"""["']?([A-Za-z0-9._-]+)["']?""")),
    ("USER_ID", _field_pattern(("user_id", "userid"), r"""["']?([A-Za-z0-9._-]+)["']?""")),
    ("ACCOUNT_ID", _field_pattern(("account_id", "account_number"), r"""["']?([A-Za-z0-9._-]+)["']?""")),
    ("TENANT_ID", _field_pattern(("tenant_id", "tenantid"), r"""["']?([A-Za-z0-9._-]+)["']?""")),
    ("SESSION_ID", _field_pattern(("session_id", "sessionid"), r"""["']?([A-Za-z0-9._-]+)["']?""")),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SECRET", _secret_pattern(("password", "passwd", "pwd", "secret"))),
    ("API_KEY", _secret_pattern(("api_key", "api-key", "apikey", "x-api-key"))),
    ("ACCESS_TOKEN", _secret_pattern(("access_token", "access-token", "refresh_token", "refresh-token", "token"))),
    ("BEARER_TOKEN", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+(?P<bearer>[A-Za-z0-9._~+/=-]+)")),
    ("JWT", re.compile(r"\b(?P<jwt>eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")),
)


def _overlaps(span: tuple[int, int], occupied: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and span[1] > start for start, end in occupied)


def detect_entities(text: str, policy: DetectionPolicy | None = None) -> list[Detection]:
    """Detect built-in and policy-defined entities with consistent precedence."""
    detections: list[Detection] = []
    occupied: list[tuple[int, int]] = []
    secret_patterns = list(SECRET_PATTERNS)
    if policy:
        secret_patterns.extend((rule.name, _secret_pattern(rule.fields)) for rule in policy.secrets)

    for kind, pattern in secret_patterns:
        for match in pattern.finditer(text):
            group = next((name for name, value in match.groupdict().items() if value is not None), None)
            start, end = match.span(group) if group else match.span()
            if start == end or _overlaps((start, end), occupied):
                continue
            detections.append(Detection(kind, text[start:end], start, end, action="REDACT"))
            occupied.append((start, end))

    context_patterns = list(CONTEXT_PATTERNS)
    if policy:
        context_patterns.extend(
            (rule.name, _field_pattern(rule.fields, r"""["']?([A-Za-z0-9._:/@+-]+)["']?"""))
            for rule in policy.identifiers
        )
    for kind, pattern in context_patterns:
        for match in pattern.finditer(text):
            start, end = match.span(1)
            if start == end or _overlaps((start, end), occupied):
                continue
            detections.append(Detection(kind, match.group(1), start, end))
            occupied.append((start, end))
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if not _overlaps((start, end), occupied):
                detections.append(Detection(kind, match.group(), start, end))
                occupied.append((start, end))
    return sorted(detections, key=lambda item: item.start)


def redact_secrets(text: str, policy: DetectionPolicy | None = None) -> str:
    result = text
    for detection in reversed(detect_entities(text, policy)):
        if detection.action == "REDACT":
            result = result[:detection.start] + "[SECRET_REDACTED]" + result[detection.end:]
    return result
