"""Configurable detection policies for SafeContext."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyRule:
    """A configurable context-aware detection rule."""

    name: str
    fields: tuple[str, ...]
    action: str


@dataclass(frozen=True)
class DetectionPolicy:
    """Collection of user-defined SafeContext detection rules."""

    identifiers: tuple[PolicyRule, ...] = ()
    secrets: tuple[PolicyRule, ...] = ()


def _validate_rule(raw_rule: Any, expected_action: str) -> PolicyRule:
    if not isinstance(raw_rule, dict):
        raise ValueError("Policy rules must be objects.")

    name = raw_rule.get("name")
    fields = raw_rule.get("fields")

    if not isinstance(name, str) or not name.strip():
        raise ValueError("Each policy rule requires a non-empty 'name'.")

    if not isinstance(fields, list) or not fields:
        raise ValueError(
            f"Policy rule '{name}' requires a non-empty 'fields' list."
        )

    clean_fields: list[str] = []
    for field in fields:
        if not isinstance(field, str) or not field.strip():
            raise ValueError(
                f"Policy rule '{name}' contains an invalid field."
            )
        clean_fields.append(field.strip())

    return PolicyRule(
        name=name.strip().upper(),
        fields=tuple(clean_fields),
        action=expected_action,
    )


def load_policy(path: Path) -> DetectionPolicy:
    """Load and validate a SafeContext JSON policy file."""

    payload = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(payload, dict):
        raise ValueError("Policy root must be a JSON object.")

    identifier_rules = tuple(
        _validate_rule(rule, "PSEUDONYMIZE")
        for rule in payload.get("identifiers", [])
    )
    secret_rules = tuple(
        _validate_rule(rule, "REDACT")
        for rule in payload.get("secrets", [])
    )

    return DetectionPolicy(
        identifiers=identifier_rules,
        secrets=secret_rules,
    )


def build_context_pattern(fields: tuple[str, ...]) -> re.Pattern[str]:
    """Build a key/value detector from configured field names."""

    field_expression = "|".join(re.escape(field) for field in fields)
    return re.compile(
        rf"(?i)\b(?:{field_expression})"
        rf"\s*[:=]\s*[\"']?([A-Za-z0-9._:/@+-]+)[\"']?"
    )


def build_secret_pattern(fields: tuple[str, ...]) -> re.Pattern[str]:
    """Build a secret key/value detector from configured field names."""

    field_expression = "|".join(re.escape(field) for field in fields)
    return re.compile(
        rf"(?i)\b(?:{field_expression})"
        rf"\s*([:=])\s*[\"']?([^\s,;\"']+)[\"']?"
    )
