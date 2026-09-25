"""Privacy validation gate for SafeContext."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .detectors import Detection, detect_entities


@dataclass(frozen=True)
class ValidationResult:
    """Result returned by the SafeContext privacy gate."""

    safe: bool
    detections: tuple[Detection, ...]

    @property
    def counts(self) -> dict[str, int]:
        return dict(Counter(item.kind for item in self.detections))


def _is_already_protected(detection: Detection) -> bool:
    """Return True when a detection is already a SafeContext-safe value.

    Context-aware detectors intentionally still recognize fields such as
    customer_id=..., even after the value has been pseudonymized. Likewise,
    secret detectors recognize the explicit redaction marker. The privacy
    gate must treat those SafeContext outputs as protected rather than as
    fresh leaks.
    """
    if detection.action == "REDACT":
        return detection.value == "[SECRET_REDACTED]"

    if detection.action == "PSEUDONYMIZE":
        expected_prefix = f"{detection.kind}_"
        suffix = detection.value[len(expected_prefix):] if detection.value.startswith(expected_prefix) else ""

        return (
            detection.value.startswith(expected_prefix)
            and len(suffix) == 8
            and all(char in "0123456789ABCDEF" for char in suffix)
        )

    return False


def validate_text(text: str) -> ValidationResult:
    """Check whether text still contains unprotected sensitive values."""
    unsafe_detections = tuple(
        detection
        for detection in detect_entities(text)
        if not _is_already_protected(detection)
    )

    return ValidationResult(
        safe=not unsafe_detections,
        detections=unsafe_detections,
    )


def format_validation_report(result: ValidationResult) -> str:
    """Create a human-readable privacy gate report without exposing values."""
    lines = [
        "SafeContext Privacy Gate",
        "",
    ]

    if result.safe:
        lines.extend(
            [
                "Status: SAFE TO SHARE",
                "",
                "No unprotected sensitive values detected.",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "Status: BLOCKED",
            "",
            "Unprotected sensitive data detected:",
        ]
    )

    for kind, count in sorted(result.counts.items()):
        lines.append(f"  {kind}: {count}")

    lines.extend(
        [
            "",
            "This content should not be sent to an external LLM.",
        ]
    )

    return "\n".join(lines)
