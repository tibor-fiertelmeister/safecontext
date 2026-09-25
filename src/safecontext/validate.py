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


def validate_text(text: str) -> ValidationResult:
    """Check whether text still contains unprotected sensitive values.

    SafeContext pseudonyms such as EMAIL_AB12CD34 are not detected as raw
    identifiers, while any remaining raw identifiers or secrets cause the
    privacy gate to fail.
    """
    detections = tuple(detect_entities(text))
    return ValidationResult(
        safe=not detections,
        detections=detections,
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
