"""Privacy validation gate for SafeContext."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re

from .detectors import Detection, detect_entities
from .mapping import MappingVault, policy_fingerprint
from .policy import DetectionPolicy


@dataclass(frozen=True)
class ValidationResult:
    safe: bool
    detections: tuple[Detection, ...]

    @property
    def counts(self) -> dict[str, int]:
        return dict(Counter(item.kind for item in self.detections))


def _is_already_protected(detection: Detection, vault: MappingVault | None) -> bool:
    if detection.action == "REDACT":
        return detection.value == "[SECRET_REDACTED]"
    if detection.action == "PSEUDONYMIZE":
        return (
            vault is not None
            and detection.value.startswith(f"{detection.kind}_")
            and detection.value in vault.reverse
        )
    return False


def validate_text(
    text: str,
    policy: DetectionPolicy | None = None,
    vault: MappingVault | None = None,
) -> ValidationResult:
    """Check detected entities against the same policy and local mapping."""
    if vault is not None and vault.policy_fingerprint != policy_fingerprint(policy):
        return ValidationResult(
            False, (Detection("POLICY_MISMATCH", "", 0, 0, action="REDACT"),)
        )
    unsafe_detections = [
        item for item in detect_entities(text, policy)
        if not _is_already_protected(item, vault)
    ]
    kinds = {"EMAIL", "IP", "HOST", "CUSTOMER_ID", "USER_ID",
             "ACCOUNT_ID", "TENANT_ID", "SESSION_ID"}
    if policy:
        kinds.update(rule.name for rule in policy.identifiers)
    for match in re.finditer(r"\b[A-Z][A-Z0-9_]*_[A-F0-9]{8}\b", text):
        token = match.group()
        if (
            token.rsplit("_", 1)[0] in kinds
            and (vault is None or token not in vault.reverse)
            and not any(item.start < match.end() and item.end > match.start()
                        for item in unsafe_detections)
        ):
            unsafe_detections.append(
                Detection("UNVERIFIED_TOKEN", token, match.start(), match.end())
            )
    return ValidationResult(not unsafe_detections, tuple(unsafe_detections))


def format_validation_report(result: ValidationResult) -> str:
    lines = ["SafeContext Privacy Gate", ""]
    if result.safe:
        return "\n".join([
            *lines,
            "Status: NO DETECTED LEAKS",
            "",
            "No unprotected values matched the configured detectors.",
            "This is not a guarantee of safe sharing.",
        ])
    lines.extend(["Status: BLOCKED", "", "Unprotected sensitive data detected:"])
    for kind, count in sorted(result.counts.items()):
        lines.append(f"  {kind}: {count}")
    lines.extend(["", "This content should not be sent to an external LLM."])
    return "\n".join(lines)
