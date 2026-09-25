"""Synthetic first-run demonstration for SafeContext."""

from __future__ import annotations

from pathlib import Path

from .core import protect_file
from .detectors import detect_entities, redact_secrets


SYNTHETIC_INPUT = (
    "2026-09-25T10:15:00Z user=alice@example.com "
    "host=prod-db-01.internal src=10.20.30.40 "
    "password=SC_DEMO_SECRET_12345\n"
)


def run_quickstart(directory: Path | None = None) -> int:
    """Run a safe, synthetic end-to-end SafeContext demonstration."""
    workdir = directory or Path.cwd()
    raw_path = workdir / "safecontext-demo.log"
    protected_path = workdir / "safecontext-demo.protected.log"
    mapping_path = workdir / ".safecontext-demo.safecontext-map.json"

    raw_path.write_text(SYNTHETIC_INPUT, encoding="utf-8")

    print("SafeContext Quickstart")
    print("======================")
    print()
    print("[1/4] Created synthetic example")
    print(f"      {raw_path.name}")

    detections = detect_entities(SYNTHETIC_INPUT)
    counts: dict[str, int] = {}
    for item in detections:
        counts[item.kind] = counts.get(item.kind, 0) + 1

    secret_detected = "[SECRET_REDACTED]" in redact_secrets(SYNTHETIC_INPUT)

    print()
    print("[2/4] Inspecting input")
    for kind in ("EMAIL", "HOST", "IP"):
        print(f"      {kind}: {counts.get(kind, 0)}")
    print(f"      SECRET: {'detected' if secret_detected else 'not detected'}")

    protect_file(raw_path, protected_path, mapping_path)
    protected = protected_path.read_text(encoding="utf-8")

    print()
    print("[3/4] Protecting locally")
    print("      Identifiers -> stable pseudonyms")
    print("      Secrets     -> [SECRET_REDACTED]")

    original_values = [item.value for item in detections]
    raw_identifier_leaked = any(value in protected for value in original_values)
    raw_secret_leaked = "SC_DEMO_SECRET_12345" in protected
    marker_present = "[SECRET_REDACTED]" in protected
    safe = not raw_identifier_leaked and not raw_secret_leaked and marker_present

    print()
    print("[4/4] Privacy validation")
    print(f"      {'PASS' if safe else 'FAIL'}")
    print()
    print("Protected file:")
    print(protected_path.name)
    print()
    print("Local mapping:")
    print(mapping_path.name)
    print()

    if safe:
        print("SafeContext is ready.")
        print("Only the protected file is intended to cross the privacy boundary.")
        return 0

    print("Quickstart validation failed. Protected output should not be shared.")
    return 1
