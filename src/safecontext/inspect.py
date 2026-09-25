from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .detectors import detect_entities


@dataclass
class InspectionResult:
    path: Path
    counts: Counter
    total_entities: int
    contains_sensitive_data: bool


def inspect_text(text: str, path: Path | None = None) -> InspectionResult:
    """
    Inspect text for sensitive entities without modifying the input.
    """

    entities = detect_entities(text)

    counts = Counter(entity.kind for entity in entities)

    return InspectionResult(
        path=path or Path("<memory>"),
        counts=counts,
        total_entities=len(entities),
        contains_sensitive_data=bool(entities),
    )


def inspect_file(path: str | Path) -> InspectionResult:
    """
    Inspect a text file for sensitive entities.
    """

    file_path = Path(path)

    text = file_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return inspect_text(text, path=file_path)


def format_inspection(result: InspectionResult) -> str:
    """
    Create a human-readable privacy inspection report.
    """

    lines = [
        "SafeContext Privacy Inspector",
        "=============================",
        "",
        f"Input: {result.path}",
        "",
        "Detected sensitive entities",
        "---------------------------",
    ]

    if not result.counts:
        lines.append("None detected")
    else:
        for kind, count in sorted(result.counts.items()):
            lines.append(f"{kind:<24} {count}")

    lines.extend(
        [
            "",
            f"Total sensitive entities: {result.total_entities}",
            "",
            "Status:",
            (
                "SENSITIVE INPUT"
                if result.contains_sensitive_data
                else "NO SENSITIVE ENTITIES DETECTED"
            ),
        ]
    )

    return "\n".join(lines)
