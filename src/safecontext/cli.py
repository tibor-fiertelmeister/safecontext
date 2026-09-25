"""Command-line interface for SafeContext."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core import protect_file, restore_file
from .inspect import inspect_text
from .mapping import MappingVault
from .policy import load_policy
from .quickstart import run_quickstart
from .validate import format_validation_report, validate_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safecontext",
        description="Locally protect sensitive text before LLM processing.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    protect = subparsers.add_parser("protect", help="Protect a text or log file.")
    protect.add_argument("input", type=Path)
    protect.add_argument("-o", "--output", type=Path)
    protect.add_argument("-m", "--mapping", type=Path)
    protect.add_argument("-p", "--policy", type=Path)

    restore = subparsers.add_parser("restore", help="Restore pseudonyms locally.")
    restore.add_argument("input", type=Path)
    restore.add_argument("-m", "--mapping", type=Path, required=True)
    restore.add_argument("-o", "--output", type=Path)

    inspect = subparsers.add_parser(
        "inspect",
        help="Inspect a file for sensitive entities without modifying it.",
    )
    inspect.add_argument("input", type=Path)
    inspect.add_argument("-p", "--policy", type=Path)

    validate = subparsers.add_parser(
        "validate",
        help="Fail if a file still contains unprotected sensitive data.",
    )
    validate.add_argument("input", type=Path)
    validate.add_argument("-p", "--policy", type=Path)
    validate.add_argument("-m", "--mapping", type=Path)

    subparsers.add_parser(
        "quickstart",
        help="Run a safe synthetic end-to-end demonstration.",
    )

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "protect":
        output = args.output or args.input.with_name(
            f"{args.input.stem}.protected{args.input.suffix}"
        )
        mapping = args.mapping or args.input.with_name(
            f".{args.input.stem}.safecontext-map.json"
        )
        policy = load_policy(args.policy) if args.policy else None
        protect_file(args.input, output, mapping, policy=policy)
        print(f"Protected file: {output}")
        print(f"Local mapping:  {mapping}")
        print(
            "WARNING: The mapping contains sensitive original identifiers. "
            "Keep it local."
        )

    elif args.command == "restore":
        output = args.output or args.input.with_name(
            f"{args.input.stem}.restored{args.input.suffix}"
        )
        restore_file(args.input, output, args.mapping)
        print(f"Restored file: {output}")

    elif args.command == "inspect":
        raw = args.input.read_text(encoding="utf-8")
        policy = load_policy(args.policy) if args.policy else None
        report = inspect_text(raw, policy=policy)
        print(report)

    elif args.command == "validate":
        raw = args.input.read_text(encoding="utf-8")
        policy = load_policy(args.policy) if args.policy else None
        vault = MappingVault.load(args.mapping) if args.mapping else None
        result = validate_text(raw, policy=policy, vault=vault)
        if args.mapping is None:
            if result.safe:
                print(
                    "SafeContext Privacy Gate\n\nStatus: BLOCKED\n\n"
                    "A local mapping is required to verify protected output."
                )
            else:
                print(format_validation_report(result))
            raise SystemExit(1)
        print(format_validation_report(result))
        if not result.safe:
            raise SystemExit(1)

    elif args.command == "quickstart":
        raise SystemExit(run_quickstart())


if __name__ == "__main__":
    main()
