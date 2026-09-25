"""Command-line interface for SafeContext."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core import protect_file, restore_file
from .inspect import format_inspection, inspect_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safecontext",
        description="Locally inspect and pseudonymize sensitive text before LLM processing.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ------------------------------------------------------------------
    # inspect
    # ------------------------------------------------------------------

    inspect = subparsers.add_parser(
        "inspect",
        help="Inspect a text or log file for sensitive entities.",
    )
    inspect.add_argument(
        "input",
        type=Path,
        help="Input file to inspect.",
    )

    # ------------------------------------------------------------------
    # protect
    # ------------------------------------------------------------------

    protect = subparsers.add_parser(
        "protect",
        help="Protect a text or log file.",
    )
    protect.add_argument("input", type=Path)
    protect.add_argument("-o", "--output", type=Path)
    protect.add_argument("-m", "--mapping", type=Path)

    # ------------------------------------------------------------------
    # restore
    # ------------------------------------------------------------------

    restore = subparsers.add_parser(
        "restore",
        help="Restore pseudonyms locally.",
    )
    restore.add_argument("input", type=Path)
    restore.add_argument(
        "-m",
        "--mapping",
        type=Path,
        required=True,
    )
    restore.add_argument("-o", "--output", type=Path)

    return parser


def main() -> None:
    args = build_parser().parse_args()

    # ------------------------------------------------------------------
    # inspect
    # ------------------------------------------------------------------

    if args.command == "inspect":
        result = inspect_file(args.input)
        print(format_inspection(result))

    # ------------------------------------------------------------------
    # protect
    # ------------------------------------------------------------------

    elif args.command == "protect":
        output = args.output or args.input.with_name(
            f"{args.input.stem}.protected{args.input.suffix}"
        )

        mapping = args.mapping or args.input.with_name(
            f".{args.input.stem}.safecontext-map.json"
        )

        protect_file(
            args.input,
            output,
            mapping,
        )

        print(f"Protected file: {output}")
        print(f"Local mapping:  {mapping}")
        print(
            "WARNING: The mapping contains sensitive original identifiers. "
            "Keep it local."
        )

    # ------------------------------------------------------------------
    # restore
    # ------------------------------------------------------------------

    elif args.command == "restore":
        output = args.output or args.input.with_name(
            f"{args.input.stem}.restored{args.input.suffix}"
        )

        restore_file(
            args.input,
            output,
            args.mapping,
        )

        print(f"Restored file: {output}")


if __name__ == "__main__":
    main()
