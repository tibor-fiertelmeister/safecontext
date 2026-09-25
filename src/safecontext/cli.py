"""Command-line interface for SafeContext."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core import protect_file, restore_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safecontext",
        description="Locally pseudonymize sensitive text before LLM processing.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    protect = subparsers.add_parser("protect", help="Protect a text or log file.")
    protect.add_argument("input", type=Path)
    protect.add_argument("-o", "--output", type=Path)
    protect.add_argument("-m", "--mapping", type=Path)

    restore = subparsers.add_parser("restore", help="Restore pseudonyms locally.")
    restore.add_argument("input", type=Path)
    restore.add_argument("-m", "--mapping", type=Path, required=True)
    restore.add_argument("-o", "--output", type=Path)

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "protect":
        output = args.output or args.input.with_name(f"{args.input.stem}.protected{args.input.suffix}")
        mapping = args.mapping or args.input.with_name(f".{args.input.stem}.safecontext-map.json")
        protect_file(args.input, output, mapping)
        print(f"Protected file: {output}")
        print(f"Local mapping:  {mapping}")
        print("WARNING: The mapping contains sensitive original identifiers. Keep it local.")

    elif args.command == "restore":
        output = args.output or args.input.with_name(f"{args.input.stem}.restored{args.input.suffix}")
        restore_file(args.input, output, args.mapping)
        print(f"Restored file: {output}")


if __name__ == "__main__":
    main()
