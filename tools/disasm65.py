from __future__ import annotations

import argparse
from pathlib import Path


def _parse_org(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid origin address: {value!r}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="disasm65",
        description="65C02 + Sweet16 disassembler (phase 1 scaffold)",
    )
    parser.add_argument("input", type=Path, help="Path to raw binary input")
    parser.add_argument(
        "--org",
        type=_parse_org,
        default=0,
        help="Origin address for binary load (default: 0)",
    )
    parser.add_argument("--control", type=Path, default=None, help="Control file path")
    parser.add_argument("--symbols", type=Path, default=None, help="Symbols file path")
    parser.add_argument(
        "--sweet16-heuristic",
        action="store_true",
        help="Enable Sweet16 detection heuristic placeholder",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.input.exists():
        parser.error(f"input file does not exist: {args.input}")

    print("Phase 1 scaffold: disassembler core not implemented yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
