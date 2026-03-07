from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_attr(module_name: str, attr_name: str) -> Any:
    try:
        module = __import__(f"tools.disasm65.{module_name}", fromlist=[attr_name])
        return getattr(module, attr_name)
    except (ImportError, AttributeError):
        pass

    module_path = Path(__file__).with_name("disasm65") / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(
        f"disasm65_cli_{module_name}", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {module_name} module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, attr_name)


parse_control = _load_attr("control", "parse_control")
parse_symbols = _load_attr("symbols", "parse_symbols")
format_edasm = _load_attr("format_edasm", "format_edasm")


def _parse_org(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid origin address: {value!r}") from exc


def _format_parse_error(path: Path, message: str) -> str:
    line_match = re.match(r"^line\s+(\d+):\s*(.*)$", message)
    if line_match is None:
        return message

    line_no = line_match.group(1)
    detail = line_match.group(2)
    return f"{path}:{line_no}:1: {detail}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="disasm65",
        description="65C02 + Sweet16 disassembler (phase 1 scaffold)",
    )
    parser.add_argument("input", type=Path, help="Path to raw binary input")
    parser.add_argument(
        "--org",
        type=_parse_org,
        default=None,
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

    data = args.input.read_bytes()

    directives = []
    if args.control is not None:
        if not args.control.exists():
            parser.error(f"control file does not exist: {args.control}")
        try:
            directives = parse_control(args.control.read_text(encoding="utf-8"))
        except ValueError as exc:
            parser.error(_format_parse_error(args.control, str(exc)))

    symbols = {}
    if args.symbols is not None:
        if not args.symbols.exists():
            parser.error(f"symbols file does not exist: {args.symbols}")
        try:
            symbols = parse_symbols(args.symbols.read_text(encoding="utf-8"))
        except ValueError as exc:
            parser.error(_format_parse_error(args.symbols, str(exc)))

    org = int(args.org) if args.org is not None else 0
    if args.org is None:
        for directive in directives:
            if str(getattr(directive, "kind", "")).upper() != "ORG":
                continue
            address = getattr(directive, "address", None)
            if address is None:
                continue
            org = int(address) & 0xFFFF
            break

    output = format_edasm(
        data=data,
        org=org,
        directives=directives,
        predefined_symbols=symbols,
        sweet16_heuristic=args.sweet16_heuristic,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
