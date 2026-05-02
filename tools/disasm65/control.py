# tools/disasm65/control.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

_TEXT_SUBTYPES = {"ASC", "DCI", "STR"}
_MODE_MAP = {
    "65": "CODE",
    "16": "SW16",
    "SWEET": "SWEET",
    "TEXT": "TEXT",
    "DATA": "DATA",
    "DW": "DW",
    "CODE": "CODE",
    "SW16": "SW16",
}
_RANGE_DIRECTIVES = {"CODE", "DATA", "DW", "SW16", "TEXT", "65", "16"}
_SINGLE_ADDRESS_DIRECTIVES = {"ORG", "ENTRY", "SWEET"}


@dataclass(frozen=True)
class ControlDirective:
    kind: str
    address: int | None = None
    start: int | None = None
    end: int | None = None
    subtype: str | None = None
    raw: str | None = None


def _to_lines(source: str | Iterable[str]) -> list[str]:
    if isinstance(source, str):
        return source.splitlines()
    return list(source)


def _parse_number(token: str, line_no: int) -> int:
    try:
        if token.startswith("$"):
            return int(token[1:], 16)
        return int(token, 10)
    except ValueError as exc:
        raise ValueError(f"line {line_no}: invalid number {token!r}") from exc


def _parse_range(text: str, kind: str, line_no: int) -> tuple[int, int]:
    if text.count(",") != 1:
        raise ValueError(f"line {line_no}: {kind} expects start,end operands")

    start_token, end_token = text.split(",", 1)
    start_parts = start_token.strip().split()
    end_parts = end_token.strip().split()
    if len(start_parts) != 1 or len(end_parts) != 1:
        raise ValueError(f"line {line_no}: {kind} expects start,end operands")

    start = _parse_number(start_parts[0], line_no)
    end = _parse_number(end_parts[0], line_no)
    if start > end:
        raise ValueError(f"line {line_no}: range start must be <= end")

    return start, end


def parse_control(source: str | Iterable[str]) -> list[ControlDirective]:
    directives: list[ControlDirective] = []

    for line_no, raw in enumerate(_to_lines(source), start=1):
        code = raw.split(";", 1)[0].strip()
        if not code:
            continue

        parts = code.split()
        first = parts[0].upper()

        # Check for "address mode" form
        if (
            first.startswith("$")
            or first[0].isdigit()
            or (
                "," in first
                and (
                    first.split(",")[0].startswith("$")
                    or first.split(",")[0][0].isdigit()
                )
            )
        ):
            if len(parts) < 2:
                raise ValueError(f"line {line_no}: expected mode after address")

            addr_part = parts[0]
            kind_token = parts[1].upper()
            kind = _MODE_MAP.get(kind_token, kind_token)

            if "," in addr_part:
                start, end = _parse_range(addr_part, kind, line_no)
                directives.append(
                    ControlDirective(kind=kind, start=start, end=end, raw=code)
                )
            else:
                address = _parse_number(addr_part, line_no)
                if kind in _SINGLE_ADDRESS_DIRECTIVES or kind == "ORG":
                    directives.append(
                        ControlDirective(kind=kind, address=address, raw=code)
                    )
                else:
                    directives.append(
                        ControlDirective(kind=kind, start=address, raw=code)
                    )
            continue

        # Existing format: "KIND operands"
        kind = _MODE_MAP.get(first, first)
        operands = parts[1:]

        if kind in _SINGLE_ADDRESS_DIRECTIVES or kind == "ORG":
            if len(operands) != 1:
                raise ValueError(f"line {line_no}: {kind} expects 1 operand")
            directives.append(
                ControlDirective(
                    kind=kind, address=_parse_number(operands[0], line_no), raw=code
                )
            )
            continue

        if kind in _RANGE_DIRECTIVES:
            if not operands:
                raise ValueError(f"line {line_no}: {kind} expects operands")

            operand_text = operands[0]
            if "," in operand_text:
                start, end = _parse_range(operand_text, kind, line_no)
            else:
                start = _parse_number(operand_text, line_no)
                end = None

            subtype = "ASC"
            if kind == "TEXT" and len(operands) > 1:
                candidate = operands[-1].upper()
                if candidate in _TEXT_SUBTYPES:
                    subtype = candidate

            directives.append(
                ControlDirective(
                    kind=kind, start=start, end=end, subtype=subtype, raw=code
                )
            )
            continue

        raise ValueError(f"line {line_no}: unknown directive {parts[0]!r}")

    return directives
