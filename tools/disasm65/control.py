from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


_TEXT_SUBTYPES = {"ASC", "DCI", "STR"}
_RANGE_DIRECTIVES = {"CODE", "DATA", "SW16"}
_SINGLE_ADDRESS_DIRECTIVES = {"ORG", "ENTRY"}


@dataclass(frozen=True)
class ControlDirective:
    kind: str
    address: int | None = None
    start: int | None = None
    end: int | None = None
    subtype: str | None = None


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
        kind = parts[0].upper()
        operands = parts[1:]

        if kind in _SINGLE_ADDRESS_DIRECTIVES:
            if len(operands) != 1 or "," in operands[0]:
                raise ValueError(f"line {line_no}: {kind} expects 1 operand")
            directives.append(ControlDirective(kind=kind, address=_parse_number(operands[0], line_no)))
            continue

        if kind in _RANGE_DIRECTIVES:
            operand_text = " ".join(operands)
            start, end = _parse_range(operand_text, kind, line_no)
            directives.append(ControlDirective(kind=kind, start=start, end=end))
            continue

        if kind == "TEXT":
            if not operands:
                raise ValueError(f"line {line_no}: TEXT expects start,end operands and optional subtype")

            subtype = "ASC"
            range_tokens = operands
            if len(operands) >= 2 and operands[-1].isalpha():
                candidate = operands[-1].upper()
                if candidate not in _TEXT_SUBTYPES:
                    if any(token.isalpha() and token.upper() in _TEXT_SUBTYPES for token in operands[:-1]):
                        raise ValueError(f"line {line_no}: TEXT expects start,end operands and optional subtype")
                    raise ValueError(f"line {line_no}: invalid TEXT subtype {operands[-1]!r}")
                subtype = candidate
                range_tokens = operands[:-1]

            range_text = " ".join(range_tokens)
            start, end = _parse_range(range_text, kind, line_no)
            directives.append(ControlDirective(kind=kind, start=start, end=end, subtype=subtype))
            continue

        raise ValueError(f"line {line_no}: unknown directive {parts[0]!r}")

    return directives
