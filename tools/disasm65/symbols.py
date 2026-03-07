from __future__ import annotations

from typing import Iterable


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


def parse_symbols(source: str | Iterable[str]) -> dict[str, int]:
    symbols: dict[str, int] = {}

    for line_no, raw in enumerate(_to_lines(source), start=1):
        code = raw.split(";", 1)[0].strip()
        if not code:
            continue

        parts = code.split()
        if len(parts) != 3 or parts[1].upper() != "EQU":
            raise ValueError(f"line {line_no}: malformed EQU line {raw.strip()!r}")

        name = parts[0]
        if name in symbols:
            raise ValueError(f"line {line_no}: duplicate symbol {name!r}")

        symbols[name] = _parse_number(parts[2], line_no)

    return symbols
