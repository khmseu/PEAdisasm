from __future__ import annotations

from typing import Iterable


AUTO_LABEL_PREFIX = "L"


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


def make_auto_label(address: int) -> str:
    return f"{AUTO_LABEL_PREFIX}{address & 0xFFFF:04X}"


def create_auto_symbols(
    addresses: Iterable[int],
    *,
    reserved_addresses: Iterable[int] = (),
    reserved_names: Iterable[str] = (),
) -> dict[str, int]:
    result: dict[str, int] = {}
    taken_names = set(reserved_names)
    reserved_address_set = {address & 0xFFFF for address in reserved_addresses}

    for address in sorted({value & 0xFFFF for value in addresses}):
        if address in reserved_address_set:
            continue

        base_name = make_auto_label(address)
        candidate = base_name
        suffix = 1
        while candidate in taken_names:
            candidate = f"{base_name}_{suffix}"
            suffix += 1

        result[candidate] = address
        taken_names.add(candidate)

    return result


def merge_symbol_maps(predefined: dict[str, int], discovered_addresses: Iterable[int]) -> dict[str, int]:
    merged = dict(predefined)
    auto_symbols = create_auto_symbols(
        discovered_addresses,
        reserved_addresses=merged.values(),
        reserved_names=merged.keys(),
    )
    merged.update(auto_symbols)
    return merged
