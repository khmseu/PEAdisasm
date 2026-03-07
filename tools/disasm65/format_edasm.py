from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_attr(module_name: str, attr_name: str) -> Any:
    try:
        module = __import__(f"tools.disasm65.{module_name}", fromlist=[attr_name])
        return getattr(module, attr_name)
    except (ImportError, AttributeError):
        pass

    try:  # pragma: no cover - package import fallback
        module = __import__(f"{module_name}", fromlist=[attr_name])
        return getattr(module, attr_name)
    except (ImportError, AttributeError):
        pass

    module_path = Path(__file__).with_name(f"{module_name}.py")
    spec = importlib.util.spec_from_file_location(
        f"disasm65_runtime_{module_name}", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {module_name} module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, attr_name)


decode_instruction = _load_attr("decode", "decode_instruction")
DecodedInstruction = _load_attr("decode", "DecodedInstruction")
discover_symbols = _load_attr("analyze", "discover_symbols")
resolve_region_kind = _load_attr("analyze", "resolve_region_kind")


_LABEL_WIDTH = 12
_MNEMONIC_WIDTH = 7
_EXECUTABLE_KINDS = {"CODE", "SW16"}
_OPERAND_ADDRESS_RE = re.compile(r"^\$([0-9A-Fa-f]{1,4})(,X)?$")


def _format_line(label: str, mnemonic: str, operand: str = "") -> str:
    label_field = f"{label:<{_LABEL_WIDTH}}" if label else " " * _LABEL_WIDTH
    if operand:
        return f"{label_field}{mnemonic:<{_MNEMONIC_WIDTH}}{operand}"
    return f"{label_field}{mnemonic}"


def _resolve_kind(address: int, directives: Sequence[Any]) -> str:
    if not directives:
        return "CODE"
    return resolve_region_kind(address, directives, fallback_kind="CODE")


def _contiguous_kind_length(
    data_len: int, org: int, offset: int, directives: Sequence[Any], kind: str
) -> int:
    length = 0
    while offset + length < data_len:
        address = org + offset + length
        if _resolve_kind(address, directives) != kind:
            break
        length += 1
    return max(1, length)


def _decode_map(
    data: bytes, org: int, directives: Sequence[Any], sweet16_heuristic: bool
) -> dict[int, Any]:
    decoded: dict[int, Any] = {}
    offset = 0

    while offset < len(data):
        address = org + offset
        kind = _resolve_kind(address, directives)

        if kind in _EXECUTABLE_KINDS:
            contiguous_length = _contiguous_kind_length(
                len(data), org, offset, directives, kind
            )
            try:
                instruction = decode_instruction(
                    data[offset:],
                    pc=address,
                    sweet16_mode=(kind == "SW16"),
                    sweet16_heuristic=sweet16_heuristic,
                )
            except ValueError:
                instruction = DecodedInstruction(
                    mnemonic="DB", operand=f"${data[offset]:02X}", length=1
                )

            if int(getattr(instruction, "length", 1)) > contiguous_length:
                instruction = DecodedInstruction(
                    mnemonic="DB", operand=f"${data[offset]:02X}", length=1
                )

            decoded[address] = instruction
            offset += max(1, int(getattr(instruction, "length", 1)))
            continue

        if kind == "TEXT":
            offset += _contiguous_kind_length(
                len(data), org, offset, directives, "TEXT"
            )
            continue

        offset += 1

    return decoded


def _entry_points(directives: Sequence[Any]) -> list[int]:
    entries: list[int] = []
    for directive in directives:
        if str(getattr(directive, "kind", "")).upper() != "ENTRY":
            continue
        address = getattr(directive, "address", None)
        if address is None:
            continue
        entries.append(int(address) & 0xFFFF)
    return entries


def _address_to_symbol(symbols: Mapping[str, int]) -> dict[int, str]:
    table: dict[int, str] = {}
    for name, address in symbols.items():
        normalized = int(address) & 0xFFFF
        if normalized not in table:
            table[normalized] = name
    return table


def _render_operand(operand: str, symbols_by_address: Mapping[int, str]) -> str:
    match = _OPERAND_ADDRESS_RE.match(operand)
    if match is None:
        return operand

    address = int(match.group(1), 16) & 0xFFFF
    symbol = symbols_by_address.get(address)
    if symbol is None:
        return operand

    suffix = match.group(2) or ""
    return f"{symbol}{suffix}"


def _text_subtype(address: int, directives: Sequence[Any]) -> str:
    for directive in directives:
        if str(getattr(directive, "kind", "")).upper() != "TEXT":
            continue
        start = getattr(directive, "start", None)
        end = getattr(directive, "end", None)
        if start is None or end is None:
            continue
        if int(start) <= address <= int(end):
            subtype = str(getattr(directive, "subtype", "ASC") or "ASC").upper()
            return subtype if subtype in {"ASC", "DCI", "STR"} else "ASC"
    return "ASC"


def _escape_ascii(data: bytes) -> str:
    parts: list[str] = []
    for value in data:
        if value == 0x5C:
            parts.append("\\\\")
            continue
        if value == 0x22:
            parts.append('\\"')
            continue
        if 0x20 <= value <= 0x7E:
            parts.append(chr(value))
            continue
        parts.append(".")
    return "".join(parts)


def format_edasm(
    *,
    data: bytes,
    org: int = 0,
    directives: Sequence[Any] | None = None,
    predefined_symbols: Mapping[str, int] | None = None,
    sweet16_heuristic: bool = False,
) -> str:
    directive_list = list(directives or [])
    predefined = dict(predefined_symbols or {})

    decoded_by_address = _decode_map(data, org, directive_list, sweet16_heuristic)
    merged_symbols = discover_symbols(
        decoded_by_address=decoded_by_address,
        directives=directive_list,
        predefined_symbols=predefined,
        seeded_entries=_entry_points(directive_list),
    )
    symbols_by_address = _address_to_symbol(merged_symbols)

    lines = [_format_line("", "ORG", f"${org & 0xFFFF:04X}")]

    offset = 0
    while offset < len(data):
        address = org + offset
        label = symbols_by_address.get(address, "")
        kind = _resolve_kind(address, directive_list)

        if kind in _EXECUTABLE_KINDS and address in decoded_by_address:
            instruction = decoded_by_address[address]
            mnemonic = str(getattr(instruction, "mnemonic", "DB")).lstrip(".").upper()
            operand = _render_operand(
                str(getattr(instruction, "operand", "")), symbols_by_address
            )
            lines.append(_format_line(label, mnemonic, operand))
            offset += max(1, int(getattr(instruction, "length", 1)))
            continue

        if kind == "TEXT":
            run_length = _contiguous_kind_length(
                len(data), org, offset, directive_list, "TEXT"
            )
            text = _escape_ascii(data[offset : offset + run_length])
            lines.append(
                _format_line(label, _text_subtype(address, directive_list), f'"{text}"')
            )
            offset += run_length
            continue

        lines.append(_format_line(label, "DB", f"${data[offset]:02X}"))
        offset += 1

    return "\n".join(lines)


__all__ = ["format_edasm"]
