# tools/disasm65/format_edasm.py
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
    try:
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
_SIMPLE_ADDRESS_RE = re.compile(r"^\$([0-9A-Fa-f]{1,4})(?:,(X|Y))?$")
_INDIRECT_RE = re.compile(r"^\(\$([0-9A-Fa-f]{1,4})\)$")
_INDIRECT_PREINDEX_RE = re.compile(r"^\(\$([0-9A-Fa-f]{1,4}),(X|Y)\)$")
_INDIRECT_POSTINDEX_RE = re.compile(r"^\(\$([0-9A-Fa-f]{1,4})\),(X|Y)$")
_ZPREL_RE = re.compile(r"^\$([0-9A-Fa-f]{1,4}),\$([0-9A-Fa-f]{1,4})$")


def _format_line(label: str, mnemonic: str, operand: str = "") -> str:
    label_field = f"{label:<{_LABEL_WIDTH}}" if label else " " * _LABEL_WIDTH
    if operand:
        return f"{label_field}{mnemonic:<{_MNEMONIC_WIDTH}}{operand}"
    return f"{label_field}{mnemonic}"


def _resolve_kind(address: int, directives: Sequence[Any]) -> str:
    if not directives:
        return "CODE"
    return resolve_region_kind(address, directives, fallback_kind="CODE")


def _get_directive_at(address: int, directives: Sequence[Any]) -> Any | None:
    for d in directives:
        if getattr(d, "address", None) == address:
            return d
        if getattr(d, "start", None) == address:
            return d
    return None


def _contiguous_kind_length(
    data_len: int, org: int, offset: int, directives: Sequence[Any], kind: str
) -> int:
    length = 0
    while offset + length < data_len:
        address = org + offset + length
        if length > 0 and _get_directive_at(address, directives):
            break
        if _resolve_kind(address, directives) != kind:
            break
        length += 1
    return max(1, length)


def _decode_map(
    data: bytes, org: int, directives: Sequence[Any], sweet16_heuristic: bool
) -> dict[int, Any]:
    decoded: dict[int, Any] = {}
    offset = 0
    bf00_payload_state = 0

    sweet_addresses = {
        d.address for d in directives if d.kind == "SWEET" and d.address is not None
    }
    if not sweet_addresses:
        sweet_addresses = {0xBF00}

    while offset < len(data):
        address = org + offset
        kind = _resolve_kind(address, directives)

        if kind in _EXECUTABLE_KINDS:
            if bf00_payload_state == 1:
                decoded[address] = DecodedInstruction(
                    mnemonic="DB", operand=f"${data[offset]:02X}", length=1
                )
                offset += 1
                bf00_payload_state = 2
                continue
            if bf00_payload_state == 2:
                contiguous_length = _contiguous_kind_length(
                    len(data), org, offset, directives, kind
                )
                if len(data) - offset >= 2 and contiguous_length >= 2:
                    value = data[offset] | (data[offset + 1] << 8)
                    decoded[address] = DecodedInstruction(
                        mnemonic="DW", operand=f"${value:04X}", length=2
                    )
                    offset += 2
                else:
                    decoded[address] = DecodedInstruction(
                        mnemonic="DB", operand=f"${data[offset]:02X}", length=1
                    )
                    offset += 1
                bf00_payload_state = 0
                continue

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
            mnemonic = str(getattr(instruction, "mnemonic", "")).upper()
            operand = str(getattr(instruction, "operand", "")).upper()
            if kind == "CODE" and mnemonic == "JSR":
                match = _SIMPLE_ADDRESS_RE.match(operand)
                if match and int(match.group(1), 16) in sweet_addresses:
                    bf00_payload_state = 1
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
        if address is not None:
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
    if not operand or operand.startswith("#"):
        return operand
    match = _SIMPLE_ADDRESS_RE.match(operand)
    if match is not None:
        address = int(match.group(1), 16) & 0xFFFF
        symbol = symbols_by_address.get(address)
        if symbol is None:
            return operand
        suffix = f",{match.group(2)}" if match.group(2) else ""
        return f"{symbol}{suffix}"
    match = _INDIRECT_RE.match(operand)
    if match is not None:
        address = int(match.group(1), 16) & 0xFFFF
        symbol = symbols_by_address.get(address)
        if symbol is None:
            return operand
        return f"({symbol})"
    match = _INDIRECT_PREINDEX_RE.match(operand)
    if match is not None:
        address = int(match.group(1), 16) & 0xFFFF
        symbol = symbols_by_address.get(address)
        if symbol is None:
            return operand
        return f"({symbol},{match.group(2)})"
    match = _INDIRECT_POSTINDEX_RE.match(operand)
    if match is not None:
        address = int(match.group(1), 16) & 0xFFFF
        symbol = symbols_by_address.get(address)
        if symbol is None:
            return operand
        return f"({symbol}),{match.group(2)}"
    match = _ZPREL_RE.match(operand)
    if match is not None:
        first = int(match.group(1), 16) & 0xFFFF
        second = int(match.group(2), 16) & 0xFFFF
        first_rendered = symbols_by_address.get(first, f"${match.group(1).upper()}")
        second_rendered = symbols_by_address.get(second, f"${match.group(2).upper()}")
        return f"{first_rendered},{second_rendered}"
    return operand


def _next_symbol_boundary(
    address: int, length: int, symbols_by_address: Mapping[int, str]
) -> int:
    if length <= 1:
        return max(1, length)
    max_length = max(1, length)
    for delta in range(1, max_length):
        if (address + delta) in symbols_by_address:
            return delta
    return max_length


def _append_interior_labels(
    lines: list[str],
    *,
    address: int,
    length: int,
    symbols_by_address: Mapping[int, str],
) -> None:
    if length <= 1:
        return
    for delta in range(1, length):
        symbol = symbols_by_address.get(address + delta)
        if symbol:
            lines.append(_format_line(symbol, ""))


def _is_printable(b: int) -> bool:
    return 0x20 <= (b & 0x7F) <= 0x7E


def _format_text_block(
    label: str, data: bytes, current_msb: bool | None
) -> tuple[list[str], bool]:
    lines = []
    i = 0
    msb = current_msb
    while i < len(data):
        new_msb = bool(data[i] & 0x80)
        if msb != new_msb:
            lines.append(_format_line("", "MSB", "ON" if new_msb else "OFF"))
            msb = new_msb
        start = i
        while i < len(data) and _is_printable(data[i]) and bool(data[i] & 0x80) == msb:
            i += 1
        if i > start:
            if i < len(data) and _is_printable(data[i]) and bool(data[i] & 0x80) != msb:
                text = "".join(chr(b & 0x7F) for b in data[start : i + 1])
                lines.append(
                    _format_line(label if start == 0 else "", "DCI", f'"{text}"')
                )
                i += 1
            else:
                text = "".join(chr(b & 0x7F) for b in data[start:i])
                lines.append(
                    _format_line(label if start == 0 else "", "ASC", f'"{text}"')
                )
            label = ""
            continue
        lines.append(_format_line(label if i == 0 else "", "DB", f"${data[i]:02X}"))
        label = ""
        i += 1
    return lines, msb


def format_edasm(
    *,
    data: bytes,
    org: int = 0,
    directives: Sequence[Any] | None = None,
    predefined_symbols: Mapping[str, int] | None = None,
    sweet16_heuristic: bool = False,
) -> str:
    directive_list = list(directives or [])
    decoded_by_address = _decode_map(data, org, directive_list, sweet16_heuristic)
    merged_symbols = discover_symbols(
        decoded_by_address=decoded_by_address,
        directives=directive_list,
        predefined_symbols=dict(predefined_symbols or {}),
        seeded_entries=_entry_points(directive_list),
    )
    symbols_by_address = _address_to_symbol(merged_symbols)

    lines = [_format_line("", "ORG", f"${org & 0xFFFF:04X}")]
    offset = 0
    current_msb = None
    active_engine = "65c02"

    while offset < len(data):
        address = org + offset
        d = _get_directive_at(address, directive_list)
        if d:
            lines.append(f"* control {d.raw}")
            if d.kind == "SW16":
                active_engine = "sweet16"
            elif d.kind == "CODE":
                active_engine = "65c02"

        label = symbols_by_address.get(address, "")
        kind = _resolve_kind(address, directive_list)

        if kind in _EXECUTABLE_KINDS and address in decoded_by_address:
            instruction = decoded_by_address[address]
            engine = getattr(instruction, "engine", "65c02")
            if engine != active_engine:
                lines.append(f"* control heuristic {engine}")
                active_engine = engine
            mnemonic = str(getattr(instruction, "mnemonic", "DB")).lstrip(".").upper()
            operand_text = str(getattr(instruction, "operand", ""))
            operand = (
                operand_text
                if mnemonic == "DB"
                else _render_operand(operand_text, symbols_by_address)
            )
            span_length = max(1, int(getattr(instruction, "length", 1)))
            lines.append(_format_line(label, mnemonic, operand))
            _append_interior_labels(
                lines,
                address=address,
                length=span_length,
                symbols_by_address=symbols_by_address,
            )
            offset += span_length
            continue

        if kind == "TEXT":
            run_length = _contiguous_kind_length(
                len(data), org, offset, directive_list, "TEXT"
            )
            span_length = _next_symbol_boundary(address, run_length, symbols_by_address)
            text_lines, new_msb = _format_text_block(
                label, data[offset : offset + span_length], current_msb
            )
            lines.extend(text_lines)
            current_msb = new_msb
            offset += span_length
            continue

        if kind == "DW":
            if len(data) - offset >= 2:
                if (address + 1) in symbols_by_address:
                    lines.append(_format_line(label, "DB", f"${data[offset]:02X}"))
                    offset += 1
                else:
                    value = data[offset] | (data[offset + 1] << 8)
                    lines.append(_format_line(label, "DW", f"${value:04X}"))
                    offset += 2
            else:
                lines.append(_format_line(label, "DB", f"${data[offset]:02X}"))
                offset += 1
            continue

        lines.append(_format_line(label, "DB", f"${data[offset]:02X}"))
        offset += 1
    return "\n".join(lines)


__all__ = ["format_edasm"]
