from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


def _load_merge_symbol_maps() -> Any:
    try:
        from tools.disasm65.symbols import merge_symbol_maps as imported

        return imported
    except ImportError:
        pass

    try:  # pragma: no cover - package import fallback
        from .symbols import merge_symbol_maps as imported

        return imported
    except ImportError:
        pass

    module_path = Path(__file__).with_name("symbols.py")
    spec = importlib.util.spec_from_file_location(
        "disasm65_symbols_runtime", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load symbols module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.merge_symbol_maps


merge_symbol_maps = _load_merge_symbol_maps()


_REGION_PRECEDENCE = ("TEXT", "SW16", "DW", "DATA", "CODE")
_EXECUTABLE_KINDS = {"CODE", "SW16"}
_SIMPLE_ADDRESS_RE = re.compile(r"^\$([0-9A-Fa-f]{1,4})(?:,(X|Y))?$")
_INDIRECT_RE = re.compile(r"^\(\$([0-9A-Fa-f]{1,4})\)$")
_INDIRECT_PREINDEX_RE = re.compile(r"^\(\$([0-9A-Fa-f]{1,4}),(X|Y)\)$")
_INDIRECT_POSTINDEX_RE = re.compile(r"^\(\$([0-9A-Fa-f]{1,4})\),(X|Y)$")
_ZPREL_RE = re.compile(r"^\$([0-9A-Fa-f]{1,4}),\$([0-9A-Fa-f]{1,4})$")


def _normalize_kind(kind: str) -> str:
    return kind.upper()


def resolve_region_kind(
    address: int, directives: Iterable[Any], fallback_kind: str = "CODE"
) -> str:
    """Resolve region kind using directive precedence and inclusive boundaries."""
    matched_kinds: set[str] = set()

    for directive in directives:
        kind = _normalize_kind(getattr(directive, "kind", ""))
        if kind not in _REGION_PRECEDENCE:
            continue

        start = getattr(directive, "start", None)
        end = getattr(directive, "end", None)
        if start is None or end is None:
            continue

        if start <= address <= end:
            matched_kinds.add(kind)

    for kind in _REGION_PRECEDENCE:
        if kind in matched_kinds:
            return kind

    return _normalize_kind(fallback_kind)


def _in_ranges(address: int, ranges: Iterable[Any]) -> bool:
    return any(rng.contains(address) for rng in ranges)


def _addresses_from_operand(mnemonic: str, operand: str) -> set[int]:
    if not operand or operand.startswith("#"):
        return set()

    match = _SIMPLE_ADDRESS_RE.match(operand)
    if match is not None:
        return {int(match.group(1), 16) & 0xFFFF}

    match = _INDIRECT_RE.match(operand)
    if match is not None:
        return {int(match.group(1), 16) & 0xFFFF}

    match = _INDIRECT_PREINDEX_RE.match(operand)
    if match is not None:
        return {int(match.group(1), 16) & 0xFFFF}

    match = _INDIRECT_POSTINDEX_RE.match(operand)
    if match is not None:
        return {int(match.group(1), 16) & 0xFFFF}

    # BBR/BBS use zp,rel; we discover both the tested zp location and target.
    match = _ZPREL_RE.match(operand)
    if match is not None and mnemonic.startswith(("BBR", "BBS")):
        return {
            int(match.group(1), 16) & 0xFFFF,
            int(match.group(2), 16) & 0xFFFF,
        }

    return set()


def _extract_targets(instruction: Any) -> set[int]:
    targets: set[int] = set()

    branch_target = getattr(instruction, "branch_target", None)
    if branch_target is not None:
        targets.add(int(branch_target) & 0xFFFF)

    mnemonic = _normalize_kind(getattr(instruction, "mnemonic", ""))
    if mnemonic in {"DB", ".DB"}:
        return targets

    operand = str(getattr(instruction, "operand", ""))
    targets.update(_addresses_from_operand(mnemonic, operand))
    return targets


def discover_symbol_targets(
    decoded_by_address: Mapping[int, Any],
    *,
    code_ranges: Iterable[Any] | None = None,
    directives: Iterable[Any] | None = None,
    seeded_entries: Iterable[int] | None = None,
    fallback_kind: str = "CODE",
) -> set[int]:
    """Collect branch/jump/call targets from executable regions and seeded entries."""
    targets: set[int] = {int(entry) & 0xFFFF for entry in (seeded_entries or [])}

    ranges = list(code_ranges or [])
    directive_list = list(directives or [])

    for address in sorted(decoded_by_address):
        if directive_list:
            resolved = resolve_region_kind(
                address, directive_list, fallback_kind=fallback_kind
            )
            if resolved not in _EXECUTABLE_KINDS:
                continue
        elif ranges and not _in_ranges(address, ranges):
            continue

        targets.update(_extract_targets(decoded_by_address[address]))

    return targets


def discover_symbols(
    decoded_by_address: Mapping[int, Any],
    *,
    code_ranges: Iterable[Any] | None = None,
    directives: Iterable[Any] | None = None,
    predefined_symbols: Mapping[str, int] | None = None,
    seeded_entries: Iterable[int] | None = None,
    fallback_kind: str = "CODE",
) -> dict[str, int]:
    targets = discover_symbol_targets(
        decoded_by_address,
        code_ranges=code_ranges,
        directives=directives,
        seeded_entries=seeded_entries,
        fallback_kind=fallback_kind,
    )

    return merge_symbol_maps(predefined_symbols or {}, targets)
