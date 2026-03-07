from __future__ import annotations

from dataclasses import dataclass, replace

try:
    from tools.disasm65.opcodes_65c02 import OPCODES_65C02
    from tools.disasm65.opcodes_sweet16 import OPCODES_SWEET16
except ImportError:  # pragma: no cover - package import fallback
    from .opcodes_65c02 import OPCODES_65C02
    from .opcodes_sweet16 import OPCODES_SWEET16


@dataclass(frozen=True)
class DecodedInstruction:
    mnemonic: str
    operand: str
    length: int
    branch_target: int | None = None
    engine: str = "65c02"
    sweet16_heuristic_enabled: bool = False


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _u16(lo: int, hi: int) -> int:
    return lo | (hi << 8)


def _require_bytes(data: bytes, required: int, opcode: int) -> None:
    if len(data) < required:
        raise ValueError(f"opcode ${opcode:02X} requires {required} bytes")


def decode_65c02(data: bytes, pc: int = 0) -> DecodedInstruction:
    if not data:
        raise ValueError("no instruction bytes provided")

    opcode = data[0]
    info = OPCODES_65C02.get(opcode)
    if info is None:
        return DecodedInstruction(
            mnemonic=".DB", operand=f"${opcode:02X}", length=1, engine="65c02"
        )

    _require_bytes(data, info.length, opcode)

    if info.mode == "imp":
        return DecodedInstruction(
            mnemonic=info.mnemonic, operand="", length=info.length, engine="65c02"
        )

    if info.mode == "imm":
        operand = f"#${data[1]:02X}"
        return DecodedInstruction(
            mnemonic=info.mnemonic, operand=operand, length=info.length, engine="65c02"
        )

    if info.mode == "zp":
        operand = f"${data[1]:02X}"
        return DecodedInstruction(
            mnemonic=info.mnemonic, operand=operand, length=info.length, engine="65c02"
        )

    if info.mode == "abs":
        address = _u16(data[1], data[2])
        operand = f"${address:04X}"
        return DecodedInstruction(
            mnemonic=info.mnemonic, operand=operand, length=info.length, engine="65c02"
        )

    if info.mode == "absx":
        address = _u16(data[1], data[2])
        operand = f"${address:04X},X"
        return DecodedInstruction(
            mnemonic=info.mnemonic, operand=operand, length=info.length, engine="65c02"
        )

    if info.mode == "rel":
        offset = _signed8(data[1])
        target = (pc + info.length + offset) & 0xFFFF
        operand = f"${target:04X}"
        return DecodedInstruction(
            mnemonic=info.mnemonic,
            operand=operand,
            length=info.length,
            branch_target=target,
            engine="65c02",
        )

    raise ValueError(f"unsupported 65C02 mode {info.mode!r}")


def decode_sweet16(data: bytes, pc: int = 0) -> DecodedInstruction:
    if not data:
        raise ValueError("no instruction bytes provided")

    opcode = data[0]

    if opcode >> 4 == 0x1:
        _require_bytes(data, 3, opcode)
        reg = opcode & 0x0F
        value = _u16(data[1], data[2])
        operand = f"R{reg},#${value:04X}"
        return DecodedInstruction(
            mnemonic="SET", operand=operand, length=3, engine="sweet16"
        )

    info = OPCODES_SWEET16.get(opcode)
    if info is None:
        return DecodedInstruction(
            mnemonic=".DB", operand=f"${opcode:02X}", length=1, engine="sweet16"
        )

    _require_bytes(data, info.length, opcode)

    if info.mode == "imp":
        return DecodedInstruction(
            mnemonic=info.mnemonic, operand="", length=info.length, engine="sweet16"
        )

    if info.mode == "rel8":
        offset = _signed8(data[1])
        target = (pc + info.length + offset) & 0xFFFF
        operand = f"${target:04X}"
        return DecodedInstruction(
            mnemonic=info.mnemonic,
            operand=operand,
            length=info.length,
            branch_target=target,
            engine="sweet16",
        )

    raise ValueError(f"unsupported Sweet16 mode {info.mode!r}")


def _looks_like_sweet16(data: bytes) -> bool:
    if not data:
        return False
    opcode = data[0]
    return opcode in OPCODES_SWEET16 or opcode >> 4 == 0x1


def decode_instruction(
    data: bytes,
    pc: int = 0,
    *,
    sweet16_mode: bool = False,
    sweet16_heuristic: bool = False,
) -> DecodedInstruction:
    use_sweet16 = sweet16_mode or (sweet16_heuristic and _looks_like_sweet16(data))

    decoded = decode_sweet16(data, pc=pc) if use_sweet16 else decode_65c02(data, pc=pc)

    if decoded.sweet16_heuristic_enabled == sweet16_heuristic:
        return decoded
    return replace(decoded, sweet16_heuristic_enabled=sweet16_heuristic)
