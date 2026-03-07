from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AddressingModeSweet16 = Literal["imp", "rel8", "reg", "reg_ind", "reg_imm16"]


@dataclass(frozen=True)
class OpcodeSweet16:
    mnemonic: str
    mode: AddressingModeSweet16
    length: int


_LENGTHS: dict[AddressingModeSweet16, int] = {
    "imp": 1,
    "rel8": 2,
    "reg": 1,
    "reg_ind": 1,
    "reg_imm16": 3,
}


def _op(mnemonic: str, mode: AddressingModeSweet16) -> OpcodeSweet16:
    return OpcodeSweet16(mnemonic=mnemonic, mode=mode, length=_LENGTHS[mode])


# 0x00-0x0F control and branch opcodes.
_LOW_NIBBLE_OPS: dict[int, tuple[str, AddressingModeSweet16]] = {
    0x00: ("RTN", "imp"),
    0x01: ("BR", "rel8"),
    0x02: ("BNC", "rel8"),
    0x03: ("BC", "rel8"),
    0x04: ("BP", "rel8"),
    0x05: ("BM", "rel8"),
    0x06: ("BZ", "rel8"),
    0x07: ("BNZ", "rel8"),
    0x08: ("BM1", "rel8"),
    0x09: ("BNM1", "rel8"),
    0x0A: ("BK", "imp"),
    0x0B: ("RS", "imp"),
    0x0C: ("BS", "rel8"),
    0x0D: ("NUL", "imp"),
    0x0E: ("NUL", "imp"),
    0x0F: ("NUL", "imp"),
}


# 0x10-0xFF register-family opcodes (high nibble selects operation).
_REGISTER_GROUPS: dict[int, tuple[str, AddressingModeSweet16]] = {
    0x1: ("SET", "reg_imm16"),
    0x2: ("LD", "reg"),
    0x3: ("ST", "reg"),
    0x4: ("LD", "reg_ind"),
    0x5: ("ST", "reg_ind"),
    0x6: ("LDD", "reg_ind"),
    0x7: ("STD", "reg_ind"),
    0x8: ("POP", "reg_ind"),
    0x9: ("STP", "reg_ind"),
    0xA: ("ADD", "reg"),
    0xB: ("SUB", "reg"),
    0xC: ("POPD", "reg_ind"),
    0xD: ("CPR", "reg"),
    0xE: ("INR", "reg"),
    0xF: ("DCR", "reg"),
}


OPCODES_SWEET16: dict[int, OpcodeSweet16] = {}

for opcode, (mnemonic, mode) in _LOW_NIBBLE_OPS.items():
    OPCODES_SWEET16[opcode] = _op(mnemonic, mode)

for high_nibble, (mnemonic, mode) in _REGISTER_GROUPS.items():
    for reg in range(0x10):
        opcode = (high_nibble << 4) | reg
        OPCODES_SWEET16[opcode] = _op(mnemonic, mode)

if len(OPCODES_SWEET16) != 0x100:
    raise RuntimeError("Sweet16 opcode map must contain 256 entries")
