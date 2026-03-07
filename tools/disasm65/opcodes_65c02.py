from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AddressingMode65C02 = Literal["imp", "imm", "abs", "absx", "zp", "rel"]


@dataclass(frozen=True)
class Opcode65C02:
    mnemonic: str
    mode: AddressingMode65C02
    length: int


# Minimal representative 65C02 set for phase 3 decode coverage.
OPCODES_65C02: dict[int, Opcode65C02] = {
    0xEA: Opcode65C02(mnemonic="NOP", mode="imp", length=1),
    0xA9: Opcode65C02(mnemonic="LDA", mode="imm", length=2),
    0x4C: Opcode65C02(mnemonic="JMP", mode="abs", length=3),
    0xBD: Opcode65C02(mnemonic="LDA", mode="absx", length=3),
    0xA5: Opcode65C02(mnemonic="LDA", mode="zp", length=2),
    0xD0: Opcode65C02(mnemonic="BNE", mode="rel", length=2),
}
