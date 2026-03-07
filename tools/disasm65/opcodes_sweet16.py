from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AddressingModeSweet16 = Literal["imp", "rel8"]


@dataclass(frozen=True)
class OpcodeSweet16:
    mnemonic: str
    mode: AddressingModeSweet16
    length: int


# Minimal representative Sweet16 set for phase 3 decode coverage.
OPCODES_SWEET16: dict[int, OpcodeSweet16] = {
    0x00: OpcodeSweet16(mnemonic="RTN", mode="imp", length=1),
    0x01: OpcodeSweet16(mnemonic="BR", mode="rel8", length=2),
}
