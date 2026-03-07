import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DECODE_PATH = REPO_ROOT / "tools" / "disasm65" / "decode.py"


spec = importlib.util.spec_from_file_location("disasm65_decode", DECODE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load disasm65 decode module")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

decode_65c02 = module.decode_65c02
OPCODES_65C02 = module.OPCODES_65C02


class TestDecode65C02(unittest.TestCase):
    def test_opcode_table_is_complete(self) -> None:
        self.assertEqual(len(OPCODES_65C02), 256)

    def test_implied_mode(self) -> None:
        inst = decode_65c02(bytes([0xEA]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "NOP")
        self.assertEqual(inst.operand, "")
        self.assertEqual(inst.length, 1)
        self.assertIsNone(inst.branch_target)

    def test_immediate_mode(self) -> None:
        inst = decode_65c02(bytes([0xA9, 0x44]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "LDA")
        self.assertEqual(inst.operand, "#$44")
        self.assertEqual(inst.length, 2)

    def test_absolute_mode(self) -> None:
        inst = decode_65c02(bytes([0x4C, 0x34, 0x12]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "JMP")
        self.assertEqual(inst.operand, "$1234")
        self.assertEqual(inst.length, 3)

    def test_absolute_indexed_mode(self) -> None:
        inst = decode_65c02(bytes([0xBD, 0x00, 0x20]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "LDA")
        self.assertEqual(inst.operand, "$2000,X")
        self.assertEqual(inst.length, 3)

    def test_zero_page_mode(self) -> None:
        inst = decode_65c02(bytes([0xA5, 0x80]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "LDA")
        self.assertEqual(inst.operand, "$80")
        self.assertEqual(inst.length, 2)

    def test_relative_branch_positive_offset(self) -> None:
        inst = decode_65c02(bytes([0xD0, 0x05]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "BNE")
        self.assertEqual(inst.operand, "$1007")
        self.assertEqual(inst.length, 2)
        self.assertEqual(inst.branch_target, 0x1007)

    def test_relative_branch_negative_offset(self) -> None:
        inst = decode_65c02(bytes([0xD0, 0xFC]), pc=0x1000)

        self.assertEqual(inst.mnemonic, "BNE")
        self.assertEqual(inst.operand, "$0FFE")
        self.assertEqual(inst.length, 2)
        self.assertEqual(inst.branch_target, 0x0FFE)

    def test_ldx_immediate_mode(self) -> None:
        inst = decode_65c02(bytes([0xA2, 0xF0]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "LDX")
        self.assertEqual(inst.operand, "#$F0")
        self.assertEqual(inst.length, 2)

    def test_sta_absolute_y_mode(self) -> None:
        inst = decode_65c02(bytes([0x99, 0x5C, 0xBF]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "STA")
        self.assertEqual(inst.operand, "$BF5C,Y")
        self.assertEqual(inst.length, 3)

    def test_lsr_accumulator_mode(self) -> None:
        inst = decode_65c02(bytes([0x4A]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "LSR")
        self.assertEqual(inst.operand, "A")
        self.assertEqual(inst.length, 1)

    def test_indirect_zero_page_mode(self) -> None:
        inst = decode_65c02(bytes([0x12, 0x44]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "ORA")
        self.assertEqual(inst.operand, "($44)")
        self.assertEqual(inst.length, 2)

    def test_indirect_absolute_indexed_x_mode(self) -> None:
        inst = decode_65c02(bytes([0x7C, 0x34, 0x12]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "JMP")
        self.assertEqual(inst.operand, "($1234,X)")
        self.assertEqual(inst.length, 3)

    def test_zero_page_relative_branch_mode(self) -> None:
        inst = decode_65c02(bytes([0x1F, 0x44, 0xFE]), pc=0x3000)

        self.assertEqual(inst.mnemonic, "BBR1")
        self.assertEqual(inst.operand, "$44,$3001")
        self.assertEqual(inst.length, 3)
        self.assertEqual(inst.branch_target, 0x3001)

    def test_brk_takes_signature_byte(self) -> None:
        inst = decode_65c02(bytes([0x00, 0xEA]), pc=0x4000)

        self.assertEqual(inst.mnemonic, "BRK")
        self.assertEqual(inst.operand, "#$EA")
        self.assertEqual(inst.length, 2)


if __name__ == "__main__":
    unittest.main()
