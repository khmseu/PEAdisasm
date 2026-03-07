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

decode_instruction = module.decode_instruction
decode_sweet16 = module.decode_sweet16
OPCODES_SWEET16 = module.OPCODES_SWEET16


class TestDecodeSweet16(unittest.TestCase):
    def test_opcode_table_is_complete(self) -> None:
        self.assertEqual(len(OPCODES_SWEET16), 256)

    def test_non_branch_set_instruction(self) -> None:
        inst = decode_sweet16(bytes([0x12, 0x34, 0x12]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "SET")
        self.assertEqual(inst.operand, "R2,#$1234")
        self.assertEqual(inst.length, 3)
        self.assertIsNone(inst.branch_target)

    def test_branch_instruction_target_signed_offset(self) -> None:
        inst = decode_sweet16(bytes([0x01, 0xFE]), pc=0x2000)

        self.assertEqual(inst.mnemonic, "BR")
        self.assertEqual(inst.operand, "$2000")
        self.assertEqual(inst.length, 2)
        self.assertEqual(inst.branch_target, 0x2000)

    def test_decode_path_heuristic_flag_switches_engine(self) -> None:
        inst = decode_instruction(
            bytes([0x01, 0x02]), pc=0x3000, sweet16_heuristic=True
        )

        self.assertEqual(inst.engine, "sweet16")
        self.assertTrue(inst.sweet16_heuristic_enabled)
        self.assertEqual(inst.mnemonic, "BR")
        self.assertEqual(inst.branch_target, 0x3004)

    def test_register_operand_forms(self) -> None:
        inst_reg = decode_sweet16(bytes([0x2A]), pc=0x2100)
        inst_reg_ind = decode_sweet16(bytes([0x4F]), pc=0x2100)

        self.assertEqual(inst_reg.mnemonic, "LD")
        self.assertEqual(inst_reg.operand, "R10")
        self.assertEqual(inst_reg.length, 1)

        self.assertEqual(inst_reg_ind.mnemonic, "LD")
        self.assertEqual(inst_reg_ind.operand, "@R15")
        self.assertEqual(inst_reg_ind.length, 1)

    def test_bs_relative_target(self) -> None:
        inst = decode_sweet16(bytes([0x0C, 0xFE]), pc=0x2200)

        self.assertEqual(inst.mnemonic, "BS")
        self.assertEqual(inst.operand, "$2200")
        self.assertEqual(inst.length, 2)
        self.assertEqual(inst.branch_target, 0x2200)


if __name__ == "__main__":
    unittest.main()
