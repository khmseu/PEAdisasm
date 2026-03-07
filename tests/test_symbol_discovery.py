import importlib.util
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYZE_PATH = REPO_ROOT / "tools" / "disasm65" / "analyze.py"
MODEL_PATH = REPO_ROOT / "tools" / "disasm65" / "model.py"


analyze_spec = importlib.util.spec_from_file_location("disasm65_analyze", ANALYZE_PATH)
if analyze_spec is None or analyze_spec.loader is None:
    raise RuntimeError("Unable to load disasm65 analyze module")
analyze_module = importlib.util.module_from_spec(analyze_spec)
sys.modules[analyze_spec.name] = analyze_module
analyze_spec.loader.exec_module(analyze_module)

model_spec = importlib.util.spec_from_file_location("disasm65_model", MODEL_PATH)
if model_spec is None or model_spec.loader is None:
    raise RuntimeError("Unable to load disasm65 model module")
model_module = importlib.util.module_from_spec(model_spec)
sys.modules[model_spec.name] = model_module
model_spec.loader.exec_module(model_module)


discover_symbols = analyze_module.discover_symbols
AddressRange = model_module.AddressRange


@dataclass(frozen=True)
class FakeInstruction:
    mnemonic: str
    operand: str
    length: int
    branch_target: int | None = None


class TestSymbolDiscovery(unittest.TestCase):
    def test_new_label_created_for_code_target(self) -> None:
        decoded = {
            0x1000: FakeInstruction(
                mnemonic="BNE", operand="$1007", length=2, branch_target=0x1007
            ),
            0x1002: FakeInstruction(mnemonic="JMP", operand="$1234", length=3),
            0x1200: FakeInstruction(
                mnemonic="BNE", operand="$1204", length=2, branch_target=0x1204
            ),
        }

        symbols = discover_symbols(
            decoded_by_address=decoded,
            code_ranges=[AddressRange(start=0x1000, end=0x10FF)],
            predefined_symbols={},
            seeded_entries=[],
        )

        self.assertEqual(symbols["L1007"], 0x1007)
        self.assertEqual(symbols["L1234"], 0x1234)
        self.assertNotIn("L1204", symbols)

    def test_predefined_symbol_precedence(self) -> None:
        decoded = {
            0x1000: FakeInstruction(
                mnemonic="BNE", operand="$1007", length=2, branch_target=0x1007
            ),
        }

        symbols = discover_symbols(
            decoded_by_address=decoded,
            code_ranges=[AddressRange(start=0x1000, end=0x10FF)],
            predefined_symbols={"RESET": 0x1007},
            seeded_entries=[],
        )

        self.assertEqual(symbols["RESET"], 0x1007)
        self.assertNotIn("L1007", symbols)

    def test_seeded_entries_create_stable_auto_labels(self) -> None:
        symbols = discover_symbols(
            decoded_by_address={},
            code_ranges=[],
            predefined_symbols={},
            seeded_entries=[0x2000, 0x1FFF],
        )

        self.assertEqual(symbols["L1FFF"], 0x1FFF)
        self.assertEqual(symbols["L2000"], 0x2000)

    def test_discovers_data_reference_labels_from_code_operands(self) -> None:
        decoded = {
            0x3000: FakeInstruction(mnemonic="LDA", operand="$1234", length=3),
            0x3003: FakeInstruction(mnemonic="STA", operand="$2000,Y", length=3),
            0x3006: FakeInstruction(mnemonic="ORA", operand="($44)", length=2),
            0x3008: FakeInstruction(mnemonic="JMP", operand="($3456)", length=3),
        }

        symbols = discover_symbols(
            decoded_by_address=decoded,
            code_ranges=[AddressRange(start=0x3000, end=0x30FF)],
            predefined_symbols={},
            seeded_entries=[],
        )

        self.assertEqual(symbols["L1234"], 0x1234)
        self.assertEqual(symbols["L2000"], 0x2000)
        self.assertEqual(symbols["L0044"], 0x0044)
        self.assertEqual(symbols["L3456"], 0x3456)

    def test_discovers_bbr_bbs_zero_page_operand_and_branch_target(self) -> None:
        decoded = {
            0x3200: FakeInstruction(
                mnemonic="BBR1",
                operand="$44,$3210",
                length=3,
                branch_target=0x3210,
            )
        }

        symbols = discover_symbols(
            decoded_by_address=decoded,
            code_ranges=[AddressRange(start=0x3200, end=0x32FF)],
            predefined_symbols={},
            seeded_entries=[],
        )

        self.assertEqual(symbols["L0044"], 0x0044)
        self.assertEqual(symbols["L3210"], 0x3210)

    def test_ignores_immediate_and_db_operands_for_data_discovery(self) -> None:
        decoded = {
            0x3400: FakeInstruction(mnemonic="LDA", operand="#$44", length=2),
            0x3402: FakeInstruction(mnemonic="DB", operand="$1234", length=1),
            0x3403: FakeInstruction(mnemonic=".DB", operand="$3456", length=1),
        }

        symbols = discover_symbols(
            decoded_by_address=decoded,
            code_ranges=[AddressRange(start=0x3400, end=0x34FF)],
            predefined_symbols={},
            seeded_entries=[],
        )

        self.assertEqual(symbols, {})


if __name__ == "__main__":
    unittest.main()
