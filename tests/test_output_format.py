import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "tools" / "disasm65.py"
FORMAT_PATH = REPO_ROOT / "tools" / "disasm65" / "format_edasm.py"
CONTROL_PATH = REPO_ROOT / "tools" / "disasm65" / "control.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures"


format_spec = importlib.util.spec_from_file_location("disasm65_format", FORMAT_PATH)
if format_spec is None or format_spec.loader is None:
    raise RuntimeError("Unable to load disasm65 format module")
format_module = importlib.util.module_from_spec(format_spec)
sys.modules[format_spec.name] = format_module
format_spec.loader.exec_module(format_module)

control_spec = importlib.util.spec_from_file_location("disasm65_control", CONTROL_PATH)
if control_spec is None or control_spec.loader is None:
    raise RuntimeError("Unable to load disasm65 control module")
control_module = importlib.util.module_from_spec(control_spec)
sys.modules[control_spec.name] = control_module
control_spec.loader.exec_module(control_module)


format_edasm = format_module.format_edasm
parse_control = control_module.parse_control


class TestOutputFormat(unittest.TestCase):
    def test_formats_label_opcode_operand_alignment(self) -> None:
        output = format_edasm(
            data=bytes([0xEA]),
            org=0x2000,
            directives=parse_control("CODE $2000,$2000"),
            predefined_symbols={"NOPLOC": 0x2000},
        )

        lines = output.splitlines()
        self.assertEqual(lines[0], "            ORG    $2000")
        self.assertRegex(lines[1], r"^NOPLOC\s+NOP$")
        self.assertNotIn(":", lines[1])

    def test_emits_db_and_asc_for_forced_regions(self) -> None:
        output = format_edasm(
            data=bytes([0x48, 0x49, 0x00]),
            org=0x3000,
            directives=parse_control("TEXT $3000,$3001\nDATA $3002,$3002"),
            predefined_symbols={},
        )

        self.assertIn('ASC    "HI"', output)
        self.assertIn("DB     $00", output)

    def test_instruction_does_not_cross_into_data_region(self) -> None:
        output = format_edasm(
            data=bytes([0x4C, 0x34, 0x12]),
            org=0x4000,
            directives=parse_control("CODE $4000,$4000\nDATA $4001,$4002"),
            predefined_symbols={},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $4000",
                "            DB     $4C",
                "            DB     $34",
                "            DB     $12",
            ],
        )

    def test_instruction_does_not_cross_into_sw16_region(self) -> None:
        output = format_edasm(
            data=bytes([0x4C, 0x00, 0xEA]),
            org=0x4100,
            directives=parse_control("CODE $4100,$4100\nSW16 $4101,$4102"),
            predefined_symbols={},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $4100",
                "            DB     $4C",
                "            RTN",
                "            INR    R10",
            ],
        )

    def test_sw16_directive_changes_decode_output(self) -> None:
        output = format_edasm(
            data=bytes([0x00, 0xEA]),
            org=0x4200,
            directives=parse_control("SW16 $4200,$4200\nCODE $4201,$4201"),
            predefined_symbols={},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $4200",
                "            RTN",
                "            NOP",
            ],
        )

    def test_end_to_end_fixture_output_via_cli(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                str(FIXTURE_DIR / "phase5_sample.bin"),
                "--org",
                "0x1000",
                "--control",
                str(FIXTURE_DIR / "phase5_sample.ctl"),
                "--symbols",
                str(FIXTURE_DIR / "phase5_sample.equ"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "            ORG    $1000",
                "START       LDA    #$41",
                "            BNE    L1007",
                '            ASC    "HI"',
                "            DB     $00",
                "L1007       JMP    START",
            ],
        )


if __name__ == "__main__":
    unittest.main()
