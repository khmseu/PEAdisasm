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

    def test_substitutes_symbols_for_common_data_operands(self) -> None:
        output = format_edasm(
            data=bytes(
                [
                    0xAD,
                    0x34,
                    0x12,
                    0xB9,
                    0x78,
                    0x56,
                    0x12,
                    0x44,
                    0x6C,
                    0x00,
                    0x20,
                    0x1F,
                    0x44,
                    0xFD,
                ]
            ),
            org=0x5000,
            directives=parse_control("CODE $5000,$500D"),
            predefined_symbols={
                "DATA1": 0x1234,
                "DATA2": 0x5678,
                "ZP44": 0x0044,
                "VEC": 0x2000,
                "TARGET": 0x5000,
            },
        )

        lines = output.splitlines()
        self.assertTrue(any("LDA    DATA1" in line for line in lines))
        self.assertTrue(any("LDA    DATA2,Y" in line for line in lines))
        self.assertTrue(any("ORA    (ZP44)" in line for line in lines))
        self.assertTrue(any("JMP    (VEC)" in line for line in lines))
        self.assertTrue(any("BBR1   ZP44,L500B" in line for line in lines))

    def test_auto_discovers_and_uses_data_label_in_operand(self) -> None:
        output = format_edasm(
            data=bytes([0xAD, 0x34, 0x12]),
            org=0x6000,
            directives=parse_control("CODE $6000,$6002"),
            predefined_symbols={},
        )

        lines = output.splitlines()
        self.assertEqual(lines[1], "            LDA    L1234")

    def test_db_literal_in_code_is_not_symbolized(self) -> None:
        output = format_edasm(
            data=bytes([0x4C, 0x34, 0x12]),
            org=0x6100,
            directives=parse_control("CODE $6100,$6100\nDATA $6101,$6102"),
            predefined_symbols={"SHOULD_NOT_APPEAR": 0x004C},
        )

        lines = output.splitlines()
        self.assertEqual(lines[1], "            DB     $4C")

    def test_jsr_bf00_consumes_inline_payload_and_resumes_decode(self) -> None:
        output = format_edasm(
            data=bytes([0x20, 0x00, 0xBF, 0x82, 0x34, 0x12, 0xEA]),
            org=0x6200,
            directives=parse_control("CODE $6200,$6206"),
            predefined_symbols={"PTR": 0x1234},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $6200",
                "            JSR    LBF00",
                "            DB     $82",
                "            DW     PTR",
                "            NOP",
            ],
        )

    def test_jsr_bf00_payload_truncation_falls_back_safely(self) -> None:
        output = format_edasm(
            data=bytes([0x20, 0x00, 0xBF, 0x82, 0x34]),
            org=0x6300,
            directives=parse_control("CODE $6300,$6304"),
            predefined_symbols={},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $6300",
                "            JSR    LBF00",
                "            DB     $82",
                "            DB     $34",
            ],
        )

    def test_dw_directive_outputs_words(self) -> None:
        output = format_edasm(
            data=bytes([0x34, 0x12, 0x78, 0x56]),
            org=0x7000,
            directives=parse_control("DW $7000,$7003"),
            predefined_symbols={},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $7000",
                "            DW     $1234",
                "            DW     $5678",
            ],
        )

    def test_dw_directive_with_odd_byte_falls_back_to_db(self) -> None:
        output = format_edasm(
            data=bytes([0x34, 0x12, 0xFF]),
            org=0x7100,
            directives=parse_control("DW $7100,$7102"),
            predefined_symbols={},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $7100",
                "            DW     $1234",
                "            DB     $FF",
            ],
        )

    def test_text_region_splits_at_symbol_address(self) -> None:
        output = format_edasm(
            data=bytes([0x41, 0x42]),
            org=0x7200,
            directives=parse_control("TEXT $7200,$7201"),
            predefined_symbols={"MIDTXT": 0x7201},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $7200",
                '            ASC    "A"',
                'MIDTXT      ASC    "B"',
            ],
        )

    def test_dw_region_splits_when_symbol_is_mid_word(self) -> None:
        output = format_edasm(
            data=bytes([0x34, 0x12]),
            org=0x7300,
            directives=parse_control("DW $7300,$7301"),
            predefined_symbols={"MIDWORD": 0x7301},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $7300",
                "            DB     $34",
                "MIDWORD     DB     $12",
            ],
        )

    def test_code_symbol_inside_instruction_emits_standalone_label(self) -> None:
        output = format_edasm(
            data=bytes([0x4C, 0x34, 0x12]),
            org=0x7400,
            directives=parse_control("CODE $7400,$7402"),
            predefined_symbols={"MIDCODE": 0x7401},
        )

        self.assertEqual(
            output.splitlines(),
            [
                "            ORG    $7400",
                "            JMP    L1234",
                "MIDCODE     ",
            ],
        )


if __name__ == "__main__":
    unittest.main()
