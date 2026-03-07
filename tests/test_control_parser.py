import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_PATH = REPO_ROOT / "tools" / "disasm65" / "control.py"


spec = importlib.util.spec_from_file_location("disasm65_control", CONTROL_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load disasm65 control module")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

ControlDirective = module.ControlDirective
parse_control = module.parse_control


class TestControlParser(unittest.TestCase):
    def test_parse_all_supported_directives(self) -> None:
        text = """
        ; control script
        ORG $1000
        ENTRY 4096
        CODE $1000,$10FF
        DATA 4352,4607
        TEXT $2000,$2003
        TEXT $2100,$2105 DCI
        SW16 $3000,$30FF
        """

        directives = parse_control(text)

        self.assertEqual(
            directives,
            [
                ControlDirective(kind="ORG", address=0x1000),
                ControlDirective(kind="ENTRY", address=4096),
                ControlDirective(kind="CODE", start=0x1000, end=0x10FF),
                ControlDirective(kind="DATA", start=4352, end=4607),
                ControlDirective(kind="TEXT", start=0x2000, end=0x2003, subtype="ASC"),
                ControlDirective(kind="TEXT", start=0x2100, end=0x2105, subtype="DCI"),
                ControlDirective(kind="SW16", start=0x3000, end=0x30FF),
            ],
        )

    def test_unknown_directive_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown directive"):
            parse_control("FOO $1000")

    def test_bad_operand_count_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "operand"):
            parse_control("CODE $1000")

    def test_extra_operands_report_operand_count_errors(self) -> None:
        with self.assertRaisesRegex(ValueError, "operand"):
            parse_control("CODE $1000,$10FF EXTRA")

        with self.assertRaisesRegex(ValueError, "operand"):
            parse_control("TEXT $2000,$2003 DCI EXTRA")

        with self.assertRaisesRegex(ValueError, "operand"):
            parse_control("ORG $1000 $1001")


if __name__ == "__main__":
    unittest.main()
