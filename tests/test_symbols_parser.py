import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SYMBOLS_PATH = REPO_ROOT / "tools" / "disasm65" / "symbols.py"


spec = importlib.util.spec_from_file_location("disasm65_symbols", SYMBOLS_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load disasm65 symbols module")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

parse_symbols = module.parse_symbols


class TestSymbolsParser(unittest.TestCase):
    def test_parse_equ_hex_decimal_and_ignore_comments(self) -> None:
        text = """
        ; predefined symbols

        RESET EQU $1234
        START EQU 4660
        ; trailing line comment
        """

        symbols = parse_symbols(text)

        self.assertEqual(symbols["RESET"], 0x1234)
        self.assertEqual(symbols["START"], 4660)
        self.assertEqual(len(symbols), 2)

    def test_rejects_malformed_equ_line(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed EQU"):
            parse_symbols("BROKEN $1234")

    def test_rejects_invalid_number(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid number"):
            parse_symbols("BAD EQU $GG")


if __name__ == "__main__":
    unittest.main()
