import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "tools" / "disasm65.py"


class TestCliSmoke(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CLI_PATH), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_help_includes_expected_options(self) -> None:
        result = self.run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())
        self.assertIn("--org", result.stdout)
        self.assertIn("--control", result.stdout)
        self.assertIn("--symbols", result.stdout)
        self.assertIn("--sweet16-heuristic", result.stdout)

    def test_missing_required_input_fails(self) -> None:
        result = self.run_cli()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "the following arguments are required: input", result.stderr.lower()
        )

    def test_valid_args_print_disassembly_output(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
            result = self.run_cli(
                tmp.name,
                "--org",
                "4096",
                "--sweet16-heuristic",
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("ORG", result.stdout)

    def test_control_org_used_when_org_not_provided(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".bin"
        ) as bin_file, tempfile.NamedTemporaryFile(
            suffix=".ctl", mode="w", encoding="utf-8"
        ) as ctl_file:
            bin_file.write(bytes([0xEA]))
            bin_file.flush()
            ctl_file.write("ORG $2000\nCODE $2000,$2000\n")
            ctl_file.flush()

            result = self.run_cli(bin_file.name, "--control", ctl_file.name)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines()[0], "            ORG    $2000")

    def test_explicit_org_zero_overrides_control_org(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".bin"
        ) as bin_file, tempfile.NamedTemporaryFile(
            suffix=".ctl", mode="w", encoding="utf-8"
        ) as ctl_file:
            bin_file.write(bytes([0xEA]))
            bin_file.flush()
            ctl_file.write("ORG $2000\nCODE $2000,$2000\n")
            ctl_file.flush()

            result = self.run_cli(
                bin_file.name, "--org", "0", "--control", ctl_file.name
            )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines()[0], "            ORG    $0000")

    def test_control_parse_error_includes_file_and_line(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".bin"
        ) as bin_file, tempfile.NamedTemporaryFile(
            suffix=".ctl", mode="w", encoding="utf-8"
        ) as ctl_file:
            bin_file.write(bytes([0xEA]))
            bin_file.flush()
            ctl_file.write("ORG $2000\nBORK $2000,$2000\n")
            ctl_file.flush()

            result = self.run_cli(bin_file.name, "--control", ctl_file.name)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{ctl_file.name}:2:1: unknown directive 'BORK'",
            result.stderr,
        )

    def test_symbols_parse_error_includes_file_and_line(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".bin"
        ) as bin_file, tempfile.NamedTemporaryFile(
            suffix=".equ", mode="w", encoding="utf-8"
        ) as sym_file:
            bin_file.write(bytes([0xEA]))
            bin_file.flush()
            sym_file.write("GOOD EQU $2000\nLASTIN WQU $2F\n")
            sym_file.flush()

            result = self.run_cli(bin_file.name, "--symbols", sym_file.name)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{sym_file.name}:2:1: malformed EQU line 'LASTIN WQU $2F'",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
