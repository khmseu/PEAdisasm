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
        self.assertIn("the following arguments are required: input", result.stderr.lower())

    def test_valid_args_print_phase1_message(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
            result = self.run_cli(
                tmp.name,
                "--org",
                "4096",
                "--control",
                "control.txt",
                "--symbols",
                "symbols.txt",
                "--sweet16-heuristic",
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("not implemented", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
