import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = REPO_ROOT / "tools" / "disasm65" / "model.py"


spec = importlib.util.spec_from_file_location("disasm65_model", MODEL_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load disasm65 model module")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

AddressRange = module.AddressRange
Config = module.Config


class TestAddressRange(unittest.TestCase):
    def test_inclusive_size_and_contains(self) -> None:
        rng = AddressRange(start=0x1000, end=0x1003)

        self.assertEqual(rng.size, 4)
        self.assertTrue(rng.contains(0x1000))
        self.assertTrue(rng.contains(0x1003))
        self.assertFalse(rng.contains(0x1004))

    def test_start_greater_than_end_raises(self) -> None:
        with self.assertRaises(ValueError):
            AddressRange(start=0x2000, end=0x1FFF)


class TestConfig(unittest.TestCase):
    def test_config_defaults(self) -> None:
        cfg = Config(input_path=Path("input.bin"))

        self.assertEqual(cfg.org, 0)
        self.assertIsNone(cfg.control)
        self.assertIsNone(cfg.symbols)
        self.assertFalse(cfg.sweet16_heuristic)


if __name__ == "__main__":
    unittest.main()
