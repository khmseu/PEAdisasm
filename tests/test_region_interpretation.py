import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYZE_PATH = REPO_ROOT / "tools" / "disasm65" / "analyze.py"
CONTROL_PATH = REPO_ROOT / "tools" / "disasm65" / "control.py"


analyze_spec = importlib.util.spec_from_file_location("disasm65_analyze", ANALYZE_PATH)
if analyze_spec is None or analyze_spec.loader is None:
    raise RuntimeError("Unable to load disasm65 analyze module")
analyze_module = importlib.util.module_from_spec(analyze_spec)
sys.modules[analyze_spec.name] = analyze_module
analyze_spec.loader.exec_module(analyze_module)

control_spec = importlib.util.spec_from_file_location("disasm65_control", CONTROL_PATH)
if control_spec is None or control_spec.loader is None:
    raise RuntimeError("Unable to load disasm65 control module")
control_module = importlib.util.module_from_spec(control_spec)
sys.modules[control_spec.name] = control_module
control_spec.loader.exec_module(control_module)


resolve_region_kind = analyze_module.resolve_region_kind
ControlDirective = control_module.ControlDirective


class TestRegionInterpretation(unittest.TestCase):
    def test_data_text_regions_override_decode_fallback(self) -> None:
        directives = [
            ControlDirective(kind="DATA", start=0x2000, end=0x2000),
            ControlDirective(kind="TEXT", start=0x2001, end=0x2001),
            ControlDirective(kind="SW16", start=0x2002, end=0x2002),
            ControlDirective(kind="CODE", start=0x2003, end=0x2003),
        ]

        self.assertEqual(resolve_region_kind(0x2000, directives, fallback_kind="CODE"), "DATA")
        self.assertEqual(resolve_region_kind(0x2001, directives, fallback_kind="CODE"), "TEXT")
        self.assertEqual(resolve_region_kind(0x2002, directives, fallback_kind="CODE"), "SW16")
        self.assertEqual(resolve_region_kind(0x2003, directives, fallback_kind="DATA"), "CODE")
        self.assertEqual(resolve_region_kind(0x2004, directives, fallback_kind="CODE"), "CODE")

    def test_explicit_precedence_with_overlap(self) -> None:
        directives = [
            ControlDirective(kind="CODE", start=0x3000, end=0x3000),
            ControlDirective(kind="DATA", start=0x3000, end=0x3000),
            ControlDirective(kind="SW16", start=0x3000, end=0x3000),
            ControlDirective(kind="TEXT", start=0x3000, end=0x3000),
        ]

        self.assertEqual(resolve_region_kind(0x3000, directives, fallback_kind="CODE"), "TEXT")

    def test_inclusive_boundaries(self) -> None:
        directives = [ControlDirective(kind="DATA", start=0x4000, end=0x4002)]

        self.assertEqual(resolve_region_kind(0x4000, directives, fallback_kind="CODE"), "DATA")
        self.assertEqual(resolve_region_kind(0x4002, directives, fallback_kind="CODE"), "DATA")
        self.assertEqual(resolve_region_kind(0x4003, directives, fallback_kind="CODE"), "CODE")


if __name__ == "__main__":
    unittest.main()
