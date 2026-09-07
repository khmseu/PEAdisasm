from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.disasm65.format_edasm import format_edasm


def test_textc_single_msb_printable():
    # Single printable byte with MSB set should emit .textc "X"
    data = bytes([0x80 | ord("A")])
    directives = [SimpleNamespace(kind="TEXT", start=0, raw=".text")]
    out = format_edasm(data=data, org=0, directives=directives)
    assert '.textc "A"' in out


def test_msb_multi_byte_emit_bytes():
    # Multi-byte MSB run must be emitted as explicit .byte values
    a = 0x80 | ord("A")
    b = 0x80 | ord("B")
    data = bytes([a, b])
    directives = [SimpleNamespace(kind="TEXT", start=0, raw=".text")]
    out = format_edasm(data=data, org=0, directives=directives)
    import re

    assert re.search(rf"\.byte\s+\${a:02X}", out)
    assert re.search(rf"\.byte\s+\${b:02X}", out)


def test_text_plain():
    # Plain 7-bit printable run should use .text
    data = b"HELLO"
    directives = [SimpleNamespace(kind="TEXT", start=0, raw=".text")]
    out = format_edasm(data=data, org=0, directives=directives)
    import re

    assert re.search(r'\.text\s+"HELLO"', out)


def test_label_colon_normalization():
    # Names provided with one or more trailing colons should normalize to a single colon
    directives = [SimpleNamespace(kind="TEXT", start=0, raw=".text")]
    out1 = format_edasm(
        data=b"\x00", org=0, directives=directives, predefined_symbols={"LOOP:": 0}
    )
    assert "LOOP:" in out1

    out2 = format_edasm(
        data=b"\x00", org=0, directives=directives, predefined_symbols={"LOOP::": 0}
    )
    # Should show a single trailing colon, not a double
    assert "LOOP:" in out2 and "LOOP::" not in out2
