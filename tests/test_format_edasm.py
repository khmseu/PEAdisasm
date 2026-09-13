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


def test_end_of_binary_predefined_label():
    # A symbol at org + len(data) should be output as a standalone label after the binary
    data = bytes([0xEA])  # NOP at $1000
    out = format_edasm(data=data, org=0x1000, predefined_symbols={"END_PROG": 0x1001})
    lines = out.splitlines()
    assert lines[-1].strip() == "END_PROG:"


def test_end_of_binary_discovered_label():
    # An instruction referencing org + len(data) should discover L1003 and emit it at the end
    data = bytes([0x4C, 0x03, 0x10])  # JMP $1003 at $1000
    out = format_edasm(data=data, org=0x1000)
    lines = out.splitlines()
    assert any("JMP    L1003" in line for line in lines)
    assert lines[-1].strip() == "L1003:"


def test_end_of_binary_with_directive():
    # A control directive at org + len(data) should emit control comment and label
    data = bytes([0xEA])  # NOP at $2000
    directives = [SimpleNamespace(kind="ENTRY", address=0x2001, raw="ENTRY $2001")]
    out = format_edasm(
        data=data,
        org=0x2000,
        directives=directives,
        predefined_symbols={"FINISH": 0x2001},
    )
    lines = out.splitlines()
    assert ";* control ENTRY $2001" in lines
    assert lines[-1].strip() == "FINISH:"
