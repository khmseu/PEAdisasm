# PEAdisasm

## Overview

PEAdisasm combines two related goals:

- Preserve and inspect Apple II EdAsm source artifacts from disk images.
- Provide a modern Python disassembler for 65C02 and Sweet16 code that emits EdAsm-like output.

The repository keeps original/reference source material under `third_party/EdAsm` and extraction outputs under `local_extract/`, while active tooling lives in `tools/disasm65.py` and `tools/disasm65/`.

## Repository Layout

- `tools/disasm65.py`: CLI entry point.
- `tools/disasm65/*`: parser, decoder, analysis, and formatting modules.
- `tests/`: unit and smoke tests plus fixtures used by the CLI/output tests.
- `third_party/EdAsm`: source image and mirrored upstream EdAsm material.
- `scripts/extract-edasm-src.sh`: extraction helper for unpacking EdAsm source from the `.2mg` image.

## Quick Start

From repository root:

```bash
# 1) Extract EdAsm source tree from the disk image
bash scripts/extract-edasm-src.sh

# 2) Run disassembler on test fixture with control and symbol files
python3 tools/disasm65.py \
  tests/fixtures/phase5_sample.bin \
  --org 0x1000 \
  --control tests/fixtures/phase5_sample.ctl \
  --symbols tests/fixtures/phase5_sample.equ
```

The extraction script accepts environment overrides when needed: `CADIUS_BIN`, `IMAGE_PATH`, and `OUTPUT_DIR`.

## CLI Usage

Synopsis:

```text
python3 tools/disasm65.py [-h] [--org ORG] [--control CONTROL] [--symbols SYMBOLS] [--sweet16-heuristic] input
```

Options:

- `input`: required path to raw binary input.
- `--org ORG`: load/origin address (accepts decimal or `0x...`); defaults to `0`, or first `ORG` from control file when `--org` is omitted.
- `--control CONTROL`: optional control file path.
- `--symbols SYMBOLS`: optional predefined symbol file path.
- `--sweet16-heuristic`: enable Sweet16 detection heuristic.

## Control File Syntax

Supported directives:

- `ORG addr`: set origin address.
- `ENTRY addr`: seed a symbol/disassembly entry point.
- `CODE start,end`: mark an executable 65C02 region.
- `DATA start,end`: force bytes to `DB` output.
- `TEXT start,end [ASC|DCI|STR]`: force text output; subtype defaults to `ASC`.
- `SW16 start,end`: mark an executable Sweet16 region.

Range semantics are inclusive for both boundaries (`start <= addr <= end`).

Example:

```text
ORG $1000
ENTRY $1000
CODE $1000,$10FF
TEXT $1100,$1110 DCI
DATA $1200,$12FF
SW16 $1300,$13FF
```

## Symbol File Syntax

Each non-empty, non-comment line must be:

```text
NAME EQU VALUE
```

`VALUE` accepts decimal or `$`-prefixed hex.
Comments start with `;` and are ignored (whole-line or trailing comments).

Examples:

```text
RESET EQU $FFFC
START EQU 4096 ; decimal form
```

## Output Style

Output is EdAsm-like and normalized for readability:

- Uppercase mnemonics/directives (`ORG`, `DB`, `ASC`, etc.).
- Labels printed without trailing `:`.
- Auto-discovered labels use `Lxxxx` (hex address), for example `L1007`.
- Predefined symbols from `--symbols` take precedence over discovered `Lxxxx` labels at the same address.

## Testing

Run the full test suite from repository root:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
