#!/bin/bash
set -euo pipefail
one=ei
python3 tools/disasm65.py \
	--control "${one}".control \
	--symbols "${one}".symbols \
	--sweet16-heuristic \
	local_extract/EDASM_SRC/EDASM.SRC/EI/EDASM.SYSTEM#FF0000 \
	>"${one}"_output.txt
