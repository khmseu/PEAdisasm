#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

if [[ $# -gt 2 ]]; then
	echo "Usage: $0 [module] [blob]" >&2
	exit 2
fi

module="${1:-ei}"
blob="${2:-${repo_root}/local_extract/EDASM_SRC/EDASM.SRC/EI/EDASM.SYSTEM#FF0000}"

python3 "${repo_root}/tools/disasm65.py" \
	--control "${script_dir}/${module}.control" \
	--symbols "${script_dir}/${module}.symbols" \
	"${blob}" \
	>"${script_dir}/${module}"_output.txt
