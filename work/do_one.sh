#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <module> <blob>" >&2
	exit 2
fi

module="${1}"
blob="${2}"

python3 "${repo_root}/tools/disasm65.py" \
	--control "${script_dir}/${module}.control" \
	--symbols "${script_dir}/${module}.symbols" \
	"${blob}" \
	>"${script_dir}/${module}"_output.txt
../k65.t2/bin/k65asm "${script_dir}/${module}"_output.txt -o "${script_dir}/${module}.bin" -l "${script_dir}/${module}.lst"
