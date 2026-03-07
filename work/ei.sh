#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${script_dir}"/do_one.sh ei "${script_dir}"/../local_extract/EDASM_SRC/EDASM.SRC/EI/EDASM.SYSTEM#FF0000
