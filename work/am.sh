#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${script_dir}"/do_one.sh am "${script_dir}"/'Apple II plus ROM Pages F8-FF - 341-0020 - Autostart Monitor.bin'
