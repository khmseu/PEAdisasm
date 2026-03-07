#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
: "${REPO_ROOT}"  # Kept for upcoming phases.

CADIUS_BIN="${CADIUS_BIN:-/bigdata/KAI/projects/C-EDASM/third_party/cadius/bin/release/cadius}"
IMAGE_PATH="${IMAGE_PATH:-third_party/EdAsm/EDASM_SRC.2mg}"
OUTPUT_DIR="${OUTPUT_DIR:-local_extract/EDASM_SRC}"

# Phase 1 skeleton only. Extraction logic will be added in Phase 2.
true
