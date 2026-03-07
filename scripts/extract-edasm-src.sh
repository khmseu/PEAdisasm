#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CADIUS_BIN="${CADIUS_BIN:-/bigdata/KAI/projects/C-EDASM/third_party/cadius/bin/release/cadius}"
IMAGE_PATH="${IMAGE_PATH:-third_party/EdAsm/EDASM_SRC.2mg}"
OUTPUT_DIR="${OUTPUT_DIR:-local_extract/EDASM_SRC}"

if [[ ! -x ${CADIUS_BIN} ]]; then
	echo "Error: CADIUS_BIN is missing or not executable: ${CADIUS_BIN}" >&2
	exit 1
fi

if [[ ${IMAGE_PATH} == /* ]]; then
	IMAGE_ABS_PATH="${IMAGE_PATH}"
else
	IMAGE_ABS_PATH="${REPO_ROOT}/${IMAGE_PATH}"
fi

if [[ ! -f ${IMAGE_ABS_PATH} ]]; then
	echo "Error: source image not found: ${IMAGE_ABS_PATH}" >&2
	exit 1
fi

if [[ ${OUTPUT_DIR} == /* ]]; then
	OUTPUT_PATH="${OUTPUT_DIR}"
else
	OUTPUT_PATH="${REPO_ROOT}/${OUTPUT_DIR}"
fi

mkdir -p "${OUTPUT_PATH}"

echo "Starting EdAsm extraction to: ${OUTPUT_PATH}"
"${CADIUS_BIN}" EXTRACTVOLUME "${IMAGE_ABS_PATH}" "${OUTPUT_PATH}"
echo "EdAsm extraction completed successfully at: ${OUTPUT_PATH}"
