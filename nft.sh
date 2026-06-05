#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PROJECT_DIR="${SCRIPT_DIR}"
if [[ ! -d "${PROJECT_DIR}/nft_forward" && -d /opt/nft-forward/nft_forward ]]; then
    PROJECT_DIR="/opt/nft-forward"
fi

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "[错误] 未找到 python3，请先安装 Python 3。" >&2
    exit 1
fi

export NFT_FORWARD_PROJECT_DIR="${NFT_FORWARD_PROJECT_DIR:-${PROJECT_DIR}}"
export PYTHONPATH="${NFT_FORWARD_PROJECT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
exec "${PYTHON_BIN}" -m nft_forward.cli "$@"
