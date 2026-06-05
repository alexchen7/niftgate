#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ ! -d "${PROJECT_DIR}/nft_forward" && -d /opt/nft-forward/nft_forward ]]; then
    PROJECT_DIR="/opt/nft-forward"
fi

export NFT_FORWARD_PROJECT_DIR="${NFT_FORWARD_PROJECT_DIR:-${PROJECT_DIR}}"
export PYTHONPATH="${NFT_FORWARD_PROJECT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
exec "${PYTHON_BIN}" -m nft_forward.cli "$@"
