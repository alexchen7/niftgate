#!/usr/bin/env bash
set -euo pipefail

orig="${SSH_ORIGINAL_COMMAND:-}"
case "${orig}" in
    nft-forward-exit-geo\ *)
        ip="${orig#nft-forward-exit-geo }"
        exec /usr/local/bin/nft.sh exit-geo "${ip}"
        ;;
    *)
        echo "command not allowed" >&2
        exit 126
        ;;
esac
