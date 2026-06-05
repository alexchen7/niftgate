#!/usr/bin/env bash
set -euo pipefail

orig="${SSH_ORIGINAL_COMMAND:-}"
case "${orig}" in
    "nft.sh status"|"nft.sh sync-ddns"|"nft.sh list"|"nft.sh allow-list"|"nft.sh ruleset list"|"nft.sh mode"|\
    nft.sh\ mode\ *|nft.sh\ ingest\ *|nft.sh\ allow\ *|\
    nft.sh\ remove-allow\ *|nft.sh\ blocked*|nft.sh\ promote-block\ *|\
    nft.sh\ delete-block\ *|nft.sh\ add-rule\ *|nft.sh\ delete-rule\ *|\
    nft.sh\ secret-url\ *|nft.sh\ ddns\ *|nft.sh\ export*|nft.sh\ import\ *|nft.sh\ pair-exit\ *)
        # shellcheck disable=SC2086
        exec /usr/local/bin/${orig}
        ;;
    *)
        echo "command not allowed" >&2
        exit 126
        ;;
esac
