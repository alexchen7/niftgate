#!/usr/bin/env bash
set -euo pipefail

exec python3 -c '
import os, shlex, sys
allowed = {
    "status", "bot-status", "sync-ddns", "sync-destinations", "list", "allow-list",
    "ruleset", "mode", "ingest", "allow", "remove-allow", "blocked", "promote-block",
    "delete-block", "add-rule", "edit-rule", "delete-rule", "secret-url", "ddns",
    "export", "import", "pair-exit", "geo-status", "geo-import", "blocked-search", "blocked-filters", "capture",
}
try:
    args = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
except ValueError:
    args = []
if len(args) < 2 or args[0] != "nft.sh" or args[1] not in allowed:
    sys.exit("command not allowed")
os.execv("/usr/local/bin/nft.sh", args)
'
