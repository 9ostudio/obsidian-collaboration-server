#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-$HOME/.config/obsidian-collaboration/server.env}"
[ -f "$ENV_FILE" ] || { echo "The Collaboration server is not installed on this machine." >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a

token=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
file="$DATA_DIR/owner-token"
rm -f "$file"
(umask 077 && printf '%s\n' "$token" > "$file")

echo "One-time owner link (open it on the computer with your vault):"
echo "  $PUBLIC_URL/setup/$token"
