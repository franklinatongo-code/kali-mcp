#!/usr/bin/env bash
# start-https.sh — restart kali-mcp + cloudflare tunnel (public HTTPS) and print details.
# Usage: ./start-https.sh [--port 8000]
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="8000"
for a in "$@"; do
  case "$a" in --port) shift;; *) ;;
  esac
done
# allow --port N
while [[ $# -gt 0 ]]; do
  case "$1" in --port) PORT="${2:-8000}"; shift 2;; *) shift;; esac
done

"$DIR/kali-mcp.sh" restart --tunnel --host 0.0.0.0 --port "$PORT" || exit 1
echo ""
echo "================ NEW DETAILS ================"
echo "Local:  http://0.0.0.0:$PORT/mcp"
if [[ -s "$DIR/.tunnel-url" ]]; then
  echo "Public: $(cat "$DIR/.tunnel-url")/mcp  (use this in Claude, Streamable HTTP + Sign in)"
else
  echo "Public: (no tunnel URL — see cloudflared.log)"
fi
if [[ -s "$DIR/.token" ]]; then
  echo "Token:  $(cat "$DIR/.token")"
  echo "Header: Authorization: Bearer <token>"
fi
echo "PIN:    disabled (open control, do not share URL)"
echo "============================================="
