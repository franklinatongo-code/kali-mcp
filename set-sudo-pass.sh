#!/bin/bash
# Set the sudo password for kali-mcp terminal tool.
# Stores in .sudo-pass (mode 600). The terminal tool reads it when
# sudo=true and no sudo_password argument is given.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
FILE="$DIR/.sudo-pass"

read -rsp "Enter sudo password: " PASS
echo

if [ -z "$PASS" ]; then
    echo "Password cannot be empty." >&2
    exit 1
fi

printf '%s' "$PASS" > "$FILE"
chmod 600 "$FILE"
echo "Saved to $FILE"
