#!/usr/bin/env bash
#
# kali-mcp.sh — start / stop / restart / status the Kali MCP HTTP server.
#
#   ./kali-mcp.sh                                # just works: starts if stopped,
#                                                # then tells you endpoint + token
#   ./kali-mcp.sh start [--host 127.0.0.1] [--port 8000]   # background daemon
#   ./kali-mcp.sh --tunnel                       # bare run + public HTTPS tunnel
#   ./kali-mcp.sh start --tunnel [--host 0.0.0.0] [--port 8000]
#   ./kali-mcp.sh stop                           # stops server AND tunnel
#   ./kali-mcp.sh restart
#   ./kali-mcp.sh status                         # server + tunnel state
#   ./kali-mcp.sh logs                           # server log tail
#   ./kali-mcp.sh tunnel-log                     # cloudflared log tail
#   ./kali-mcp.sh token                          # show bearer token
#   ./kali-mcp.sh tunnel-url                     # show public HTTPS URL
#
# Notes:
#   * This manages the HTTP server ("any AI" mode). The stdio server that
#     opencode uses is spawned by opencode itself — nothing to start/stop.
#   * Token is auto-generated on first start, stored in .token (mode 600).
#   * Binding a non-loopback --host REQUIRES the token (server.py enforces it).
#   * --tunnel launches cloudflared (public https://*.trycloudflare.com),
#     parses its URL, and auto allow-lists that hostname in the server
#     (MCP DNS-rebinding protection would 421 it otherwise).
#   * State files (same folder): .kali-mcp.pid .cloudflared.pid .token
#     .tunnel-url kali-mcp.log cloudflared.log
#
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$DIR/.venv/bin/python"
SRV="$DIR/server.py"
PIDF="$DIR/.kali-mcp.pid"
TPIDF="$DIR/.cloudflared.pid"
TOK="$DIR/.token"
LOG="$DIR/kali-mcp.log"
TLOG="$DIR/cloudflared.log"
TURLF="$DIR/.tunnel-url"

HOST="127.0.0.1"
PORT="8000"
TUNNEL=0
ALLOW_ARGS=()
if [[ $# -eq 0 ]]; then CMD="up"; else CMD="$1"; shift; fi
# allow flags before OR after the command: ./kali-mcp.sh --tunnel  ==  ./kali-mcp.sh start --tunnel
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --tunnel) TUNNEL=1; shift ;;
    --allow-host) ALLOW_ARGS+=(--allow-host "${2:-}"); shift 2 ;;
    up|start|stop|restart|status|logs|tunnel-log|token|tunnel-url)
      CMD="$1"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
# bare "--tunnel" with no command means up-with-tunnel
[[ "$CMD" == "--tunnel" ]] && { CMD="up"; TUNNEL=1; }

[[ -x "$PY" ]]  || { echo "Missing venv python: $PY" >&2; exit 1; }
[[ -f "$SRV" ]] || { echo "Missing server: $SRV" >&2; exit 1; }

is_loopback() { [[ "$1" == 127.0.0.1 || "$1" == localhost || "$1" == "::1" ]]; }

pid_running() { # $1 = pid -> 0 if alive AND is our server
  kill -0 "$1" 2>/dev/null || return 1
  ps -p "$1" -o args= 2>/dev/null | grep -q "kali-mcp/server.py --http" || return 1
}

saved_pid() { [[ -f "$PIDF" ]] && cat "$PIDF" || echo ""; }

ensure_token() {
  if [[ ! -s "$TOK" ]]; then
    openssl rand -hex 32 > "$TOK" 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOK"
    chmod 600 "$TOK"
  fi
  cat "$TOK"
}

# host/port the RUNNING server uses (parsed from its command line).
running_endpoint() { # $1 = pid -> prints "host port"
  local args host="127.0.0.1" port="8000"
  args="$(ps -p "$1" -o args= 2>/dev/null || true)"
  [[ "$args" =~ --host\ ([^[:space:]]+) ]] && host="${BASH_REMATCH[1]}"
  [[ "$args" =~ --port\ ([0-9]+) ]]        && port="${BASH_REMATCH[1]}"
  echo "$host $port"
}

tell() { # $1 = pid -> print endpoint + token summary
  local host port
  read -r host port < <(running_endpoint "$1")
  echo "     Endpoint: http://$host:$port/mcp"
  if [[ -s "$TOK" ]]; then
    echo "     Token:    $(cat "$TOK")"
    echo "     Header:   Authorization: Bearer <token>"
  else
    echo "     Token:    (none — loopback only)"
  fi
  if [[ -s "$TURLF" ]] && tunnel_running; then
    echo "     Public:   $(cat "$TURLF")/mcp  (https, Claude-ready)"
  fi
}

# ── cloudflared tunnel ──────────────────────────────────────────────

tunnel_pid() { [[ -f "$TPIDF" ]] && cat "$TPIDF" || echo ""; }

tunnel_running() {
  local tp; tp="$(tunnel_pid)"
  [[ -n "$tp" ]] || return 1
  kill -0 "$tp" 2>/dev/null || return 1
  ps -p "$tp" -o args= 2>/dev/null | grep -q "cloudflared.*tunnel" || return 1
}

tunnel_host() { # prints tunnel hostname (no scheme) or ""
  [[ -s "$TURLF" ]] || return 1
  sed -e 's#^https://##' -e 's#/$##' "$TURLF"
}

do_start_tunnel() {
  command -v cloudflared >/dev/null 2>&1 || {
    echo "[FAIL] cloudflared not installed. Install: download the .deb from" >&2
    echo "  https://github.com/cloudflare/cloudflared/releases then sudo dpkg -i" >&2
    return 1
  }
  local tp; tp="$(tunnel_pid)"
  if tunnel_running; then
    echo "[*] Tunnel already RUNNING (pid $tp): $(cat "$TURLF" 2>/dev/null || echo '?')"
    return 0
  fi
  rm -f "$TPIDF" "$TURLF"
  : > "$TLOG"  # truncate: grep must see THIS launch's URL, not an old one
  echo "[*] Starting cloudflared tunnel -> http://127.0.0.1:$PORT ..."
  nohup cloudflared tunnel --url "http://127.0.0.1:$PORT" >>"$TLOG" 2>&1 &
  echo $! > "$TPIDF"
  local url="" i
  for ((i=0; i<30; i++)); do
    url="$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$TLOG" 2>/dev/null | grep -v '^https://api\.trycloudflare\.com$' | tail -n 1 || true)"
    [[ -n "$url" ]] && break
    sleep 2
  done
  if [[ -z "$url" ]]; then
    echo "[FAIL] No tunnel URL after ~60s — tail $TLOG:" >&2
    tail -n 10 "$TLOG" >&2 || true
    kill "$(cat "$TPIDF")" 2>/dev/null; rm -f "$TPIDF"
    return 1
  fi
  echo "$url" > "$TURLF"
  echo "[OK] Tunnel up: $url"
}

do_stop_tunnel() {
  local tp; tp="$(tunnel_pid)"
  local stopped=0
  if [[ -n "$tp" ]] && kill -0 "$tp" 2>/dev/null; then
    kill "$tp" 2>/dev/null && stopped=1
    sleep 1
    kill -0 "$tp" 2>/dev/null && kill -9 "$tp" 2>/dev/null || true
  fi
  rm -f "$TPIDF"
  local stray; stray="$(pgrep -f "cloudflared tunnel --url http://127.0.0.1:$PORT" || true)"
  if [[ -n "$stray" ]]; then
    echo "[*] Killing stray tunnel pid(s) for port $PORT: $stray"
    # shellcheck disable=SC2086
    kill $stray 2>/dev/null || true
    stopped=1
  fi
  [[ "$stopped" -eq 1 ]] && echo "[OK] Tunnel stopped." || echo "Tunnel already STOPPED."
}

do_up() {
  local pid; pid="$(saved_pid)"
  if [[ -n "$pid" ]] && pid_running "$pid"; then
    echo "[OK] kali-mcp is RUNNING (pid $pid)."
    tell "$pid"
    return 0
  fi
  [[ -n "$pid" ]] && rm -f "$PIDF"
  do_start && { echo "[OK] kali-mcp is up."; return 0; }
  return 1
}

do_status() {
  local pid; pid="$(saved_pid)"
  if [[ -n "$pid" ]] && pid_running "$pid"; then
    echo "RUNNING (pid $pid)"
    local host port
    read -r host port < <(running_endpoint "$pid")
    (ss -tlnp 2>/dev/null | grep -E ":$port\b" || echo "(port $port not seen yet — still starting?)") | head -n 5
    tell "$pid"
    return 0
  fi
  # stale pidfile?
  [[ -n "$pid" ]] && { echo "STALE pidfile (pid $pid dead) — cleaning."; rm -f "$PIDF"; }
  local stray; stray="$(pgrep -f "kali-mcp/server.py --http.*--port $PORT" || true)"
  if [[ -n "$stray" ]]; then
    echo "RUNNING without pidfile (pid(s): $stray). Run '$0 stop' to clean up."
    return 0
  fi
  echo "STOPPED (server)"
  if [[ -f "$TPIDF" || -s "$TURLF" ]]; then
    if tunnel_running; then
      echo "Tunnel RUNNING (pid $(tunnel_pid)): $(cat "$TURLF" 2>/dev/null || echo '?')"
      return 0
    else
      echo "Tunnel STOPPED"
    fi
  fi
  return 1
}

do_start() {
  local pid; pid="$(saved_pid)"
  if [[ -n "$pid" ]] && pid_running "$pid"; then
    local rhost rport
    read -r rhost rport < <(running_endpoint "$pid")
    if [[ "$rport" != "$PORT" ]]; then
      # NEVER touch a server on another port: one managed server per script.
      echo "[FAIL] A kali-mcp server is already RUNNING on :$rport (pid $pid)." >&2
      echo "  Stop it first ('$0 stop --port $rport') or reuse its port ('$0 --port $rport ...')." >&2
      echo "  Refusing to disturb it." >&2
      return 1
    fi
    if [[ "$TUNNEL" -eq 0 ]]; then
      echo "Already RUNNING (pid $pid). '$0 restart' to bounce it."
      return 0
    fi
    # Tunnel => fresh random hostname each launch, so bounce the server
    # to allow-list it (otherwise the SDK 421s the new Host).
    echo "[*] Bouncing server (pid $pid) to allow-list the new tunnel hostname ..."
    kill "$pid" 2>/dev/null || true
    sleep 2
    rm -f "$PIDF"
    pid=""
  fi
  rm -f "$PIDF"
  # Tunnel FIRST: its random hostname must be allow-listed in the server
  # (MCP DNS-rebinding protection 421s unknown Host headers).
  if [[ "$TUNNEL" -eq 1 ]]; then
    do_start_tunnel || return 1
    ALLOW_ARGS+=(--allow-host "$(tunnel_host)")
  fi
  local token; token="$(ensure_token)"
  if ! is_loopback "$HOST"; then
    echo "[!] Binding $HOST (non-loopback). Token auth is mandatory — server refuses otherwise."
  fi
  echo "[*] Starting kali-mcp on http://$HOST:$PORT/mcp ..."
  KALI_MCP_TOKEN="$token" nohup "$PY" "$SRV" --http --host "$HOST" --port "$PORT" \
    "${ALLOW_ARGS[@]}" >>"$LOG" 2>&1 &
  echo $! > "$PIDF"
  sleep 2
  if pid_running "$(cat "$PIDF")"; then
    echo "[OK] Started (pid $(cat "$PIDF"), log $LOG)"
    echo "     Endpoint: http://$HOST:$PORT/mcp"
    echo "     Token:    $token"
    echo "     Header:   Authorization: Bearer <token>"
  else
    echo "[FAIL] Process died — last log lines:" >&2
    tail -n 15 "$LOG" >&2 || true
    rm -f "$PIDF"
    return 1
  fi
}

do_stop() {
  local pid; pid="$(saved_pid)"
  if [[ -n "$pid" ]] && pid_running "$pid"; then
    local rhost rport
    read -r rhost rport < <(running_endpoint "$pid")
    if [[ "$rport" != "$PORT" ]]; then
      echo "[FAIL] Refusing: pidfile server runs on :$rport, you asked --port $PORT." >&2
      echo "  Run '$0 stop --port $rport' (or '$0 status' to see)." >&2
      return 1
    fi
  fi
  local stopped=0
  if [[ -n "$pid" ]] && pid_running "$pid"; then
    kill "$pid" 2>/dev/null && stopped=1
    for _ in $(seq 1 10); do pid_running "$pid" || break; sleep 1; done
    pid_running "$pid" 2>/dev/null && { kill -9 "$pid" 2>/dev/null; stopped=1; }
  fi
  rm -f "$PIDF"
  local stray; stray="$(pgrep -f "kali-mcp/server.py --http.*--port $PORT" || true)"
  if [[ -n "$stray" ]]; then
    echo "[*] Killing stray server pid(s) on port $PORT: $stray"
    # shellcheck disable=SC2086
    kill $stray 2>/dev/null || true
    stopped=1
  fi
  [[ "$stopped" -eq 1 ]] && echo "[OK] Stopped." || echo "Already STOPPED."
  # Tunnel stops with the server (same command manages both).
  do_stop_tunnel
}

case "$CMD" in
  up)      do_up ;;
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_stop; sleep 1; do_start ;;
  status)  do_status ;;
  logs)    [[ -f "$LOG" ]] && tail -n 50 "$LOG" || echo "(no log yet)" ;;
  tunnel-log) [[ -f "$TLOG" ]] && tail -n 50 "$TLOG" || echo "(no tunnel log yet)" ;;
  token)   [[ -s "$TOK" ]] && cat "$TOK" && echo || echo "(no token yet — created on first start)" ;;
  pin)     [[ -s "$DIR/.pin" ]] && cat "$DIR/.pin" && echo || echo "(no PIN yet — created on first tool use/server start)" ;;
  tunnel-url) [[ -s "$TURLF" ]] && { cat "$TURLF"; echo; } || echo "(no tunnel URL — start with --tunnel)" ;;
  *) echo "Usage: $0 [up|start|stop|restart|status|logs|tunnel-log|token|tunnel-url] [--host H] [--port P] [--tunnel] [--allow-host H]  (no args = up)" >&2; exit 1 ;;
esac
