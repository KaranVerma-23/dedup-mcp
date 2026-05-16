#!/usr/bin/env bash
# Start dedup-mcp HTTP + ngrok tunnel in one go.
# Logs each process to its own file in /tmp; kills both cleanly on Ctrl-C.
#
# Usage:   ./scripts/serve-tunnel.sh
# Outputs: prints the public ngrok URL once it's ready.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8080}"
NODE_BIN="${NODE_BIN:-$HOME/.nvm/versions/node/v18.20.8/bin/node}"
LOG_DIR="${LOG_DIR:-/tmp}"
MCP_LOG="$LOG_DIR/dedup-mcp.log"
NGROK_LOG="$LOG_DIR/dedup-mcp-ngrok.log"

# ── Load Harness credentials so the new `dedupe_pipeline` tool can hit the
#    STO API directly (no harness-mcp involved).
#    Looks for an .env file in (in order): dedup-mcp's own root, then the
#    sibling mcp-server / harness-mcp project. First match wins; existing env
#    vars take precedence over file values.
load_env_file() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  # Read KEY=VALUE lines; don't clobber already-set env vars.
  # NOTE: Without explicit \r/\n trimming, values that happen to fall on
  # the last line of a file with no trailing newline (or a CRLF file) end
  # up with stray whitespace that silently breaks downstream PAT parsing.
  while IFS='=' read -r key val || [[ -n "$key" ]]; do
    [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
    # Strip surrounding quotes
    val="${val#\"}"; val="${val%\"}"
    val="${val#\'}"; val="${val%\'}"
    # Strip any trailing CR/LF/whitespace (defensive — see note above)
    val="${val%$'\r'}"
    val="${val%$'\n'}"
    val="${val%%[[:space:]]}"
    if [[ -z "${!key:-}" ]]; then
      export "$key=$val"
    fi
  done < "$f"
  echo "  ✓ loaded credentials from $f"
}

if [[ -z "${HARNESS_API_KEY:-}" ]]; then
  load_env_file "$ROOT/.env" \
    || load_env_file "$ROOT/../mcp-server/.env" \
    || load_env_file "$ROOT/../harness-mcp/.env" \
    || true
fi

# STO_DATABASE_URL powers the `backend=sql` path (~10x faster, surfaces
# per-occurrence file/line for SAST). It lives in sto-core/.env as
# APP_DATABASE_DATASOURCE; load that as a fallback alias.
if [[ -z "${STO_DATABASE_URL:-}" ]]; then
  load_env_file "$ROOT/../STO/sto-core/.env" || true
  if [[ -z "${STO_DATABASE_URL:-}" && -n "${APP_DATABASE_DATASOURCE:-}" ]]; then
    export STO_DATABASE_URL="$APP_DATABASE_DATASOURCE"
    echo "  ✓ aliased APP_DATABASE_DATASOURCE → STO_DATABASE_URL"
  fi
fi

if [[ -z "${HARNESS_BASE_URL:-}" || -z "${HARNESS_API_KEY:-}" ]]; then
  echo "WARNING: HARNESS_BASE_URL / HARNESS_API_KEY not set — the dedupe_pipeline"
  echo "         tool will fail at call time for backend=api. Set them in env or"
  echo "         in dedup-mcp/.env before running this script."
fi
if [[ -z "${STO_DATABASE_URL:-}" ]]; then
  echo "WARNING: STO_DATABASE_URL not set — the dedupe_pipeline tool will fail"
  echo "         for backend=sql (the fast demo path). Source it from"
  echo "         sto-core/.env (APP_DATABASE_DATASOURCE)."
fi

cleanup() {
  echo ""
  echo "Shutting down..."
  [[ -n "${MCP_PID:-}" ]] && kill "$MCP_PID" 2>/dev/null || true
  [[ -n "${NGROK_PID:-}" ]] && kill "$NGROK_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "Stopped."
}
trap cleanup EXIT INT TERM

# 1) Start dedup-mcp HTTP server. Inherits credentials from this shell so
#    dedupe_pipeline can talk to the Harness STO backend (API or SQL).
echo "Starting dedup-mcp on port $PORT..."
PORT="$PORT" \
HARNESS_BASE_URL="${HARNESS_BASE_URL:-}" \
HARNESS_API_KEY="${HARNESS_API_KEY:-}" \
HARNESS_ACCOUNT_ID="${HARNESS_ACCOUNT_ID:-}" \
STO_DATABASE_URL="${STO_DATABASE_URL:-}" \
  "$NODE_BIN" "$ROOT/dist/cli.js" http > "$MCP_LOG" 2>&1 &
MCP_PID=$!

# 2) Wait for the server to be ready (use /health — /mcp now returns 400
#    without a session header per the MCP Streamable HTTP spec).
for i in {1..15}; do
  if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done
if ! curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
  echo "dedup-mcp failed to start. Tail of $MCP_LOG:"
  tail -20 "$MCP_LOG"
  exit 1
fi
echo "  ✓ dedup-mcp ready  (logs: $MCP_LOG)"

# 3) Start ngrok
# --response-header-add: bypasses ngrok's free-plan browser interstitial which
#   otherwise sends HTML to the Harness platform instead of JSON-RPC.
#   (Pattern from Himanshu Agrawal's working config in #agent-dev-days-2026.)
echo "Starting ngrok tunnel..."
ngrok http \
  --log=stdout \
  --response-header-add "ngrok-skip-browser-warning: true" \
  "$PORT" > "$NGROK_LOG" 2>&1 &
NGROK_PID=$!

# 4) Pull the public URL from ngrok's local API (port 4040)
PUBLIC_URL=""
for i in {1..30}; do
  # ngrok serves either *.ngrok-free.app or *.ngrok-free.dev depending on plan/region
  PUBLIC_URL="$(curl -sf http://localhost:4040/api/tunnels 2>/dev/null \
    | grep -oE 'https://[a-z0-9-]+\.ngrok-free\.(app|dev)' \
    | head -1 || true)"
  if [[ -n "$PUBLIC_URL" ]]; then break; fi
  sleep 0.5
done

if [[ -z "$PUBLIC_URL" ]]; then
  echo "ngrok didn't surface a public URL. Tail of $NGROK_LOG:"
  tail -30 "$NGROK_LOG"
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  dedup-mcp public URL:  $PUBLIC_URL/mcp"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Health check:  curl $PUBLIC_URL/mcp"
echo "  ngrok web UI:  http://localhost:4040"
echo ""
echo "  Press Ctrl-C to stop both processes."
echo ""

# 5) Wait until either process dies (or user hits Ctrl-C)
wait -n "$MCP_PID" "$NGROK_PID"
