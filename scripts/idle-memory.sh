#!/bin/sh
# Starts a socketchat server in a temporary folder, waits for it to settle,
# and prints its resident memory. Target: under 20 MB.
set -eu

BIN="${1:-target/release/socketchat}"
DIR="$(mktemp -d)"
PORT="${PORT:-17555}"
trap 'kill "$PID" 2>/dev/null || true; rm -r "$DIR"' EXIT

"$BIN" server init --data-dir "$DIR" --host 127.0.0.1 --listen "127.0.0.1:$PORT" >/dev/null
"$BIN" server run --data-dir "$DIR" >/dev/null &
PID=$!
sleep 5
RSS_KB="$(ps -o rss= -p "$PID" | tr -d ' ')"
echo "idle server memory: $((RSS_KB / 1024)) MB (${RSS_KB} KB)"
