#!/bin/sh
# Times how long the chat screen takes to open and draw once, against a
# local server with one group. Target: under 300 ms.
set -eu

BIN="${1:-target/release/socketchat}"
DIR="$(mktemp -d)"
PORT="${PORT:-17556}"
trap 'kill "$PID" 2>/dev/null || true; rm -r "$DIR"' EXIT

export SOCKETCHAT_PASSPHRASE=startup-check SOCKETCHAT_NAME=Timer SOCKETCHAT_HOME="$DIR/me"
"$BIN" server init --data-dir "$DIR/server" --host 127.0.0.1 --listen "127.0.0.1:$PORT" >/dev/null
"$BIN" server run --data-dir "$DIR/server" >/dev/null &
PID=$!
sleep 1
"$BIN" join "$("$BIN" server invite --data-dir "$DIR/server" 2>/dev/null)" >/dev/null
"$BIN" new "Timing" >/dev/null

for i in 1 2 3; do
  START=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
  # The screen needs a terminal, so run it inside one made by script(1).
  if [ "$(uname)" = Darwin ]; then
    SOCKETCHAT_EXIT_AFTER_DRAW=1 script -q /dev/null sh -c "stty rows 24 cols 80; exec '$BIN'" >/dev/null 2>&1 </dev/null || true
  else
    SOCKETCHAT_EXIT_AFTER_DRAW=1 script -qec "stty rows 24 cols 80; exec '$BIN'" /dev/null >/dev/null 2>&1 </dev/null || true
  fi
  END=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
  echo "run $i: $(perl -e "printf '%d', ($END - $START) * 1000") ms to first draw"
done
