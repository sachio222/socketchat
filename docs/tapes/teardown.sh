#!/usr/bin/env bash
# Stops the demo server started by setup.sh and removes /tmp/sc-demo.
set -u

DEMO=/tmp/sc-demo

if [ -f "$DEMO/server.pid" ]; then
  pid="$(cat "$DEMO/server.pid")"
  if kill -0 "$pid" 2> /dev/null; then
    kill -INT "$pid" 2> /dev/null
    for _ in $(seq 30); do
      kill -0 "$pid" 2> /dev/null || break
      sleep 0.1
    done
    kill -0 "$pid" 2> /dev/null && kill -KILL "$pid" 2> /dev/null
  fi
fi

# Only ever this one folder.
if [ -d "$DEMO" ]; then
  rm -r -f -- "$DEMO"
fi
exit 0
