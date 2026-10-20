#!/usr/bin/env bash
# Helper for join.tape. Waits until Cy's `socketchat join` has finished, then
# syncs Ada's app so it lets Cy into Book club.
#
# The tape sets PROMPT_COMMAND to add a line to /tmp/sc-demo/prompts each
# time the shell shows a prompt. $1 is the line count when this helper
# starts; two more prompts (this command's own, then the join's) mean the
# join is done.
DEMO=/tmp/sc-demo
want=$(( ${1:-0} + 2 ))
for _ in $(seq 600); do
  [ "$(wc -l < "$DEMO/prompts")" -ge "$want" ] && break
  sleep 0.1
done
for _ in 1 2 3; do
  SOCKETCHAT_HOME="$DEMO/ada" SOCKETCHAT_PASSPHRASE=demo-ada \
    "$DEMO/bin/socketchat" sync > /dev/null 2>&1
done
