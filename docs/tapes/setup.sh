#!/usr/bin/env bash
# Builds the demo state the README screenshots are recorded from.
#
#   docs/tapes/setup.sh            server, Ada, Bo and Cy in "Book club", with messages
#   docs/tapes/setup.sh --no-cy    the same without Cy; Cy's invite link is saved
#                                  to /tmp/sc-demo/cy-invite.txt for join.tape
#
# Everything lives in /tmp/sc-demo. The server listens on 127.0.0.1:17444
# in the background. Run docs/tapes/teardown.sh to stop it and remove the folder.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO=/tmp/sc-demo
PORT=17444
BIN="${SOCKETCHAT_BIN:-$ROOT/target/release/socketchat}"

if [ ! -x "$BIN" ]; then
  echo "No socketchat binary at $BIN. Build it with: cargo build --release -p socketchat" >&2
  exit 1
fi

"$ROOT/docs/tapes/teardown.sh"
mkdir -p "$DEMO/bin" "$DEMO/files"
ln -s "$BIN" "$DEMO/bin/socketchat"
export PATH="$DEMO/bin:$PATH"

# One person's commands: as ada socketchat sync
as() {
  local who="$1"; shift
  local name; name="$(printf '%s' "${who:0:1}" | tr a-z A-Z)${who:1}"
  SOCKETCHAT_HOME="$DEMO/$who" SOCKETCHAT_NAME="$name" \
    SOCKETCHAT_PASSPHRASE="demo-$who" "$@"
}

# Server.
socketchat server init --data-dir "$DEMO/server" --host 127.0.0.1 \
  --listen "127.0.0.1:$PORT" > /dev/null
nohup socketchat server run --data-dir "$DEMO/server" > "$DEMO/server.log" 2>&1 &
echo $! > "$DEMO/server.pid"
for _ in $(seq 50); do
  grep -q listening "$DEMO/server.log" && break
  sleep 0.1
done
grep -q listening "$DEMO/server.log" || { echo "The server did not start." >&2; cat "$DEMO/server.log" >&2; exit 1; }

# Ada joins the server and starts the group.
as ada socketchat join "$(socketchat server invite --data-dir "$DEMO/server" 2>/dev/null)" > /dev/null 2>&1
as ada socketchat new "Book club" > /dev/null

# Brings one person into Book club through an invite from Ada.
add() {
  local who="$1" link
  link="$(as ada socketchat invite --group "Book club" 2>/dev/null)"
  as "$who" socketchat join "$link" > /dev/null 2>&1
  as ada socketchat sync > /dev/null
  as "$who" socketchat sync > /dev/null
}

say() {
  local who="$1"; shift
  as "$who" socketchat send --group "Book club" "$*"
  sleep 1
}

add bo
say ada "Finished Piranesi last night. Who picks the next one?"
say bo "My turn, I think. How about The Remains of the Day? It's short."

if [ "${1:-}" = "--no-cy" ]; then
  as ada socketchat invite --group "Book club" 2>/dev/null > "$DEMO/cy-invite.txt"
  as ada socketchat sync > /dev/null
  exit 0
fi

add cy
say cy "Hi both, thanks for having me. I can borrow it from the library this week."
say ada "Great. Thursday at 7, same café?"
say bo "Thursday works for me."
say cy "Same. I'll bring the snacks."

# A small file for Bo to send from the chat screen in chat.tape.
cat > "$DEMO/files/reading-plan.txt" <<'EOF'
The Remains of the Day: reading plan
Week 1: chapters 1 to 2
Week 2: chapters 3 to 4
Week 3: to the end, then we meet
EOF

for p in ada bo cy; do as "$p" socketchat sync > /dev/null; done
