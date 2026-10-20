# Cy joins Book club with an invite link from Ada, waits, then syncs.
# Run from the repo root after a release build:  vhs docs/tapes/join.tape

Output "/tmp/socketchat-join.gif"

Set Shell bash
Set FontSize 16
Set Width 1180
Set Height 260
Set Padding 20
# Catppuccin Mocha with true black and white, so QR codes keep their contrast.
Set Theme { "name": "socketchat", "background": "#1e1e2e", "foreground": "#cdd6f4", "cursor": "#f5e0dc", "selection": "#585b70", "black": "#000000", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#f5c2e7", "cyan": "#94e2d5", "white": "#bac2de", "brightBlack": "#7f849c", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#f5c2e7", "brightCyan": "#94e2d5", "brightWhite": "#ffffff" }
Set TypingSpeed 35ms
Env PS1 "$ "
Env BASH_SILENCE_DEPRECATION_WARNING "1"

# Ada and Bo are in Book club. Cy has the link Ada sent, and nothing else.
# Ada's app lets Cy in once the join command below has finished.
Hide
Type "docs/tapes/setup.sh --no-cy && export PATH=/tmp/sc-demo/bin:$PATH" Enter
Wait@60s /\$\s*$/
Type `export SOCKETCHAT_HOME=/tmp/sc-demo/cy SOCKETCHAT_NAME=Cy SOCKETCHAT_PASSPHRASE="$(cat /tmp/sc-demo/cy.pass)" LINK="$(cat /tmp/sc-demo/cy-invite.txt)"; PROMPT_COMMAND='echo >> /tmp/sc-demo/prompts'` Enter
Sleep 500ms
Type `n0=$(wc -l < /tmp/sc-demo/prompts); docs/tapes/let-cy-in.sh "$n0" & disown; clear` Enter
Sleep 500ms
Show

Type `socketchat join "$LINK"` Enter
# The chat screen opens after the waiting line; close it to show the line.
Sleep 3s
Ctrl+C
Sleep 3s
Type "socketchat sync" Enter
Sleep 3s
Screenshot "docs/images/join.png"
Sleep 500ms

Hide
Type "unset PROMPT_COMMAND; docs/tapes/teardown.sh" Enter
Sleep 1s
