# Setting up a server and starting it.
# Run from the repo root after a release build:  vhs docs/tapes/server.tape

Output "/tmp/socketchat-server.gif"

Set Shell bash
Set FontSize 16
Set Width 1180
Set Height 720
Set Padding 20
# Catppuccin Mocha with true black and white, so QR codes keep their contrast.
Set Theme { "name": "socketchat", "background": "#1e1e2e", "foreground": "#cdd6f4", "cursor": "#f5e0dc", "selection": "#585b70", "black": "#000000", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#f5c2e7", "cyan": "#94e2d5", "white": "#bac2de", "brightBlack": "#7f849c", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#f5c2e7", "brightCyan": "#94e2d5", "brightWhite": "#ffffff" }
Set TypingSpeed 25ms
Env PS1 "$ "
Env BASH_SILENCE_DEPRECATION_WARNING "1"

# A clean /tmp/sc-demo with socketchat on the PATH and no server yet.
Hide
Type `docs/tapes/teardown.sh; mkdir -p /tmp/sc-demo/bin && ln -s "$PWD/target/release/socketchat" /tmp/sc-demo/bin/socketchat && export PATH=/tmp/sc-demo/bin:$PATH; clear` Enter
Sleep 1s
Show

Type "socketchat server init --data-dir /tmp/sc-demo/server --host 127.0.0.1 --listen 127.0.0.1:17444" Enter
# Wait for the prompt so the next command is not typed into init's output.
Wait@30s /\$\s*$/
Sleep 500ms
Type "socketchat server run --data-dir /tmp/sc-demo/server" Enter
Sleep 2s
Screenshot "docs/images/server.png"
Sleep 500ms
Ctrl+C
Sleep 1s

Hide
Type "docs/tapes/teardown.sh" Enter
Sleep 1s
