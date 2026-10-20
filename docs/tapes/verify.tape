# The /verify Bo box with the 60-digit safety number.
# Run from the repo root after a release build:  vhs docs/tapes/verify.tape

Output "/tmp/socketchat-verify.gif"

Set Shell bash
Set FontSize 16
Set Width 1080
Set Height 1080
Set Padding 20
# Catppuccin Mocha with true black and white, so QR codes keep their contrast.
Set Theme { "name": "socketchat", "background": "#1e1e2e", "foreground": "#cdd6f4", "cursor": "#f5e0dc", "selection": "#585b70", "black": "#000000", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#f5c2e7", "cyan": "#94e2d5", "white": "#bac2de", "brightBlack": "#7f849c", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#f5c2e7", "brightCyan": "#94e2d5", "brightWhite": "#ffffff" }
Set TypingSpeed 35ms
Env PS1 "$ "
Env BASH_SILENCE_DEPRECATION_WARNING "1"

Hide
Type "docs/tapes/setup.sh && export PATH=/tmp/sc-demo/bin:$PATH" Enter
Wait@60s /\$\s*$/
Type "export SOCKETCHAT_HOME=/tmp/sc-demo/ada SOCKETCHAT_PASSPHRASE=demo-ada; clear" Enter
Sleep 500ms
Show

Type "socketchat" Enter
Sleep 3s
Type "/verify Bo"
Sleep 500ms
Enter
Sleep 2s
Screenshot "docs/images/verify.png"
Sleep 500ms
Escape
Sleep 500ms
Ctrl+C

Hide
Type "docs/tapes/teardown.sh" Enter
Sleep 1s
