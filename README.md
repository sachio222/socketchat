# Socketchat

Socketchat is a full-featured encrypted chat with a server you run yourself. The server runs anywhere, from a cloud server or a home computer down to a small device such as a Raspberry Pi, and you invite people with a link. The server passes messages along but cannot read them: messages, files and changes to who is in a room are end-to-end encrypted, which means only the people in a chat can read them.

What you get:

- Rooms, which are group chats, and direct messages.
- Invite links, shown as text and as a QR code.
- Verification with safety numbers, so you can check that nobody sits between you and a friend.
- Files, photos and videos. Photos lose their location and device data before they leave, and Socketchat asks before sending one it cannot clean.
- Admins, who can remove people, make other admins and rename a room. A room closes for everyone once its admins agree.
- Room history that leaves your computer once you are out of the room and have read it.
- Post-quantum protection, meaning protection against a future quantum computer, on by default.
- A server that cannot read your messages.

Socketchat v4 is a terminal app written in Rust. Its encryption comes from a published standard and an audited library, with no home-made cryptography.

## Why it exists

No other project we know of pairs a light self-hosted server with standard group encryption and post-quantum protection. The group encryption standard is MLS (Messaging Layer Security), published by the Internet Engineering Task Force (IETF) as RFC 9420 in 2023. In MLS a sender encrypts a message once and the server copies it to every member.

How nearby projects compare:

- **Matrix** can be self-hosted, but its server is heavy.
- **Wire** uses MLS, but self-hosting it needs its Enterprise edition.
- **SimpleX** is light, but in a group the sender's own device delivers every message to every member.
- **Signal** hides group membership from its servers with anonymous credentials, which it built for its own service. That code is licensed under the AGPL and sits outside the MLS standard.

Socketchat's server is one program with its data in one folder. A release build on a Mac used 10 MB of memory while idle.

## Quick start

Install Socketchat with one command. On macOS or Linux, run this in a terminal:

```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sachio222/socketchat/releases/latest/download/socketchat-installer.sh | sh
```

On Windows, run this in PowerShell:

```
powershell -ExecutionPolicy Bypass -c "irm https://github.com/sachio222/socketchat/releases/latest/download/socketchat-installer.ps1 | iex"
```

With Homebrew, on macOS or Linux:

```
brew install sachio222/tap/socketchat
```

The installer downloads a prebuilt `socketchat` program for your computer, puts it in `~/.local/bin`, and adds that folder to your PATH if it is missing. Open a new terminal afterwards so the PATH change takes effect. You do not need Rust or any other library, because the encryption code is built into the program. When it finishes, the installer lists the next steps: `socketchat server init` and `socketchat server run` set up and start your own server, `socketchat join '<invite link>'` joins a server you were invited to, and `socketchat` opens the chat screen. For a server friends on other computers can reach, add `--host <address>` to `server init`. Running `socketchat` before you join a server prints the same steps.

Prebuilt programs cover:

- macOS on Apple silicon and on Intel.
- Linux on Intel or AMD (x86_64), which covers most cloud servers and desktop computers, and on 64-bit ARM (aarch64), which includes a Raspberry Pi 4 or Zero 2 W running 64-bit Raspberry Pi OS. They need glibc 2.35 or newer, which Ubuntu 22.04, Debian 12 and Raspberry Pi OS 12 (Bookworm) have.
- 64-bit Windows on Intel or AMD.

**Updating.** Once a day Socketchat asks GitHub whether a newer release is out. When one is, the chat screen's bottom line and the output of commands such as `socketchat sync` say so: "Socketchat 0.5.3 is out. Run socketchat update." `socketchat update` installs nothing: it prints the command that installs the new version, which is `brew upgrade socketchat` for a Homebrew install and the install command above for the installer. On macOS and Linux the install command checks a SHA-256 checksum from the same release before it installs; on Windows it checks none. Nothing installs until you run one of those commands. The check is one request to GitHub for the newest release, and it carries nothing about you or your chats; GitHub sees your IP address, as with any web request. To turn it off, type `/updates off` in the chat screen, or set `SOCKETCHAT_NO_UPDATE_CHECK=1`. Then Socketchat makes no request to GitHub at all. [SECURITY.md](SECURITY.md) says what the check sends.

From 0.5.1 on, every file in a release has a GitHub build attestation: a signed record of the commit and the release workflow that built it. To check a file you downloaded from the release page, install the GitHub CLI and run `gh attestation verify <file> --owner sachio222 --cert-identity-regex '^https://github\.com/sachio222/socketchat(_v4)?/\.github/workflows/release\.yml@refs/tags/v'`. Release 0.5.1 was built while the repository was named socketchat_v4, so the check accepts both names.

**Or build from source**, for a system the prebuilt programs do not cover. You need the Rust toolchain from [rustup.rs](https://rustup.rs). On Linux, also install the OpenSSL headers, which the encrypted local database needs:

```
sudo apt install build-essential pkg-config libssl-dev
```

Then install Socketchat:

```
cargo install --locked --git https://github.com/sachio222/socketchat socketchat
```

On Windows, add `--features vendored-openssl` to that command. It builds OpenSSL from source, which needs the Visual Studio C++ build tools and [Strawberry Perl](https://strawberryperl.com).

The first build compiles Socketchat and all its libraries. It takes several minutes on a fast machine (about five and a half minutes in a clean arm64 Linux container on an Apple Silicon Mac) and much longer on a Raspberry Pi.

Once Socketchat is installed, the steps below take a few minutes.

On the machine that will be the server, set it up and start it. Use the name or IP address other people will dial for `--host`:

```
socketchat server init --host chat.example.com
socketchat server run
```

`init` prints the acceptable-use statement, writes a config file, and makes a TLS certificate, which lets apps check that they reached your server and encrypts the connection. Invite links carry the certificate's fingerprint, so nobody copies files between machines. People reach the server on port 7444, so open that port on your firewall or router.

In a second terminal on the server, make a one-time invite link for yourself:

```
socketchat server invite
```

On your own computer, use the link. The first time, Socketchat asks for a display name and a passphrase that encrypts everything it keeps on this computer:

```
socketchat join "socketchat://chat.example.com:7444/j/..."
```

The chat screen opens. Start a room and invite a friend:

```
/new Friends
/invite
```

`/invite` shows a link and a QR code, and copies an invite message to your clipboard. A phone that scans the QR code opens socketchat.org/join, which shows your friend how to install Socketchat on a computer and the command that joins. The message tells your friend to install Socketchat on their computer from socketchat.org and then run `socketchat join` with the link in quotes, ready to paste into a terminal. A line under the link says whether the copy worked, and C copies the message again. While your app is open, it lets them in. Your friend's app checks that the link came from you and marks you verified. From then on, either of you opens the chat screen with:

```
socketchat
```

Type `/help` in the chat screen to see every command. Click a room to open it, click a panel to move to it, and scroll messages and long boxes with the mouse wheel. Boxes have buttons, such as Yes and No when Socketchat asks a question. To select text, hold Shift as you drag (Option or Fn on a Mac), or type `/mouse off` to give the mouse back to your terminal. Tab completes a command as you type it, and Shift-Tab steps back through the matches. Up and Down in the message box step through the messages you sent and commands you ran in the open room. Socketchat keeps them in memory only, until it closes, and `/leave`, `/clear` and `/forget` drop them at once. `/switch` opens another room, and Tab completes its name. `/details` shows a room's admins, size and age, `/mute` hides its new-message count, `/invites` lists the invite links you made that still work, and `/theme` shows the colors or switches between phosphor, the default, and classic, and `/about` shows the version and what Socketchat is. The version also sits at the right end of the bottom line when the window is wide enough. The open room's server shows next to its name. `/servers` lists every server you use, with how many of your rooms are on it and whether Socketchat can reach it, and `/forget <number>` deletes a server you no longer use, with its rooms, from this computer. The server is not told, so leave its rooms first if it still works. New rooms go on the open room's server, and `/new` says which one. From a terminal, `socketchat servers` lists them, `socketchat servers --forget <number>` forgets one, and `socketchat new <name> --server <number>` picks where a room goes. Admins rename a room with `/title` and ask to close it with `/close`. `/topic <text>` sets the room's topic, one line that shows under the room's name for everyone in it; `/topic` shows it with who set it and when, and `/topic --clear` removes it. Only admins set the topic until an admin runs `/settings topic anyone`. From a terminal, `socketchat topic --group <name>` prints a room's topic, adding text sets it, and `--clear` removes it. `/settings` shows who can invite people into the open room, whether slow mode is on and who can set the topic. Admins let only admins invite with `/settings invite admins` (or anyone again with `/settings invite anyone`), make each member who isn't an admin wait between messages with `/settings slow <seconds>`, or turn that off with `/settings slow off`, and choose who sets the topic with `/settings topic anyone` or `/settings topic admins`. A server limits how fast each member posts in a room; a message over the limit waits in the app, which says when it goes, and sends it then. [docs/running-a-server.md](docs/running-a-server.md) covers a server that runs all the time.

## What leaving and closing delete

When you leave a room, Socketchat deletes the room's keys from your computer at once. When you are removed or the room closes, it deletes them as soon as your app learns of it, which for an app that was not running is its next sync with the server. The room's messages go once you have read them: after your own leave at once, and after a removal or a close when you open another room or quit. Messages you have not read stay until you read them. Once 30 days have passed since the room ended for you, Socketchat deletes them anyway the next time it opens, you open another room or it quits. `/clear` deletes a room's messages and its files list from your computer while you stay in it. Deletion happens in each person's own app, so other members keep their copies, and anyone can photograph a screen. A 0.5.0 server deletes everything it holds for a room once the last member's app leaves while alone in it, as an admin's app does at the end of a close. [SECURITY.md](SECURITY.md) has the details.

## Screenshots

A room with three people:

![A room with three people](docs/images/chat.png)

The invite box with its QR code:

![The invite box with a QR code](docs/images/invite.png)

Two people comparing safety numbers, a 60-digit number that matches on both screens when nobody sits between them:

![Comparing safety numbers](docs/images/verify.png)

Setting up and running a server:

![Server init and run](docs/images/server.png)

Joining from the command line:

![Joining from the command line](docs/images/join.png)

## What the server sees

The server stores and forwards encrypted data. It never sees message text, file contents, display names, room names, room topics, or any key that can decrypt them. It does see when encrypted messages and files move, how big each file is, each message's size rounded up to blocks of 256 bytes, the IP addresses of connected apps, and for each room a list of random keys, the signed changes to that list, and the room's settings: whether only admins can invite, slow mode, and whether only admins can set the topic. A person gets a fresh random key in every room, so no key or ID in the server's records ties one person's rooms together. Someone watching the server live can still link a person's rooms by IP address and connection.

[SECURITY.md](SECURITY.md) has the full list, the cryptography, and what Socketchat does not protect.

## Documents

- [SECURITY.md](SECURITY.md): what the server sees, the cryptography, limits, and how to report a vulnerability.
- [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md): what Socketchat is for.
- [docs/files-photos-videos.md](docs/files-photos-videos.md): how sending files works and its limits, for everyone.
- [docs/running-a-server.md](docs/running-a-server.md): a server that runs all the time, on a cloud server, a home computer or a Raspberry Pi.
- [CHANGELOG.md](CHANGELOG.md): what changed in each release.
- [ROADMAP.md](ROADMAP.md): planned work, and where help is welcome.
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing and reviews.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): Contributor Covenant 2.1.
- [docs/architecture.md](docs/architecture.md) and [docs/protocol.md](docs/protocol.md): how the code fits together, for contributors.
- [docs/design.md](docs/design.md): the design Socketchat v4.0 was built from.
- [site/](site/): the pages served at socketchat.org.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
