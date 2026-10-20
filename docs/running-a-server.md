# Running a server

This guide sets up a socketchat server that runs all the time, on a cloud server, a computer at home, or a small device such as a Raspberry Pi. It covers installing, setup, configuration, opening the port, running under systemd, backups, upgrades and cleanup of old data. The server is one program, `socketchat server`, with its data in one folder.

A socketchat server stores and forwards encrypted messages and files. It never holds a key that can read them. As the operator you answer for what happens on your server; read [ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md), which `init` also prints.

## Pick a machine

- **A cloud server.** The smallest Linux plan most providers offer is enough to start. It needs a public IP address or a domain name.
- **A computer at home that stays on.** The steps below are for Linux. The `socketchat server` commands work the same on macOS and Windows.
- **A Raspberry Pi 4 or Raspberry Pi Zero 2 W.** Use 64-bit Raspberry Pi OS. The project builds and tests on 64-bit ARM Linux (aarch64) on every change.

## Install

On the server, run the installer:

```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sachio222/socketchat_v4/releases/latest/download/socketchat-installer.sh | sh
```

It downloads a prebuilt `socketchat` program and puts it in `~/.local/bin/socketchat`. The program has its encryption libraries built in, so the server needs no Rust, no OpenSSL and no other package.

The Linux programs cover Intel or AMD (x86_64) and 64-bit ARM (aarch64). They need glibc 2.35 or newer, which Ubuntu 22.04, Debian 12 and Raspberry Pi OS 12 (Bookworm) have. A Raspberry Pi 4 or Zero 2 W running 64-bit Raspberry Pi OS uses the aarch64 program. 32-bit Raspberry Pi OS is not covered; install the 64-bit edition instead.

### Build from source

Build from source on a system the prebuilt programs do not cover. The first build compiles socketchat and all its libraries. It takes several minutes on a fast machine and much longer on a Raspberry Pi.

On the machine itself, install Rust from [rustup.rs](https://rustup.rs) and the build tools:

```
sudo apt install build-essential pkg-config libssl-dev
cargo install --locked --git https://github.com/sachio222/socketchat_v4 socketchat
```

`--locked` builds with the exact dependency versions the project tested. cargo puts the binary in `~/.cargo/bin/socketchat`.

If you cannot install `libssl-dev`, build OpenSSL from source instead. This needs a C compiler, `make` and `perl`:

```
cargo install --locked --git https://github.com/sachio222/socketchat_v4 socketchat --features vendored-openssl
```

**For a Raspberry Pi, build somewhere faster.** Build on a faster 64-bit ARM Linux machine running the same OS release as the Pi, or cross-compile for `aarch64-unknown-linux-gnu`, then copy the `socketchat` binary to the Pi. Building with `--features vendored-openssl` avoids depending on the Pi's OpenSSL version.

## Set up

Create a user for the server and put the binary where systemd can find it:

```
sudo useradd --system --home-dir /var/lib/socketchat --shell /usr/sbin/nologin socketchat
sudo install -d -o socketchat -g socketchat -m 700 /var/lib/socketchat
sudo install -m 755 ~/.local/bin/socketchat /usr/local/bin/socketchat
```

If you built from source, copy `~/.cargo/bin/socketchat` instead.

Run `init` as that user:

```
sudo -u socketchat socketchat server init --data-dir /var/lib/socketchat --host chat.example.com
```

- `--host` is the name or IP address people dial. Invite links carry it. The default is `localhost`, which only works on the same machine.
- `--listen` is the address and port to listen on. The default is `0.0.0.0:7444`, every IPv4 address on port 7444. Use `--listen [::]:7444` to listen on IPv6.
- `--data-dir` is where the server keeps everything. Without it, the server uses a folder under the user's home, such as `~/.local/share/socketchat-server` on Linux.

`init` writes `socketchat-server.toml`, makes a self-signed TLS certificate (it encrypts connections and lets apps recognize your server), creates an empty database, and prints the certificate's fingerprint. Invite links carry that fingerprint, and apps refuse any server whose certificate does not match it, so nobody copies certificates by hand. `init` refuses to run in a folder that already has a certificate.

## Configuration

`socketchat-server.toml` in the data directory holds these keys. The server reads it at start, so restart after an edit. `socketchat server run --config <file>` uses a config file from somewhere else.

| Key | Default | What it does |
|---|---|---|
| `listen` | `0.0.0.0:7444` | Address and port to listen on. |
| `public_host` | value of `--host` | Name or address people dial. Invite links carry it. |
| `data_dir` | the folder from `init` | Where the database, certificate and file pieces live, as a full path. |
| `retention_days` | `30` | Days the server keeps messages and files nobody has fetched. |
| `max_file_mb` | `100` | Largest file anyone can send, in megabytes of 1,000,000 bytes. |
| `invite_ttl_hours` | `24` | Hours an invite link stays usable. |
| `members_can_invite` | `true` | Whether members, not only admins, can make group invite links. When `false`, only admins make group links, only you make server invites, and people who join through a group link can chat there but cannot start their own groups until you send them a server invite. |
| `require_standard_suite` | `false` | When `true`, new groups must use the standard MLS suite (0x0001), which has no post-quantum protection. Groups that already exist keep their suite. |
| `max_connections` | `1000` | Most connections served at once. |

`socketchat server invite --data-dir /var/lib/socketchat` prints a one-time link that registers one new person. It works while the server runs.

### Limits set in the server

These limits are not in the config file:

- **Connections.** An app must say hello within 10 seconds of connecting, and the server closes a connection that sends nothing for 5 minutes. Apps reconnect on their own the next time they need the server, so people see no error.
- **Server invites from members.** When `members_can_invite` is `true`, each account can make 5 server invite links in a window that lasts the link lifetime rounded up to whole days, plus one day: two days with the default 24 hours. The next request gets "you have made 5 server invite links lately; try again in a day or two". Links you print with `socketchat server invite` do not count.
- **Message size.** The server refuses an encrypted message over 1,047,552 bytes, just under the 1 MiB frame limit. Files are not affected, since they travel in 64 KiB pieces.

## Open the port

People connect over TCP to the port in `listen`, 7444 by default. Invite links carry that same port number.

- **Home network:** forward TCP port 7444 on your router to the server machine, using the same port number outside and inside. Use your public IP address or a dynamic DNS name for `--host`.
- **Firewall on the machine:** for example, `sudo ufw allow 7444/tcp`.
- **Cloud server:** also allow inbound TCP 7444 in the provider's firewall or security group.

## Run it with systemd

Save this as `/etc/systemd/system/socketchat.service`:

```
[Unit]
Description=socketchat server
After=network-online.target
Wants=network-online.target

[Service]
User=socketchat
Group=socketchat
ExecStart=/usr/local/bin/socketchat server run --data-dir /var/lib/socketchat
Restart=on-failure
KillSignal=SIGINT
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/socketchat

[Install]
WantedBy=multi-user.target
```

`KillSignal=SIGINT` sends the same signal as Ctrl-C, which the server handles by closing connections and stopping cleanly. Then:

```
sudo systemctl daemon-reload
sudo systemctl enable --now socketchat
sudo -u socketchat socketchat server invite --data-dir /var/lib/socketchat
```

`journalctl -u socketchat` shows the address and certificate fingerprint the server printed at start.

## What retention does

Every hour, starting one hour after the server starts, a cleanup task deletes:

- messages older than `retention_days`, and Welcomes (the messages that let a new member in) nobody fetched in that time;
- files older than `retention_days`;
- invite links past their expiry;
- join requests nobody acted on within 7 days, and mailboxes made for joins that never finished.

Messages and files also go sooner: the server deletes a message once every member's app confirms it has it, and a file once every member has saved it.

## Back up

The data directory holds everything: `server.db` and its `-wal` and `-shm` files, `cert.der`, `key.der`, `socketchat-server.toml`, and a `files` folder.

1. Stop the server: `sudo systemctl stop socketchat`.
2. Copy the whole data directory somewhere safe.
3. Start the server again: `sudo systemctl start socketchat`.

Keep `cert.der` and `key.der` above all. Every invite link and every member's app pins this certificate's fingerprint. If you lose it, every app refuses to connect and everyone has to join again. Their apps show the old and new fingerprints and change nothing until each person accepts the new certificate, with `socketchat join --new-certificate <link>` or with Y in the chat screen, so tell them to expect it. `key.der` is the certificate's private key, so store backups where only you can read them.

If you restore to a different path, change `data_dir` in `socketchat-server.toml` to match.

## Upgrade

1. Run the installer again to get the newest release, or rebuild from source, as in "Install".
2. Back up the data directory, as above.
3. `sudo systemctl stop socketchat`, then `sudo install -m 755 ~/.local/bin/socketchat /usr/local/bin/socketchat` (or `~/.cargo/bin/socketchat` after a source build), then `sudo systemctl start socketchat`.

Apps and servers send a protocol number when they connect (1 in v4.0). If a new release changes it, apps and servers with different numbers refuse to talk, so tell your members to upgrade too.

## Measured numbers

- Idle memory: 10 MB for a release build on an Apple Silicon Mac. The design target is under 20 MB.
- Chat screen: first draw at 80 by 24 characters in about 58 ms on the same Mac. The target is under 300 ms.
- Raspberry Pi numbers are not measured yet. `scripts/idle-memory.sh` measures idle memory on any machine; please share your results in an issue.
