# Changelog

Each release of socketchat has a section here. Version numbers follow [Semantic Versioning](https://semver.org): the first number changes when something stops working the old way, the second for new features, the third for fixes.

## Unreleased

- Planned for 0.5.0 (see [ROADMAP.md](ROADMAP.md)): rename and close rooms (closing needs the admins to agree), a `/switch` command with Tab completion, history that is deleted when you leave or a room closes, and a way to see and cancel invite links you sent.
- A check now keeps libraries released less than 30 days ago out of `Cargo.lock`; run it with `sh scripts/crate-age-check.sh`. 47 libraries went back to older releases. `openmls` 0.9.1 stays, because socketchat pins that exact version.
- A 0.5.0 server still serves apps on 0.4.0, so you can update the server first.
- A 0.5.0 app still works with a server on 0.4.0. A feature that needs a newer server says so and leaves the rest of the app alone.

## 0.4.0 - 2026-10-20

The first release of socketchat v4: a rewrite in Rust of the earlier Python versions, with standard group encryption and a server you run yourself.

- **Group chats encrypted end to end with MLS** (RFC 9420, through OpenMLS 0.9.1), on the hybrid post-quantum suite ML-KEM-768 with X25519 by default. The suite comes from an IETF draft that is not final; [SECURITY.md](SECURITY.md) explains what that means.
- **Invite links** with no usernames or directory. A link works once, expires after the time the server sets (24 hours unless changed), and lets the new person check who invited them.
- **Verification**: safety numbers to compare in person, with a QR code.
- **A server that cannot read**: it checks signed group changes and admin rights, stores only encrypted data, and keeps no record that ties one person's groups together.
- **Files, photos and videos**, encrypted in chunks with a fresh key per file. Photos lose their location and device data before sending; videos ask first, because they keep theirs.
- **A terminal chat screen** that works at 80 by 24 and over SSH, with commands for invites, direct chats, files, verification and admins.
- **Encrypted local storage** keyed by your passphrase, locked so only one copy of socketchat opens a profile at a time.
- **A server built to face the open internet**: every connection has a memory budget, idle and silent connections are closed, large backlogs come back in pages, and a server that is full says so. Three rounds of security review went into this release.
- **One-line installers** for macOS, Linux and Windows. The Linux programs run on Intel and AMD machines and on 64-bit ARM, which includes a Raspberry Pi 4 or Zero 2 W.
