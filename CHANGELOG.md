# Changelog

Each release of socketchat has a section here. Version numbers follow [Semantic Versioning](https://semver.org): the first number changes when something stops working the old way, the second for new features, the third for fixes.

## Unreleased

Planned for 0.5.0: rename and close rooms (closing needs the admins to agree), a `/switch` command with Tab completion, history that is deleted when you leave or a room closes, and a way to see and cancel invite links you sent. See [ROADMAP.md](ROADMAP.md).

## 0.4.0 - 2026-10-20

The first release of socketchat v4: a rewrite in Rust of the earlier Python versions, with standard group encryption and a small server you run yourself.

- **Group chats encrypted end to end with MLS** (RFC 9420, through OpenMLS 0.9.1), on the hybrid post-quantum suite ML-KEM-768 with X25519 by default. The suite comes from an IETF draft that is not final; [SECURITY.md](SECURITY.md) explains what that means.
- **Invite links** with no usernames or directory. A link works once, expires after the time the server sets (24 hours unless changed), and lets the new person check who invited them.
- **Verification**: safety numbers to compare in person, with a QR code.
- **A server that cannot read**: it checks signed group changes and admin rights, stores only encrypted data, and keeps no record that ties one person's groups together.
- **Files, photos and videos**, encrypted in chunks with a fresh key per file. Photos lose their location and device data before sending; videos ask first, because they keep theirs.
- **A terminal chat screen** that works at 80 by 24 and over SSH, with commands for invites, direct chats, files, verification and admins.
- **Encrypted local storage** keyed by your passphrase.
- **One-line installers** for macOS, Linux (including a 64-bit Raspberry Pi) and Windows.
