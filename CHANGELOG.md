# Changelog

Each release of socketchat has a section here. Version numbers follow [Semantic Versioning](https://semver.org): the first number changes when something stops working the old way, the second for new features, the third for fixes.

## 0.5.0 - 2026-10-21

This release lets you move between rooms, rename them and close them, deletes a room's history from your computer once you are done with it, and lists the invite links you made that still work. Apps and servers on 0.4.0 still work with 0.5.0.

- **Moving between rooms**: `/switch` opens another room, and Tab completes its name. Unread counts stay right after you close and reopen the app, and `socketchat log` marks the room it prints as read. Anything you had before this update counts as read.
- **Renaming a room**: admins rename a room for everyone with `/title`, and the room shows who renamed it.
- **Closing a room**: `/close` asks to close a room for everyone, and the room closes once its admins agree: every admin when the room has up to three, more than half of them when it has more. A room with one admin closes at once. `/keep` says no, and a request to close stays open for seven days.
- **Room details and muting**: `/details` shows a room's admins, how many people are in it and when it was made. A server on 0.4.0 cannot say when, so that line is left out. `/mute` hides a room's new-message count on your own computer, nobody else sees that you muted it, and `/unmute` shows the count again.
- **Leaving, removal and closing**: when you leave a room, socketchat deletes the room's keys from your computer at once. When you are removed or the room closes, it deletes them as soon as your app learns of it, which for an app that was not running is its next sync with the server. When you leave, the room's messages go at the same time, and `/leave` first shows any new messages and asks you to type `/leave` again. A room you were removed from or that closed stays on screen, saying so, and its read messages go when you open another room or quit. Unread messages stay until you read them and still show who wrote them. Once 30 days have passed since the room ended for you, socketchat deletes them anyway the next time it opens, you open another room or it quits.
- **Deleting data on your computer**: `/clear` deletes a room's messages from your computer while you stay in it. socketchat turns on SQLite's `secure_delete`, so deleted rows are overwritten inside your encrypted profile. A join request made with 0.5.0 no longer leaves spare keys on your computer once you join. Opening 0.5.0 deletes the history of rooms you left with 0.4.0.
- **Invite links you made**: `/invites` lists the ones that still work, and `/cancel <number>` stops one. From a terminal, `socketchat invites` lists them, and `socketchat invites --cancel <number>` stops one and names the link it cancelled.
- **Servers delete rooms nobody is in**: a 0.5.0 server deletes everything it holds for a room at once when a 0.5.0 app leaves it as the room's only member, as happens at the end of a close. Its hourly sweep also deletes rooms that have no members.
- **Working with 0.4.0**: apps and servers now use protocol 2, and still use protocol 1 with apps and servers on 0.4.0. A 0.5.0 server serves apps on 0.4.0, so you can update the server first. A 0.5.0 app works with a server on 0.4.0. A feature that needs a newer server says so and leaves the rest of the app alone.
- **Messages from add-ons and other programs**: rooms now carry them, end-to-end encrypted like text. One that carries a summary line shows it in the chat, and apps on 0.4.0 skip them. Each app also tells its rooms which version it runs.
- **Contributors**: `sh scripts/crate-age-check.sh` keeps libraries released less than 30 days ago out of `Cargo.lock`, so this release builds against older versions of some of them.

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
