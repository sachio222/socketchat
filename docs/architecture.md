# Architecture

This document explains how socketchat v4.0's code fits together, for people who want to change it. Read it with [protocol.md](protocol.md), which describes the bytes on the wire, and [SECURITY.md](../SECURITY.md), which says what each part protects.

A relay server keeps an ordered log of MLS messages for each group and checks every group change it can read. Clients hold every key that decrypts anything.

## Terms

- **MLS (Messaging Layer Security):** the IETF standard for encrypted group chat, RFC 9420. socketchat uses the OpenMLS library.
- **Epoch:** a numbered version of a group's state. Every change to the group starts a new epoch with new keys.
- **Commit:** an MLS message that changes the group and moves it to the next epoch. **Proposal:** a suggested change that a later Commit applies.
- **Welcome:** an MLS message that lets a new member join.
- **KeyPackage:** a public bundle a person publishes so others can add them to a group.
- **PublicMessage / PrivateMessage:** MLS's two wire formats. A PublicMessage is signed but readable; a PrivateMessage is encrypted.
- **GroupContext extension:** extra data in a group's shared state that every member agrees on through MLS.
- **PublicGroup:** OpenMLS's view of a group from the outside: members, their public keys and the GroupContext, with no secret that decrypts anything.

## Crates

| Crate | Job |
|---|---|
| `socketchat-proto` | Frames, the request, response and push enums, and invite links. No cryptography and no I/O, so client and server agree on bytes and nothing else. |
| `socketchat-core` | The client engine with no screen. Holds keys, runs MLS groups through OpenMLS, makes and redeems invites, encrypts files, keeps local storage, and talks to servers. The server also uses its `keys` and `suite` modules. |
| `socketchat-server` | The relay. One task per connection, one SQLite database, and an hourly cleanup task. |
| `socketchat-tui` | The terminal chat screen, built with ratatui and crossterm, on top of `socketchat-core`. |
| `socketchat-testkit` | `TestServer` and `TestClient` helpers, and the integration tests that need a real server. It exists because `socketchat-server` depends on `socketchat-core`, so core's own tests cannot start a server. |
| `socketchat` | The binary. `socketchat` opens the chat screen, `socketchat server ...` runs the relay, `socketchat join <link>` redeems a link, and `new`, `invite`, `send`, `log` and `sync` serve scripts. |

## The client engine

`socketchat_core::client::Client` is the whole client without a screen. Tests drive several at once against one server, and the terminal app is one front end on top.

- **Opening.** `Client::create_profile` makes a profile with an identity key and a display name; `Client::open` unlocks an existing one with the passphrase.
- **Acting.** Methods such as `join`, `create_group`, `invite`, `send_text`, `send_file`, `save_file`, `dm`, `remove_member`, `make_admin`, `leave` and `set_display_name` each do one thing and return when the server has answered.
- **Receiving.** `sync` fetches everything new from every server, applies it, and queues events. `take_events` hands them over, oldest first: `Joined` (with whether the join was verified), `JoinRequestHandled`, `Message`, `MembersChanged`, `GroupRenamed`, `NameChanged`, `Left`, `FileOffered`, `Warning`, `Disconnected` and `Reconnected`.
- **Waiting.** `wait(max)` returns when a server pushes something, a connection drops, or time runs out. It only listens, so it is safe to cancel. The chat screen waits inside `select!` alongside key presses, then calls `sync` outside it, so an MLS step never stops halfway.

During `sync` the client also refreshes its own keys in any group where they are more than a week old (`KEY_REFRESH_SECS`), and repeats its profile in groups where someone new joined, since a newcomer cannot read older messages.

What travels inside encrypted application messages is the `AppMsg` enum in `appmsg.rs`: text, a member's profile (display name plus the identity key's signature over their group key), the group name, invite vouchers, file offers, and the steps for opening a direct message. All text from other people passes through `sanitize.rs`, which strips terminal control characters and direction overrides and caps the length.

## Keys

Every key is Ed25519. Each person holds:

- an **identity key**, one per person, which stays on their device. Invite links carry its fingerprint and safety numbers are built from it. Its public half reaches the server in one place only, the voucher that travels with a Welcome (see "Invites");
- a **group key** for every group they join. It is their MLS credential in that group, and the group's mailbox on the server belongs to it. A `Binding`, signed by the identity key, ties the two together inside the group's encrypted messages;
- a **server account key**, one per server, which lets them create groups.

A connection signs in by signing a random challenge with each key it uses. The server never records which account created which group or mailbox.

## The server's checks on group changes

The server loads each group as an OpenMLS `PublicGroup` (in `groups.rs`) and checks every message before it enters the log:

- **Wire format.** Commits and Proposals must be PublicMessages, so the server can read and check them. Application messages must be PrivateMessages from a current member, for the current epoch or one of the two before it.
- **Admin list.** The admins' group keys live in a GroupContext extension with type `0xff00`, from the private-use range of RFC 9420. Each entry is a 2-byte length (always 32) followed by the key. Anything malformed reads as no admins, which means "refuse".
- **Who may do what.** Adding someone needs an admin, or any member when the server allows members to invite. Removing someone else, or changing the admin list, needs an admin. Anyone may remove themselves. A member may only propose their own removal; other proposals are refused. Other proposal kinds, such as ReInit, are refused.
- **Admins never run out.** After a change at least one admin must remain. If the last admin leaves, that Commit must make the longest-standing remaining member the only admin, and the server refuses it otherwise.
- **Adds match invites.** Someone can only be added if their mailbox redeemed an invite to this group.
- **Epoch ordering.** The server accepts a Commit for epoch N only while the group sits at epoch N. The first valid Commit wins and gets the next sequence number. A Commit for any other epoch gets `Conflict { epoch }`; that client fetches what it missed and tries again. If a reply is lost on the way, the client keeps the Commit staged and merges it when the same bytes come back in the log.

New groups get one check of their own: the group must hold only its creator, as its only admin, with a mailbox registered for that purpose, on an allowed suite.

## Per-group keys and mailboxes

Every time a person joins or creates a group, their app makes a fresh group key and registers it as a new mailbox. The server's database therefore shows each group as a separate set of random keys. A direct message started with `/dm` inside a shared group exchanges the new chat's KeyPackages and token through that group's encrypted messages, so the server sees two unrelated groups.

## Invites

An invite link holds the server address, a token the server stores, and, after the `#`, the server certificate's fingerprint. A group invite adds the inviter's identity fingerprint and a random invite secret. Apps never send the part after `#` to the server.

1. The inviter's app asks the server for a token, then signs a **voucher** with its identity key: the token, a SHA-256 hash of the secret, the group ID, the inviter's group key and an expiry. It sends the voucher and the secret to the group inside an encrypted message, so any member can complete the join.
2. The joiner's app pins the server certificate, makes a fresh group key, registers a mailbox with the token, and lodges a KeyPackage for each allowed suite, with an HMAC-SHA256 tag keyed by the invite secret.
3. The server pushes the join request to the group's online members. The inviter's app, or any admin's, checks the tag against the secret, adds the KeyPackage that matches the group's suite with a Commit, and posts the Welcome with the voucher. In v4.0 the voucher travels beside the Welcome unencrypted, so the server sees the inviter's identity key and group key; [SECURITY.md](../SECURITY.md) explains the effect.
4. The joiner's app checks the voucher's signature against the fingerprint in the link, its token, secret and group, and that the member who added them is the voucher's inviter or an admin. Anything else shows a red warning.

The token works once and expires after `invite_ttl_hours`. A lodged request waits up to 7 days. A group invite can also register a server account for the joiner when the server allows members to invite.

## Files

`files.rs` seals a file in 64 KiB chunks with XChaCha20-Poly1305 STREAM, under a fresh random key and nonce prefix, while hashing the plaintext with SHA-256. JPEG, PNG and WebP images lose their metadata first; files are recognized by their first bytes, not their names. Videos need an explicit yes. The app uploads chunks in order (`FileBegin`, `FileChunk`, `FileEnd`), then sends a `FileOffer` with the key, nonce prefix, name, size and hash inside the group. Saving downloads chunk by chunk to a temporary file, checks the hash, and links the result under a name that never replaces an existing file. Memory use stays flat however large the file is.

The server stores chunks as files under `files/` in its data directory and deletes a file once every member except the sender has reported `FileDone`, or at retention.

## Storage

**Client.** One SQLite file, `socketchat.db`, encrypted with SQLCipher. The key comes from the passphrase through Argon2id (19 MiB, 2 passes) with a random salt in a file beside it. socketchat's own tables (profile, servers, groups, members, trusted identities, messages, vouchers, files, pending joins) and OpenMLS's group state share that one connection, which `openmls_sqlite_storage` accepts. The profile lives in the platform's data folder, or in `SOCKETCHAT_HOME` if set.

**Server.** One SQLite file, `server.db`, in WAL mode, unencrypted because it holds nothing readable: accounts, invites, mailboxes, groups, the group log, join requests, Welcomes, file metadata and file receipts, plus OpenMLS's PublicGroup state. WAL mode lets `socketchat server invite` add an invite while the server runs. The hourly sweep in `retention.rs` deletes expired log entries, Welcomes, files, invites, join requests and unfinished mailboxes. A log entry also goes once every member has acknowledged it.
