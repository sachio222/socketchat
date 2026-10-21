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
| `socketchat` | The binary. `socketchat` opens the chat screen, `socketchat server ...` runs the relay, `socketchat join <link>` redeems a link, `socketchat invites` lists and cancels open invite links, and `new`, `invite`, `send`, `log` and `sync` serve scripts. |

## The client engine

`socketchat_core::client::Client` is the whole client without a screen. Tests drive several at once against one server, and the terminal app is one front end on top.

- **Opening.** `Client::create_profile` makes a profile with an identity key and a display name; `Client::open` unlocks an existing one with the passphrase. Opening also finishes any room ending that stopped part way, deletes the history of rooms left with 0.4.0, and runs `purge_read` (see "Rooms that end").
- **Acting.** Methods such as `join`, `create_group`, `invite`, `send_text`, `send_file`, `save_file`, `dm`, `remove_member`, `make_admin`, `leave` and `set_display_name` each do one thing and return when the server has answered. Rooms add `rename_room` (admins only), `details` (admins, size, creation and join times, mute state and any request to close), `vote_close` and `close_state` (see "Closing a room"), and calls that send nothing: `mark_seen`, `mark_seen_upto`, `set_muted` and `clear_history`. `lines_to_read` gives the lines a script reads next: the newest ones, or the oldest unread ones when more are unread than it asks for. `invites` lists this person's open invite links on every server and `cancel_invite` stops one. `send_extension` sends a message for an add-on or another program, and `extensions` reads a room's stored ones after a sequence number, at most 500 at a time.
- **Receiving.** `sync` fetches everything new from every server, applies it, and queues events. `take_events` hands them over, oldest first: `Joined` (with whether the join was verified), `JoinRequestHandled`, `Message`, `MembersChanged`, `GroupRenamed`, `NameChanged`, `Left { group, name }` (with the room's name, since its record may already be gone), `FileOffered`, `Extension` (a stored message for an add-on), `CloseVote` (an admin voted on closing a room), `Closed` (a room was closed, and by whom; `Left` follows), `Warning`, `Disconnected` and `Reconnected`.
- **Connecting.** Each connection says Hello with protocol 2. When the server answers `VersionMismatch` naming protocol 1, the client connects once more with 1. `Conn::protocol` gives the version agreed, and `Client::protocol_for` gives it for a room's server. A request newer than the connection's version fails in the app with `NetError::Unsupported` without reaching the server; it does not count as a lost connection.
- **Waiting.** `wait(max)` returns when a server pushes something, a connection drops, or time runs out. It only listens, so it is safe to cancel. The chat screen waits inside `select!` alongside key presses, then calls `sync` outside it, so an MLS step never stops halfway.

During `sync` the client also refreshes its own keys in any group where they are more than a week old (`KEY_REFRESH_SECS`), and repeats its profile, and the group's name and kind, in groups where someone new joined, since a newcomer cannot read older messages. It fetches each group's log until the server sends an empty page, or a page that does not move past where it started. It reads waiting join requests a page at a time, each page starting after the last request of the one before, until a page comes back empty, and tries each request once per sync. A dropped connection shows as `Event::Disconnected` and the next sync reconnects; a problem in one group, or with one join request, becomes an `Event::Warning` and sync carries on with the rest. When a Commit from someone else, or any message from a later epoch, will not apply, the client warns once that the chat fell out of step.

What travels inside encrypted application messages is the `AppMsg` enum in `appmsg.rs`: text, a member's profile (display name plus the identity key's signature over their group key), the group name, invite vouchers, a joiner's proof that they hold an invite link, file offers, the steps for opening a direct message, messages for add-ons and other programs, the app version each member runs, and admins' votes on closing a room. [protocol.md](protocol.md) lists every variant and the rules for adding one. All text from other people passes through `sanitize.rs`. Names lose terminal control characters, direction controls and invisible characters (Unicode format characters and Hangul fillers), so two different names cannot look the same. Message text loses only control characters other than the newline, and direction controls (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069). Joiners and tag characters stay, so emoji sequences such as a family, subdivision flags such as Scotland's, and scripts that need a zero-width non-joiner, such as Persian, arrive intact. Both are capped in length. The server's own refusal and error text goes through the message-text filter too.

## Keys

Every key is Ed25519. Each person holds:

- an **identity key**, one per person, which stays on their device. Invite links carry its fingerprint and safety numbers are built from it. Its public half never reaches the server in readable form: it travels inside the group's encrypted messages and inside the voucher sealed for a joiner (see "Invites");
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
- **Epoch ordering.** The server accepts a Commit for epoch N only while the group sits at epoch N. The first valid Commit wins and gets the next sequence number. A Commit for any other epoch gets `Conflict { epoch }`; that client fetches what it missed and tries again. If a reply is lost on the way, the Commit stays staged in OpenMLS's storage, so it survives a restart. Before its next change or message in that group, the client reads the log to the end: OpenMLS recognizes its own Commit (`OwnPendingCommit`) and the client merges it, records who it added and removed, and repeats its profile and the group's name for anyone it added; a different Commit for that epoch replaces it; and a log that ends without it means the server never took it, so the client drops it.

  When the post times out instead, the server may still be working on it. The client closes that connection and keeps the Commit staged through one more sync round, even if the log ends without it, and makes no new Commit in that group until it is settled. One window stays open. If the server takes the Commit only after that round, the client has already dropped it, cannot apply what follows, and says the chat fell out of step. An admin then removes the member and invites them again.

New groups get one check of their own: the group must hold only its creator, as its only admin, with a mailbox registered for that purpose, on an allowed suite.

## Per-group keys and mailboxes

Every time a person joins or creates a group, their app makes a fresh group key and registers it as a new mailbox. The server's database therefore shows each group as a separate set of random keys. A direct message started with `/dm` inside a shared group exchanges the new chat's KeyPackages and token through that group's encrypted messages, so the server sees two unrelated groups. The request carries the asker's key in the new chat; the other app counts the chat as verified only when the Welcome comes from that key, for that chat, and the asker's identity is already verified.

## Invites

An invite link holds the server address, a token the server stores, and, after the `#`, the server certificate's fingerprint. A group invite adds the inviter's identity fingerprint and a random invite secret. Apps never send the part after `#` to the server.

1. The inviter's app asks the server for a token, then signs a **voucher** with its identity key: the token, a SHA-256 hash of the secret, the group ID, the inviter's group key and an expiry. It sends the group the voucher, the public half of the request key, and the seal key, inside an encrypted message, so any admin can complete the join. Both keys come from the secret with HKDF-SHA256: the request key is an Ed25519 key whose seed is derived with info `socketchat/v1/invite-sign` (`invite_signing_key` in `keys.rs`), and the seal key is `voucher_seal_key`. The secret itself stays with the inviter and the link. A member's app keeps a voucher only when its sender is the inviter it names, with the identity that sender proved in their profile, and a later voucher for the same token never replaces it.
2. The joiner's app pins the server certificate, makes a fresh group key, registers a mailbox with the token, and lodges a KeyPackage for each allowed suite. Each KeyPackage carries, in a KeyPackage extension of type `0xff01`, an Ed25519 signature over the token and the new mailbox key, made with the request key it derives from the secret (`sign_join_request` in `keys.rs`). The KeyPackage's own signature, by the mailbox key, covers that extension, and the bundle stays the plain list of KeyPackages the server checks.
3. The server pushes the join request to the group's online members. The inviter's app, or any admin's, checks the signature against the public key from the voucher message (`join_request_ok`), adds the KeyPackage that matches the group's suite with a Commit, and posts the Welcome with the voucher. The voucher travels beside the Welcome sealed under the seal key (`seal_voucher` in `keys.rs`), so the server stores and forwards it without seeing the inviter's identity key.
4. The joiner's app opens the voucher with the seal key it derives from the link's secret, then checks its signature against the fingerprint in the link, its token, secret and group, and that the member who added them is the voucher's inviter or an admin. Anything else shows a red warning.
5. The joiner's app posts an `InviteProof`: an HMAC over the group ID and its new group key, under a third key derived from the secret (`invite_proof` in `keys.rs`). Only the inviter's app can check it, and other members cannot make it from the keys they hold, so the inviter's app marks the newcomer verified only on a good proof. The app stores the proof before posting it and posts any proof it still owes on each sync, so a connection that drops right after the Welcome does not lose it; its profile is owed the same way.

Members hold only the request key's public half, so they can check a request but cannot make one: a member cannot bring someone in through another person's link, even where only admins may invite. A request that fails the check is ignored, with one warning per request each session.

A link that names a server this profile already uses, with a different certificate, is refused with `CoreError::NewCertificate`, which carries both fingerprints. `Client::join_new_certificate` (the CLI's `socketchat join --new-certificate`, or Y in the chat screen's confirm box) connects under the link's certificate on a connection of its own and changes the pin only after that connection and the redeem both succeed.

The token works once and expires after `invite_ttl_hours`. A lodged request waits up to 7 days. A group invite can also register a server account for the joiner when the server allows members to invite.

## Files

`files.rs` seals a file in 64 KiB chunks with XChaCha20-Poly1305 STREAM, under a fresh random key and nonce prefix, while hashing the plaintext with SHA-256. JPEG, PNG and WebP images lose their metadata first; files are recognized by their first bytes, not their names. Videos need an explicit yes. The app uploads chunks in order (`FileBegin`, `FileChunk`, `FileEnd`), then sends a `FileOffer` with the key, nonce prefix, name, size and hash inside the group. Saving downloads chunk by chunk to a temporary file, checks the hash, and hard-links the result under a name that never replaces an existing file. On drives without hard links, such as FAT32 and exFAT, it copies the result into a new file under such a name instead. Memory use stays flat however large the file is.

The server stores chunks as files under `files/` in its data directory and deletes a file once every member except the sender has reported `FileDone`, or at retention.

## Rooms that end

A room ends for a person when they leave it, an admin removes them, or it closes (`Ended::Left`, `Ended::Removed`, `Ended::Closed`). `Client::end_room` first writes an `ended_rooms` row with the room's name, kind, the reason, the time and the seen mark. From then on the room counts as ended, and if a later step fails, the next `Client::open` finishes the job. Then `Store::end_room` deletes, in one transaction, the room's rows in every `ROOM_STATE_TABLES` table (members, vouchers, files, owed proofs, expected joiners, close votes, kept closes and invite links made into it), everything OpenMLS holds for the group, and the `groups` row with this member's group key. Before it deletes, it copies into `ended_names` the names of the people whose lines are still stored, so those lines keep their senders.

The room's history (`ROOM_HISTORY_TABLES`: `messages`, `extensions` and `ended_names`) stays until it is read. Each room keeps a seen mark, `groups.seen_seq`: a line counts as seen once the chat screen has shown its room, once this person sends in that room, or once `socketchat log` prints it. The CLI marks lines seen only up to the newest one it printed. `purge_read(keep)` deletes every ended room with nothing unseen except `keep`, the room on screen, and every room that ended at least `KEEP_UNSEEN_SECS` (30 days) ago. The chat screen calls it when another room opens and when it quits, and the CLI's commands call it before they finish. After this person's own leave with nothing unseen, `end_room` deletes the history at once.

Each deletion ends with `Store::checkpoint`, a `wal_checkpoint(TRUNCATE)` that clears old copies of the deleted rows out of SQLite's write-ahead log. When the log stays busy through three tries, the deletion still counts as done and the client warns.

A joiner lodges one KeyPackage per allowed suite. OpenMLS deletes the one a Welcome uses, and the client deletes the others with their private keys; `pending_joins.key_package_refs` remembers which they are.

## Closing a room

`close.rs` holds the rules and the tally, with no I/O. `close_needed` gives how many admins must agree: every admin when the room has up to 3, `n / 2 + 1` of `n` above that. `requests` counts each admin's newest vote, from the admins still in the room only.

`vote_close(gid, yes)` posts a `CloseVote`. The first yes starts a request with a random 16-byte ID, and the request stays open for `CLOSE_ASK_SECS` (7 days) from its first vote. A request that can no longer pass is kept, and `close_kept` remembers that, so it stays kept even when admins change later. The admin whose vote passes a request finishes the close at once, inside `vote_close`: it posts `Closed`, removes everyone else with one Commit, sends `LastLeave` so the server deletes the room, and ends the room as `Ended::Closed`. Another admin whose yes is in the count finishes it the same way during `sync` only when it finds the request passed and no `Closed` has arrived, as after the first admin's app stopped part way. Racing Commits resolve through the server's epoch check, so a close never waits on one app. Other members end the room as closed when they see `Closed` from an admin whose request passed, or when that admin's Commit removes them; `groups.closing` remembers a `Closed` that arrived first. `close_state` gives the request to show, as a `CloseView`.

## Invite lists

`invites_made` records each invite link this app makes: its token, server, room and expiry. `Client::invites` asks each server on protocol 2 for the open links (`ListInvites`). The server finds room links by their maker's keys, but keeps no record of who made a server link, so the app names its own by token, at most 100 per request. A link the server no longer lists was used, has expired or was cancelled, and the app forgets it. A server it cannot reach, or one on protocol 1, is skipped with a warning. `cancel_invite` sends `CancelInvite` and forgets the link.

## Storage

**Client.** One SQLite file, `socketchat.db`, encrypted with SQLCipher. The key comes from the passphrase through Argon2id (19 MiB, 2 passes, 1 lane for new profiles) with a random salt in a file beside it. That file starts with `sckdf` and a version byte 1, then the memory in KiB, passes and lanes as big-endian 32-bit numbers, then the 16-byte salt; a bare 16-byte salt from an older profile means the settings above. A file that asks for more than 256 MiB of memory, 16 passes or 8 lanes, or for less than 8 KiB of memory per lane, is refused with "the profile's salt file is damaged" before any hashing starts, so a changed file cannot hang the app or run a 512 MB Raspberry Pi Zero 2 W out of memory. While the profile is open, the app holds an operating-system lock on a `lock` file beside it, so a second app on the same profile stops with "socketchat is already open on this profile." socketchat's own tables (profile, servers, groups, members, trusted identities, messages, vouchers, files, pending joins, invite proofs still owed) and OpenMLS's group state share that one connection, which `openmls_sqlite_storage` accepts. The profile lives in the platform's data folder, or in `SOCKETCHAT_HOME` if set.

socketchat 0.5.0 adds these tables:

| Table | What it holds |
|---|---|
| `extensions` | Messages for add-ons and other programs: room, sequence number, sender, namespace, kind, version, body, summary and time. |
| `invites_made` | Invite links this app made: token, server, room (none for a server link) and expiry. |
| `ended_rooms` | Rooms this person is no longer in whose history is still here: name, kind, why it ended, when, and the seen mark. |
| `ended_names` | Names of the people whose lines are still stored for an ended room. |
| `close_votes` | Each admin's votes on closing a room: request ID, voter, yes or no, and when this app got it. |
| `close_kept` | Requests to close that this app saw end without closing. |

It also adds columns through `ADDED_COLUMNS`: `members.app_version` (the version a member said they run), `groups.announced_version` (the version this app last told the room), `groups.seen_seq` (the seen mark), `groups.muted`, `groups.closing` (a `Closed` this app knows of in the room, its own included while it closes the room) and `pending_joins.key_package_refs` (the KeyPackages lodged with a join request). On a profile from 0.4.0, every room starts with all of its history marked seen. `secure_delete` is on, so SQLite overwrites deleted rows inside the encrypted file.

**Server.** One SQLite file, `server.db`, in WAL mode, unencrypted because it holds nothing readable: accounts, invites, mailboxes, groups, the group log, join requests, Welcomes, file metadata and file receipts, plus OpenMLS's PublicGroup state. WAL mode lets `socketchat server invite` add an invite while the server runs. Secure delete is on, so SQLite overwrites deleted rows and cleared fields with zeros instead of leaving them in free pages. The hourly sweep in `retention.rs` deletes expired log entries, Welcomes, files, invites, join requests and unfinished mailboxes, and every group with no joined member. A log entry also goes once every member has acknowledged it. `delete_group` in `groups.rs` deletes a group and everything held for it in one transaction, for `LastLeave` and for the sweep, then removes its file chunks from disk.
