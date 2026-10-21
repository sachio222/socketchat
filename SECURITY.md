# Security

This document says what socketchat v4.0 protects, what it does not, and how to report a vulnerability. Every claim here matches the code in this repository. If you find one that does not, that is a bug: please report it.

The server never holds a key that can read messages, files, display names or group names. It does see sizes, timing, IP addresses, and each group's list of random member keys. Message contents have post-quantum protection; the connection to the server does not yet.

## Terms

- **End-to-end encryption:** only the people in a chat can read it. The server and anyone watching the network see scrambled data.
- **MLS (Messaging Layer Security):** the internet standard for encrypted group chat, RFC 9420. Each change to a group (someone joins, leaves, or refreshes keys) starts a new **epoch** with new keys.
- **Commit:** an MLS message that changes the group and moves it to the next epoch. A **proposal** is a suggested change that a later Commit applies.
- **Welcome:** an MLS message that lets a new member join a group.
- **KeyPackage:** a public bundle a person publishes so others can add them to a group.
- **Post-quantum:** safe against a future quantum computer. ML-KEM is the United States standard (FIPS 203) for post-quantum key exchange. X25519 is today's common key exchange. A **hybrid** uses both, so it is never weaker than X25519 alone.
- **Identity key:** each person's long-term signing key. Its private half stays on their device. Invite links carry its fingerprint (a SHA-256 hash), and safety numbers are built from it.
- **Room:** a group chat. The protocol calls it a group.
- **Group key:** a fresh signing key a person makes for each group they join.
- **Mailbox:** where the server keeps a member's encrypted messages for one group. Its ID is that member's group key.
- **Safety number:** a 60-digit number built from two people's identity keys. If both screens show the same number, nobody sits in the middle.

## What the server sees

- For each group: the members' group keys, which double as mailbox IDs, and the group's admin list.
- Every group change. Commits and proposals travel signed but unencrypted, so the server can check them (see below).
- Each person's server account key, which lets them create groups. Stored records do not connect it to any group.
- The size and timing of every encrypted message and file, and which mailbox uploaded each file.
- IP addresses of connected apps. An app signs in with all of its keys for a server on one connection, so an operator watching live traffic can link one person's mailboxes through their IP address and connection, even though stored records cannot. An app asks for its list of open invite links on that same connection, and the server keeps no record of the question.
- Each connection's protocol version, which tells apps on 0.4.0 (protocol 1) from newer ones (protocol 2).
- When a room ends. Closing a room shows as an admin's Commit that removes everyone else, followed by that admin leaving. When the last member's app, on 0.5.0 or later, leaves while alone in the room, the server deletes everything it holds for that room at once: its log, the Welcomes waiting for its mailboxes, its mailboxes, invite links, join requests, files and MLS state. Its hourly sweep also deletes rooms with no members. The votes to close travel encrypted, so the server never sees them.

Stored rows also carry creation times. Someone holding the server database can sometimes guess a link from times alone, for example an account and a mailbox registered in the same second when a new person joins with a group invite.

## What the server never sees

- Message text, file contents, display names, group names.
- Any key that can decrypt messages or files.
- Any identity key or safety number. The voucher an inviter sends with a Welcome holds the inviter's identity key, and it travels sealed for the joiner under a key the server does not have.
- The secret part of an invite link. It sits after the `#`, which apps never send to the server.

## Why the server knows group membership

The server delivers each encrypted message to the mailboxes in a group, so it has to know which mailboxes those are. It also checks every Commit before anyone sees it: the signature, the epoch, and that the sender may make that change. Removing someone else or changing the admin list needs an admin, and so does adding someone when the operator has turned off member invites. Those checks stop a non-admin's change and two changes racing for one epoch.

The server cannot check the encrypted parts of a Commit, the new keys it hands each member. A buggy or hostile app can still send a Commit that passes the server's checks but that some members cannot apply. Those members fall out of step: they stop being able to read the group. Their app says so ("This chat fell out of step. Ask an admin to remove you and invite you again.") instead of going quiet, and an admin can remove them and invite them again.

socketchat limits what that knowledge reveals. Group keys and mailboxes are per group, so the database shows separate groups of random keys. Names, group names and identity keys travel only inside encrypted messages or the sealed voucher. Retention is short and set by the operator. The server database overwrites deleted rows and cleared fields with zeros (SQLite's `secure_delete`), so expired messages and the name of a used invite's maker do not linger in free pages. Hiding membership from the server completely is the first item in [ROADMAP.md](ROADMAP.md).

## What stays on your computer

socketchat keeps its data in one encrypted profile on your computer (see "Local data" under "Cryptography").

- **Rooms you are in** keep their messages, files list, member list and keys there.
- **When you leave a room, are removed from it or it closes,** socketchat deletes its keys and MLS state, with its member list, files list and your record of invite links into it. After your own leave this happens at once. After a removal or a close it happens as soon as your app learns of it, which for an app that was not running is its next sync with the server. The room's messages and add-on messages go once you have read them:
  - When you leave with everything read, they go at once. The chat screen first shows any messages you have not read and asks you to type `/leave` again.
  - When you were removed or the room closed, they go when you open another room or quit socketchat.
  - A room with messages you have not read keeps its messages until you read them. Once 30 days have passed since the room ended, socketchat deletes them, read or not, the next time it opens, you open another room, or it or one of its commands finishes. The names of the people who wrote those messages stay with them until they go.
- **`/clear`** deletes a room's messages from your computer while you stay in it.
- **Spare join keys.** A join request carries one KeyPackage for each kind of encryption socketchat allows (see "Cryptography"). For a join request made with 0.5.0, socketchat deletes the ones the join did not use, with their private keys, once you join. A request lodged with 0.4.0 keeps its spare keys.
- **Deleted rows are overwritten** inside the encrypted file (SQLite's `secure_delete`). socketchat then clears old copies of them out of the profile's log file (SQLite's write-ahead log). If the profile is busy at that moment, old copies can stay in that log file until a later tidy-up, and the app warns when that happens.
- **Files you saved** stay where you saved them.
- **Rooms you left with 0.4.0** lose their history when 0.5.0 first opens the profile.

## Cryptography

- **Group encryption:** MLS (RFC 9420) through OpenMLS 0.9.1, a Rust implementation that SRLabs audited in 2026.
- **Default suite:** `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (0x004F). It uses the hybrid ML-KEM-768 + X25519 key exchange, so recorded traffic stays confidential even against a future quantum computer.
- **Draft status:** suite 0x004F comes from an IETF draft that is not final, and it may change before publication. The suite choice lives in one file, `crates/socketchat-core/src/suite.rs`, so groups can move to the final suite later.
- **Provider:** openmls_rust_crypto 0.6.0 with OpenMLS's `draft-ietf-mls-pq-ciphersuites` feature, which uses an experimental HPKE path in hpke-rs. The 2026 SRLabs audit covered the OpenMLS core. It did not cover this experimental post-quantum path.
- **Fallback suite:** the standard `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001), which has no post-quantum protection. A server operator can require it with `require_standard_suite = true`; the server then refuses new groups on any other suite. Groups that already exist keep their suite.
- **Signatures:** Ed25519 everywhere, which is not post-quantum. Forging one would take a quantum computer at the moment of the attack. Every socketchat signature outside MLS covers a context string first, so a signature made for one purpose never verifies for another.
- **Connection:** TLS 1.3 through rustls 0.23.45 with the ring crypto provider. Its key exchange is classical X25519, so the connection layer is not post-quantum, while message contents inside it are. Someone who records traffic today and later breaks X25519 would learn what the server itself sees, but not message or file contents. The server makes a self-signed certificate at `init`. Invite links carry its SHA-256 fingerprint and apps pin it, so no certificate authority is involved. A link with a different fingerprint for a server already in use changes nothing until the person accepts it, and the new pin takes effect only after a connection under it works.
- **Files:** XChaCha20-Poly1305 in the STREAM construction, in 64 KiB chunks, with a fresh random key per file. STREAM catches chunks that were changed, dropped or reordered. The file key, name and SHA-256 hash travel inside an encrypted MLS message, and the receiving app checks the hash before saving.
- **Invites:** the joiner signs their request, meaning the token and their new mailbox key, with an Ed25519 key whose seed comes from the invite secret through HKDF-SHA256, and sends the signature inside their KeyPackage. A server without the link cannot slip in its own KeyPackage. Other members hold only that key's public half, so they can check a request but cannot make one. The inviter also signs a voucher with their identity key, which the joiner checks against the fingerprint in the link. Other members get the voucher, the public key and a seal key derived from the secret, never the secret itself, so any admin can check and complete a join. A member's app accepts a voucher only from the inviter it names, signed by the identity that member proved in the group. The inviter's app marks the new member verified only after the joiner proves, with a second key derived from the secret, that they hold the link itself; no other member can make that proof. The voucher reaches the joiner sealed with XChaCha20-Poly1305 under a key derived from the invite secret with HKDF-SHA256, so the server stores and forwards it without being able to read it.
- **Local data:** one SQLite file encrypted with SQLCipher, keyed by Argon2id from your passphrase at 19 MiB of memory and 2 passes (the OWASP minimum, chosen so small devices such as a Raspberry Pi open a profile quickly). The salt sits beside the file with the Argon2id settings the profile was made with, so a later release can raise the settings for new profiles without locking anyone out. A salt file that asks for more than 256 MiB of memory, 16 passes or 8 lanes is refused as damaged before any hashing starts, so a changed file cannot hang the app or run a 512 MB device such as a Raspberry Pi Zero 2 W out of memory. Only one app at a time can open a profile; a second one gets "socketchat is already open on this profile."
- **Key refresh:** MLS changes encryption keys with every group change. Each app also refreshes its own keys in a group when they are more than a week old, so a stolen encryption key stops unlocking new messages.
- **Randomness:** the operating system's random source, through the libraries above.

## What socketchat does not protect

- **Metadata.** The server sees sizes, timing, IP addresses and each group's list of random keys, as described above.
- **What happens after delivery.** Receivers can save, copy, screenshot or forward anything you send. Deleting messages or a file removes your copy only.
- **Other people's copies of a room.** Deletion happens in each person's own app. A member on 0.4.0, or a changed app, keeps its copy of the history, and anyone can copy or photograph a screen.
- **One admin acting alone.** The server checks admin rights, not votes. One admin can remove every other member, one by one or at once with a changed app, then leave, which deletes the room from the server. Closing only once the admins agree is a rule inside standard socketchat apps.
- **What add-ons send.** Messages from add-ons and other programs are end-to-end encrypted like text. socketchat checks only their namespace and kind, stores them, and shows their summary line when they carry one. What the rest of a message says, and what an add-on does with it, is up to that add-on.
- **Video location data.** socketchat removes location and device data from JPEG, PNG and WebP photos. It does not remove them from videos, and asks before sending one. See [docs/files-photos-videos.md](docs/files-photos-videos.md).
- **An unlocked device.** If someone gets your computer while socketchat is open, or learns your passphrase, they get your identity key and your messages. Do not put `SOCKETCHAT_PASSPHRASE` in a shell profile on a shared machine.
- **A stolen identity key.** Whoever holds it can pose as you. The identity key never decrypts messages. v4.0 has no command to replace an identity key. If yours is exposed, ask an admin to remove you, set up a fresh profile, join again through new invites, and compare safety numbers with your contacts again.
- **A dishonest server's availability.** A server can delay, drop or refuse messages. It cannot read them, and MLS detects any change to their contents.
- **Idle and slow connections.** The server closes a connection that does not say hello within 10 seconds or sends nothing for 5 minutes. A connection may have at most 2 MiB of replies and pushes waiting; the server closes it when a push would go over, and when a write makes no progress for 30 seconds, so a client that stops reading cannot hold memory or a connection slot. One address can hold at most 256 connections unless the operator sets `max_per_ip` lower or higher; the default is high because a whole office or school can share one address. The server answers each connection past that limit with a short refusal the app shows, and while 64 refusals are under way it drops further ones before TLS, so turning people away stays cheap. Apps reconnect and catch up on their own. Each account can make 5 server invite links every two days with the default settings, so one account cannot fill a server with new accounts.
- **Unverified joins.** When an invite check fails, the app shows a red warning. A verified mark comes from the invite link or from comparing safety numbers with `/verify`; a matching display name proves nothing.

## Known advisories

The project checks dependencies with `cargo deny check` on every change. Its `deny.toml` lists the advisories it ignores and why.

- **RUSTSEC-2026-0285 (rustls):** applies to socketchat. Fixed by pinning rustls 0.23.45.
- **RUSTSEC-2026-0346 to RUSTSEC-2026-0349 (rustls):** fixed only in rustls 0.23.46. That release is under 30 days old, the project's minimum age for a dependency, so the upgrade waits until 2026-11-13. None applies to socketchat today:
  - 0346 needs a custom client session store that prints session values; socketchat has none.
  - 0347 needs Encrypted Client Hello, which socketchat does not use.
  - 0348 needs rustls's brotli feature, which is off.
  - 0349 is a downgrade of a hybrid TLS key exchange; socketchat's TLS uses classical key exchange only.
- **RUSTSEC-2026-0173 (proc-macro-error2, unmaintained):** a macro crate that runs only at build time, under hpke-rs. It does not run in socketchat, and no maintained replacement exists upstream yet.

## Reporting a vulnerability

Report security problems privately through GitHub's private vulnerability reporting on https://github.com/sachio222/socketchat_v4: open the Security tab and choose "Report a vulnerability". Do not open a public issue for a security problem. Say what you found, how to reproduce it, and which version or commit you tested.
