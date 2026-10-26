# Socketchat v4 design

Status: the design Socketchat v4.0 was built from, 2026-10-19. Where the code differs, the code and SECURITY.md describe what v4.0 does.

## What this is and why

Socketchat v4 is an encrypted group chat for people who want to run their own server. You install it from GitHub, start a server on any small machine, and invite people with a link. The server passes messages along but can never read them.

v1 through v3 were Python experiments. v3 claimed end-to-end encryption, but its server handed out everyone's keys, so whoever ran the server could read every message. v4 is a rewrite that fixes this at the root: it uses a published standard for group encryption and an audited library to run it.

The gap v4 fills: no project today pairs a tiny self-hosted server with standard group encryption and post-quantum protection. Matrix can be self-hosted, but its server is heavy. Wire uses the group standard, but self-hosting needs its Enterprise edition. SimpleX is light, but in a group the sender's own device delivers every message to every member.

## Terms used in this document

- **End-to-end encryption:** only the people in a chat can read it. The server and anyone watching the network see scrambled data.
- **MLS (Messaging Layer Security):** the internet standard for encrypted group chat, published by the Internet Engineering Task Force (IETF) as RFC 9420 in 2023. A sender encrypts a message once and the server copies it to every member. Each change to the group (someone joins, leaves, or refreshes keys) starts a new **epoch** with new keys.
- **OpenMLS:** a Rust implementation of MLS. SRLabs audited it independently in 2026. v4 uses OpenMLS 0.9.
- **Commit:** an MLS message that changes the group and moves it to the next epoch.
- **Welcome:** an MLS message that lets a new member join a group.
- **KeyPackage:** a public bundle a person publishes so others can add them to a group.
- **Post-quantum:** safe against a future quantum computer. ML-KEM is the United States standard (FIPS 203) for post-quantum key exchange. X25519 is today's standard key exchange. A **hybrid** uses both, so it is never weaker than X25519 alone.
- **Fingerprint:** a short hash of a public key or certificate. Two people who see the same fingerprint know they hold the same key.
- **Safety number:** a 60-digit number built from two people's fingerprints. If both screens show the same number, nobody sits in the middle.
- **Relay server:** the v4 server. It stores and forwards encrypted data, and holds no keys that can read it.

## Goals

1. Messages, group changes and files are end-to-end encrypted with MLS. The server never holds readable text or message keys.
2. Post-quantum protection is on by default, using the hybrid ML-KEM-768 + X25519 suite.
3. A stranger goes from `git clone` to two people chatting in under five minutes, with no hand-copied certificates or keys.
4. Group chats work from day one. Direct messages are two-person groups.
5. Files, photos and videos send end-to-end encrypted, with their limits stated plainly in the app and the docs.
6. The server runs well on very small machines, such as a Raspberry Pi Zero 2 W with 512 MB of memory.
7. The project invites collaboration: clear docs, tests a contributor can run with one command, and a code of conduct.

## Non-goals for this version

- Phone or desktop graphical apps. v4 is a terminal app.
- Servers that talk to each other (federation). Everyone in a group uses the same server.
- Voice and video calls.
- One person on several devices. MLS supports it; v4 starts with one device per person and leaves room to add linking later.
- Message search on the server, bots, read receipts and typing indicators.

## Anti-goals: v4 fails if any of these happen, even if it works

- Home-made cryptography. Every primitive and protocol comes from a reviewed library or a published standard.
- A server that can read messages, file contents, display names or group names.
- Setup that requires copying certificate or key files between machines.
- Accounts tied to a phone number or email address.
- Any telemetry or phone-home.
- Copy that oversells. Every security claim in the docs matches what the code does.

## Stance on use

Socketchat is for people who want private conversations they control. It is not for illegal content or for people who mean harm. The project states this in an acceptable-use statement (`ACCEPTABLE_USE.md`), linked from the README and printed when a server starts for the first time. Contributors follow a code of conduct (Contributor Covenant 2.1). Each server's operator answers for what happens on their server. The license stays a standard open-source license; the stance is a statement, not a license term.

## How people use it

### Running a server

```
cargo install --git https://github.com/sachio222/socketchat
socketchat server init        # writes config, makes a TLS certificate, prints the acceptable-use statement
socketchat server run
socketchat server invite      # prints a one-time link for the first person
```

### Joining and chatting

```
socketchat join "socketchat://..."   # first run: pick a display name and a passphrase
socketchat                            # opens the chat screen
```

1. The person who runs the server sends an invite link by text or in person.
2. The new person runs `socketchat join <link>`, picks a display name and a passphrase for their local data, and is in.
3. To bring a friend into a group, a member types `/invite`. The app shows a link and a QR code. A phone that scans the code opens the join page on socketchat.org.
4. The friend runs `socketchat join <link>` and lands in that group.

### Names

- Everyone picks their own display name and can change it.
- Others see that name by default. Anyone can rename a contact on their own screen; only they see the new name.
- Names are not unique and cannot be searched.
- Trust follows the key, not the name. A name change posts a notice in every shared chat. Someone new who calls themselves "Ana" does not inherit Ana's verified mark.
- Display names travel inside encrypted messages. The server never sees them.

### Verification

- An invite link carries the fingerprint of the inviter's identity key. When the new member's app receives the Welcome, it checks the invite against that key. It marks the inviter verified once the inviter's app confirms the join from inside the group, and until then says it is waiting for them. A server that tries to insert itself fails this check and the app shows a red warning.
- `/verify <name>` shows the safety number and a QR code for an in-person check.
- The member list shows a mark beside each verified person.

### The chat screen

A terminal interface with four areas:

- Left: groups and direct messages, with unread counts.
- Middle: messages, newest at the bottom, with time and sender. Under the room's name, the first line holds its topic, cut to the window.
- Right: members of the current group, with verified marks.
- Bottom: the input line and a one-line help bar with the keys for the current area.

Keys: Tab moves between areas, or completes a command that starts with `/`; Ctrl-K opens a quick switcher; Up and Down in the message box bring back the lines sent in the open room, kept in memory only; Page Up and Page Down scroll; Enter sends; Esc cancels. The mouse opens a room, moves between areas, scrolls and presses the buttons on boxes, until `/mouse off` gives it back to the terminal. Slash commands: `/invite`, `/invite --dm`, `/join <link>`, `/new <group name>`, `/dm <name>`, `/send <path>`, `/save <file> [dir]`, `/verify <name>`, `/rename <name> <new>`, `/name <new>`, `/kick <name>`, `/topic [text]`, `/topic --clear`, `/settings`, `/leave`, `/servers`, `/forget <number>`, `/theme`, `/mouse on|off`, `/help`, `/quit`.

The screen stays readable at 80 by 24 characters and works over SSH.

## Files, photos and videos

### How it works

1. The sender's app picks a fresh random key for the file and encrypts it in 64 KiB chunks with XChaCha20-Poly1305 in the STREAM construction, which detects reordered, dropped or altered chunks.
2. It uploads the encrypted chunks to the server's file store.
3. It sends an MLS message to the group with the file name, size, type, SHA-256 hash, and the file key.
4. Each member's app downloads the chunks, decrypts, checks the hash, and saves the file when the person types `/save`.

Files stream through memory one chunk at a time, so a large video never loads whole into RAM on either end.

### Limits the app and docs state plainly

- **Receivers control what you send.** They can save, copy, screenshot or forward it. Encryption protects a file on its way, not after it arrives.
- **Photos carry hidden data.** Phone photos usually hold the location where they were taken and the device model (EXIF data). v4 removes this from JPEG, PNG, WebP and GIF images before sending, says so, and asks before sending a photo it cannot clean.
- **Videos keep their hidden data.** v4 does not remove location or device data from video files. The app shows a warning before sending any video and asks for a yes.
- **No take-backs.** Deleting a file removes your copy only.
- **The server sees size and timing.** It sees how big an encrypted file is and when it moves, never what is inside.
- **Size limit.** Each server sets a maximum file size (default 100 MB).
- **Files expire.** The server deletes a file once every member has downloaded it, or after the retention period (default 30 days), whichever comes first.

## Security model

### What the server sees

- For each group, the members' group keys and mailbox IDs. A person gets a fresh group key and mailbox in every group they join, so the server's records cannot link one person across two groups.
- The signed membership changes and the admin list for each group.
- The size of each encrypted message, rounded up to a whole number of 256-byte blocks (apps on 0.5.1 and older send exact sizes), the size of each encrypted file, and when each message and file moves.
- IP addresses of connected clients. An operator who watches live traffic can link one person's mailboxes through their IP address and connection, even though the stored records cannot.

### What the server never sees

- Message text, file contents, display names, group names, room topics.
- Any key that can decrypt messages or files.
- Anyone's identity key, the key contacts use to verify each other.

### Group membership and the server

The server has to know which mailboxes are in each group, because it delivers each encrypted message to those mailboxes. It also checks every group change: the signature, the epoch, and the group's admin list, so a change from a non-admin, or a second change for an epoch that already moved on, is refused before it reaches anyone. It cannot check the encrypted parts of a change, the new keys each member receives. A buggy or hostile app can still send a change that passes these checks but that some members cannot apply. Those members fall out of step and stop being able to read the group; their app tells them so, and an admin can remove them and invite them again.

v4 limits what that knowledge reveals:

- Group keys and mailboxes are per group, as described above, so the server's database shows separate groups of random keys, never one person's set of groups.
- Identity keys, display names and group names travel only inside encrypted messages.
- Retention is short and set by the operator.

Hiding membership from the server completely needs anonymous credentials: cryptography that lets a member prove they belong to a group without saying who they are. Signal built this for its own service. It is not part of the MLS standard, Signal's implementation is licensed under the AGPL and published for Signal's own use, and building our own version would break the rule against home-made cryptography. Full membership hiding is the first item on the project roadmap (`ROADMAP.md`), tracked as a "help wanted" issue. It moves into the code when a reviewed specification with a permissively licensed implementation exists, for example if IETF work on private MLS delivery becomes a standard.

### Threats and answers

| If this happens | Then |
|---|---|
| Someone learns your display name | Nothing. There is no directory and no address to message. |
| An invite link leaks | Links are single-use and expire (default 24 hours). An admin can remove anyone; MLS changes the group keys at once, so removed people cannot read anything sent after. |
| Someone takes over the server | They get encrypted data, random IDs and timing. They cannot read messages, and the stored records do not show which groups one person belongs to. If they try to sit in the middle of a new invite, the fingerprint check fails. |
| Someone steals a laptop | Local messages and keys are encrypted with a key derived from the person's passphrase. |
| Someone records traffic today and gets a quantum computer later | The hybrid post-quantum suite protects message confidentiality. |
| An encryption key is stolen today | MLS changes encryption keys with every group change, and the app refreshes its own on a schedule (default weekly), so a stolen encryption key stops unlocking new messages. |
| Someone steals your signing key | They can pose as you. v4.0 has no command yet to reset an identity; set up a fresh profile and verify your contacts again. The signing key never decrypts messages. |

### Cryptography choices

- **Group encryption:** MLS (RFC 9420) through OpenMLS 0.9.
- **Default suite:** `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (0x004F), from the IETF MLS working group's post-quantum draft. It gives post-quantum confidentiality. Signatures stay Ed25519, which is not post-quantum; an attacker would need a quantum computer at the moment of the attack to forge one, while recorded traffic is the threat that exists today.
- **Provider:** openmls_rust_crypto 0.6, with OpenMLS's `draft-ietf-mls-pq-ciphersuites` feature and the experimental HPKE path in hpke-rs-rust-crypto that this suite needs. The 2026 SRLabs audit covered the OpenMLS core. It did not cover this experimental post-quantum path, and SECURITY.md says so.
- **Draft status:** this suite comes from an IETF draft that is not final. The docs say so, and the code keeps the suite choice in one place so groups can move to the final suite when it is published. The standard suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) stays available as a fallback the server operator can require.
- **Transport:** TLS 1.3 with rustls. The server makes a self-signed certificate at `init`. Invite links carry its SHA-256 fingerprint, and clients pin it. No certificate authority, no hand copying.
- **Files:** XChaCha20-Poly1305 STREAM, a fresh key per file.
- **Local data at rest:** SQLite encrypted with SQLCipher, keyed by Argon2id from the person's passphrase. openmls_sqlite_storage accepts an existing rusqlite connection, so the client opens a SQLCipher connection (rusqlite 0.37 with `bundled-sqlcipher`, the version openmls_sqlite_storage 0.3 uses), sets the key, and hands it over.
- **Randomness:** the operating system's random source through the libraries above.

## Architecture

### One program, three parts

A single binary named `socketchat`:

- `socketchat server ...` runs the relay server.
- `socketchat` with no subcommand opens the chat screen.
- `socketchat join <link>` joins a server or a group.

Cargo workspace:

| Crate | Job |
|---|---|
| `socketchat-proto` | Wire messages, framing, invite link format. No crypto, no I/O. |
| `socketchat-core` | The client engine with no screen: identity, MLS groups through OpenMLS, invites, verification, file encryption, local encrypted storage, the connection to the server. |
| `socketchat-server` | The relay: accounts, mailboxes, group message logs, KeyPackage store, file store, invites, retention. |
| `socketchat-tui` | The terminal interface on top of `socketchat-core`, built with ratatui and crossterm. |
| `socketchat` | The binary that wires the subcommands together. |

Keeping the client engine separate from the screen lets tests drive several clients with no terminal, and leaves room for other front ends later.

### Wire protocol

- TCP with TLS 1.3. Default port 7444.
- Each frame is a 4-byte big-endian length and a body encoded with postcard (a compact binary serde format). Maximum frame size 1 MiB; file data moves in chunk frames.
- One request/response enum and one push enum, versioned by a protocol number sent at connect.
- MLS messages ride inside frames as opaque bytes. The server reads only the plaintext MLS header fields it needs: group ID, epoch and content type.

### Keys, accounts and sign-in

Each person holds three kinds of Ed25519 signing key:

- **Identity key.** One per person. It never leaves their device and never goes to the server. Invite links carry its fingerprint, and safety numbers are built from it.
- **Group key.** A fresh key for every group the person joins. It is their MLS credential key in that group, and the group's mailbox on the server belongs to it. Inside the group's encrypted messages, the identity key signs the group key, so other members know who it is. The server never sees that signature.
- **Server account key.** One per server. It lets a person create groups and redeem server invites. Registering it needs an invite token. The server does not record which account created which group.

Sign-in is challenge and response: the server sends a random challenge and the client signs it with each key it uses on that connection.

### Groups and ordering

- Every group has an ordered log on the server. Each entry has a sequence number.
- The server accepts a Commit for epoch N only while the group sits at epoch N. The first valid Commit wins. A late Commit gets a "conflict" reply, and that client catches up and retries.
- Members fetch entries after their last sequence number and acknowledge them. The server deletes an entry once every member has acknowledged it, or after the retention period.
- Clients connected live get entries pushed at once.

### Invites

An invite link looks like this:

```
socketchat://chat.example.com:7444/j/<token>#<server-cert-fpr>.<inviter-key-fpr>.<invite-secret>
```

The token is random and stored on the server with its group, creator, expiry and remaining uses. Everything after `#` is the link fragment, which clients never send to the server. The invite secret lives only there, so a server cannot forge a join request even if someone has taken it over.

The QR code in the invite box holds the web form of the link, `https://socketchat.org/join#socketchat://...`, because a phone camera opens web addresses and has no app for `socketchat://`. Browsers never send the part after `#` to the web server, so the join page reads the invite in the browser and shows how to install Socketchat on a computer and the command that joins. `socketchat join` and `/join` take either form.

When the inviter creates the link, their client also signs a **voucher**: the token, a hash of the invite secret, the group ID, the inviter's group key and an expiry, signed with the inviter's identity key. The voucher goes to the group inside an encrypted MLS message, together with the public half of a signing key derived from the invite secret, which checks the joiner's request, and a key derived from the secret that seals the voucher for the joiner. Every member's client holds these and the server never sees them. The secret itself stays with the inviter and the joiner. A member's client keeps a voucher only when the member who posted it is the inviter it names, signed by the identity that member proved in the group, and never lets a later voucher replace it.

Redeeming an invite:

1. The joining client connects and checks the server certificate against the fingerprint in the link.
2. It makes a fresh group key and registers a new mailbox for it using the token.
3. It uploads a KeyPackage for that group key against the token. The KeyPackage carries the joiner's signature over the token and the new mailbox key, made with a signing key derived from the invite secret.
4. The server notifies the inviter's client. If the inviter is offline, any group admin who is online can act. The joiner's screen says who it is waiting for.
5. That client finds the matching voucher and keys, which members receive together inside the group's encrypted messages. It checks the signature with the public key it holds, adds the KeyPackage with a Commit, and sends the Welcome to the joiner's mailbox along with the inviter's signed voucher. The voucher travels sealed under a key derived from the invite secret, so the server cannot read it.
6. The joiner processes the Welcome and checks the voucher's signature against the identity fingerprint in the link. When that signature holds, the adder is either the group key the voucher names or an admin of the group, and that group key is in the group, the join waits for the inviter. It counts as verified once that group key posts a profile in the group, bound to the identity that signed the voucher. The inviter's client posts its profile after every add, so this happens on its own. Anything else shows the red warning.
7. The joiner posts a proof made from the invite secret itself, bound to their new group key. Only the inviter's client can check it, and only someone holding the link can make it, so the inviter marks the newcomer verified only then. It accepts one proof per link, from the key that joined with it. The client stores the proof before posting it, and posts it again on a later sync if the connection drops first.

Members hold only the public half of the request key, so they can check a join request but cannot make one. A member who tries to bring someone in through an admin's link, for example in a group where only admins may invite, makes a request that every client ignores.

A link can name a server the person already uses with a different certificate. That happens when the operator sets the server up again, and when someone sends a fake link to cut the person off from their chats. The client changes nothing and shows both fingerprints. The person can accept the new certificate with `socketchat join --new-certificate <link>`, or with Y in the chat screen's confirm box. The client trusts it only after a connection under the new certificate and the redeem both succeed.

The 24-hour expiry covers redeeming the link. Once a join request is lodged, it waits up to 7 days for someone to act.

To start a direct message with someone you already share a group with, use `/dm <name>`. The two apps exchange the new chat's KeyPackage and mailbox inside the shared group's encrypted messages, so the server's records do not link the two chats. The request names the asker's key in the new chat, and the other person's app marks the direct message verified only when that key added them to that chat and they had already verified the asker. For anyone else, `/invite --dm` makes a link that opens a new two-person chat.

A server invite from `socketchat server invite` registers a server account key with no group, so the person can then create groups. When the operator allows members to make accounts, a group invite also registers a server account key for the joiner, so they can start their own groups and direct messages. The server does not record which invite created which account or mailbox. The operator can turn off members' ability to bring new people onto the server (`members_make_accounts = false`). Who can bring people into a room is the room's own setting (see "Room settings"), unless the operator lets only admins invite into every room (`members_can_invite_to_rooms = false`).

### Roles

Each group has admins and members. The creator is the first admin. Admins can invite, remove members, make others admins and change the room's settings. Members can send messages and files, and invite people unless the room's admins let only admins invite.

MLS has no built-in roles, so v4 keeps them in group state that every member and the server can check:

- The admin list lives in a GroupContext extension: a list of admin group keys that every member agrees on through MLS.
- Commits and Proposals travel as MLS PublicMessages, which are signed but not encrypted. Application messages (chat text, files, profiles, vouchers) stay encrypted as PrivateMessages.
- The server checks each Commit's signature, its epoch, and that an admin sent it whenever it removes someone else, changes the admin list or the room's settings, or adds someone to a room that lets only admins invite. A Commit that fails is refused before any member sees it. The server cannot check a Commit's encrypted parts, so a member whose app cannot apply one falls out of step; the app says so, and an admin can remove and invite them again.
- The same PublicMessages tell the server who is in each group, which it needs for routing, deleting acknowledged entries and expiring files.
- Leaving: `/leave` sends a Remove proposal for yourself, and the next online member's client commits it on its own.
- If the last admin leaves, their leave Commit must promote the longest-standing member, and the server refuses it otherwise.
- Each app also checks these rules before it applies a change, refuses any change that no member signed, and judges the longest-standing member from its own record of who joined when.

This choice is a tradeoff: the server learns each group's membership changes and admin list, as per-group keys and mailbox IDs. It still never sees names, text or files. "Group membership and the server" above explains the limits and the roadmap.

### Room settings

Each room has three settings, and its admins change them:

- **Who can invite:** anyone in the room, the default, or admins only. It covers making the room's invite links and adding the people who use them.
- **Slow mode:** off, the default, or a number of seconds, up to 6 hours, that each member who is not an admin waits between messages. Admins are not held, as Discord does it.
- **Who can set the topic:** admins only, the default, as the `+t` mode of IRC (Internet Relay Chat) works, or anyone in the room. Apps enforce it, since the topic itself is encrypted (see "Room topic").

The operator can also let only admins invite into every room on the server (`members_can_invite_to_rooms = false`). That rule is stricter than any room's, and the server applies it whatever the room says; apps ask for it with `ServerRules` and show it in `/details`.

The settings live in a second GroupContext extension, type `0xff02`, beside the admin list. Only a Commit changes them, so MLS authenticates every change and every member holds the same settings in each epoch. Commits travel as signed PublicMessages, so the server reads the settings from the group state it already keeps for the admin list and enforces them: in an admins-only room it refuses a member's room link and a member's add, and it holds members to the slow mode. The server checks that an admin signed every Commit that changes a setting, and every app checks the same, each against the admins as they stood before that Commit. A change from anyone else, a member removed before it arrived included, is refused by the server and by every app, and the room keeps its settings. When the last admin leaves, the member who hands on the role cannot change the settings in the same Commit. Apps also check each add against the setting, so in an admins-only room a member's add that reached them would be refused there too.

The room name and topic travel the other way, as encrypted application messages, so the server never sees them. The settings could travel that way too, but then the server could not enforce them. They say who may bring people in, how often members post and who may set the topic, nothing about what anyone writes, so the server reading them reveals little; `SECURITY.md` lists them under what the server sees.

MLS lets a room hold an extension only while every member's app lists it among its capabilities, so the settings come with two rules:

- A room on the defaults holds no settings extension. It looks exactly as rooms did before settings existed, and apps up to 0.5.1 join and chat in it as before.
- An admin can change a setting only once everyone in the room runs Socketchat 0.5.2 or later. An app that updates refreshes its keys in each of its rooms on its own, which tells the room it knows settings; until then the admin's app names who it waits for. While a room has settings, an app up to 0.5.1 cannot join it, and the server tells its owner to update when they use a link. Setting all three back to the defaults removes the extension again.

The extension holds entries, each a type, a length and a value, in order of type. Later settings fit beside these, and an app keeps the entries it does not know when it changes one it does. A new setting type must stay opaque to older apps: an app never refuses a change because of the contents of a type it does not know, or a room would split between app versions. Because every member's app must take the extension, one member whose app lacks the capability blocks every settings change until they update or an admin removes them.

A server from before 0.5.2 does not know room settings and cannot keep them, so apps refuse to set them there.

### Room topic

A room's topic is one line that every member sees under the room's name, as IRC's `/topic` sets it. `/topic <text>` sets it, `/topic` shows it with who set it and when, and `/topic --clear` removes it; `socketchat topic --group <name> [text]` and `--clear` do the same from a terminal. The room shows a notice such as "Topic: Piranesi, chapters 1 to 5 (set by Ada, verified, 2026-10-25)" each time it changes, and a newcomer sees the same notice on joining. `/details` shows the whole topic.

The topic travels as an encrypted application message, `AppMsg::Topic`, the way the room name does, so the server never sees it, and it is padded like every message. It carries the text, the group key of the member who set it, the time they set it, and that key's signature over the room, the time and the text (context `socketchat/v1/topic`). An empty text removes the topic.

Every app judges a topic by the room at the point it arrives in the log, as it judges changes to the settings: the sender must be in the room, and be an admin, or any member while the room lets anyone set the topic. A new topic must name its sender as its setter. A topic from anyone else, or from a member removed before it arrived, changes nothing. When someone joins, each admin's app passes the topic on, marked as passed on and still signed by whoever set it; an app takes a topic passed on only while it has none for the room, so it never replaces a newer one, and the signature keeps the app that passes it on from changing the text or naming another setter.

Before an app keeps or shows a topic, it cleans it with the strict filter that names get (`clean_topic` in `sanitize.rs`): no control characters or escape codes, no direction controls or isolates, no invisible characters or Hangul fillers, line breaks and other whitespace folded to single spaces, and at most 300 characters. The setter's app refuses a longer topic, every other app cuts it, and one over 4,096 bytes is ignored whole. Every place the topic shows starts it with `Topic:` and draws it in its own color, never in the colors of notices, warnings or the verified mark. It is plain text, so a link shows as its full address.

A topic counts toward the posting pace like any message, and the app encrypts nothing for it while the room holds the member back. Leaving, `/clear`, `/forget` and a room's ending delete the topic from the computer with the room's other state. Apps up to 0.5.1 do not know the message and ignore it.

### Posting pace

The server limits how fast each member posts in each room, so one member cannot flood a room before an admin removes them. It keeps a token bucket for each member key in each room, counting messages and bytes: a member starts with a burst, then gets one message back every few seconds. A room's slow mode adds a second limit for members who are not admins, and a post must pass both, so the stricter one holds. Admins are never held by slow mode, and get ten times a member's pace rather than none, so one account that makes its own room still meets a limit. Commits that only take people out never count. A request to leave never counts either, and the server takes one per member per epoch, at the size apps send it. The buckets live in the server's memory, from the mailbox each connection posts with, which the server already knows; a restart gives everyone a full burst again.

Over the limit, the server stores nothing and answers `SlowDown` with the time to wait. It never removes or bans anyone for posting fast. The app then encrypts nothing for that room until the wait is over, and it also counts out a room's slow mode after its own posts: every message an app encrypts moves its sender's keys on in the room, so a stream of refused ones would leave them further ahead than other members can follow. The app keeps a held text and sends it once the server allows, after any texts already waiting in that room, and the chat screen says "This room limits fast posting; sending in 4 seconds." A held text goes only to the people who were in the room when it was typed; if anyone joined or left meanwhile, the app hands it back unsent. Messages the app sends on its own, such as a member's name after someone joins, wait the same way and go on a later sync. An app on 0.5.1 or older hears the wait in words, as a refusal.

### Server storage

SQLite in WAL mode, one file. Tables for accounts, mailboxes, groups, group membership, group log entries, KeyPackages, invites and file chunk metadata. File chunks live as files on disk under the data directory. A background task deletes expired entries, files and invites every hour.

### Server configuration

`socketchat-server.toml` with:

- listen address
- data directory
- `retention_days` (default 30)
- `max_file_mb` (default 100)
- `invite_ttl_hours` (default 24)
- `members_make_accounts` (default true)
- `members_can_invite_to_rooms` (default true; files from before 0.5.2 had one key, `members_can_invite`, for both, which the server still reads)
- `require_standard_suite` (default false)
- `max_connections` (default 1,000)
- `max_per_ip` (default 256)
- `max_frame_before_sign_in` (default 8,192 bytes)
- `max_buffered_before_sign_in_mb` (default 8)
- `max_accounts_from_room_links` (default 100)
- `max_room_messages_mb` (default 200)
- `max_room_files_mb` (default 4,000)
- `max_member_files_mb` (default 4,000)
- `max_room_welcomes` (default 100)
- `max_stored_mb` (default 8,000)
- `rate_burst_messages` (default 30)
- `rate_seconds_per_message` (default 5)
- `rate_burst_kb` (default 2,000)
- `rate_kb_per_second` (default 10)

### Performance targets

- Server idle memory under 20 MB. A Raspberry Pi 4 serves 1,000 connected clients.
- Client opens to the chat screen in under 300 ms on a laptop.
- Files stream in chunks; memory use does not grow with file size.
- Release builds use link-time optimization and strip symbols.

## Testing

- Unit tests in every crate.
- Integration tests start a real server on a free port with several headless clients built on `socketchat-core`. They cover:
  - a direct message
  - a group of three
  - adding and removing a member, where the removed member cannot read later messages
  - delivery to someone who was offline
  - two Commits at once, where one wins and the other retries cleanly
  - invite expiry and single use
  - a mismatched server certificate being refused
  - a mismatched inviter fingerprint showing a warning
  - file transfer with EXIF removed and the hash checked
  - a large file staying within a fixed memory budget
  - a server restart keeping all state
  - a check that every byte the server stored for a test chat holds none of the plaintext
  - a check that the server's stored data holds no identity key, and no key or mailbox that appears in two groups
- Terminal interface tests render screens with ratatui's TestBackend and compare them to snapshots.
- The frame decoder is fuzzed.
- Continuous integration on GitHub Actions: tests, clippy with warnings as errors, rustfmt, and a dependency audit with cargo-deny on Linux x86_64 and macOS arm64, plus a build check for Linux aarch64 (Raspberry Pi).

## Documentation

- `README.md`: what Socketchat is, a quick start under five minutes, terminal screenshots, and links to everything below.
- `SECURITY.md`: what the server sees and never sees, crypto choices, the post-quantum draft status, and how to report a vulnerability.
- `ACCEPTABLE_USE.md`: the stance on use.
- `ROADMAP.md`: planned work, with full membership hiding first, plus multi-device linking and the move to the final post-quantum suite.
- `CODE_OF_CONDUCT.md`: Contributor Covenant 2.1.
- `CONTRIBUTING.md`: building, testing, the review process, and the rule against home-made crypto.
- `docs/files-photos-videos.md`: the limits above, written for people who are not technical.
- `docs/running-a-server.md`: setup on a Raspberry Pi and a small cloud server, a systemd unit, backups and upgrades.
- `docs/architecture.md` and `docs/protocol.md`: for contributors.
- Screenshots: real terminal captures of the app running against a local server, made with VHS (a terminal recorder from Charm) from tape scripts kept in `docs/tapes/`, so anyone can regenerate them.

## License

`MIT OR Apache-2.0`, the usual dual license in Rust projects.

## Decisions and their tradeoffs

- An invite secret in the link fragment, plus an inviter-signed voucher, so any admin can complete a join and a server can never forge one.
- Commits travel as signed PublicMessages, so the server enforces admin rights and learns membership. This trades some privacy for those checks; "Group membership and the server" above explains the limits.
- A join request waits up to 7 days once lodged.
- `/invite --dm` for direct messages with people you share no group with.
- Weekly refresh covers encryption keys only. Resetting your signing key is a separate, visible action.
- Suite 0x004F through openmls_rust_crypto's experimental path, with the audit's coverage stated honestly.
- A fresh group key and mailbox per group, with the identity key kept off the server, so stored server data cannot link one person across groups. Full membership hiding goes first on the roadmap and in a "help wanted" issue.
- Room settings in the signed group context, next to the admin list, so the server and every app enforce them and no one but an admin can change them. The server reads who may invite and the slow mode; changing a setting needs every member on 0.5.2 or later.
- A pace limit per member per room that refuses with a wait and never removes anyone, as Matrix and Discord do; the app holds the message and sends it later.

A proof of concept on 2026-10-19 showed that suite 0x004F, server checks of signed Commits with no group secrets, admin refusal, `welcome_sender`, self-leave, SQLCipher storage, and a native Linux aarch64 build all work with the crate versions above.

## Left to the implementation

- Exact crate versions and feature flags, within the libraries named here.
- Table layouts, frame enum details and error types.
- The exact layout of the chat screen and its colors, within the areas and keys above.
- How often clients refresh their own keys, within "at least weekly".
- Whether VHS or ratatui's own capture makes the cleanest screenshots, as long as they show the real app.
