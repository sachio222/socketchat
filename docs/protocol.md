# Protocol

This document describes what Socketchat v4.0 sends between app and server, for contributors and anyone writing a compatible client. The source of truth is `crates/socketchat-proto` (frames, messages, links) and `crates/socketchat-core/src/keys.rs` (signatures and the sealed voucher). [architecture.md](architecture.md) explains the terms MLS, epoch, Commit, Welcome and KeyPackage.

## Connection and framing

- TCP with TLS 1.3, default port 7444. The server presents a self-signed certificate; the app accepts it only if its SHA-256 matches the fingerprint in the invite link.
- Every frame is a 4-byte big-endian length followed by that many bytes of body. A body over 1 MiB (1,048,576 bytes) closes the connection.
- Bodies are encoded with postcard, a compact binary serde format. The app sends `ClientFrame` values; the server sends `ServerFrame` values.
- MLS messages, Welcomes and KeyPackages ride inside frames as opaque bytes in their standard TLS encoding.

## Hello

The first frame from the app must be `Hello { version }`, with the newest protocol number the app speaks. Socketchat 0.5.2 speaks protocol 3, 0.5.0 and 0.5.1 speak protocol 2, and 0.4.0 speaks only protocol 1. A 0.5.2 server serves all three.

- `HelloOk { version }`: the server speaks this version; requests may follow.
- `VersionMismatch { server }`: the server does not serve this version. `server` is the newest one it does, and the server closes the connection. When that number is at least 1 and lower than the app's own, the app connects once more and says Hello with it, so a 0.5.0 app talks to a 0.4.0 server over protocol 1. Any other number ends the attempt with "the server speaks protocol N; update Socketchat".
- `Busy(Full)`: the server already serves `max_connections` connections (1,000 by default) and closes the connection.
- `Busy(Network)`: the connection's address already holds `max_per_ip` connections (256 by default; an IPv6 address counts by its /64 network) and the server closes the connection. While 64 such connections are already being turned away, the server drops the next one before TLS instead.

The app shows a `Busy` reply as "this server is full right now; try again in a few minutes" or "this server has too many connections from your network right now; try again in a few minutes".

Every request needs protocol 1 or later, and the ones marked "Protocol 2" in the table below need protocol 2. An app does not send a request newer than its connection's version. It tells the person "this server runs an older version of Socketchat that can't do that yet; ask the person who runs it to update it" and carries on with everything else. A server that gets such a request anyway answers `Refused("this server needs a newer app for that")`. A protocol-1 connection never gets a frame that 0.4.0 cannot decode: the responses added in protocol 2 answer only protocol-2 requests, and pushes are unchanged. Protocol 3 adds one response, `SlowDown`, which goes only to connections on protocol 3; an older connection gets `Refused` with the wait in words instead. An app takes protocol 3 to mean that the server also enforces each room's settings (see "Room settings").

The server also closes the connection, without a reply, when the first frame is anything else, when a frame before Hello announces a body over 16 bytes, or when no Hello arrives within 10 seconds. Until the connection signs in, a frame over `max_frame_before_sign_in` bytes (8,192 by default) closes it, and so does reaching 60 seconds after connecting, whatever it sent. Later it closes a connection that sends nothing for 5 minutes. Each connection may have at most 2 MiB of replies and pushes waiting to be written. The server handles the next request only once there is room for the largest reply, and closes the connection when a push would not fit. A write that makes no progress for 30 seconds also closes it, so a client that stops reading frees its slot. Apps reconnect when they next need the server and fetch what they missed.

## Requests and responses

After Hello, the app sends `Req { id, body }` and the server answers with `Resp { id, body }` carrying the same `id`. The server answers requests in the order they arrive.

Most requests need the connection to have signed in with a key first, through `Challenge` and `Prove` or one of the `Register` requests. A `Prove` or `Register` request that succeeds signs the connection in.

### Requests

| Request | What it does |
|---|---|
| `Challenge` | Asks for a random 32-byte challenge to sign for this connection. |
| `Prove { key, sig }` | Signs in with a key the server already knows: an account key or a mailbox. |
| `RegisterAccount { token, key, sig }` | Registers a server account key with an invite token, and signs in with it. A group token registers an account only if the connection that made it held an account with room left under `max_accounts_from_room_links`; otherwise it is refused, and the token still redeems a mailbox. |
| `RegisterMailbox { token, key, sig }` | Registers a group key as a mailbox. `token: Some` redeems a group invite; `None` reserves a mailbox for a group the signed-in account is about to create. A group invite is refused, and stays unused, while its room has `max_room_welcomes` joins waiting (Welcomes not yet fetched and invites redeemed but not yet added) or no room in its messages for an add. |
| `CreateGroup { group_info, ratchet_tree }` | Creates a group from an MLS GroupInfo and ratchet tree. The group must hold only its creator, as its only admin, and a ratchet tree over 16 KiB is refused. |
| `Post { group, mls, welcome }` | Adds an MLS message to the group log. A Commit that adds someone may carry a `WelcomeOut { token, welcome, voucher }` for the joiner, with `voucher` sealed as described under "Sealed voucher" below. An MLS message over 1,047,552 bytes is refused. So is a message past the room's or the server's storage limit, and a Commit that adds someone while the room has `max_room_welcomes` Welcomes waiting. A post from a member who posted faster than the room allows gets `SlowDown`, and nothing is stored (see "Posting pace"). In a room that lets only admins invite, a Commit from a member that adds someone is refused, and so is any Commit from a member that changes the room's settings. Past those limits the server still takes, up to a tenth past the room's limit and a fiftieth past the server's, each member's first leave Proposal of at most 4 KiB, and Commits that only remove people; neither may carry more than 64 bytes of authenticated data. A Commit that lost a race for its epoch while the server checked it gets `Conflict`. |
| `Fetch { group, after, limit }` | Returns log entries after sequence number `after`: at most 500, and no more than fit about 900 KiB, but always at least one when there is one. Fetch again until the reply is empty. |
| `Ack { group, seq }` | Says this mailbox has everything up to `seq`; entries every member has acknowledged are deleted. |
| `Members { group }` | Lists the group's mailboxes and the sequence number at which each joined. |
| `CreateInvite { group }` | Makes an invite token: for a group (`Some`), or for the server (`None`). In a room that lets only admins invite, a member who is not an admin gets `Refused("in this room only admins can make invite links")`, and on a server whose operator lets only admins invite into rooms, `Refused("on this server only admins can make invite links")`. An account can make 5 server invites per window (the link lifetime rounded up to days, plus a day), and only while the server lets members make accounts. |
| `RedeemInvite { token, key_package, mac }` | Lodges a join request: a postcard list of one or two KeyPackages, at most 8 KiB in all, each signed by the mailbox that redeemed the token. Each KeyPackage carries the joiner's signature on the request (see "Other formats"). Apps send `mac` as 32 zero bytes, and nothing reads it. In a room with settings, KeyPackages whose leaf capabilities lack type `0xff02` get `Refused("this room needs Socketchat 0.5.2 or later; update Socketchat, then ask for a new invite link")`. |
| `PendingJoins { group, after }` | Lists join requests for a group that are less than 7 days old, ordered by when they were lodged and then by token, starting strictly after `after` (the `(lodged_unix, token)` of the last request the client already has; none starts from the oldest). Each reply holds as many as fit about 900 KiB, and at least one; an empty reply means the end. A request leaves the list when its Welcome is posted or it expires. |
| `FetchWelcomes` | Returns and deletes Welcomes waiting for this connection's mailboxes. |
| `FileBegin { group, size }` | Starts an upload and returns a file ID. Refused if `size` is over the server's limit, or would take the sender's, the room's or the server's stored files past its limit (files may use nine tenths of the server's). Starting an upload while the sender has 3 unfinished ones deletes the oldest of them first. An unfinished upload counts at the bytes received and is deleted 6 hours after it began; each `FileChunk` is checked against the same limits. |
| `FileChunk { file, index, data }` | Uploads one sealed chunk (at most 64 KiB plus a 16-byte tag), in order, from the sender only. |
| `FileEnd { file }` | Marks an upload complete once every chunk has arrived. |
| `FileGet { file, index }` | Downloads one sealed chunk, for group members. |
| `FileDone { file }` | Says this mailbox has saved the file. When every member except the sender has, the server deletes it. |
| `ListInvites { server_tokens }` | Protocol 2. Lists the open invite links that this connection's keys made into groups, plus the open server links named in `server_tokens`. The server keeps no record of who made a server link, so the app remembers its own and names them here. A request names at most 100 (more is refused with "ask about at most 100 links at a time"), so an app with more asks in chunks of 100. The reply holds at most 500 links. |
| `CancelInvite { token }` | Protocol 2. Deletes an open link: a group link one of this connection's keys made, or a server link while the connection is signed in with an account key. A cancelled server link still counts against the account's server invites. A link that was already used, has expired or was cancelled gets `Refused("that link was already used, has expired or was cancelled")`. |
| `GroupCreated { group }` | Protocol 2. Asks when the group was created on this server. Only members may ask. |
| `ServerRules` | Protocol 3. Asks for the server's own rule on members inviting into rooms, which rooms cannot change. |
| `LastLeave { group }` | Protocol 2. The only member leaves, and the server deletes the group in one transaction: its log, the Welcomes waiting for its mailboxes, join requests, invites, mailboxes, files with their chunks, and its OpenMLS state. Refused with "other people are still in this group" while anyone else is in it. |

### Responses

| Response | Meaning |
|---|---|
| `Ok` | Done. |
| `Challenge([u8; 32])` | The challenge to sign. |
| `Posted { seq }` | The message entered the log at this sequence number. |
| `Conflict { epoch }` | A Commit lost the race; the group is now at `epoch`. Fetch, catch up and try again. |
| `Refused(String)` | The server checked the request and said no, with a reason a person can read. |
| `Entries(Vec<Entry>)` | Log entries, each a `seq` and MLS bytes. |
| `Members(Vec<MemberInfo>)` | Mailbox keys and the sequence number at which each joined. |
| `Invite { token, expires_unix }` | A new invite token and its expiry. |
| `JoinLodged` | The join request is stored and online members have heard about it. |
| `Joins(Vec<JoinRequest>)` | Pending join requests: token, KeyPackages, the unused `mac` field and the time each was lodged. |
| `Welcomes(Vec<WelcomeIn>)` | Welcomes, each with its mailbox and sealed voucher. |
| `File(FileId)` | The ID for a new upload. |
| `Chunk(Vec<u8>)` | One sealed file chunk. |
| `Error(String)` | Something failed on the server, or the request made no sense. |
| `Invites(Vec<InviteInfo>)` | Protocol 2. Answers `ListInvites`: each link's token, its group (none for a server link) and its expiry, oldest expiry first. |
| `GroupCreated { created_unix }` | Protocol 2. Answers `GroupCreated` with the time the server stored the group. |
| `ServerRules { members_can_invite_to_rooms }` | Protocol 3. Answers `ServerRules`. When false, the server treats every room as admins-only for invite links and adds, whatever the room's setting says. |
| `SlowDown { retry_after_ms }` | Protocol 3. Answers a `Post` from a member who posted faster than the room allows. Nothing was stored; post again after `retry_after_ms` milliseconds. A connection on protocol 1 or 2 gets `Refused("this room limits fast posting; try again in N seconds")` instead. |

### Sealed voucher

The `voucher` field of `WelcomeOut` and `WelcomeIn` carries the inviter's signed voucher (see "Signed byte strings") sealed for the joiner, who holds the invite secret from the link. The server stores and forwards these bytes and has no key that opens them. A direct message carries an empty `voucher`. Members who complete a join get the seal key, not the secret, from the inviter's `AppMsg::Voucher`.

- **Plaintext:** the postcard-encoded `Voucher` struct from `keys.rs`: token, SHA-256 of the invite secret, group ID, inviter's group key, expiry, inviter's identity key and signature.
- **Key:** HKDF-SHA256 with no salt, the 32-byte invite secret as input key material, and info `socketchat/v1/voucher-seal`, expanded to 32 bytes.
- **Cipher:** XChaCha20-Poly1305 with a random 24-byte nonce and `socketchat/v1/voucher-seal` as associated data.
- **Bytes:** nonce (24) ‖ ciphertext with its 16-byte tag.

The joiner's app derives the same key from the link's secret and opens the voucher. A wrong secret or any changed byte fails to open, and the app then treats the join as unverified.

### Room settings

A room's settings live in GroupContext extension type `0xff02`, next to the admin list, and only a Commit changes them. The value is a run of entries in increasing order of type, each a 2-byte big-endian type, a 2-byte big-endian length and that many bytes:

| Type | Setting | Value |
|---|---|---|
| 1 | Who can invite | 1 byte: 0 for anyone in the room, 1 for admins only. Left out when 0. |
| 2 | Slow mode | 4-byte big-endian number of seconds, at most 21,600 (6 hours). Left out when 0. |
| 3 | Who can set the topic | 1 byte: 0 for admins only, 1 for anyone in the room. Left out when 0. Apps enforce it; the server only keeps it. |

An app keeps entries of a type it does not know, as they are, when it changes the others. A value that breaks these rules (types out of order or repeated, a known setting of the wrong length or out of range, or more than 1,024 bytes in all) makes the whole Commit refused, by the server and by apps. A room on the defaults holds no `0xff02` extension, and its required capabilities name only `0xff00`, as before. A room with settings names both `0xff00` and `0xff02` in its required capabilities, so MLS refuses to add anyone whose KeyPackage lacks `0xff02`, and refuses the change while any member's leaf lacks it. Apps from 0.5.2 on list `0xff02` in their leaf capabilities and refresh their own leaf (a Commit with a new path) in any room where it is missing.

The server and apps judge each Commit by the room as it stood before it:

- A Commit that changes the settings needs an admin.
- A Commit that adds someone needs an admin while the room lets only admins invite, or while the server's `members_can_invite_to_rooms` is false.
- The Commit that hands the admin role on when the last admin leaves must keep the settings unchanged.
- When a Commit turns admins-only on, or takes someone off the admin list of an admins-only room, the server deletes the open links that members who are not admins made in that room, with the joins waiting on them.
- At `RegisterMailbox`, `RegisterAccount` and `RedeemInvite`, a room link works only while its maker may still invite: an admin, or any member while both the room and the server's `members_can_invite_to_rooms` allow it. Otherwise the answer is `Refused("this invite link stopped working, because the person who made it can no longer invite people into this room; ask an admin of the room for a new one")`.

### Posting pace

The server counts each member's posts in each room: every `Post` except leave Proposals and Commits that only remove people. A post must pass two limits:

- **The server's pace**, a token bucket per member key per room: `rate_burst_messages` messages (30 by default) and `rate_burst_kb` kilobytes (2,000), refilled at one message every `rate_seconds_per_message` seconds (5) and `rate_kb_per_second` kilobytes a second (10). The byte allowance is never less than one message of the largest size. Admins get ten times the burst and the refill. A burst of 0 turns this limit off; a refill of 0 turns off that kind of limit.
- **The room's slow mode**, for members who are not admins: one post per slow-mode period.

A post is charged only once nothing else will refuse it, and the answer to a refused one carries the longer of the two waits. The buckets live in the server's memory only. A leave Proposal is taken once per member per epoch, at most 4 KiB with at most 64 bytes of authenticated data; another is refused while the first waits for a Commit.

## Pushes

The server sends `Push` frames, with no request, to connections signed in with the right keys:

| Push | When |
|---|---|
| `Entry { group, entry }` | A new log entry in a group this connection belongs to. The sender's own connection does not get it. |
| `Welcome(WelcomeIn)` | Someone added one of this connection's mailboxes to a group. |
| `JoinRequest { group, request }` | Someone lodged a join request for a group this connection belongs to. |

## Invite links

```
socketchat://<host>:<port>/j/<token>#<cert-fpr>[.<inviter-fpr>.<invite-secret>]
```

- Every value after the host is base64url without padding.
- `<port>` may be left out; it then defaults to 7444.
- `<token>` is 16 random bytes the server stores with the invite.
- `<cert-fpr>` is the SHA-256 of the server's certificate (32 bytes).
- A server invite stops there. A group invite adds `<inviter-fpr>`, the SHA-256 of the inviter's identity public key, and `<invite-secret>`, 32 random bytes.
- Everything after `#` is the link fragment, which apps never send to the server.

A link also has a web form, for phones: `https://socketchat.org/join#` followed by the whole link, as in `https://socketchat.org/join#socketchat://chat.example.com:7444/j/...`. Browsers never send the part after `#` to the web server, so the join page reads the invite inside the browser. Apps take the web form, the same with `/join/#`, and the `socketchat://` link, and check the link inside in the same way. They refuse every other web address, and they read a link without ever opening it.

## Signed byte strings

Every Socketchat signature outside MLS is Ed25519 over a context string, one zero byte, then the message:

```
signed = context || 0x00 || message
```

Verification uses Ed25519's strict mode. The context strings are:

| Context | Message | Used for |
|---|---|---|
| `socketchat/v1/auth` | challenge (32) ‖ public key (32) | Signing in, and registering accounts and mailboxes. |
| `socketchat/v1/group-key-binding` | group ID (16) ‖ group key (32) | An identity key vouching for its owner's key in one group. Sent only inside encrypted messages. |
| `socketchat/v1/voucher` | token (16) ‖ SHA-256 of invite secret (32) ‖ group ID (16) ‖ inviter's group key (32) ‖ expiry as big-endian u64 (8) | An inviter vouching for a link they made. |
| `socketchat/v1/join-request` | token (16) ‖ joiner's new mailbox key (32) | A joiner asking to join through a link, signed with the request key derived from the link's secret. |
| `socketchat/v1/topic` | group ID (16) ‖ set time as big-endian u64 (8) ‖ topic text as UTF-8 | A member's group key signing the topic they set for a room. Sent only inside encrypted messages. |

Numbers in parentheses are byte lengths.

## Other formats

- **Keys derived from the invite secret:** HKDF-SHA256 with no salt and the 32-byte secret as input key material, expanded to 32 bytes, with info `socketchat/v1/invite-sign` (the seed of the Ed25519 request key), `socketchat/v1/voucher-seal` (the seal key) or `socketchat/v1/invite-proof` (the proof key). The inviter sends members the request key's public half and the seal key. The request key's private half and the proof key never leave the inviter and the joiner.
- **Join request signature:** Ed25519 under the request key, with context `socketchat/v1/join-request` (see "Signed byte strings"). Each KeyPackage the joiner lodges holds it in a KeyPackage extension of type `0xff01`, as the 64 signature bytes, so the KeyPackage's own signature by the mailbox key covers it. The member who adds the joiner checks it against the public key from the inviter's `AppMsg::Voucher` and ignores a request that fails.
- **Invite proof:** HMAC-SHA256 under the proof key, over group ID (16) ‖ the joiner's group key (32). The joiner posts it in the group as `AppMsg::InviteProof`; the inviter's app checks it before marking the joiner verified.
- **KeyPackage bundle:** a postcard-encoded list of TLS-encoded KeyPackages, one per allowed suite (0x004F, then 0x0001). The member who adds the joiner picks the one matching the group's suite.
- **Admin list:** GroupContext extension type `0xff00`, a run of entries, each a 2-byte big-endian length of 32 followed by a 32-byte Ed25519 key.
- **Room settings:** GroupContext extension type `0xff02`; see "Room settings" above.
- **Application messages:** inside MLS PrivateMessages, the postcard-encoded `AppMsg` enum from `crates/socketchat-core/src/appmsg.rs` (see "Application messages" below).
- **Padding:** apps from 0.5.2 on fill the `padding` field of every PrivateMessageContent (RFC 9420, section 6.3.1) with zero bytes, so that the content's length plus the suite's hash length (32 bytes for both suites) is a whole multiple of 256. This is OpenMLS's `padding_size` setting, in `PADDING_BLOCK` in `crates/socketchat-core/src/suite.rs`. A text of up to 169 ASCII characters gives a 318-byte MLS message in either suite, and each further block adds 256 bytes. RFC 9420 receivers strip zero padding, so apps on 0.4.0 to 0.5.1 read padded messages, and 0.5.2 reads the unpadded messages those apps send. Group changes travel as PublicMessages and carry no padding.
- **Voucher on the wire:** sealed for the joiner, as described under "Sealed voucher".
- **Safety number:** built the way Signal's numeric fingerprint (version 1) builds its digits. For each of the two identity keys, start from a 2-byte zero, the key, and the key again; then 5,200 times, replace that value with SHA-512 of the value followed by the key. Read the first 30 bytes as six 5-byte big-endian numbers, each modulo 100,000 and written as 5 digits. The two 30-digit halves are sorted and joined into 60 digits, so both people see the same number.

## Application messages

Everything members send each other inside a group travels as one `AppMsg` value per MLS application message, encoded with postcard. Postcard writes an enum variant as its number, counted from 0 in the order below, followed by its fields.

| # | Variant | What it carries |
|---|---|---|
| 0 | `Text { body }` | A chat message. |
| 1 | `Profile { display_name, binding }` | The sender's display name, and a `Binding`: the group ID, the sender's group key, their identity key, and the identity key's signature over the group key (context `socketchat/v1/group-key-binding`). |
| 2 | `GroupName { name }` | The room's name. Apps take a new name from an admin, and from any member while they have no name for the room, which is how a newcomer learns it. |
| 3 | `Voucher { voucher, request_key, seal_key }` | An invite link's signed voucher, the public half of the request key, and the seal key (see "Other formats"). |
| 4 | `File(FileOffer)` | A file offer: file ID, name, size, media type, SHA-256 of the plaintext, the file key and the 19-byte nonce prefix. |
| 5 | `IsDm` | Marks the group as a two-person direct message. |
| 6 | `DmRequest { to, group, token, dm_key }` | Asks the member whose group key is `to` to open a direct message in the new group `group`. `token` registers their mailbox there, and `dm_key` is the asker's key in the new group. |
| 7 | `DmAccept { to, group, token, key_packages }` | Answers a `DmRequest` with a KeyPackage bundle for the new group. |
| 8 | `InviteProof { token, proof }` | A joiner's proof that they hold the invite link `token` belongs to (see "Other formats"). |
| 9 | `Extension(Extension)` | A message for an add-on or another program, described below. |
| 10 | `AppInfo { app_version }` | The Socketchat version the sender runs. Apps keep at most 32 characters of it. Each app sends it once to every room that has not heard its current version, and again after someone joins. |
| 11 | `CloseVote { close_id, yes }` | An admin's vote on closing the room. `close_id` is 16 random bytes that name one request to close: the first yes starts a request, and later votes name it. |
| 12 | `Closed { close_id }` | Request `close_id` passed, and the sender is closing the room. |
| 13 | `Topic(Topic)` | The room's topic, or its removal, described below. |
| 14 | `AddAsk { to, ask, reply_key }` | Starts an invite by name to another room for the member whose group key is `to`. `ask` is 16 random bytes that name the invite, and `reply_key` is the inviter's 32-byte HPKE public key for the answer. It names no room. |
| 15 | `AddKey { to, ask, key, offer_by }` | The member invited gives the inviter, `to`, a 32-byte HPKE public key made for invite `ask`, and says until when, in Unix seconds by its clock, it waits for the offer. |
| 16 | `AddOffer { to, ask, sealed }` | The room to join, its server and an invite token, sealed for the member invited. |
| 17 | `AddAnswer { to, ask, sealed }` | KeyPackages for the room, sealed for the inviter, sent when the person joins. |

Variants 9 to 12 are new in Socketchat 0.5.0, variant 13 in 0.5.2, and variants 14 to 17 in the release after 0.5.2.

- **Skip rule.** An app ignores an application message it cannot decode. Socketchat 0.4.0 cannot decode variants 9 to 17, 0.5.0 and 0.5.1 cannot decode variants 13 to 17, and 0.5.2 cannot decode variants 14 to 17, so they skip them and show nothing.
- **Sender.** An app takes a message as its sender's only when the credential MLS checked it against, from the epoch it was written in, holds the group key of the member in that place in the group now. A message from an earlier epoch whose place someone else holds now is ignored.
- **Append-only rule.** New variants go at the end of the enum, and an existing variant's fields never change, so an older app still decodes every variant it knows.
- **Closing.** Apps count a `CloseVote` or a `Closed` only from an admin still in the room, and only each admin's newest vote on a request. A request passes when enough admins say yes: every admin when the room has up to 3, and `n / 2 + 1` of `n` admins above that. It ends without closing once too many say no for the rest to reach that number, or 7 days after its first vote. The admin whose yes passes the request finishes the close at once: it posts `Closed`, removes everyone else with one Commit, then sends `LastLeave`. Other apps end the room when they read that `Closed` or the Commit that removes them. Another admin whose yes is in the count finishes the close the same way only if its app finds the request passed before any `Closed` arrives, as when the first admin's app stopped part way. Racing Commits resolve through the server's epoch check.

An `Extension` carries:

- `namespace`: names the add-on. 1 to 32 bytes of `a-z`, `0-9` and `-`.
- `kind`: the sort of message. 1 to 32 bytes of `a-z`, `0-9`, `.`, `_` and `-`.
- `version`: a 16-bit number for the layout of `body`, which the add-on defines.
- `body`: bytes for the add-on. The whole encrypted message must fit the server's limit of 1,047,552 bytes.
- `summary`: an optional line for people. Apps clean it the way they clean message text, put it on one line, cut it at 200 characters, and drop it when nothing is left. The chat shows the summary as a line from its sender; a message without one shows nothing.

An app refuses to send an `Extension` whose namespace or kind breaks these rules, and ignores any such `Extension` it receives.

A `Topic` carries:

- `text`: the topic, or empty to remove it. An app sends at most 300 characters as `clean_topic` in `sanitize.rs` cleans them, and ignores a topic whose text is over 4,096 bytes.
- `set_by`: the group key of the member who set it.
- `set_unix`: when they set it, in seconds since 1970 by their clock.
- `sig`: `set_by`'s signature, with context `socketchat/v1/topic` (see "Signed byte strings").
- `repost`: true when an admin's app passes the topic on after someone joins.

Apps take a `Topic` only from a sender who is in the room and may set the topic at that point in the log: an admin, or any member while the room's settings let anyone set it (type 3). The signature must check out under `set_by`. A topic with `repost` false must have `set_by` equal to its sender, and replaces the room's topic unless it is the same one. A topic with `repost` true counts only in an app that holds no topic for the room, and never when its text is empty. Apps clean the text with `clean_topic` before they keep or show it. Each admin's app sends the room's topic, if it has one, with `repost` true after someone joins, beside its profile.

### Inviting someone you share a room with

`/invite <name>` invites a member of a room both people share, room A, to another room, room B, which the inviter is in. Everything travels in room A as application messages, so every member of room A can read them; what only the two of them should see is sealed inside.

1. The inviter's app makes an invite token for room B with `CreateInvite`, so the server checks that the inviter may bring people in, then posts `AddAsk` in room A with a fresh HPKE key pair's public half.
2. The app of the member invited, `to`, posts `AddKey` with a fresh HPKE public key of its own. It does this without asking the person, and only when the sender of `AddAsk` has posted a profile in room A, this member's own profile is not held back there, fewer than 3 asks from that sender in room A are open, fewer than 20 invites wait for this member to join, and no invite from the sender's identity ran out unjoined in the last hour.
3. The inviter's app posts `AddOffer`, sealed to that key, while `offer_by` is more than 60 seconds away by its own clock; past that it ends the invite and sends nothing. The app of the member invited opens it and writes a line saying who invites them to which room, and how to join, into the room its chat screen has open, or into room A while no chat screen is open. Where the line goes is up to the app and sends nothing.
4. When the person types `/join` for that invite, their app connects to room B's server, registers a new mailbox with the token (`RegisterMailbox`), makes KeyPackages for it with no join signature, and posts `AddAnswer`, sealed to the inviter's key, with the KeyPackage bundle.
5. The inviter's app adds the KeyPackage that matches room B's suite with a Commit, under the same rules as any add, and posts the Welcome with the token and an empty `voucher`. Once the invite ends any other way, it cancels the token with `CancelInvite`.

An app takes `AddKey` and `AddAnswer` only from the member its own `AddAsk` went to, and `AddOffer` only from the member who sent the `AddAsk` it answered, each for the invite `ask` names, at the step that invite has reached. An invite is open for 24 hours from the inviter's `AddAsk` and from the invited member's first sight of it, and ends early once either person is no longer in room A. The invited member's app drops an ask whose offer has not come by `offer_by`: 10 minutes after the ask arrived, plus twice room A's slow mode. Each side forgets an invite once it is answered, so an invite works once, and the token works once on the server. There is no message for declining: an invite nobody joins runs out.

**Sealing.** HPKE (RFC 9180) in base mode with DHKEM(X25519, HKDF-SHA256) (0x0020), HKDF-SHA256 (0x0001) and ChaCha20Poly1305 (0x0003), single-shot. Each key pair comes from 32 random bytes through HPKE's DeriveKeyPair and serves one invite.

- **Info:** `socketchat/v1/add-offer` for an offer, `socketchat/v1/add-answer` for an answer.
- **Associated data:** room A's group ID (16) ‖ `ask` (16) ‖ the sender's group key in room A (32) ‖ the recipient's group key in room A (32).
- **`sealed`:** `Sealed { enc, ct }`, the HPKE encapsulated key (32 bytes) and the ciphertext with its 16-byte tag. Apps open at most 16 KiB of ciphertext.
- **Offer plaintext:** the postcard-encoded `Offer` from `crates/socketchat-core/src/add.rs`: room name, room B's group ID, the server's host, port and certificate fingerprint, the token, the inviter's group key in room B, and the expiry as Unix seconds; then zero bytes up to a whole number of 1,024-byte blocks.
- **Answer plaintext:** the postcard-encoded `Answer { key_packages }`, a KeyPackage bundle as `RedeemInvite` carries one; then zero bytes up to a whole number of 4,096-byte blocks.

The invited member's app keeps an offer only when its expiry is in the future and no more than 25 hours after it first saw the invite, its port is not 0 and its host passes the same check as an invite link's. It records the join it waits for as `add:` followed, in hex and split by `:`, by the inviter's identity key, their group key in room B and room B's group ID, and judges the Welcome the way it judges a direct message's (see "Per-group keys and mailboxes" in [architecture.md](architecture.md)), except that its profile stays out of room B unless the join checks out as verified.

**Versions.** Apps send `AddAsk` only to a member whose `AppInfo` names a version after 0.5.2. No server change is needed: the steps use `CreateInvite`, `RegisterMailbox` and `Post` from protocol 1, and `CancelInvite` from protocol 2. On a protocol-1 server an unused token expires on its own.
