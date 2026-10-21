# Protocol

This document describes what socketchat v4.0 sends between app and server, for contributors and anyone writing a compatible client. The source of truth is `crates/socketchat-proto` (frames, messages, links) and `crates/socketchat-core/src/keys.rs` (signatures and the sealed voucher). [architecture.md](architecture.md) explains the terms MLS, epoch, Commit, Welcome and KeyPackage.

## Connection and framing

- TCP with TLS 1.3, default port 7444. The server presents a self-signed certificate; the app accepts it only if its SHA-256 matches the fingerprint in the invite link.
- Every frame is a 4-byte big-endian length followed by that many bytes of body. A body over 1 MiB (1,048,576 bytes) closes the connection.
- Bodies are encoded with postcard, a compact binary serde format. The app sends `ClientFrame` values; the server sends `ServerFrame` values.
- MLS messages, Welcomes and KeyPackages ride inside frames as opaque bytes in their standard TLS encoding.

## Hello

The first frame from the app must be `Hello { version }`, with the newest protocol number the app speaks. socketchat 0.5.0 speaks protocol 2, and 0.4.0 speaks only protocol 1. A 0.5.0 server serves both.

- `HelloOk { version }`: the server speaks this version; requests may follow.
- `VersionMismatch { server }`: the server does not serve this version. `server` is the newest one it does, and the server closes the connection. When that number is at least 1 and lower than the app's own, the app connects once more and says Hello with it, so a 0.5.0 app talks to a 0.4.0 server over protocol 1. Any other number ends the attempt with "the server speaks protocol N; update socketchat".
- `Busy(Full)`: the server already serves `max_connections` connections (1,000 by default) and closes the connection.
- `Busy(Network)`: the connection's address already holds `max_per_ip` connections (256 by default; an IPv6 address counts by its /64 network) and the server closes the connection. While 64 such connections are already being turned away, the server drops the next one before TLS instead.

The app shows a `Busy` reply as "this server is full right now; try again in a few minutes" or "this server has too many connections from your network right now; try again in a few minutes".

Every request needs protocol 1 or later, and the ones marked "Protocol 2" in the table below need protocol 2. An app does not send a request newer than its connection's version. It tells the person "this server runs an older version of socketchat that can't do that yet; ask the person who runs it to update it" and carries on with everything else. A server that gets such a request anyway answers `Refused("this server needs a newer app for that")`. A protocol-1 connection never gets a frame that 0.4.0 cannot decode: the responses added in protocol 2 answer only protocol-2 requests, and pushes are unchanged.

The server also closes the connection, without a reply, when the first frame is anything else or when no Hello arrives within 10 seconds. Later it closes a connection that sends nothing for 5 minutes. Each connection may have at most 2 MiB of replies and pushes waiting to be written. The server handles the next request only once there is room for the largest reply, and closes the connection when a push would not fit. A write that makes no progress for 30 seconds also closes it, so a client that stops reading frees its slot. Apps reconnect when they next need the server and fetch what they missed.

## Requests and responses

After Hello, the app sends `Req { id, body }` and the server answers with `Resp { id, body }` carrying the same `id`. The server answers requests in the order they arrive.

Most requests need the connection to have signed in with a key first, through `Challenge` and `Prove` or one of the `Register` requests.

### Requests

| Request | What it does |
|---|---|
| `Challenge` | Asks for a random 32-byte challenge to sign for this connection. |
| `Prove { key, sig }` | Signs in with a key the server already knows: an account key or a mailbox. |
| `RegisterAccount { token, key, sig }` | Registers a server account key with an invite token, and signs in with it. |
| `RegisterMailbox { token, key, sig }` | Registers a group key as a mailbox. `token: Some` redeems a group invite; `None` reserves a mailbox for a group the signed-in account is about to create. |
| `CreateGroup { group_info, ratchet_tree }` | Creates a group from an MLS GroupInfo and ratchet tree. The group must hold only its creator, as its only admin. |
| `Post { group, mls, welcome }` | Adds an MLS message to the group log. A Commit that adds someone may carry a `WelcomeOut { token, welcome, voucher }` for the joiner, with `voucher` sealed as described under "Sealed voucher" below. An MLS message over 1,047,552 bytes is refused. |
| `Fetch { group, after, limit }` | Returns log entries after sequence number `after`: at most 500, and no more than fit about 900 KiB, but always at least one when there is one. Fetch again until the reply is empty. |
| `Ack { group, seq }` | Says this mailbox has everything up to `seq`; entries every member has acknowledged are deleted. |
| `Members { group }` | Lists the group's mailboxes and the sequence number at which each joined. |
| `CreateInvite { group }` | Makes an invite token: for a group (`Some`), or for the server (`None`). An account can make 5 server invites per window (the link lifetime rounded up to days, plus a day). |
| `RedeemInvite { token, key_package, mac }` | Lodges a join request: a postcard list of one or two KeyPackages, at most 8 KiB in all, each signed by the mailbox that redeemed the token. Each KeyPackage carries the joiner's signature on the request (see "Other formats"). Apps send `mac` as 32 zero bytes, and nothing reads it. |
| `PendingJoins { group, after }` | Lists join requests for a group that are less than 7 days old, ordered by when they were lodged and then by token, starting strictly after `after` (the `(lodged_unix, token)` of the last request the client already has; none starts from the oldest). Each reply holds as many as fit about 900 KiB, and at least one; an empty reply means the end. A request leaves the list when its Welcome is posted or it expires. |
| `FetchWelcomes` | Returns and deletes Welcomes waiting for this connection's mailboxes. |
| `FileBegin { group, size }` | Starts an upload and returns a file ID. Refused if `size` is over the server's limit. |
| `FileChunk { file, index, data }` | Uploads one sealed chunk (at most 64 KiB plus a 16-byte tag), in order, from the sender only. |
| `FileEnd { file }` | Marks an upload complete once every chunk has arrived. |
| `FileGet { file, index }` | Downloads one sealed chunk, for group members. |
| `FileDone { file }` | Says this mailbox has saved the file. When every member except the sender has, the server deletes it. |
| `ListInvites { server_tokens }` | Protocol 2. Lists the open invite links that this connection's keys made into groups, plus the open server links named in `server_tokens`. The server keeps no record of who made a server link, so the app remembers its own and names them here. A request names at most 100 (more is refused with "ask about at most 100 links at a time"), so an app with more asks in chunks of 100. The reply holds at most 500 links. |
| `CancelInvite { token }` | Protocol 2. Deletes an open link: a group link one of this connection's keys made, or a server link while the connection is signed in with an account key. A cancelled server link still counts against the account's server invites. A link that was already used, has expired or was cancelled gets `Refused("that link was already used, has expired or was cancelled")`. |
| `GroupCreated { group }` | Protocol 2. Asks when the group was created on this server. Only members may ask. |
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

### Sealed voucher

The `voucher` field of `WelcomeOut` and `WelcomeIn` carries the inviter's signed voucher (see "Signed byte strings") sealed for the joiner, who holds the invite secret from the link. The server stores and forwards these bytes and has no key that opens them. A direct message carries an empty `voucher`. Members who complete a join get the seal key, not the secret, from the inviter's `AppMsg::Voucher`.

- **Plaintext:** the postcard-encoded `Voucher` struct from `keys.rs`: token, SHA-256 of the invite secret, group ID, inviter's group key, expiry, inviter's identity key and signature.
- **Key:** HKDF-SHA256 with no salt, the 32-byte invite secret as input key material, and info `socketchat/v1/voucher-seal`, expanded to 32 bytes.
- **Cipher:** XChaCha20-Poly1305 with a random 24-byte nonce and `socketchat/v1/voucher-seal` as associated data.
- **Bytes:** nonce (24) ‖ ciphertext with its 16-byte tag.

The joiner's app derives the same key from the link's secret and opens the voucher. A wrong secret or any changed byte fails to open, and the app then treats the join as unverified.

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

## Signed byte strings

Every socketchat signature outside MLS is Ed25519 over a context string, one zero byte, then the message:

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

Numbers in parentheses are byte lengths.

## Other formats

- **Keys derived from the invite secret:** HKDF-SHA256 with no salt and the 32-byte secret as input key material, expanded to 32 bytes, with info `socketchat/v1/invite-sign` (the seed of the Ed25519 request key), `socketchat/v1/voucher-seal` (the seal key) or `socketchat/v1/invite-proof` (the proof key). The inviter sends members the request key's public half and the seal key. The request key's private half and the proof key never leave the inviter and the joiner.
- **Join request signature:** Ed25519 under the request key, with context `socketchat/v1/join-request` (see "Signed byte strings"). Each KeyPackage the joiner lodges holds it in a KeyPackage extension of type `0xff01`, as the 64 signature bytes, so the KeyPackage's own signature by the mailbox key covers it. The member who adds the joiner checks it against the public key from the inviter's `AppMsg::Voucher` and ignores a request that fails.
- **Invite proof:** HMAC-SHA256 under the proof key, over group ID (16) ‖ the joiner's group key (32). The joiner posts it in the group as `AppMsg::InviteProof`; the inviter's app checks it before marking the joiner verified.
- **KeyPackage bundle:** a postcard-encoded list of TLS-encoded KeyPackages, one per allowed suite (0x004F, then 0x0001). The member who adds the joiner picks the one matching the group's suite.
- **Admin list:** GroupContext extension type `0xff00`, a run of entries, each a 2-byte big-endian length of 32 followed by a 32-byte Ed25519 key.
- **Application messages:** inside MLS PrivateMessages, the postcard-encoded `AppMsg` enum from `crates/socketchat-core/src/appmsg.rs` (see "Application messages" below).
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
| 10 | `AppInfo { app_version }` | The socketchat version the sender runs. Apps keep at most 32 characters of it. Each app sends it once to every room that has not heard its current version, and again after someone joins. |
| 11 | `CloseVote { close_id, yes }` | An admin's vote on closing the room. `close_id` is 16 random bytes that name one request to close: the first yes starts a request, and later votes name it. |
| 12 | `Closed { close_id }` | Request `close_id` passed, and the sender is closing the room. |

Variants 9 to 12 are new in socketchat 0.5.0.

- **Skip rule.** An app ignores an application message it cannot decode. socketchat 0.4.0 cannot decode variants 9 to 12, so it skips them and shows nothing.
- **Append-only rule.** New variants go at the end of the enum, and an existing variant's fields never change, so an older app still decodes every variant it knows.
- **Closing.** Apps count a `CloseVote` or a `Closed` only from an admin still in the room, and only each admin's newest vote on a request. A request passes when enough admins say yes: every admin when the room has up to 3, and `n / 2 + 1` of `n` admins above that. It ends without closing once too many say no for the rest to reach that number, or 7 days after its first vote. The admin whose yes passes the request finishes the close at once: it posts `Closed`, removes everyone else with one Commit, then sends `LastLeave`. Other apps end the room when they read that `Closed` or the Commit that removes them. Another admin whose yes is in the count finishes the close the same way only if its app finds the request passed before any `Closed` arrives, as when the first admin's app stopped part way. Racing Commits resolve through the server's epoch check.

An `Extension` carries:

- `namespace`: names the add-on. 1 to 32 bytes of `a-z`, `0-9` and `-`.
- `kind`: the sort of message. 1 to 32 bytes of `a-z`, `0-9`, `.`, `_` and `-`.
- `version`: a 16-bit number for the layout of `body`, which the add-on defines.
- `body`: bytes for the add-on. The whole encrypted message must fit the server's limit of 1,047,552 bytes.
- `summary`: an optional line for people. Apps clean it the way they clean message text, put it on one line, cut it at 200 characters, and drop it when nothing is left. The chat shows the summary as a line from its sender; a message without one shows nothing.

An app refuses to send an `Extension` whose namespace or kind breaks these rules, and ignores any such `Extension` it receives.
