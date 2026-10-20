# Protocol

This document describes what socketchat v4.0 sends between app and server, for contributors and anyone writing a compatible client. The source of truth is `crates/socketchat-proto` (frames, messages, links) and `crates/socketchat-core/src/keys.rs` (signatures and the sealed voucher). [architecture.md](architecture.md) explains the terms MLS, epoch, Commit, Welcome and KeyPackage.

## Connection and framing

- TCP with TLS 1.3, default port 7444. The server presents a self-signed certificate; the app accepts it only if its SHA-256 matches the fingerprint in the invite link.
- Every frame is a 4-byte big-endian length followed by that many bytes of body. A body over 1 MiB (1,048,576 bytes) closes the connection.
- Bodies are encoded with postcard, a compact binary serde format. The app sends `ClientFrame` values; the server sends `ServerFrame` values.
- MLS messages, Welcomes and KeyPackages ride inside frames as opaque bytes in their standard TLS encoding.

## Hello

The first frame from the app must be `Hello { version }`. The protocol number in v4.0 is 1.

- `HelloOk { version }`: the server speaks this version; requests may follow.
- `VersionMismatch { server }`: the server speaks another version and closes the connection.

The server also closes the connection, without a reply, when the first frame is anything else, when no Hello arrives within 10 seconds, or when it already serves `max_connections` connections. Later it closes a connection that sends nothing for 5 minutes, or one that stops reading while 64 replies and pushes wait for it. Apps reconnect when they next need the server and fetch what they missed.

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
| `RedeemInvite { token, key_package, mac }` | Lodges a join request: a postcard list of one or two KeyPackages, at most 8 KiB in all, each signed by the mailbox that redeemed the token, and their HMAC. |
| `PendingJoins { group }` | Lists join requests for a group that are less than 7 days old, oldest first, as many as fit about 900 KiB. A request leaves the list when its Welcome is posted or it expires. |
| `FetchWelcomes` | Returns and deletes Welcomes waiting for this connection's mailboxes. |
| `FileBegin { group, size }` | Starts an upload and returns a file ID. Refused if `size` is over the server's limit. |
| `FileChunk { file, index, data }` | Uploads one sealed chunk (at most 64 KiB plus a 16-byte tag), in order, from the sender only. |
| `FileEnd { file }` | Marks an upload complete once every chunk has arrived. |
| `FileGet { file, index }` | Downloads one sealed chunk, for group members. |
| `FileDone { file }` | Says this mailbox has saved the file. When every member except the sender has, the server deletes it. |

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
| `Joins(Vec<JoinRequest>)` | Pending join requests: token, KeyPackages, HMAC and the time each was lodged. |
| `Welcomes(Vec<WelcomeIn>)` | Welcomes, each with its mailbox and sealed voucher. |
| `File(FileId)` | The ID for a new upload. |
| `Chunk(Vec<u8>)` | One sealed file chunk. |
| `Error(String)` | Something failed on the server, or the request made no sense. |

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

Numbers in parentheses are byte lengths.

## Other formats

- **Keys derived from the invite secret:** HKDF-SHA256 with no salt and the 32-byte secret as input key material, expanded to 32 bytes, with info `socketchat/v1/invite-mac` (the MAC key), `socketchat/v1/voucher-seal` (the seal key) or `socketchat/v1/invite-proof` (the proof key). The inviter sends members the MAC and seal keys; the proof key never leaves the inviter and the joiner.
- **Invite MAC:** HMAC-SHA256 under the MAC key, over the KeyPackage bytes the joiner lodges.
- **Invite proof:** HMAC-SHA256 under the proof key, over group ID (16) ‖ the joiner's group key (32). The joiner posts it in the group as `AppMsg::InviteProof`; the inviter's app checks it before marking the joiner verified.
- **KeyPackage bundle:** a postcard-encoded list of TLS-encoded KeyPackages, one per allowed suite (0x004F, then 0x0001). The member who adds the joiner picks the one matching the group's suite.
- **Admin list:** GroupContext extension type `0xff00`, a run of entries, each a 2-byte big-endian length of 32 followed by a 32-byte Ed25519 key.
- **Application messages:** inside MLS PrivateMessages, the postcard-encoded `AppMsg` enum from `crates/socketchat-core/src/appmsg.rs`.
- **Voucher on the wire:** sealed for the joiner, as described under "Sealed voucher".
- **Safety number:** built the way Signal's numeric fingerprint (version 1) builds its digits. For each of the two identity keys, start from a 2-byte zero, the key, and the key again; then 5,200 times, replace that value with SHA-512 of the value followed by the key. Read the first 30 bytes as six 5-byte big-endian numbers, each modulo 100,000 and written as 5 digits. The two 30-digit halves are sorted and joined into 60 digits, so both people see the same number.
