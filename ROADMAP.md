# Roadmap

This is the work planned after Socketchat v4.0, in priority order. Each item says what it is, why v4.0 does not have it, and how you can help. If you want to pick one up, open an issue first so we can agree on the approach; [CONTRIBUTING.md](CONTRIBUTING.md) explains how reviews work.

## 1. Hide group membership from the server

**What it is.** Today the server knows which mailboxes (where it holds each member's encrypted messages) belong to each group, because it delivers messages to them and checks every group change against the group's admin list. Full hiding means a member could prove they belong to a group without the server learning which member they are. The cryptography for that is called anonymous credentials. Signal built it for its own service.

**Why it is not in v4.0.** Anonymous credentials are not part of the MLS standard (Messaging Layer Security, RFC 9420). Signal's implementation is licensed under the AGPL and published for Signal's own use. Writing our own would break the project's rule against home-made cryptography. We will adopt it when a reviewed specification with a permissively licensed implementation exists, for example if IETF work on private MLS delivery becomes a standard.

**What v4.0 already does.** Each person makes a fresh group key and mailbox for every group they join, so the server's records show separate groups of random keys. Names, group names and identity keys travel only inside encrypted messages. When someone joins through an invite, the inviter's signed voucher travels next to the Welcome, the MLS message that lets the joiner in, sealed under a key derived from the invite secret, so the server never sees the inviter's identity key (see [SECURITY.md](SECURITY.md)).

**How to help.** Follow the IETF MLS working group and report specifications or implementations that fit. If you know anonymous credential systems, review designs that could sit beside MLS.

## 2. Post-quantum protection for the connection

**What it is.** The connection between an app and the server uses TLS 1.3 with classical X25519 key exchange. Message and file contents inside it already have post-quantum protection through MLS; the connection itself does not. rustls, the TLS library Socketchat uses, offers the hybrid X25519MLKEM768 key exchange through its aws-lc-rs crypto provider.

**Why it is not in v4.0.** Socketchat uses rustls with the ring provider, which has no ML-KEM. Switching to aws-lc-rs adds a native library that must build and pass tests on every platform the project supports: macOS, Windows, and Linux on Intel, AMD and 64-bit ARM. The move should also wait for rustls 0.23.46 or later, which fixes a downgrade problem in hybrid key exchange (RUSTSEC-2026-0349).

**How to help.** Try the aws-lc-rs provider on Linux x86_64, macOS arm64 and Linux aarch64, and report build times and memory use on a Raspberry Pi.

## 3. Move to the final post-quantum MLS suite

**What it is.** Socketchat's default suite, 0x004F, comes from an IETF draft that is not final. When the IETF publishes the final post-quantum suite, new groups should use it.

**Why it is not in v4.0.** The final suite does not exist yet. The suite choice already sits in one file, `crates/socketchat-core/src/suite.rs`. Existing groups are harder: MLS fixes a group's suite for its whole life. RFC 9420 has a ReInit proposal for moving a group to a new suite, and the v4.0 server refuses it today.

**How to help.** Track the draft and OpenMLS's support for it. Design how a group moves to a new suite, whether through ReInit or by starting a new group with the same members.

## 4. More than one device per person

**What it is.** Using one identity on a laptop and a phone at once. MLS supports this: each device would be its own member of the group, tied to the person's identity key.

**Why it is not in v4.0.** v4.0 starts with one device per person to keep the first release small. Linking devices safely needs its own design: how a new device proves it belongs to you, how your contacts see it, and what happens when you lose one.

**How to help.** Propose a linking design in an issue. It must keep identity keys off the server.

## 5. A graphical app

**What it is.** A desktop or phone app with windows and touch, beside the terminal app.

**Why it is not in v4.0.** v4.0 is a terminal app. The client engine, `socketchat-core`, has no screen code, so a graphical app can sit on top of it without touching the cryptography.

**How to help.** Build a prototype on `socketchat-core`. [docs/architecture.md](docs/architecture.md) describes its events and calls.

## 6. Servers that talk to each other (exploratory)

**What it is.** Federation: people on different servers sharing one group.

**Why it is not in v4.0.** Everyone in a group uses the same server, and the server's checks on group changes assume it holds the whole group log. Federation would change the trust model and add metadata that crosses servers. We have no design yet and no promise that it fits Socketchat.

**How to help.** Write up how federation could work with MLS, and what each server would learn, before any code.
