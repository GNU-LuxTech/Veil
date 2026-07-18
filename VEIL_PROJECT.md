# VEIL

### Ephemeral. Encrypted. Untraced

> A session-based, P2P terminal messaging application built on Tor onion services.
> No servers. No logs. No persistence. If you're not there to receive it, it doesn't exist.

---

## Concept

Veil is a command-line messaging application for people who treat privacy as a non-negotiable.
Inspired by the aesthetics of SSH and Termux, it operates entirely over the Tor network using
onion services — making it NAT-transparent, IP-anonymous, and structurally incapable of
leaking your identity or message history.

Unlike conventional messaging apps, Veil is **session-based and synchronous only**.
Both users must be online simultaneously to communicate. There is no store-and-forward,
no push notifications, no cloud backup. Messages live in RAM for the duration of the
session and are gone the moment the connection closes.

This is not a limitation — it is a deliberate architectural philosophy.

---

## Core Principles

| Principle | What It Means in Practice |
|---|---|
| **Zero persistence** | Messages exist only in RAM. No logs, no database, no disk writes. |
| **Zero identity** | No phone number, no email, no username registry. Your keypair is your identity. |
| **Zero servers** | No central infrastructure. Tor handles routing. |
| **Zero trust** | You must explicitly accept every incoming connection. Nothing is automatic. |
| **Synchronous only** | Both parties must be online. No offline delivery, by design. |

---

## How It Works

### Identity

Each user generates an **Ed25519 keypair** on first launch. No registration required.
Your identity is your **Tor v3 onion address** — a 56-character string derived directly
from your public key. It never changes. It cannot be faked.

```
Your address:  veilzf8n1abc4xyz...onion
```

Share this with someone the same way you'd share an SSH host address — out-of-band,
over Signal, written on paper, spoken in person. There is no in-app directory.

### Discovery

There is no discovery server. Veil does not broadcast your presence.
You are reachable only when:

1. The app is running.
2. Someone already knows your onion address.

### Connection Flow

```
[VEIL] incoming connection from veil7x3k9mq2p...onion
[VEIL] accept or reject? /accept | /reject

> /accept

[VEIL] performing key handshake...
[VEIL] session established. this exchange is ephemeral.
──────────────────────────────────────────────
[veil7x] yo
[you]    hey. what do you need?
[veil7x] /send ./payload.txt
[VEIL]   receiving file... [████████████] done.
[veil7x] /disconnect
[VEIL]   session terminated. no record kept.
──────────────────────────────────────────────
```

### Encryption

All traffic is end-to-end encrypted over Tor. On session establishment,
a **session key exchange** (X25519 ECDH) is performed to derive a symmetric session key.
This key exists only in memory. Traffic is encrypted with **ChaCha20-Poly1305**.

Because sessions are synchronous and ephemeral, there is no need for the Double Ratchet
protocol's asynchronous complexity. Tor's layered encryption provides transport-level
anonymity on top.

---

## CLI Interface (Design)

Veil has no graphical interface. The terminal IS the product.

```
veil --init                        # generate keypair, display your onion address
veil --address                     # print your onion address
veil --connect veil7x3k...onion    # initiate connection request to a peer
veil --listen                      # listen for incoming connections
veil --listen --auto-accept @alice # whitelist a known address
```

### In-session commands

```
/send <filepath>      # send a file over the active session
/clip                 # send clipboard contents
/clear                # clear the terminal screen (local only)
/whoami               # display your own onion address
/whois                # display peer's onion address
/disconnect           # terminate the session cleanly
```

---

## What Veil Is NOT

- **Not asynchronous** — if the other person is offline, the message doesn't exist.
- **Not a group chat** — sessions are strictly 1-to-1.
- **Not a phone number replacement** — onion addresses are your identity.
- **Not cloud-synced** — there is nothing to sync. There is no cloud.
- **Not recoverable** — lose your private key, lose your identity.

---

## Why Tor Onion Services?

| Problem | Standard P2P | Veil (Tor Onion) |
|---|---|---|
| NAT traversal | STUN/TURN servers required | Tor handles routing natively |
| IP anonymity | IP exposed to peer | Neither peer sees the other's IP |
| Address stability | IP changes constantly | Onion address is permanent |
| Discovery | DHT broadcasts your presence | No broadcasting. Invite-only. |
| Infrastructure | Relay servers cost money | Tor network is free and distributed |

---

## Tech Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Language** | Go | Native Tor support via `bine`, strong concurrency |
| **Tor integration** | `bine` (Go Tor controller) | Embeds Tor directly — no external Tor install required |
| **Onion services** | Tor v3 (Ed25519) | Self-authenticating, NAT-transparent addresses |
| **Key exchange** | X25519 ECDH | Fast, secure, standard |
| **Symmetric encryption** | ChaCha20-Poly1305 | Modern AEAD cipher, mobile-friendly |
| **TUI** | `bubbletea` (Go) | Termux-style terminal UI framework |
| **Key storage** | Local file (permissions 0600) | Private key never leaves the device |

---

## Threat Model

### Veil protects against

- Mass surveillance and metadata collection
- Corporate data harvesting
- Man-in-the-middle attacks (key is authenticated via onion address)
- IP address exposure to peers
- Message recovery after session ends
- Server seizure (there are no servers)

### Veil does NOT protect against

- A compromised device (keylogger, root access)
- Someone physically watching your screen
- Losing your private key
- Social engineering (Veil cannot verify *who* is behind an onion address)

---

## Licensing Philosophy

Veil will be **source-available**, not open-source in the permissive sense.

The source code will be publicly auditable — because a privacy app that cannot be audited
is just a black box with marketing copy. However, a restrictive license will prevent
commercial forks and re-branding. You can read the code. You cannot sell it.

This is the balance between **cryptographic transparency** (required for trust)
and **intellectual property protection** (required for sustainability).

---

## Roadmap

### Phase 1 — Core

- [x] Keypair generation on first launch
- [x] Embedded Tor daemon via `bine`
- [x] Onion service creation and display
- [x] Outbound connection to a peer's onion address
- [x] Inbound connection listener with accept/reject prompt
- [x] X25519 session key exchange
- [x] ChaCha20-Poly1305 encrypted message stream
- [x] Basic TUI (send/receive messages)

### Phase 2 — Master UI

- [ ] Interactive TUI Main Menu (Host vs Join)
- [ ] Graceful CLI flag bypass (hybrid CLI/TUI mode)
- [ ] Loading screens (Tor daemon startup, onion service creation)
- [ ] Address input form

### Phase 3 — Features

- [ ] `/send` file transfer over active session
- [ ] Contact alias system (local nickname → onion address mapping)
- [ ] `--auto-accept` whitelist for trusted addresses
- [ ] Session transcript opt-in (encrypted, local only)
- [ ] Multi-platform builds (Linux, macOS, Windows, Android via Termux)

### Phase 4 — Hardening

- [ ] Traffic padding (resist timing analysis)
- [ ] Canary mode (detect if binary has been tampered)
- [ ] External security audit
- [ ] Source-available public release

---

*"Privacy is not about having something to hide. It's about having something to protect."*
