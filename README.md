# mini-P2P

A minimal peer-to-peer encrypted chat over UDP, written from scratch in Go with **zero third-party dependencies**.

Every protocol component is hand-implemented — no sockets library, no crypto framework, just the Go standard library.

## What it does

Multiple peers on a LAN exchange AES-256-GCM encrypted messages directly over UDP, with ECDH (X25519) key exchange for the handshake. No central server, no message broker — every peer is both client and server.

```
Peer A (9001)                          Peer B (9002)
     │                                    │
     │  1. Broadcast public key           │
     │ ──────────────────────────────────→│
     │  2. Reply with own public key      │
     │ ←──────────────────────────────────│
     │  3. Derive shared secret via ECDH  │
     │     (same key on both sides)       │
     │                                    │
     │  4. AES-256-GCM encrypted chat     │
     │ ───── [0x01][nonce][cipher] ──────→│
     │ ←──── [0x01][nonce][cipher] ────── │
```

## Wire protocol

| Type byte | Payload | Purpose |
|---|---|---|
| `0x00` | 32-byte X25519 public key | Handshake |
| `0x01` | 12-byte nonce + AES-GCM ciphertext+tag | Encrypted message |

## How the handshake works

UDP is connectionless — there is no built-in handshake like TCP. This project implements a **symmetric handshake** over UDP:

1. On startup, each peer generates an X25519 keypair and sends its public key immediately
2. A 5-second ticker keeps re-sending the public key until the peer's key is received (handles the case where the other side starts later)
3. On receiving a public key: derive the shared secret via ECDH, **immediately reply with your own public key** (solves the asymmetric deadlock where one side stops broadcasting before the other has received its key)
4. Duplicate handshake packets are ignored via the peer map

The shared secret from X25519 (32 bytes) is used directly as the AES-256 key. No HKDF — this is a learning project, kept minimal on purpose.

## Commands

```
@127.0.0.1:9002 hello     → send only to that peer
hello everyone             → broadcast to all known peers
/list                      → list known peers
```

## Concurrency model

A single goroutine **owns** the peer map (`map[string][]byte`). Other goroutines never touch the map directly — they send requests over channels:

```
peerStore (single goroutine owns map[string][]byte)
    ├── setChan  ← Set(addr, secret)      (handshake writes)
    ├── getChan  ← Get(addr)              (read key for encrypt/decrypt)
    └── listChan ← List()                 (snapshot all peers for broadcast)
```

Because state has exactly one owner, **no mutexes are needed** — this is Go's "share memory by communicating" pattern instead of "communicate by sharing memory."

> Note: the map key is `addr.String()` — NOT `*net.UDPAddr`. Go's `net.UDPAddr` pointers are freshly allocated on every `ReadFromUDP`, so pointer keys never match. Use the value-semantic string form.

## Build & run

```bash
go build -o p2p .

# Terminal 1
./p2p -port 9001 -peer 127.0.0.1:9002

# Terminal 2
./p2p -port 9002 -peer 127.0.0.1:9001

# Terminal 3 (optional)
./p2p -port 9003 -peer 127.0.0.1:9001
```

Type a message and press Enter to broadcast. Use `@addr msg` to target one peer.

## Verify encryption on the wire

```bash
sudo tcpdump -i lo0 -n -X udp port 9001
```

Handshake packets appear as 33-byte `[0x00]` + public key. Chat packets are `[0x01]` + nonce + ciphertext — you will **not** find your plaintext in the hex dump.

## What's intentionally missing (learning project)

- **No identity verification** — this is a Noise `NN` pattern: any peer that sends a public key gets a shared secret. No long-term keys, no authentication against MITM.
- **No NAT traversal** — both peers must be directly reachable (LAN or loopback).
- **No peer discovery** — the peer address is given via `-peer` flag. (UDP broadcast discovery is a planned next step.)
- **No reliability layer** — UDP packets can be lost. A chat message that gets dropped is simply gone.
- **No nonce reuse protection** — nonces are 12 random bytes per message, which is statistically safe for chat volume, but not audited for adversarial use.

## File layout

```
peer.go   — handshake, peerStore (channel-based), stdin UI, UDP loop
crypto.go — AES-256-GCM encrypt/decrypt
```
