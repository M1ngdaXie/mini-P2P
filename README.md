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
| `0x00` | 32-byte X25519 public key | Handshake (also used for broadcast discovery) |
| `0x01` | 12-byte nonce + AES-GCM ciphertext+tag | Encrypted message |

## Peer discovery (UDP broadcast)

Peers discover each other automatically on the same LAN — no server, no pre-known addresses.

```
Peer A (10.x.x.x)                    Peer B (10.x.x.x)
     │                                    │
     │  1. Broadcast own pubkey           │
     │     to 255.255.255.255:9999        │
     │ ──────────────────────────────────→│
     │  2. Reply with own pubkey          │
     │     (sent directly to A's addr)    │
     │ ←──────────────────────────────────│
     │  3. ECDH → HKDF → shared key       │
     │                                    │
     │  4. Encrypted chat via 0x01        │
```

Implementation notes:

- **One socket does both** — the chat socket (`-port`) sends the broadcast, so the source port in the packet *is* the sender's chat port. No separate send socket needed.
- **A second socket listens on UDP :9999** for incoming broadcasts. It only receives; it never sends.
- **Self-broadcast filtering** — the sender's own broadcast loops back to its own :9999 listener. Filtered by comparing the source port to our chat port.
- **Port-9999 contention** — only one process per machine can bind :9999 (UDP port exclusivity is per network namespace). On a second instance the listener degrades to *send-only*: it still broadcasts (harmless) but cannot receive. The `-peer` direct path keeps working.
- **Address normalization** — a broadcast packet's source IP is the sender's LAN IP (e.g. `10.3.150.79`), while `-peer` direct connections use `127.0.0.1`. Both refer to the same peer, so the handshake normalizes the sender's own machine IPs to `127.0.0.1` — one key per peer regardless of discovery path. Foreign IPs (real multi-machine peers) are left untouched.

## How the handshake works

UDP is connectionless — there is no built-in handshake like TCP. This project implements a **symmetric handshake** over UDP:

1. On startup, each peer generates an X25519 keypair and sends its public key immediately
2. A 5-second ticker keeps re-sending the public key until the peer's key is received (handles the case where the other side starts later)
3. On receiving a public key: derive the shared secret via ECDH, **immediately reply with your own public key** (solves the asymmetric deadlock where one side stops broadcasting before the other has received its key)
4. Duplicate handshake packets are ignored via the peer map

The shared secret from X25519 (32 bytes) is passed through **HKDF-SHA256** to derive the AES-256 key:

```go
hkdf.Key(sha256.New, rawSecret, []byte("mini-p2p-v1"), "Mingda is damowang", 32)
```

The salt (`"mini-p2p-v1"`) and info are **fixed protocol constants** — they must match on both sides, otherwise the two peers derive different keys. They are public values; their purpose is domain separation, not secrecy (the ECDH secret is already high-entropy).

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

# --- Mode 1: direct (-peer) ---
# Terminal 1
./p2p -port 9001 -peer 127.0.0.1:9002
# Terminal 2
./p2p -port 9002 -peer 127.0.0.1:9001

# --- Mode 2: broadcast discovery (no -peer) ---
# All peers on the same LAN discover each other via :9999
./p2p -port 9001
./p2p -port 9002
```

Type a message and press Enter to broadcast. Use `@addr msg` to target one peer. `/list` shows known peers.

### Testing discovery across machines (verified with Docker)

UDP broadcast on one machine collides on :9999 (only one listener per network namespace), so real discovery must be tested across machines or containers:

```bash
# cross-compile for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o p2p-linux .

docker run -d --name p2p-a --network bridge alpine sleep 300
docker run -d --name p2p-b --network bridge alpine sleep 300
docker cp p2p-linux p2p-a:/p2p
docker cp p2p-linux p2p-b:/p2p
docker exec -d p2p-a /p2p -port 9001
docker exec -d p2p-b /p2p -port 9002
# each container has its own network namespace → both bind :9999 fine,
# broadcast crosses the bridge → handshake completes
```

## Verify encryption on the wire

```bash
sudo tcpdump -i lo0 -n -X udp port 9001
```

Handshake packets appear as 33-byte `[0x00]` + public key. Chat packets are `[0x01]` + nonce + ciphertext — you will **not** find your plaintext in the hex dump.

## What's intentionally missing (learning project)

- **No identity verification** — this is a Noise `NN` pattern: any peer that sends a public key gets a shared secret. No long-term keys, no authentication against MITM.
- **No NAT traversal** — both peers must be directly reachable (LAN or loopback). Broadcast discovery only works within one broadcast domain.
- **No key rotation / peer state** — a peer that restarts with a new keypair is still treated as the old peer; the old shared secret stays in the map and decryption breaks. (Known issue — a proper fix needs per-peer state: track the peer's public key alongside the secret, re-handshake when it changes, and notify peers on shutdown.)
- **No reliability layer** — UDP packets can be lost. A chat message that gets dropped is simply gone.
- **No nonce reuse protection** — nonces are 12 random bytes per message, which is statistically safe for chat volume, but not audited for adversarial use.
- **`-peer` defaults to `127.0.0.1:9002`** — when running in a container/isolated network without another peer on that port, the ticker talks to itself (loopback self-handshake). Always pass an explicit `-peer` or rely on discovery.

## File layout

```
peer.go    — handshake, peerStore (channel-based), stdin UI, UDP loop,
             broadcast discovery (BroadcastAndListen), address normalization
crypto.go  — HKDF key derivation, AES-256-GCM encrypt/decrypt
```
