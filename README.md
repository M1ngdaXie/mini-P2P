# mini-P2P

A minimal peer-to-peer encrypted chat over UDP, written from scratch in Go with **zero third-party dependencies**.

Every protocol component is hand-implemented — no sockets library, no crypto framework, just the Go standard library.

## What it does

Multiple peers on a LAN exchange AES-256-GCM encrypted messages directly over UDP, with ECDH (X25519) key exchange for the handshake. No central server, no message broker — every peer is both client and server.

Handshakes converge on their own (no user input needed): each peer confirms it received the other's public key, patrol re-sends confirmations until both sides acknowledge, then goes quiet. Messages carry sequence numbers and are acknowledged — the plumbing for reliable delivery over lossy UDP.

## Wire protocol

Every packet starts with a 1-byte type. Handshake packets share a fixed layout:

```
[type 1B][sessionId 16B][public key 32B]   ← 49 bytes, handshake only
[type 1B][seq 8B][nonce 12B][ciphertext+tag]  ← data
[type 1B][seq 8B]                             ← ACK
```

| Type byte | Payload | Purpose |
|---|---|---|
| `0x00` | sessionId + X25519 public key | Handshake: "here's my key, I don't have yours yet" (also used for broadcast discovery) |
| `0x03` | sessionId + X25519 public key | Handshake confirm: "here's my key, I already have yours" (identical payload, 1-bit difference in the type byte) |
| `0x01` | seq (big-endian) + nonce + AES-GCM ciphertext+tag | Encrypted message |
| `0x02` | seq (big-endian) | ACK for a received message |

## How the handshake converges (self-closing, no user input)

UDP is connectionless — there is no built-in handshake like TCP. This project implements a **two-bit mutual confirmation** over UDP:

1. On startup each peer generates an X25519 keypair, a random 16-byte `sessionId`, and broadcasts a `0x00` handshake packet ("I don't have your key yet").
2. On receiving a public key: derive the shared secret via ECDH → HKDF, and store the peer (`state = handshaking`).
3. A **patrol** goroutine ticks every second and re-sends a `0x03` confirm to every peer whose handshake isn't fully seated — "I already have your key."
4. Two booleans per peer drive convergence:
   - `PeerHasMyKey` — set when we receive their `0x03` (they have our key)
   - `SentConfirm` — set when we sent them a `0x03` (we have theirs)
   - Handshake is **seated** when both are true → patrol stops re-sending that peer.
5. Patrol retries are bounded (`maxPatrol = 10`). The two-generals problem makes "the other side definitely got my final confirm" unprovable, so after the retry budget it stops — any real hole gets exposed by the data-layer ACK instead.

Because confirmations ride the patrol timer (clock-driven) instead of replying to every packet (event-driven), the "mirror echo" storm of naive reply-on-receive handshakes never happens — the two sides each run their own clock, so they never amplify each other.

The shared secret from X25519 (32 bytes) is passed through **HKDF-SHA256** to derive the AES-256 key:

```go
hkdf.Key(sha256.New, rawSecret, []byte("mini-p2p-v1"), "Mingda is damowang", 32)
```

The salt (`"mini-p2p-v1"`) and info are **fixed protocol constants** — they must match on both sides, otherwise the two peers derive different keys. They are public values; their purpose is domain separation, not secrecy (the ECDH secret is already high-entropy).

## Sequence numbers & ACK

- Every sent message gets a monotonically increasing 8-byte sequence number (per peer), allocated inside the store so allocation is atomic.
- The receiver replies with a `0x02` ACK carrying the same seq.
- Receiving a decryptable message or an ACK upgrades the peer to `established`.
- This is the plumbing for a reliability layer — **retransmission is not yet implemented** (a dropped message is still simply gone; see "What's intentionally missing").

## Loss simulation (for testing reliability code)

```bash
./p2p -port 9001 -loss 0.5     # drop ~50% of outgoing data packets
```

Only `0x01` data packets go through the lossy path — handshake/ACK packets are never dropped, so handshake convergence stays deterministic while you develop retransmission.

## Peer discovery (UDP broadcast)

Peers discover each other automatically on the same LAN — no server, no pre-known addresses.

```
Peer A (10.x.x.x)                    Peer B (10.x.x.x)
     │                                    │
     │  1. Broadcast own pubkey (0x00)    │
     │     to 255.255.255.255:9999        │
     │ ──────────────────────────────────→│
     │  2. ECDH → HKDF → shared key       │
     │  3. Patrol confirms (0x03) both    │
     │     directions until seated        │
     │                                    │
     │  4. Encrypted chat via 0x01/0x02   │
```

Implementation notes:

- **One socket does both** — the chat socket (`-port`) sends the broadcast, so the source port in the packet *is* the sender's chat port. No separate send socket needed.
- **A second socket listens on UDP :9999** for incoming broadcasts. It only receives; it never sends.
- **Self-broadcast filtering** — the sender's own broadcast loops back to its own :9999 listener. Filtered by comparing the source port to our chat port.
- **Port-9999 contention** — only one process per machine can bind :9999 (UDP port exclusivity is per network namespace). On a second instance the listener degrades to *send-only*: it still broadcasts (harmless) but cannot receive. The `-peer` direct path keeps working.
- **Address normalization** — a broadcast packet's source IP is the sender's LAN IP (e.g. `10.3.150.79`), while `-peer` direct connections use `127.0.0.1`. Both refer to the same peer, so the handshake normalizes the sender's own machine IPs to `127.0.0.1` — one key per peer regardless of discovery path. Foreign IPs (real multi-machine peers) are left untouched.

## Commands

```
@127.0.0.1:9002 hello     → send only to that peer
hello everyone             → broadcast to all known peers
/list                      → list known peers + handshake state
```

## Concurrency model

A single goroutine **owns** the peer map (`map[string]Peer`). Other goroutines never touch the map directly — they send requests over channels:

```
peerStore (single goroutine owns map[string]Peer)
    ├── setChan       ← Set(...)           (create peer on first handshake)
    ├── getChan       ← Get(addr)          (read peer for encrypt/decrypt)
    ├── listChan      ← List()             (snapshot peers for broadcast)
    ├── changeChan    ← ChangeState / SetPeerHasMyKey / MarkPatrolSent
    ├── incrementChan ← increment(addr)    (atomic seq allocation)
    └── PatrolChan    ← PatrolPeers()      (which peers still need confirming)
```

Because state has exactly one owner, **no mutexes are needed** — this is Go's "share memory by communicating" pattern instead of "communicating by sharing memory."

Two pitfalls the channel design specifically avoids:

- **Read-modify-write must be one channel op** — seq allocation returns the new value on a per-call reply channel, so two goroutines can't get the same seq.
- **Cross-channel ordering is not guaranteed** — Go's `select` picks uniformly at random among ready cases, so a `changeChan` request can be processed before a `setChan` request sent earlier. One-shot writes (like the "peer has my key" bit) are folded into `Set` so they can't be lost to reordering.

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

Type a message and press Enter to broadcast. Use `@addr msg` to target one peer. `/list` shows known peers and whether each handshake is seated (`established` / `handshaking`).

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

Handshake packets are 49 bytes: `[0x00|0x03]` + sessionId + public key. Chat packets are `[0x01]` + seq + nonce + ciphertext — you will **not** find your plaintext in the hex dump. ACKs are 9 bytes: `[0x02]` + seq.

## What's intentionally missing (learning project)

- **No identity verification** — this is a Noise `NN` pattern: any peer that sends a public key gets a shared secret. No long-term keys, no authentication against MITM.
- **No NAT traversal** — both peers must be directly reachable (LAN or loopback). Broadcast discovery only works within one broadcast domain.
- **No message retransmission yet** — ACKs exist and sequence numbers are in place, but a dropped `0x01` is still simply gone. The loss simulation (`-loss`) is there so this can be built and verified.
- **No key rotation** — `sessionId` is generated per process and carried in every handshake packet, but the comparison logic is still a TODO: a peer that restarts with a new keypair is still treated as the old peer, the old shared secret stays in the map and decryption breaks. (Planned: compare sessionIds, drop the stale entry, re-handshake.)
- **No nonce reuse protection** — nonces are 12 random bytes per message, which is statistically safe for chat volume, but not audited for adversarial use.

## File layout

```
peer.go    — handshake + patrol, peerStore (channel-based), seq/ACK,
             stdin UI, UDP loop, broadcast discovery, address normalization
crypto.go  — HKDF key derivation, AES-256-GCM encrypt/decrypt
```
