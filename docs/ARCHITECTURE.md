# meshlink — Architecture

`meshlink` is a mini zero-trust mesh VPN built in Go, mirroring the product
stack described in the fromquantum job ad: an encrypted transport layer, NAT
traversal, transport fallback, and a modular client. It runs entirely on
localhost during development — NAT boxes are simulated so hole punching and
relay fallback can be demonstrated without root or real networking hardware.

## Components

```
                    ┌──────────────────────────┐
                    │ coordinator (TCP)        │  control plane:
                    │   peer registry          │  register + broadcast peer
                    │   (UDP) STUN endpoint    │  lists; NAT endpoint discovery
                    └──────────┬───────────────┘
                       TCP/JSON│
            ┌──────────────────┴──────────────────┐
            │                                     │
   ┌────── natbox1 (NAT sim) ──┐        ┌── natbox2 (NAT sim) ─┐
   │ public 127.0.0.1:19301    │        │ public 127.0.0.1:19302│
   │ door   127.0.0.1:19401    │        │ door   127.0.0.1:19402│
   └───────┬───────────────────┘        └───────┬───────────────┘
           │ dataplane (Noise/UDP)              │
        agent a                              agent b
    (127.0.0.1:19501)                    (127.0.0.1:19502)
            └─────────────── relay (UDP 127.0.0.1:19205) ───────┘
```

## Data plane

- Every UDP datagram is one *frame*: `[1B type][2B length][payload]`
  (see `internal/record`).
- Encryption: Noise Protocol Framework, **XX pattern**,
  `DH25519 + ChaCha20-Poly1305 + SHA256`, prologue `meshlink-v1`
  (see `internal/noisework`).
- Identity: each agent holds a persistent X25519 keypair. The coordinator
  distributes public keys; after the XX handshake both sides **verify** the
  peer's static key against the coordinator-registered key. The relay never
  sees plaintext — encryption is end-to-end.
- Roles: the lexicographically smaller agent ID is the handshake initiator,
  so both sides agree without extra signalling (`internal/disco`).

## Path selection

1. **Direct (P2P):** both sides emit probes (`type=4`) toward each other's
   advertised endpoint to open NAT mappings, then run the Noise handshake.
2. **Relay fallback:** if the direct handshake cannot complete within
   `disco.DirectAttempt`, traffic switches to the relay: frames are wrapped
   `[magic 0x52][src][dst][frame]`; the relay forwards ciphertext by peer ID
   (`internal/relay`).
3. **Roaming back:** while established on relay, the agent keeps re-probing
   direct (`disco.ReestablishInterval`) and re-handshakes over P2P when
   possible.

## NAT simulation (`internal/nat`, `cmd/natbox`)

A natbox has a *public* socket (the outside world's view) and an *inside
door*. Agents behind it egress through the door (`[dst][payload]` wrapper).
Behaviors:

- `fullcone`    — one mapping per inside host; inbound from any source OK.
- `restricted`  — inbound only from IPs previously contacted.
- `symmetric`   — a **fresh public port per destination**; inbound only on the
  exact mapping the peer used to reach us. This is what makes classic
  simultaneous-open hole punching fail and demonstrates the relay.

## Control plane (`internal/protocol`, `internal/coordinator`)

Agents dial `coordinator` (TCP), send `register {id, pubkey, endpoints}`,
and receive `peer_list` broadcasts containing every registered peer. The
first endpoint is the STUN-learned public address; the second (optional) is
the relay. Re-registration updates endpoint mappings. The coordinator also
answers STUN binding requests on a UDP port.

## Ping / liveness

An established session carries JSON messages over Noise:
`{"cmd":"ping","s":seq,"ts":nanos}` → `{"cmd":"pong","s":seq,"ts":nanos}`.
The pinger reports RTT, loss and the active path (`direct|relay`).

## Known limitations (MVP)

- The control plane authenticates via Noise XX and pins the coordinator's
  static key, but it has no TLS certificate story; operator trust is out of
  band (key distribution).
- Sessions roam relay→direct but not direct→relay mid-session.
- Overlay addresses are statically assigned (`-tun-peer`); no dynamic address
  allocation yet.
- TUN support exists (`internal/tun`, `internal/agent/tunbridge.go`) but is
  root-required and not exercised by `make demo`; real-internet NAT
  verification (beyond the simulator) is an open Faz 4 item.

## Directory overview

```
cmd/{coordinator,relay,natbox,agent}   thin binaries
internal/record      frame codec
internal/noisework   Noise XX handshake + session (rekey, replay window)
internal/control     authenticated control connection + framing
internal/stun        RFC 8489 binding client/server
internal/nat         NAT simulator
internal/relay       UDP relay server (name pinning, rate limits)
internal/protocol    control-plane JSON
internal/coordinator control-plane server (Noise-auth, key pinning)
internal/disco       punching policy (timing, roles, path enum)
internal/peer        per-peer session state machine
internal/agent       client glue (keys, STUN, register, receive loop)
internal/tun         TUN device + IPv4 route table (Faz 4)
```