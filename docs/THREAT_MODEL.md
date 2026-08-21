# meshlink — Threat Model (v0.x → v1.0)

Date: 2026-08-19
This document is the cornerstone of the transition from MVP to production
realism. The current code is a **demo/MVP**; this model explicitly lists which
controls are missing.

---

## 1. Scope and Assets

The system consists of four components: **agent** (client), **coordinator**
(control plane: registration + STUN), **relay** (data plane transport) and the
optional **TUN bridge** (real IP data transport, requires root). The demo also
includes **natbox**, which mimics real NAT devices — it is not present in
production.

Assets:

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Agent X25519 static key | High | High | — |
| Session data (end-to-end plaintext) | High | High | Medium |
| Coordinator registry (name→key, endpoint) | Medium | High | High |
| Relay message flow | Medium (direction/identity metadata) | High | High |
| STUN responses (XOR-MAPPED-ADDRESS) | Low | High | Low |

## 2. Trust Boundaries

```
 [güvenilir]                   [yarı güvenilir / ağa düşman]          [güvenilir]
 agent A ──coord/STUN──▶ coordinator ◀──coord/STUN── agent B
     │                                                            │
     └─────Noise (E2E)──▶ relay (ciphertext only) ◀──Noise──────┘
```

- **Agent core** is fully trusted; **coordinator and relay** are "network-exposed,
  transport is sacred" (they cannot see the data because Noise is E2E).
- The **network path** (internet/NATs) is considered entirely hostile.
- **natbox** is a demo artifact; no production trust boundary is drawn around it.
- The control channel is now Noise-authenticated; the coordinator's authenticity
  is verified at the client via a pinned key (Phase 3).

## 3. Threats (STRIDE)

### 3.1 T1 — Unprivileged network attacker (data path)
- **Replay:** re-transmission of recorded DATA ciphertext. The WireGuard-style
  sliding window (2048) at the receiver rejects old nonces and duplicates
  → **mitigated** (Phase 2).
- **Rekey-state DoS:** a spoofed datagram with a wild nonce used to advance
  the one-way epoch keys before authentication, locking the receive direction
  until the next re-handshake. `DecryptAt` now derives the candidate epoch key
  on a throwaway cipher state and commits the rekey only after the AEAD check
  passes → **mitigated**.
- **Half-open handshake DoS:** a lost HS3 used to leave the responder
  half-open for up to the 24 h session age. The initiator now re-emits HS3
  until the responder answers with authenticated data, duplicate HS1s
  retransmit the cached HS2 instead of resetting the responder, and stale
  half-open state is cleared after a 10 s timeout → **mitigated**.
- **UDP DoS/reflection:** amplification by claiming a name to the relay; packets
  with spoofed source addresses. Name→address pinning + per-source pps/byte
  limits + per-name quota are active → **mitigated** (Phase 3).
- **Handshake flood:** CPU exhaustion via HS1 (each request creates new handshake
  state). The responder has a concurrent handshake budget + handshake timeout →
  **mitigated** (Phase 3).
- **STUN spoofing:** injecting a wrong endpoint — txid verification exists and
  key verification recovers the session → **mitigated**.

### 3.2 T2 — Rogue agent (malicious client that can register)
- **Name hijacking:** registering the name "a" before the legitimate "a" and
  blocking the ping. Key pinning + rejection of identity/key mismatch at the
  coordinator → **mitigated** (Phase 3).
- **Fake relay claim:** sending packets to the relay with someone else's srcID.
  Name→address pinning prevents this → **mitigated** (Phase 3, old M1 closes).
- **Misdirection with bogus endpoint:** spamming the coordinator with a bad
  endpoint; other agents verify the key during the handshake but probe the wrong
  address → **partially mitigated** (the control channel is Noise-authenticated,
  registration changes are no longer possible on the unencrypted network).

### 3.3 T3 — Coordinator / relay operator attacker
- The control channel was unencrypted/TLS-less → closed with a Noise-authenticated
  control channel + coordinator pubkey pinning → **mitigated** (Phase 3).
- The relay keeps the name→address table; an operator can swap a subscriber or
  observe the flow (metadata: who talks to whom at what time). E2E Noise does not
  fix this; metadata privacy is a separate requirement → **documented acceptance**.

### 3.4 T4 — Local operation
- Key file: `0600` perms are **good**; however plaintext privkey → disk
  encryption/KMS is a production requirement.
- Key + plaintext in memory dump / core dump → mlock/guard should be considered
  in production (post-v1).

## 4. Current Mitigations (implemented)

- Noise XX + DH25519 + ChaCha20-Poly1305 + SHA256; two-way static key
  verification (with coordinator-distributed pubkey, optional).
- Key pinning: the coordinator rejects a registration with the same name + a
  different key; relay name→address pinning prevents delivery disruption.
- Noise-authenticated control channel: registration/control traffic is encrypted
  and cannot be swapped.
- Data plane: sliding window (2048) replay rejection, periodic rekey, nonce
  exhaustion guard + `maxEpochJump` DoS cap, session age limit.
- Relay rate-limit/quota (per-source pps/byte, per-name quota); handshake budget
  + timeout (relay and control).
- STUN txid verification.
- Size limits in communication (control `maxMsgLen`, relay/nat envelope), frame
  validity checking.
- Datagram size contract (65507-3-8-16 = 65480 plaintext ceiling, the relay path
  is additionally tightened).
- Coordinator broadcast write deadline; bounded control reads.
- `-race`-clean unit tests; parser fuzzers; end-to-end demo; CI workflow.

## 5. Known Gaps (production blockers)

| # | Gap | Impact | Status |
|---|---|---|---|
| G1 | — (replay window + rekey) | — | ✅ Phase 2 |
| G2 | — (relay name pinning) | — | ✅ Phase 3 |
| G3 | — (control Noise-auth) | — | ✅ Phase 3 |
| G4 | — (relay rate-limit/quota) | — | ✅ Phase 3 |
| G5 | — (handshake budget/timeout) | — | ✅ Phase 3 |
| G6 | TUN lifecycle + real-network verification | Real-network NAT testing for VPN use is open | 🔶 Phase 4 partial |
| G7 | — (fuzz, CI, health logs) | — | ✅ Phase 1 |
| G8 | — (rekey, replay window) | — | ✅ Phase 2 |
| G9 | Environment-variable config; metrics/Prometheus | Operational predictability | 🔶 v1.1+ |

## 6. Accepted Risks (MVP)

- **Control-plane metadata trust:** the coordinator/relay operator seeing
  "who talks to whom when" information is accepted despite E2E encryption.
- **Parallelism / DTLS:** the UDP data plane does not use DTLS; energy/metadata
  analysis is theoretically possible (WireGuard model acceptance).
- The **natbox simulation** does not cover the diversity of real internet NATs
  (Cone/Cone, carrier-grade, etc.); real-network testing is a Phase 4 leftover.

## 7. Closure Controls (roadmap mapping)

Phase 1 → G7, G9; Phase 2 → G1, G8; Phase 3 → G2–G5; Phase 4 → G6.
At the end of each phase, tests + documentation are updated; this table is
updated as well.
