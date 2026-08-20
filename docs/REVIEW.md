# meshlink — Code Review Report

Date: 2026-08-19 · Scope: all source, tests, documentation, Makefile, demo script.
Method: 5-axis review + live verification via `gofmt` / `go vet` / `go test -race` / `make demo`.

---

## Status

| Item | Severity | Status |
|---|---|---|
| H1 — `Peer.Run` didn't watch `p.done` → goroutine leak | High | ✅ Fixed + regression test |
| H2 — Restricted NAT `contactIP` wasn't accumulating | High | ✅ Fixed + multi-target test |
| H3 — No coordinator ID→pubkey pinning | Medium/security | ✅ Fixed + test |
| M1 — Relay source name unverified | Medium/security | ✅ Fixed (Phase 3: name→address pinning) + test |
| M2 — `MaxPlaintextLen` exceeded the UDP limit | Medium | ✅ Fixed (65504; relay path further narrowed) |
| M3 — `scripts/demo.sh` wasn't executable | Medium | ✅ `chmod +x` |
| M4 — README stale natbox flags | Medium | ✅ Updated |
| M5 — `disco.MaxPunchAttempts` dead constant + SPEC "max 10" | Medium | ✅ Removed / documented |
| D1 — nat `wg.Add`/`Wait` concurrency | Low | ✅ `closed` guard |
| D2 — Ping summary path captured at run start | Low | ✅ Read at end of run |
| D3 — Control conn. has no write deadline | Low | ✅ `broadcastWriteDeadline` + write mutex |
| D4 — Ping send error was being swallowed | Low | ✅ Logged |
| D5 — JSON decoding error was silent | Low | ✅ Logged |
| D6 — `nat.decodeOutbound` test shim in production | Low | ✅ Moved to test file |
| D7 — `go.mod` `// indirect` comments | Low | ✅ `go mod tidy` |
| D8 — `receiveLoop` copy on every packet | Low | ✅ Only matching frame is copied |
| Bonus | — | ✅ Dead `peer.maxPlaintext()` removed |

## Verification

```
gofmt -l .                → boş
go vet ./...              → temiz
go build ./...            → ok
go test -count=1 -race ./... → tümü ok (control/coordinator/peer/nat/agent/tun yeni testler dahil)
make demo                 → phase 1 path=direct PASS · phase 2 path=relay PASS
```

---

## Previous Session Findings and Resolution Details

### H1 — `Peer.Run` doesn't watch `p.done` (goroutine leak)
`internal/peer/peer.go` — `Run` only waited on `ctx.Done()`; the `p.done` closed by
`Close()` wasn't watched in the loop and `p.recv` never closed (two goroutines
leaking the `applyPeers` prune forever). Fix:

- `p.done` now closes exactly once via `doneOnce sync.Once`.
- `Run`'s defer closes `recv` under lock (no concurrent-send race).
- `onData` does a guarded (`closed`/`recvClosed`), non-blocking send under lock.
- Regression test: `internal/peer/peer_test.go` (`TestRunExitsWhenClosed`,
  `TestRunExitsOnCancel`, `TestNoDataAfterClose`).

### H2 — Restricted NAT `contactIP` accumulation
`internal/nat/nat.go` — `e.contactIP[ipKey(dst.IP)] = true` was missing in the
mapping-refresh branch; the host was wrongly DROPping inbound traffic from IPs
it had later contacted. Regression test:
`internal/nat/nat_test.go` → `TestAddressRestrictedMultiTarget`.

### H3 — Coordinator key pinning
`internal/coordinator/coordinator.go` — A different `PubKey` with the same ID
raises a TypeError (registration isn't overwritten); an empty pubkey is
rejected; re-registration with the same key (endpoint refresh) remains free.
Regression test: `TestRegistrationKeyPinning`.

### M2 — Datagram size contract
- `internal/noisework/noisework.go`: `maxPlaintextLen = 65507 - 3 - 16 = 65504`
  (25535 − IP(20) − UDP(8) headers; frame hdr 3; AEAD tag 16).
- `internal/relay/relay.go`: `MaxHeaderLen` exported (worst case 133 B).
- `internal/peer/peer.go`: `Send` limit on the relay path is `MaxPlaintextLen - MaxHeaderLen`.
- Test/SPEC/noisework_test adapted; `record`'s 65535 encoding contract (a codec
  limit, not a single packet) preserved.

### D8 — `receiveLoop` allocation reduction
`internal/agent/agent.go` — A dedicated frame copy is made only for the matching
frame; non-matching (idle-dropped) datagrams are dropped without copying from
the shared buffer. Relay demux is still by peer ID.

---

## Phase 3/4 Session Additional Findings

### D9 — Concurrent control writers could corrupt frames (High)
`internal/control` — Two `handleClient` instances could write concurrently to
the same client `*control.Conn` (broadcast + personal reply); since `WriteMsg`
made two separate `Write` calls (length header + ciphertext), framing could
corrupt under `-race`. Fix: `Conn.wm sync.Mutex` + atomic single-buffer write.
`TestRegistrationAndBroadcast` was made deterministic in ordering.

### D10 — Control handshake had no timeout (Medium)
`internal/control` — Because `Initiate`/`Accept` weren't bounded by a
`handshakeTimeout`, hung peers could lock the acceptor. Fix:
`SetDeadline(handshakeTimeout)` at entry, cleared after success.
`TestWrongCoordinatorKey` now returns deterministically on the client side.

### Y1 — TUN bridge (Phase 4 / G6, partial)
`internal/tun` (utun/TUN opening, `Router` IPv4 forwarding, `BufferDevice`) +
`internal/agent/tunbridge.go` (device ⇄ peer session bridge, `-tun`/`-tun-ip`/
`-tun-peer`). Rootless unit tests: `internal/tun/tun_test.go`,
`internal/agent/tunbridge_test.go`. Real device opening is skipped in tests via
`t.Skip`; real network verification is a Phase 4 remnant (docs/TUN.md).

---

## Test Coverage Assessment

Present: record, noisework, stun, nat, relay, coordinator, protocol, peer,
control, tun, agent (tun bridge) — very good. Fuzzers: record, relay, nat,
stun, protocol. Open (v1.1): real-internet NAT verification; live e2e TUN
lifecycle (requires root).

## Closing

All applicable items in the report were resolved and verification was done in
three layers (unit test `-race`, `go vet`/`gofmt`, end-to-end `make demo`). M1
(relay-side authentication) was closed in Phase 3; real-network tests were
intentionally left as a Phase 4 remnant.

---

## Re-review — 2026-08-20 (post documentation pass)

Second full pass over the data/control planes. Adds a replay-window
commit-after-auth gate, serialized control-plane encryption, coordinator
registry lifecycle management, and daemon hygiene.

### Newly fixed findings

| Item | Severity | Fix |
|---|---|---|
| R1 — Replay window slid on unauthenticated datagrams | High/security | Nonce is committed to the window **only after** the frame's AEAD authenticates (`replayWindow.Check`/`Commit`; `Peer.onData`) |
| R2 — Concurrent `control.WriteMsg` encrypted outside the lock | High/security | Encryption moved inside `wm`, so the Noise AEAD nonce counter advances under one writer (ChaCha20-Poly1305 nonce reuse) |
| R3 — Coordinator registry lived forever after disconnect | High/availability | `dropClient` prunes the registration + broadcast slot on disconnect; names are reusable immediately |
| R4 — Coordinator had no read idle timeout | High/availability | `control.SetReadDeadline` + 90 s idle re-armed before every `ReadMsg` |
| R5 — Agent re-registration closed the *replacement* control conn | High | `ctrlReaderLoop` closes its local `ctrl`, never the shared `a.ctrl` field |
| R6 — Corrupt keyfile silently rotated the node identity | High/security | `LoadOrCreateKeyfile` now errors on an unreadable existing keyfile and never overwrites it |
| R7 — Roaming probe abandonment over one lost HS1 | Medium/availability | Relay→direct roaming gets a full `DirectAttempt` window, then reverts to relay (`abandonRoaming`) |
| R8 — Keepalive error killed the peer goroutine | Medium/availability | Failed keepalives now `continue` the Run loop instead of returning |
| R9 — Noise session keys had no age limit | Medium/security | `sessionMaxAge` (24 h) forces a re-handshake (`forceRehandshake`) |
| R10 — Stale advertised endpoints kept forever | Medium | `applyPeers` refreshes known peers via `Peer.SetDirectEP` on every peer_list |
| R11 — Per-source budgets can't cap a multi-source flood | Medium/availability | `GlobalMaxPPS`/`GlobalMaxBytesPS` bound total relay work across all sources (defaults 5000 pps / 8 MiB/s); `maybeSweep` now also runs on drop paths |
| R12 — `take` let one oversized packet consume a full budget window | Low | Effective cost is clamped to the cap |
| R13 — `make fuzz-smoke` was broken | Low | Per-package/per-function fuzz loop |
| R14 — `record.Frame` silently wrapped oversized payloads | Low | Panics (programmer-error guard) |
| R15 — STUN read deadline leaked onto the caller's socket | Low | Deadline cleared on return |
| R16 — Router `PktsIn` counted malformed datagrams | Low | Counter only counts valid offered traffic |
| R17 — `protocol.TypeHello` dead | Low | Removed |
| R18 — `scripts/tun-demo.sh` macOS defaults clashed with system utun + sudo dropped overrides | Low | Free-index scan; `sudo env` carries `TUN_*/IP_*/PEER_*` through; pre-sudo temp leak removed |
| R19 — Stale dependencies (x/crypto 2021) | Low | x/crypto v0.55.0, x/sys v0.47.0, `go mod tidy -diff` clean |

### Behavioral notes

- Reorder tolerance applies within a rekey epoch; frames lagging a full epoch
  are deterministically dropped (one-way epoch keys) — documented in SPEC §3.
- Coordinator broadcast now snapshots control sessions under the lock and
  evicts stalled writers so one blocked reader cannot stall the mesh.
