# meshlink — Production Roadmap (v1)

Current status: **Phase 1–3 complete; Phase 4 partial** (TUN code + documentation
ready; real-internet NAT test open). At the end of each phase `gofmt` / `go vet` /
`go test -race` / `make demo` are kept green.

## Phase 1 — Trust/Quality Infrastructure (goal: G7, G9) — ✅ complete

- ✅ GitHub Actions CI: `.github/workflows/ci.yml` — `gofmt`, `go vet`,
  `go test -race ./...`, `make demo`.
- ✅ Fuzz tests: `record`, `relay`, `nat`, `stun`, `protocol` decoders
  (plain malformed input, truncation, length-field exaggeration) + `make fuzz-smoke`.
- ✅ Bounded control reads: `control.ReadMsg` `maxMsgLen` cap, handshake
  lengths 16-bit cap; memory DoS surface closed.
- ✅ Structured logging: `log/slog` (`level=INFO msg=...`), error/warning/info.
- ✅ Config: flag validation (`--name`/`--keyfile`/`--coord-pubkey` required);
  when the key file is missing it is created with `0600` and perms are preserved.
  (Environment-variable-based config → v1.1+.)

## Phase 2 — Tunnel Core Hardening (goal: G1, G8) — ✅ complete

- ✅ **Replay window + loss tolerance:** explicit 64-bit nonce in DATA frames;
  WireGuard-style sliding window at the receiver (bitmap, 2048 packets). Very old
  records/replays rejected; session does not lock up after loss
  (`internal/noisework`, `internal/peer`).
- ✅ **Periodic rekey:** `RekeyEvery` message triggers a key rotation; both
  directions at the same limit, lost packets tracked via epoch jumps.
- ✅ Nonce exhaustion guard (`MaxNonce`), `maxEpochJump` DoS cap, and session
  age limit.
- ✅ Tests: drop, replay, out-of-order arrival, stale nonce, rekey gap
  (`TestDecryptAtLossReorderAndRekey`, `TestRekeyRotatesKeys`,
  `TestRekeyJumpCapped`).

## Phase 3 — Control + Relay Security (goal: G2–G5) — ✅ complete

- ✅ **Relay name pinning:** if the network address bound to a name changes, it
  cannot be claimed from another channel (name hijacking/delivery disruption closed).
- ✅ **Relay rate-limit/quota:** pps/byte limit per source address + quota per
  name; amplification surface narrowed.
- ✅ **Handshake/CPU budget + handshake timeout:** concurrent handshake state
  limit on the responder side and explicit takeover/decay timeouts
  (relay + control).
- ✅ **Control-plane Noise auth:** register channel encrypted with Noise XX and
  the coordinator key pinned at the client; name→key binding verified on the
  coordinator side (identity/key mismatches rejected).

## Phase 4 — Real Data Transport (TUN) (goal: G6) — 🔶 partial

- ✅ `internal/tun`: utun/TUN interface opening, IPv4 routing (`Router`),
  in-memory test device (`BufferDevice`); macOS `utun`, Linux `/dev/net/tun`.
- ✅ Agent→tun bridge: `internal/agent/tunbridge.go` — routing encrypted session
  data as IP packets (`-tun`, `-tun-ip`,
  `-tun-peer id=ip`).
- ✅ OS address configuration steps (requires root) → `docs/TUN.md`.
- ⏸ Real-internet NAT test (beyond the simulator) — open; requires validation
  on a real network.

## Next steps (v1.1+)

- Environment-variable-based config; real-internet NAT validation (Phase 4 leftover).
- Live config rotation; cryptographic key store/KMS; Prometheus metrics;
  plaintext memory protection (mlock); WireGuard-like session timeouts;
  handshake/core function health status.

## Ops tooling (post-v1 addendum)

- ✅ `agent status --json`: machine-readable snapshot on stdout (logs on
  stderr; durations as ms/s floats, `rtt_ms` null until sampled).
- ✅ `agent status --probe-peer <id>`: pings one peer from the same instance
  before snapshotting so path/RTT reflect a real, established tunnel.
- ✅ Ecosystem: the JSON feed is ingested by
  [HomeNetIQ](https://github.com/firfircelik/homenetiq) to score mesh health
  (path/RTT/rekeys) in its self-hosted dashboard.
