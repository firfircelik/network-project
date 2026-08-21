# meshlink

**🌐 Languages:** [English](README.md) · [Türkçe](README.tr.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Deutsch](README.de.md)

Encrypted, NAT-traversing P2P mesh VPN written in Go. Agents talk over
Noise-XX encrypted tunnels, punch through NATs with STUN + simultaneous-open
hole punching, and fall back to a relay when a direct path is impossible —
self-contained with a built-in NAT simulator, so the whole stack runs on
localhost without root.

## Features

- **End-to-end encryption** — Noise Protocol Framework, XX pattern,
  X25519 + ChaCha20-Poly1305 + SHA256. The relay only ever forwards
  ciphertext; decryption happens on the two endpoints.
- **Authenticated control plane** — agent ↔ coordinator sessions are
  Noise-XX encrypted and the agent pins the coordinator's static key
  (`--coord-pubkey`), so registration and peer lists cannot be observed or
  rewritten on the wire.
- **Replay protection + loss tolerance** — every DATA frame leads with an
  explicit 64-bit nonce; the receiver accepts it through a WireGuard-style
  2048-entry sliding window (reordering tolerated, replays and ancient
  nonces dropped). Periodic rekey rotates keys deterministically with a
  rekey-DoS cap.
- **NAT traversal** — STUN endpoint discovery plus simultaneous-open hole
  punching for full-cone and address-restricted NATs; relay fallback and
  re-probing keep symmetric-NAT sessions alive.
- **Relay hardening** — per-source pps/byte rate limits, per-name quotas and
  name→address pinning.
- **Real traffic (TUN)** — an L3 TUN bridge (macOS `utun`, Linux
  `/dev/net/tun`) routes IPv4 packets through the encrypted sessions;
  verified with `make tun-demo`.
- **NAT simulator** — `internal/nat` models full-cone, address-restricted and
  symmetric behaviors for reproducible local testing.
- **Operations UX** — a one-shot `agent status` snapshot (peers, path, RTT,
  rekey counters, coordinator registry) and a live `agent tui` dashboard, plus
  `make lan-demo` for a VPS-free two-device check on the same Wi-Fi/LAN.

## Quickstart

Requires **Go 1.26+**.

```sh
make demo
```

Runs the full stack against simulated NATs in two phases:

1. **full-cone** pair → hole punching succeeds, pings report `path=direct`;
2. **symmetric** pair → direct punching fails, the relay takes over and pings
   still succeed end-to-end (`path=relay`).

## Run manually

Step 1 — build and start the services:

```sh
make build
bin/coordinator -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile coord.key
# note the "control public key ...: <hex>" line from the first startup
bin/relay -addr 127.0.0.1:19205
```

Step 2 — simulate NATs:

```sh
bin/natbox -name nat1 -behavior fullcone -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
bin/natbox -name nat2 -behavior fullcone -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502
```

Step 3 — agents (each needs `--coord-pubkey <hex>` from the coordinator log):

```sh
bin/agent up --name a --keyfile key.a --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

bin/agent ping --name b --keyfile key.b --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --peer a --count 3
```

`--relay ""` disables the relay (fully direct paths); `--nat ""` skips the
NAT boxes (directly reachable sockets). Without a NAT in the path the data
socket must be bound to `0.0.0.0` (`--data 0.0.0.0:19501`) so STUN sees a
real source address — see `docs/TUN.md` / `docs/REALNET.md`.

### Two devices on the same Wi-Fi/LAN (no VPS)

```sh
make lan-demo
```

Starts coordinator + relay locally, binds both agent sockets to `0.0.0.0` and
pings through the real LAN/wireless interface (`path=direct`). It prints the
exact commands to copy onto a second device.

### Observing the mesh

```sh
# one-shot snapshot: local key/endpoint, coordinator registry, per-peer
# established/path/RTT/rekey counters — readable by scripts and humans
bin/agent status --name b --keyfile key.b --data 0.0.0.0:19502 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

# machine-readable variant for scripts/collectors (logs go to stderr):
bin/agent status --json --name b --keyfile key.b --data 0.0.0.0:19502 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --probe-peer a   # optional: ping first so path/RTT are real

# live terminal dashboard: same fields, refreshed every second, RTT history
bin/agent tui --name b --keyfile key.b --data 0.0.0.0:19502 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205
```

> The JSON snapshot is what [HomeNetIQ](https://github.com/firfircelik/homenetiq)
> ingests to score mesh health (path, RTT, rekeys) in its dashboard.

## Tests

```sh
make test          # go test -race ./internal/...
make fuzz-smoke    # 10s parser fuzz per package (record, relay, nat, stun, protocol)
make demo          # simulated-NAT end-to-end demo (no root)
make lan-demo      # real direct path over the LAN/Wi-Fi interface (no root, no VPS)
make tun-demo      # real TUN end-to-end on macOS/Linux (root; re-execs via sudo)
```

### Measuring wire-level loss (retransmissions)

File hashes can match while the TCP stack still retransmits on the wire. To
measure that directly instead of inferring it, capture the transfer N times and
count TCP retransmission-analysis events:

```sh
RETX_IFACE=en0 \
  RETX_RUNS=10 \
  RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' \
  scripts/retx-check.sh
```

Prints one row per run (`wall`/`cap` duration, `MB`, `retx`/`fast`/`spur`/
`dup`/`ooo`/`lost` counters, average ACK RTT) and exits `0` only when **zero**
packets show retransmission/reordering/loss indicators — a wire-level clean
result, not an inferred one. `RETX_CAP_FILTER` narrows the capture to the
transfer endpoints. Existing captures can be re-analyzed with
`scripts/retx-check.sh --analyze <dir>` (capture falls back to `tcpdump`;
analysis needs `tshark`). On a real interface the capture needs root:
`sudo env RETX_IFACE=en0 RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' scripts/retx-check.sh`.

CI runs `gofmt` → `go vet` → `go test -race ./...` → `make demo` on every
push to `main`:

[![CI](https://github.com/firfircelik/network-project/actions/workflows/ci.yml/badge.svg)](https://github.com/firfircelik/network-project/actions/workflows/ci.yml)

## Documentation

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | components, data plane, path selection, NAT model |
| [`docs/SPEC.md`](docs/SPEC.md) | wire formats and package-level contracts |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | threat model, mitigations, open gaps |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | implementation phases and status |
| [`docs/TUN.md`](docs/TUN.md) | TUN bridge — macOS, Linux, cross-machine |
| [`docs/REALNET.md`](docs/REALNET.md) | real-internet verification recipe (VPS) |
| [`docs/REVIEW.md`](docs/REVIEW.md) | code review log |

## Status

Phase 1 (CI, fuzz, config/log hygiene) and Phase 2 (replay window, rekey,
nonce guards) are complete; Phase 3 (authenticated control plane, relay
pinning + rate limits, handshake budgets) is complete; Phase 4 (TUN bridge)
is implemented and documented — the remaining item is verification on the
real internet (see `docs/REALNET.md`).