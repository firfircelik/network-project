# meshlink

A mini zero-trust mesh VPN built in Go — a working counterpart to the
"güvenli bağlantı altyapısının çekirdek aktarım katmanı" role at fromquantum.
Noise-protocol encrypted tunnels, UDP hole punching, relay fallback and NAT
simulation, all runnable on localhost without root.

## Demo (two phases)

```
make demo
```

- **Phase 1 — full-cone NATs:** hole punching succeeds; `agent b ping a`
  reports `path=direct`.
- **Phase 2 — symmetric NATs:** classic hole punching fails; the tunnel
  reverts to `path=relay` and pings still succeed end-to-end.

The two agents sit behind two simulated NAT boxes (`cmd/natbox`). A
coordinator provides the peer registry + STUN; a relay forwards ciphertext
only (never plaintext).

## Run manually

```
make build

# services
bin/coordinator -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201
bin/relay -addr 127.0.0.1:19205

# simulated NATs
bin/natbox -name nat1 -behavior fullcone -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
bin/natbox -name nat2 -behavior fullcone -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502

# agent a (daemon)
bin/agent up --name a --keyfile /tmp/k.a --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
  --coordinator 127.0.0.1:19200 --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

# agent b: ping over the encrypted tunnel
bin/agent ping --name b --keyfile /tmp/k.b --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
  --coordinator 127.0.0.1:19200 --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --peer a --count 3
```

`--relay ""` disables the relay (fully direct). `--nat ""` runs agents with
directly reachable sockets (no NAT in the path).

## Documentation

- `docs/ARCHITECTURE.md` — components, data plane, path selection, NAT model.
- `docs/SPEC.md` — wire formats and package contracts.

## Tests

```
make test   # go test -race ./internal/...
```

## Why this project exists

It is a portfolio/learning project built along the job requirements: encrypted
channel design (Noise + AEAD), UDP primary transport with relay fallback, NAT
traversal (STUN + hole punching), session continuity under transport change,
modular interfaces (`peer.Transport`), and design documentation. TUN/OS
integration, out-of-order replay windows and multi-relay routing remain listed
as next steps in `docs/ARCHITECTURE.md`.