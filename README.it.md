# meshlink

**🌐 Languages:** [English](README.md) · [Türkçe](README.tr.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Deutsch](README.de.md)

VPN mesh P2P crittografata e in grado di attraversare i NAT, scritta in Go. Gli agent comunicano tramite tunnel crittografati Noise-XX, bucano i NAT con STUN + hole punching ad apertura simultanea e ripiegano su un relay quando un percorso diretto è impossibile — autosufficiente, con un simulatore NAT integrato, così l'intero stack gira su localhost senza root.

## Funzionalità

- **Crittografia end-to-end** — Noise Protocol Framework, pattern XX,
  X25519 + ChaCha20-Poly1305 + SHA256. Il relay inoltra solo testo cifrato;
  la decifratura avviene sui due endpoint.
- **Piano di controllo autenticato** — le sessioni agent ↔ coordinator sono
  crittografate con Noise-XX e l'agent fissa la chiave statica del coordinator
  (`--coord-pubkey`), quindi registrazione ed elenchi dei peer non possono essere
  osservati né riscritti sul cavo.
- **Protezione da replay + tolleranza alla perdita** — ogni frame DATA inizia con un
  nonce esplicito a 64 bit; il ricevitore lo accetta tramite una finestra scorrevole
  da 2048 voci stile WireGuard (il riordino è tollerato, replay e nonce antichi
  vengono scartati). Il rekey periodico ruota le chiavi in modo deterministico con
  un limite anti-DoS sul rekey.
- **Attraversamento NAT** — scoperta dell'endpoint tramite STUN più hole punching
  ad apertura simultanea per NAT full-cone e address-restricted; il fallback al
  relay e il re-probing mantengono vive le sessioni su NAT symmetric.
- **Rafforzamento del relay** — limiti di velocità pps/byte per sorgente, quote per
  nome e pinning nome→indirizzo.
- **Traffico reale (TUN)** — un bridge TUN L3 (macOS `utun`, Linux
  `/dev/net/tun`) instrada i pacchetti IPv4 attraverso le sessioni crittografate;
  verificato con `make tun-demo`.
- **Simulatore NAT** — `internal/nat` modella i comportamenti full-cone,
  address-restricted e symmetric per test locali riproducibili.

## Avvio rapido

Richiede **Go 1.26+**.

```sh
make demo
```

Esegue l'intero stack contro NAT simulati in due fasi:

1. coppia **full-cone** → l'hole punching riesce, i ping riportano `path=direct`;
2. coppia **symmetric** → il punching diretto fallisce, il relay subentra e i ping
   riescono comunque end-to-end (`path=relay`).

## Esecuzione manuale

Passo 1 — build e avvio dei servizi:

```sh
make build
bin/coordinator -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile coord.key
# annotare la riga "control public key ...: <hex>" del primo avvio
bin/relay -addr 127.0.0.1:19205
```

Passo 2 — simulazione dei NAT:

```sh
bin/natbox -name nat1 -behavior fullcone -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
bin/natbox -name nat2 -behavior fullcone -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502
```

Passo 3 — agent (ognuno ha bisogno di `--coord-pubkey <hex>` dal log del coordinator):

```sh
bin/agent up --name a --keyfile key.a --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

bin/agent ping --name b --keyfile key.b --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --peer a --count 3
```

`--relay ""` disattiva il relay (percorsi completamente diretti); `--nat ""` salta i
NAT box (socket direttamente raggiungibili). Senza un NAT nel percorso la socket dati
deve essere associata a `0.0.0.0` (`--data 0.0.0.0:19501`) così STUN vede un
indirizzo sorgente reale — vedi `docs/it/TUN.md` / `docs/it/REALNET.md`.

## Test

```sh
make test          # go test -race ./internal/...
make fuzz-smoke    # 10s di fuzz del parser per pacchetto (record, relay, nat, stun, protocol)
make demo          # demo end-to-end con NAT simulati (senza root)
make tun-demo      # TUN reale end-to-end su macOS/Linux (root; ri-esegue tramite sudo)
```

La CI esegue `gofmt` → `go vet` → `go test -race ./...` → `make demo` a ogni
push su `main`:

[![CI](https://github.com/firfircelik/network-project/actions/workflows/ci.yml/badge.svg)](https://github.com/firfircelik/network-project/actions/workflows/ci.yml)

## Documentazione

| Doc | Contents |
|---|---|
| [`docs/it/ARCHITECTURE.md`](docs/it/ARCHITECTURE.md) | components, data plane, path selection, NAT model |
| [`docs/it/SPEC.md`](docs/it/SPEC.md) | wire formats and package-level contracts |
| [`docs/it/THREAT_MODEL.md`](docs/it/THREAT_MODEL.md) | threat model, mitigations, open gaps |
| [`docs/it/ROADMAP.md`](docs/it/ROADMAP.md) | implementation phases and status |
| [`docs/it/TUN.md`](docs/it/TUN.md) | TUN bridge — macOS, Linux, cross-machine |
| [`docs/it/REALNET.md`](docs/it/REALNET.md) | real-internet verification recipe (VPS) |
| [`docs/it/REVIEW.md`](docs/it/REVIEW.md) | code review log |

## Stato

La Fase 1 (CI, fuzz, igiene di configurazione/log) e la Fase 2 (finestra anti-replay,
rekey, protezioni dei nonce) sono complete; la Fase 3 (piano di controllo autenticato,
pinning + limiti di velocità del relay, budget di handshake) è completa; la Fase 4
(bridge TUN) è implementata e documentata — l'elemento rimanente è la verifica su
internet reale (vedi `docs/it/REALNET.md`).
