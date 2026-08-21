# meshlink

[![CI](https://github.com/firfircelik/network-project/actions/workflows/ci.yml/badge.svg)](https://github.com/firfircelik/network-project/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 Languages:** [English](README.md) · [Türkçe](README.tr.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Deutsch](README.de.md)

Verschlüsseltes, NAT-überwindendes P2P-Mesh-VPN in Go. Agents kommunizieren
über Noise-XX-verschlüsselte Tunnel, durchstoßen NATs mit STUN + simultanem
Hole Punching („simultaneous-open") und fallen auf ein Relay zurück, wenn ein
direkter Pfad unmöglich ist — in sich geschlossen mit eingebautem
NAT-Simulator, sodass der gesamte Stack ohne Root auf localhost läuft.

## Features

- **Ende-zu-Ende-Verschlüsselung** — Noise Protocol Framework, XX-Muster,
  X25519 + ChaCha20-Poly1305 + SHA256. Das Relay leitet ausschließlich
  Ciphertext weiter; die Entschlüsselung erfolgt an den beiden Endpunkten.
- **Authentifizierte Kontrollebene** — Agent ↔ Koordinator-Sitzungen sind
  Noise-XX-verschlüsselt und der Agent pinnt den statischen Schlüssel des
  Koordinators (`--coord-pubkey`), sodass Registrierung und Peer-Listen auf
  dem Draht nicht beobachtet oder umgeschrieben werden können.
- **Replay-Schutz + Verlusttoleranz** — jeder DATA-Frame beginnt mit einer
  expliziten 64-Bit-Nonce; der Empfänger akzeptiert sie über ein
  WireGuard-artiges Schiebefenster mit 2048 Einträgen (Neuordnung toleriert,
  Replays und uralte Nonces verworfen). Periodisches Rekeying rotiert
  Schlüssel deterministisch mit einer Rekey-DoS-Obergrenze.
- **NAT-Traversal** — STUN-Endpunkt-Erkennung plus simultanes Hole Punching
  für Full-Cone- und Address-Restricted-NATs; Relay-Fallback und erneutes
  Proben halten symmetrische NAT-Sitzungen am Leben.
- **Relay-Härtung** — PPS/Byte-Ratenlimits pro Quelle, Kontingente pro Name
  und Name→Adresse-Pinning.
- **Echter Datenverkehr (TUN)** — eine L3-TUN-Brücke (macOS `utun`, Linux
  `/dev/net/tun`) leitet IPv4-Pakete durch die verschlüsselten Sitzungen;
  verifiziert mit `make tun-demo`.
- **NAT-Simulator** — `internal/nat` modelliert Full-Cone-,
  Address-Restricted- und Symmetric-Verhalten für reproduzierbares lokales
  Testen.

## Schnellstart

Erfordert **Go 1.26+**.

```sh
make demo
```

Führt den gesamten Stack in zwei Phasen gegen simulierte NATs aus:

1. **Full-Cone**-Paar → Hole Punching gelingt, Pings melden `path=direct`;
2. **Symmetric**-Paar → direktes Punching schlägt fehl, das Relay übernimmt
   und Pings gelingen weiterhin Ende-zu-Ende (`path=relay`).

## Manuell ausführen

Schritt 1 — Dienste bauen und starten:

```sh
make build
bin/coordinator -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile coord.key
# note the "control public key ...: <hex>" line from the first startup
bin/relay -addr 127.0.0.1:19205
```

Schritt 2 — NATs simulieren:

```sh
bin/natbox -name nat1 -behavior fullcone -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
bin/natbox -name nat2 -behavior fullcone -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502
```

Schritt 3 — Agents (jeder benötigt `--coord-pubkey <hex>` aus dem
Koordinator-Log):

```sh
bin/agent up --name a --keyfile key.a --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

bin/agent ping --name b --keyfile key.b --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --peer a --count 3
```

`--relay ""` deaktiviert das Relay (vollständig direkte Pfade); `--nat ""`
überspringt die NAT-Boxen (direkt erreichbare Sockets). Ohne NAT im Pfad muss
der Datensocket an `0.0.0.0` gebunden werden (`--data 0.0.0.0:19501`), damit
STUN eine echte Quelladresse sieht — siehe `docs/de/TUN.md` /
`docs/de/REALNET.md`.

## Tests

```sh
make test          # go test -race ./internal/...
make fuzz-smoke    # 10s parser fuzz per package (record, relay, nat, stun, protocol)
make demo          # simulated-NAT end-to-end demo (no root)
make tun-demo      # real TUN end-to-end on macOS/Linux (root; re-execs via sudo)
```

### Verlustmessung auf der Leitung (Wiederholungen)

Datei-Hashes können übereinstimmen, während der TCP-Stack dennoch auf der
Leitung wiederholt. Um das direkt zu messen statt zu folgern, den Transfer
N-mal aufzeichnen und die TCP-Wiederholungs-Analyseereignisse zählen:

```sh
RETX_IFACE=en0 \
  RETX_RUNS=10 \
  RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' \
  scripts/retx-check.sh
```

Gibt pro Durchlauf eine Zeile aus (`wall`/`cap`-Dauer, `MB`, Zähler
`retx`/`fast`/`spur`/`dup`/`ooo`/`lost`, durchschnittliche ACK-RTT) und endet
nur mit `0`, wenn **kein** Paket Wiederholungs-/Neuordnungs-/Verlustanzeichen
zeigt — ein sauberes Ergebnis auf Leitungsebene, nicht gefolgert.
`RETX_CAP_FILTER` begrenzt die Aufzeichnung auf die Transfer-Endpunkte.
Vorhandene Aufzeichnungen lassen sich mit
`scripts/retx-check.sh --analyze <dir>` erneut analysieren (die Aufzeichnung
kann auf `tcpdump` zurückfallen; für die Analyse wird `tshark` benötigt).
Auf einer echten Schnittstelle erfordert die Aufzeichnung root:
`sudo env RETX_IFACE=en0 RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' scripts/retx-check.sh`.

CI führt bei jedem Push auf `main` `gofmt` → `go vet` → `go test -race ./...`
→ `make demo` aus:

## Dokumentation

| Doku | Inhalt |
|---|---|
| [`docs/de/ARCHITECTURE.md`](docs/de/ARCHITECTURE.md) | Komponenten, Datenebene, Pfadauswahl, NAT-Modell |
| [`docs/de/SPEC.md`](docs/de/SPEC.md) | Drahtformate und Verträge auf Paketebene |
| [`docs/de/THREAT_MODEL.md`](docs/de/THREAT_MODEL.md) | Bedrohungsmodell, Gegenmaßnahmen, offene Lücken |
| [`docs/de/ROADMAP.md`](docs/de/ROADMAP.md) | Implementierungsphasen und Status |
| [`docs/de/TUN.md`](docs/de/TUN.md) | TUN-Brücke — macOS, Linux, geräteübergreifend |
| [`docs/de/REALNET.md`](docs/de/REALNET.md) | Rezept zur Verifikation im realen Internet (VPS) |
| [`docs/de/REVIEW.md`](docs/de/REVIEW.md) | Code-Review-Protokoll |

