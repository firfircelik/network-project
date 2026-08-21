# meshlink

[![CI](https://github.com/firfircelik/network-project/actions/workflows/ci.yml/badge.svg)](https://github.com/firfircelik/network-project/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 Languages:** [English](README.md) · [Türkçe](README.tr.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Deutsch](README.de.md)

VPN maillé P2P chiffré avec traversée de NAT, écrit en Go. Les agents échangent
via des tunnels chiffrés Noise-XX, percent les NAT par STUN + ouverture
simultanée de trou, et basculent vers un relais quand un chemin direct est
impossible — autonome, avec un simulateur NAT intégré, de sorte que toute la
pile s'exécute sur localhost sans root.

## Fonctionnalités

- **Chiffrement de bout en bout** — Framework de protocole Noise, motif XX,
  X25519 + ChaCha20-Poly1305 + SHA256. Le relais ne transmet jamais que du
  texte chiffré ; le déchiffrement s'effectue sur les deux extrémités.
- **Plan de contrôle authentifié** — les sessions agent ↔ coordinateur sont
  chiffrées en Noise-XX et l'agent épingle la clé statique du coordinateur
  (`--coord-pubkey`), de sorte que l'enregistrement et les listes de pairs ne
  peuvent être ni observés ni réécrits sur le fil.
- **Protection anti-rejeu + tolérance aux pertes** — chaque trame DATA commence
  par un nonce explicite de 64 bits ; le récepteur l'accepte via une fenêtre
  glissante de 2048 entrées de type WireGuard (réordonnancement toléré, rejeux
  et nonces anciens rejetés). Un rekey périodique fait tourner les clés de façon
  déterministe avec un plafond anti-DoS.
- **Traversée de NAT** — découverte d'endpoint STUN plus ouverture simultanée de
  trou pour les NAT full-cone et address-restricted ; le repli sur relais et le
  re-sondage maintiennent les sessions des NAT symmetric en vie.
- **Durcissement du relais** — limites de débit pps/octets par source, quotas
  par nom et épinglage nom→adresse.
- **Trafic réel (TUN)** — un pont TUN L3 (macOS `utun`, Linux
  `/dev/net/tun`) route les paquets IPv4 à travers les sessions chiffrées ;
  vérifié avec `make tun-demo`.
- **Simulateur NAT** — `internal/nat` modélise les comportements full-cone,
  address-restricted et symmetric pour des tests locaux reproductibles.

## Démarrage rapide

Requiert **Go 1.26+**.

```sh
make demo
```

Exécute toute la pile contre des NAT simulés en deux phases :

1. paire **full-cone** → l'ouverture de trou réussit, les pings indiquent `path=direct` ;
2. paire **symmetric** → l'ouverture directe échoue, le relais prend le relais et les pings
   aboutissent toujours de bout en bout (`path=relay`).

## Exécution manuelle

Étape 1 — compiler et démarrer les services :

```sh
make build
bin/coordinator -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile coord.key
# notez la ligne « control public key ...: <hex> » du premier démarrage
bin/relay -addr 127.0.0.1:19205
```

Étape 2 — simuler les NAT :

```sh
bin/natbox -name nat1 -behavior fullcone -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
bin/natbox -name nat2 -behavior fullcone -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502
```

Étape 3 — agents (chacun a besoin du `--coord-pubkey <hex>` du journal du coordinateur) :

```sh
bin/agent up --name a --keyfile key.a --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

bin/agent ping --name b --keyfile key.b --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --peer a --count 3
```

`--relay ""` désactive le relais (chemins entièrement directs) ; `--nat ""` contourne les
boîtes NAT (sockets directement joignables). Sans NAT sur le chemin, le socket de données
doit être lié à `0.0.0.0` (`--data 0.0.0.0:19501`) pour que STUN voie une véritable
adresse source — voir `docs/fr/TUN.md` / `docs/fr/REALNET.md`.

## Tests

```sh
make test          # go test -race ./internal/...
make fuzz-smoke    # fuzz d'analyseur 10 s par paquet (record, relay, nat, stun, protocol)
make demo          # démo de bout en bout avec NAT simulé (sans root)
make tun-demo      # bout en bout TUN réel sur macOS/Linux (root ; ré-exécution via sudo)
```

### Mesure de perte sur le fil (retransmissions)

Les hash de fichiers peuvent correspondre pendant que la pile TCP retransmet
pourtant sur le fil. Pour le mesurer directement au lieu de le déduire,
capturez le transfert N fois et comptez les événements d'analyse des
retransmissions TCP :

```sh
RETX_IFACE=en0 \
  RETX_RUNS=10 \
  RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' \
  scripts/retx-check.sh
```

Affiche une ligne par passage (`wall`/`cap` durée, `MB`, compteurs
`retx`/`fast`/`spur`/`dup`/`ooo`/`lost`, RTT ACK moyen) et sort avec `0`
seulement lorsqu'**aucun** paquet ne montre d'indicateur de
retransmission/réordonnancement/perte — un résultat propre au niveau du fil,
non inféré. `RETX_CAP_FILTER` restreint la capture aux points d'extrémité du
transfert. Les captures existantes peuvent être ré-analysées avec
`scripts/retx-check.sh --analyze <dir>` (la capture peut utiliser `tcpdump` ;
l'analyse nécessite `tshark`). Sur une interface réelle, la capture exige root :
`sudo env RETX_IFACE=en0 RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' scripts/retx-check.sh`.

La CI exécute `gofmt` → `go vet` → `go test -race ./...` → `make demo` à chaque
push sur `main` :

## Documentation

| Doc | Contenu |
|---|---|
| [`docs/fr/ARCHITECTURE.md`](docs/fr/ARCHITECTURE.md) | composants, plan de données, sélection de chemin, modèle NAT |
| [`docs/fr/SPEC.md`](docs/fr/SPEC.md) | formats sur le fil et contrats au niveau des paquets |
| [`docs/fr/THREAT_MODEL.md`](docs/fr/THREAT_MODEL.md) | modèle de menaces, mesures d'atténuation, lacunes ouvertes |
| [`docs/fr/ROADMAP.md`](docs/fr/ROADMAP.md) | phases d'implémentation et statut |
| [`docs/fr/TUN.md`](docs/fr/TUN.md) | pont TUN — macOS, Linux, multi-machine |
| [`docs/fr/REALNET.md`](docs/fr/REALNET.md) | recette de vérification sur le vrai internet (VPS) |
| [`docs/fr/REVIEW.md`](docs/fr/REVIEW.md) | journal de revue de code |

## Statut

La phase 1 (CI, fuzz, hygiène de la configuration et des journaux) et la phase 2 (fenêtre
anti-rejeu, rekey, gardes de nonce) sont terminées ; la phase 3 (plan de contrôle
authentifié, épinglage du relais + limites de débit, budgets de handshake) est terminée ;
la phase 4 (pont TUN) est implémentée et documentée — l'élément restant est la vérification
sur le vrai internet (voir `docs/fr/REALNET.md`).
