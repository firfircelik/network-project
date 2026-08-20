# meshlink TUN (transport de données réel)

Objectif de la phase 4 (G6) : transporter du trafic IP réel sur des sessions chiffrées.
`agent up` ouvre une interface TUN (macOS `utunN`, Linux `/dev/net/tun`),
route les paquets IP qu'il lit depuis l'interface vers la session chiffrée du bon pair
selon la table d'adresses d'overlay ; il écrit aussi sur l'interface les paquets
déchiffrés provenant des pairs.

## Vérification

- **Machine unique (root suffit) :** `make tun-demo` — deux utun
  + deux `agent up` sur une seule machine, le trafic ICMP est forcé à travers le
  tunnel avec `-host`/`ip route` et `ping 10.62.0.2` est vérifié (scr : `scripts/tun-demo.sh`).
- **Vrai internet :** des clients sur deux réseaux différents + coordinateur/relais
  sur un VPS public → `docs/fr/REALNET.md`.

## Architecture

```
                    ┌──────────────────────────── agent ────────────────────────────┐
  OS routing table  │                                                              │
  dst 10.60.0.2 ──► │ TUN device ──► tun.Router ──(dest IP lookup)──► peer.Send()   │ ─► Noise sessi
    (utun9, dev)    │                    ▲                                           │
                    │                    │          decrypted payloads (p.Recv())    │
                    │                    └──────────── tunnel bridge ────────────────┘ ◄─ Noise session
                    └──────────────────────────────────────────────────────────────┘
```

- `internal/tun` : accès au dispositif TUN (`Device`) + routage IPv4 (`Router`)
  + un dispositif en mémoire pour les tests (`BufferDevice`).
- `internal/agent/tunbridge.go` : le pont entre le dispositif et les sessions de pairs.
- Les attributions d'adresses d'overlay sont données avec `-tun-peer <id>=<ip>` ; dès que le
  nom est appris du coordinateur, la route est installée.

## Étapes de configuration et d'exécution macOS (requiert root)

1. Compiler et démarrer le coordinateur :

   ```sh
   make build
   bin/coordinator -keyfile bin/coord.key
   ```

   Noter la valeur `control public key ...: <hex>` dans la sortie.

2. Côté agent « a » (utun9) :

   ```sh
   bin/agent up --name a --keyfile bin/key.a \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19501 \
     --tun utun9 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
   sudo ifconfig utun9 10.60.0.1/24 up
   ```

3. Côté agent « b » (utun10) :

   ```sh
   bin/agent up --name b --keyfile bin/key.b \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19502 \
     --tun utun10 --tun-ip 10.60.0.2 --tun-peer a=10.60.0.1
   sudo ifconfig utun10 10.60.0.2/24 up
   ```

4. Tester :

   ```sh
   ping -c 3 10.60.0.2   # sur le portable a : l'ICMP vers b passe par le tunnel
   ```

## Étapes de configuration et d'exécution Linux

Mêmes flags ; le dispositif TUN utilise `/dev/net/tun` (IFF_TUN|IFF_NO_PI) via
`internal/tun/tun_linux.go`. Si le nom est laissé vide, le noyau ouvre une
interface libre sous la forme `meshlink%d` :

```sh
sudo ip tuntap add dev meshlink0 mode tun
bin/agent up --name a ... --tun meshlink0 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
sudo ip addr add 10.60.0.1/24 dev meshlink0
sudo ip link set meshlink0 up
```

## Test multi-machine — Linux + macOS sur le même LAN

Deux machines séparées, deux OS séparés, même réseau : les agents se voient
par ouverture de trou directe (`path=direct`) et se pingent via
l'overlay. Comme le format sur le fil est big-endian dans tous les champs de longueur, il n'y a
aucune différence de plateforme ; seuls le nom du dispositif et la commande d'interface sont
spécifiques à l'OS. Des routes `/32` sont aussi requises ici — sinon le noyau
essaie la destination d'overlay via la passerelle par défaut.

Mac (par ex. `192.168.1.10`) : coordinateur + relais + agent a

```sh
bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key &
bin/relay -addr 0.0.0.0:19205 &
# lire <coord_pub_hex> dans la sortie

bin/agent up --name a --keyfile key.a \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up
sudo route add -host 10.62.0.2 -interface utun9
ping -c 3 10.62.0.2
```

Linux (par ex. `192.168.1.20`) : agent b

```sh
bin/agent up --name b --keyfile key.b \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun meshlink_b --tun-ip 10.62.0.2 --tun-peer a=10.61.0.1
sudo ip addr add 10.62.0.2/24 dev meshlink_b
sudo ip link set meshlink_b up
sudo ip route add 10.61.0.1/32 dev meshlink_b
ping -c 3 10.61.0.1
```

Des deux côtés, si `ping` est sans perte et que la ligne `public endpoint (STUN)`
des journaux montre l'IP LAN de l'autre machine, le **maillage multiplateforme est
vérifié (`path=direct`)**. La même recette s'applique au vrai internet ;
la seule différence est que le coordinateur/relais se trouve sur un VPS public
(`docs/fr/REALNET.md`).

## Limites et détails

- Les adresses d'overlay sont gérées avec une table statique `-tun-peer` (de type
  `AllowedIPs` de WireGuard) ; l'attribution dynamique est sur la liste « v1.1+ ».
- Le routage est pour de l'IPv4 pur (TUN L3) ; L2 (TAP)/IPv6 dans une version ultérieure.
- L'accès TUN requiert root ; les tests s'exécutent sans root avec `BufferDevice`, et si
  aucun dispositif réel ne peut être ouvert, le test est ignoré avec `t.Skip`.
- Les destinations absentes de la table de routage sont silencieusement abandonnées (`PktsDropped`) ;
  les compteurs `Pings/Routed/Dropped` sont conservés sur `Router`.
