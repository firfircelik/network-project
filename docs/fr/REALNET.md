# meshlink — Vérification NAT sur le vrai internet (reliquat de la phase 4)

La démo **simule** le comportement NAT avec `natbox` (fullcone/restricted/
symmetric). Pour clôturer la vérification, le même flux doit être démontré
sur un **réseau réel** :

- **Ouverture de trou directe (path=direct)** sur au moins une paire cone/restricted,
- **Repli sur relais (path=relay)** quand le chemin direct échoue.

De plus, le pont TUN est vérifié avec un e2e réel qui requiert root
(`make tun-demo`, sur une seule machine).

## Installation — serveur public (coordinateur + relais)

Le plus simple : un VPS bon marché (~5 $/mois dans le cloud) + deux réseaux différents côté
client (par ex. Wi-Fi domestique + partage de connexion depuis un téléphone mobile).

1. Compiler en croisé les binaires serveur (linux/amd64) :

   ```sh
   make build
   GOOS=linux GOARCH=amd64 go build -o bin/linux/coordinator ./cmd/coordinator
   GOOS=linux GOARCH=amd64 go build -o bin/linux/relay       ./cmd/relay
   GOOS=linux GOARCH=amd64 go build -o bin/linux/agent       ./cmd/agent
   scp bin/linux/{coordinator,relay,agent} user@vps:/opt/meshlink/
   ```

2. Ouvrir dans le groupe de sécurité : TCP **19200**, UDP **19201**, UDP **19205**
   (0.0.0.0/0 ; restreindre par source en production).

3. Exécuter sur le serveur :

   ```sh
   # coordinateur : à la première exécution, génère et imprime sa clé
   bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key
   # relais
   bin/relay -addr 0.0.0.0:19205
   ```

   Noter la clé `control public key ...: <hex>` de la sortie — elle est
   donnée aux **clients** comme `--coord-pubkey`.

## Clients — sur deux réseaux différents

4. Compiler les binaires clients (par machine) : pour macOS `GOOS=darwin
   GOARCH=amd64` (ou `arm64`), pour Linux `GOOS=linux`.

5. Sur la machine A (lier le socket de données à `0.0.0.0` — STUN doit voir la vraie
   IP source ; s'il est lié à `127.0.0.1`, aucun trou ne peut être ouvert) :

   ```sh
   bin/agent up --name a --keyfile key.a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19501
   ```

   Vérification : la ligne `public endpoint (STUN)` du journal doit afficher une
   adresse **publique** (pas 127.0.0.1). Pour un NAT domestique, il doit s'agir de l'IP
   WAN.

6. Démarrer la machine B de la même façon avec `--name b --data 0.0.0.0:19502`.

7. Exécuter depuis B :

   ```sh
   bin/agent ping --name b --keyfile key.b --peer a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19502 --count 3 --interval 1s
   ```

Résultats attendus :

| Scénario | NAT | Chemin attendu |
|---|---|---|
| Deux NAT domestiques/ADSL | fullcone / restricted | `direct` |
| Partage de connexion / mobile | symmetric (ou financier) | `relay` |
| Mixte | restricted + symmetric | `relay` |

Si `path=relay` apparaît, le système **fonctionne correctement** — les NAT mobiles
ne peuvent pas être percés et le repli sur relais maintient le trafic. Les deux cas
sont une vérification valide pour la phase 4 : quel que soit le chemin utilisé, `received=count`
doit être vrai.

## Utilisation de TUN sur un réseau réel

Le chemin trou/relais fonctionne exactement de la même façon ; il suffit de donner à
chaque client une adresse d'overlay :

```sh
# Côté A
bin/agent up --name a --keyfile key.a \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up

# Côté B
bin/agent up --name b --keyfile key.b \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19502 \
  --tun utun10 --tun-ip 10.62.0.2 --tun-peer a=10.61.0.1
sudo ifconfig utun10 10.62.0.2/24 up

# Sur la machine B, ping à travers l'overlay :
ping -c 3 10.61.0.1
```

(Sur Linux, `/dev/net/tun` + `ip addr add ... dev meshlink0` sont utilisés ; les détails
et les notes de routes hôte macOS sont dans `docs/fr/TUN.md`.)

## Pré-vérification locale (root suffit, pas de VPS)

```sh
make tun-demo        # ouvre deux utun, fait passer l'ICMP par le tunnel avec les routes hôte
```

## Dépannage

| Symptôme | Cause possible | Correctif |
|---|---|---|
| Endpoint STUN `127.0.0.1` | `--data 127.0.0.1:...` a été utilisé | `--data 0.0.0.0:19501` |
| Délai de handshake (contrôle) | `--coord-pubkey` erroné/absent | Copier le `<hex>` depuis le journal du serveur |
| `ping` : aucune réponse | 19200/19201/19205 fermés | Ouvrir le groupe de sécurité du VPS |
| `path=relay` mais pertes de paquets | UDP entrant du relais vers le client fermé | Autoriser l'UDP entrant sur 19501/19502 dans le pare-feu local des machines A/B |
| Ping TUN avec 100 % de pertes | adresse d'overlay de `<peer>` incohérente | `-tun-peer` doit être symétrique des deux côtés |

## Note de sécurité

0.0.0.0/0 est ouvert pour la vérification ; ensuite, le relais/coordinateur devrait
être déplacé vers une liste blanche ou un contrôle d'accès dans le cadre des « risques
acceptés » de la section 6 de `docs/fr/THREAT_MODEL.md` (la limitation de débit/épinglage
de signature du relais est déjà active dans le code).
