# meshlink — Architecture

`meshlink` est un mini VPN maillé zéro confiance construit en Go : une couche de
transport chiffrée, la traversée de NAT, un basculement de transport et un client
modulaire. Pendant le développement, il s'exécute entièrement sur localhost — les
boîtes NAT sont simulées, de sorte que l'ouverture de trou et le repli sur relais
peuvent être démontrés sans root ni matériel réseau réel.

## Composants

```
                    ┌──────────────────────────┐
                    │ coordinator (TCP)        │  control plane:
                    │   peer registry          │  register + broadcast peer
                    │   (UDP) STUN endpoint    │  lists; NAT endpoint discovery
                    └──────────┬───────────────┘
                       TCP/JSON│
            ┌──────────────────┴──────────────────┐
            │                                     │
   ┌────── natbox1 (NAT sim) ──┐        ┌── natbox2 (NAT sim) ─┐
   │ public 127.0.0.1:19301    │        │ public 127.0.0.1:19302│
   │ door   127.0.0.1:19401    │        │ door   127.0.0.1:19402│
   └───────┬───────────────────┘        └───────┬───────────────┘
           │ dataplane (Noise/UDP)              │
        agent a                              agent b
    (127.0.0.1:19501)                    (127.0.0.1:19502)
            └─────────────── relay (UDP 127.0.0.1:19205) ───────┘
```

## Plan de données

- Chaque datagramme UDP est une *trame* : `[1B type][2B length][payload]`
  (voir `internal/record`).
- Chiffrement : Framework de protocole Noise, **motif XX**,
  `DH25519 + ChaCha20-Poly1305 + SHA256`, prologue `meshlink-v1`
  (voir `internal/noisework`).
- Identité : chaque agent détient une paire de clés X25519 persistante. Le coordinateur
  distribue les clés publiques ; après le handshake XX, les deux côtés **vérifient** la
  clé statique du pair par rapport à la clé enregistrée auprès du coordinateur. Le relais ne
  voit jamais de texte clair — le chiffrement est de bout en bout.
- Rôles : l'ID d'agent lexicographiquement plus petit est l'initiateur du handshake,
  de sorte que les deux côtés s'accordent sans signalisation supplémentaire (`internal/disco`).

## Sélection de chemin

1. **Direct (P2P) :** les deux côtés émettent des sondes (`type=4`) vers l'endpoint
   annoncé de l'autre pour ouvrir les mappings NAT, puis exécutent le handshake Noise.
2. **Repli sur relais :** si le handshake direct ne peut aboutir dans
   `disco.DirectAttempt`, le trafic bascule vers le relais : les trames sont enveloppées
   `[magic 0x52][src][dst][frame]` ; le relais transmet le texte chiffré par ID de pair
   (`internal/relay`).
3. **Retour itinérant :** une fois établie sur le relais, l'agent continue de re-sonder le
   direct (`disco.ReestablishInterval`) et relance le handshake P2P quand c'est possible.

## Simulation NAT (`internal/nat`, `cmd/natbox`)

Une natbox a un socket *public* (la vue du monde extérieur) et une *porte
intérieure (inside door)*. Les agents derrière elle sortent par la porte (enveloppe
`[dst][payload]`). Comportements :

- `fullcone`    — un mapping par hôte intérieur ; entrant de toute source accepté.
- `restricted`  — entrant seulement depuis des IP précédemment contactées.
- `symmetric`   — un **port public neuf par destination** ; entrant uniquement sur le
  mapping exact que le pair a utilisé pour nous joindre. C'est ce qui fait échouer
  l'ouverture simultanée de trou classique et démontre le relais.

## Plan de contrôle (`internal/protocol`, `internal/coordinator`)

Les agents se connectent au `coordinator` (TCP), envoient `register {id, pubkey, endpoints}`,
et reçoivent des diffusions `peer_list` contenant tous les pairs enregistrés. Le
premier endpoint est l'adresse publique apprise par STUN ; le second (optionnel) est
le relais. Une ré-inscription met à jour les mappings d'endpoints. Le coordinateur
répond aussi aux requêtes de binding STUN sur un port UDP.

## Ping / vivacité

Une session établie transporte des messages JSON sur Noise :
`{"cmd":"ping","s":seq,"ts":nanos}` → `{"cmd":"pong","s":seq,"ts":nanos}`.
Le pingeur rapporte le RTT, les pertes et le chemin actif (`direct|relay`).

## Limitations connues (MVP)

- Le plan de contrôle s'authentifie via Noise XX et épingle la clé statique du
  coordinateur, mais il n'a pas de volet certificat TLS ; la confiance de l'opérateur est
  hors bande (distribution des clés).
- Les sessions basculent du relais vers le direct, mais pas du direct vers le relais
  en cours de session.
- Les adresses d'overlay sont attribuées statiquement (`-tun-peer`) ; pas encore
  d'attribution dynamique d'adresses.
- Le support TUN existe (`internal/tun`, `internal/agent/tunbridge.go`) mais
  requiert root et n'est pas exercé par `make demo` ; la vérification NAT sur le vrai
  internet (au-delà du simulateur) est un élément ouvert de la phase 4.

## Aperçu des dossiers

```
cmd/{coordinator,relay,natbox,agent}   binaires légers
internal/record      codec de trame
internal/noisework   handshake Noise XX + session (rekey, fenêtre anti-rejeu)
internal/control     connexion de contrôle authentifiée + trame
internal/stun        client/serveur de binding RFC 8489
internal/nat         simulateur NAT
internal/relay       serveur de relais UDP (épinglage de nom, limites de débit)
internal/protocol    JSON du plan de contrôle
internal/coordinator serveur du plan de contrôle (auth Noise, épinglage de clé)
internal/disco       politique de perçage (temporisation, rôles, énumération de chemins)
internal/peer        machine à états de session par pair
internal/agent       colle du client (clés, STUN, inscription, boucle de réception)
internal/tun         dispositif TUN + table de routes IPv4 (phase 4)
```
