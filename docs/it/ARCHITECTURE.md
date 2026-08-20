# meshlink — Architettura

`meshlink` è una mini VPN mesh zero-trust scritta in Go: un livello di trasporto
crittografato, l'attraversamento NAT, il fallback del trasporto e un client modulare.
Durante lo sviluppo gira interamente su localhost — i NAT box sono simulati, così
l'hole punching e il fallback al relay possono essere dimostrati senza root o
hardware di rete reale.

## Componenti

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

## Data plane

- Ogni datagramma UDP è un *frame*: `[1B type][2B length][payload]`
  (vedi `internal/record`).
- Crittografia: Noise Protocol Framework, **pattern XX**,
  `DH25519 + ChaCha20-Poly1305 + SHA256`, prologo `meshlink-v1`
  (vedi `internal/noisework`).
- Identità: ogni agent possiede una coppia di chiavi X25519 persistente. Il coordinator
  distribuisce le chiavi pubbliche; dopo l'handshake XX entrambi i lati **verificano** la
  chiave statica del peer rispetto alla chiave registrata presso il coordinator. Il relay
  non vede mai testo in chiaro — la crittografia è end-to-end.
- Ruoli: l'ID di agent lessicograficamente minore è l'iniziatore dell'handshake,
  così entrambi i lati concordano senza segnalazioni aggiuntive (`internal/disco`).

## Selezione del percorso

1. **Diretto (P2P):** entrambi i lati emettono probe (`type=4`) verso l'endpoint
   pubblicizzato dell'altro per aprire i mapping NAT, poi eseguono l'handshake Noise.
2. **Fallback al relay:** se l'handshake diretto non può completarsi entro
   `disco.DirectAttempt`, il traffico passa al relay: i frame vengono incapsulati
   `[magic 0x52][src][dst][frame]`; il relay inoltra il testo cifrato in base all'ID
   del peer (`internal/relay`).
3. **Ritorno al diretto:** mentre è stabilita sul relay, l'agent continua a ri-probare
   il percorso diretto (`disco.ReestablishInterval`) e ri-esegue l'handshake su P2P
   quando possibile.

## Simulazione NAT (`internal/nat`, `cmd/natbox`)

Un natbox ha una socket *public* (la vista del mondo esterno) e un *inside door*.
Gli agent che stanno dietro escono attraverso il door (incapsulamento `[dst][payload]`).
Comportamenti:

- `fullcone`    — un mapping per host interno; traffico in ingresso da qualsiasi
  sorgente OK.
- `restricted`  — traffico in ingresso solo da IP contattati in precedenza.
- `symmetric`   — una **porta pubblica nuova per ogni destinazione**; traffico in
  ingresso solo sul mapping esatto che il peer ha usato per raggiungerci. È questo che
  fa fallire il classico hole punching ad apertura simultanea e dimostra il relay.

## Piano di controllo (`internal/protocol`, `internal/coordinator`)

Gli agent contattano il `coordinator` (TCP), inviano `register {id, pubkey, endpoints}`
e ricevono le broadcast `peer_list` contenenti ogni peer registrato. Il primo endpoint
è l'indirizzo pubblico appreso via STUN; il secondo (opzionale) è il relay. La
ri-registrazione aggiorna i mapping degli endpoint. Il coordinator risponde anche alle
binding request STUN su una porta UDP.

## Ping / liveness

Una sessione stabilita trasporta messaggi JSON su Noise:
`{"cmd":"ping","s":seq,"ts":nanos}` → `{"cmd":"pong","s":seq,"ts":nanos}`.
Il pinger riporta RTT, perdita e percorso attivo (`direct|relay`).

## Limitazioni note (MVP)

- Il piano di controllo autentica tramite Noise XX e fissa la chiave statica del
  coordinator, ma non ha una gestione dei certificati TLS; la fiducia dell'operatore è
  fuori banda (distribuzione delle chiavi).
- Le sessioni migrano relay→direct ma non direct→relay a metà sessione.
- Gli indirizzi overlay sono assegnati staticamente (`-tun-peer`); nessuna allocazione
  dinamica degli indirizzi per ora.
- Il supporto TUN esiste (`internal/tun`, `internal/agent/tunbridge.go`) ma richiede
  root e non è esercitato da `make demo`; la verifica NAT su internet reale (oltre il
  simulatore) è una voce aperta della Fase 4.

## Panoramica delle directory

```
cmd/{coordinator,relay,natbox,agent}   binari sottili
internal/record      codec dei frame
internal/noisework   handshake Noise XX + sessione (rekey, finestra anti-replay)
internal/control     connessione di controllo autenticata + framing
internal/stun        client/server binding RFC 8489
internal/nat         simulatore NAT
internal/relay       server relay UDP (pinning dei nomi, limiti di velocità)
internal/protocol    JSON del piano di controllo
internal/coordinator server del piano di controllo (auth Noise, pinning delle chiavi)
internal/disco       politica di punching (timing, ruoli, enum del percorso)
internal/peer        macchina a stati della sessione per peer
internal/agent       collante client (chiavi, STUN, register, loop di ricezione)
internal/tun         dispositivo TUN + tabella di routing IPv4 (Fase 4)
```
