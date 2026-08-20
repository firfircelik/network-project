# meshlink TUN (Trasporto dati reale)

Obiettivo della Fase 4 (G6): trasportare traffico IP reale su sessioni crittografate.
`agent up` apre un'interfaccia TUN (macOS `utunN`, Linux `/dev/net/tun`),
instrada i pacchetti IP letti dall'interfaccia verso la sessione crittografata del
peer corretto in base alla tabella degli indirizzi overlay; scrive inoltre
sull'interfaccia i pacchetti decifrati che arrivano dai peer.

## Verifica

- **Macchina singola (basta root):** `make tun-demo` — due utun
  + due `agent up` su una singola macchina, il traffico ICMP viene forzato attraverso
  il tunnel con `-host`/`ip route` e viene verificato `ping 10.62.0.2` (scr: `scripts/tun-demo.sh`).
- **Internet reale:** client su due reti diverse + coordinator/relay
  su un VPS pubblico → `docs/it/REALNET.md`.

## Architettura

```
                    ┌──────────────────────────── agent ────────────────────────────┐
  OS routing table  │                                                              │
  dst 10.60.0.2 ──► │ TUN device ──► tun.Router ──(dest IP lookup)──► peer.Send()   │ ─► Noise sessi
    (utun9, dev)    │                    ▲                                           │
                    │                    │          decrypted payloads (p.Recv())    │
                    │                    └──────────── tunnel bridge ────────────────┘ ◄─ Noise session
                    └──────────────────────────────────────────────────────────────┘
```

- `internal/tun`: accesso al dispositivo TUN (`Device`) + routing IPv4 (`Router`)
  + un dispositivo in memoria per i test (`BufferDevice`).
- `internal/agent/tunbridge.go`: il ponte tra il dispositivo e le sessioni dei peer.
- Gli indirizzi overlay sono assegnati con `-tun-peer <id>=<ip>`; quando il nome viene
  appreso dal coordinator, la route viene installata.

## Passi di setup ed esecuzione su macOS (richiede root)

1. Build e avvio del coordinator:

   ```sh
   make build
   bin/coordinator -keyfile bin/coord.key
   ```

   Annotare il valore `control public key ...: <hex>` nell'output.

2. Lato agent "a" (utun9):

   ```sh
   bin/agent up --name a --keyfile bin/key.a \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19501 \
     --tun utun9 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
   sudo ifconfig utun9 10.60.0.1/24 up
   ```

3. Lato agent "b" (utun10):

   ```sh
   bin/agent up --name b --keyfile bin/key.b \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19502 \
     --tun utun10 --tun-ip 10.60.0.2 --tun-peer a=10.60.0.1
   sudo ifconfig utun10 10.60.0.2/24 up
   ```

4. Test:

   ```sh
   ping -c 3 10.60.0.2   # sul laptop a: l'ICMP verso b passa attraverso il tunnel
   ```

## Passi di setup ed esecuzione su Linux

Stessi flag; il dispositivo TUN usa `/dev/net/tun` (IFF_TUN|IFF_NO_PI) tramite
`internal/tun/tun_linux.go`. Se il nome viene lasciato vuoto, il kernel apre
un'interfaccia libera come `meshlink%d`:

```sh
sudo ip tuntap add dev meshlink0 mode tun
bin/agent up --name a ... --tun meshlink0 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
sudo ip addr add 10.60.0.1/24 dev meshlink0
sudo ip link set meshlink0 up
```

## Test cross-macchina — Linux + macOS sulla stessa LAN

Due macchine separate, due sistemi operativi separati, stessa rete: gli agent si
vedono tramite hole punching diretto (`path=direct`) e si pingano attraverso
l'overlay. Poiché il formato wire è big-endian in tutti i campi di lunghezza, non c'è
differenza di piattaforma; solo il nome del dispositivo e il comando dell'interfaccia
dipendono dall'OS. Qui sono necessarie anche le route `/32` — altrimenti il kernel
prova a raggiungere la destinazione overlay tramite il gateway predefinito.

Mac (es. `192.168.1.10`): coordinator + relay + agent a

```sh
bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key &
bin/relay -addr 0.0.0.0:19205 &
# leggere <coord_pub_hex> dall'output

bin/agent up --name a --keyfile key.a \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up
sudo route add -host 10.62.0.2 -interface utun9
ping -c 3 10.62.0.2
```

Linux (es. `192.168.1.20`): agent b

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

Su entrambi i lati, se il `ping` non perde pacchetti e la riga `public endpoint (STUN)`
nei log mostra l'IP LAN dell'altra macchina, **la mesh cross-platform è verificata
(`path=direct`)**. La stessa ricetta vale per internet reale; l'unica differenza è che
coordinator/relay sono su un VPS pubblico (`docs/it/REALNET.md`).

## Limiti e dettagli

- Gli indirizzi overlay sono gestiti con una tabella statica `-tun-peer` (simile ad
  `AllowedIPs` di WireGuard); l'allocazione dinamica è nell'elenco "v1.1+".
- Il routing è per il semplice IPv4 (TUN L3); L2 (TAP)/IPv6 in una versione successiva.
- L'accesso a TUN richiede root; i test girano senza root con `BufferDevice`, e se
  non è possibile aprire un dispositivo reale, il test viene saltato con `t.Skip`.
- Le destinazioni non presenti nella tabella di routing vengono scartate
  silenziosamente (`PktsDropped`); i contatori `Pings/Routed/Dropped` sono mantenuti
  su `Router`.
