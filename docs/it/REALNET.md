# meshlink — Verifica NAT su internet reale (residuo della Fase 4)

La demo **simula** il comportamento dei NAT con `natbox` (fullcone/restricted/
symmetric). Per chiudere la verifica, lo stesso flusso deve essere mostrato
in esecuzione su una **rete reale**:

- **Hole punching diretto (path=direct)** su almeno una coppia cone/restricted,
- **Fallback al relay (path=relay)** quando il percorso diretto fallisce.

Inoltre, il bridge TUN è verificato con un e2e reale che richiede root
(`make tun-demo`, su una singola macchina).

## Setup — server pubblico (coordinator + relay)

Il più semplice: un VPS economico (cloud ~$5/mese) + due reti diverse sul lato client
(es. Wi-Fi di casa + tethering da un telefono mobile).

1. Cross-compila i binari del server (linux/amd64):

   ```sh
   make build
   GOOS=linux GOARCH=amd64 go build -o bin/linux/coordinator ./cmd/coordinator
   GOOS=linux GOARCH=amd64 go build -o bin/linux/relay       ./cmd/relay
   GOOS=linux GOARCH=amd64 go build -o bin/linux/agent       ./cmd/agent
   scp bin/linux/{coordinator,relay,agent} user@vps:/opt/meshlink/
   ```

2. Apri nel security group: TCP **19200**, UDP **19201**, UDP **19205**
   (0.0.0.0/0; in produzione restringi per sorgente).

3. Esegui sul server:

   ```sh
   # coordinator: al primo avvio genera e stampa la propria chiave
   bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key
   # relay
   bin/relay -addr 0.0.0.0:19205
   ```

   Annotare la chiave `control public key ...: <hex>` dall'output — questa viene
   data ai **client** come `--coord-pubkey`.

## Client — su due reti diverse

4. Compila i binari del client (per macchina): per macOS `GOOS=darwin
   GOARCH=amd64` (o `arm64`), per Linux `GOOS=linux`.

5. Sulla macchina A (associa la socket dati a `0.0.0.0` — STUN deve vedere l'IP
   sorgente reale; se è associata a `127.0.0.1`, nessun buco può essere aperto):

   ```sh
   bin/agent up --name a --keyfile key.a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19501
   ```

   Verifica: la riga `public endpoint (STUN)` nel log deve mostrare un
   indirizzo **pubblico** (non 127.0.0.1). Per un NAT domestico, dovrebbe essere
   l'IP WAN.

6. Avvia la macchina B allo stesso modo con `--name b --data 0.0.0.0:19502`.

7. Esegui da B:

   ```sh
   bin/agent ping --name b --keyfile key.b --peer a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19502 --count 3 --interval 1s
   ```

Risultati attesi:

| Scenario | NATs | Expected path |
|---|---|---|
| Two home/ADSL NATs | fullcone / restricted | `direct` |
| Tethering / mobile | symmetric (or financial) | `relay` |
| Mixed | restricted + symmetric | `relay` |

Se appare `path=relay`, il sistema **funziona correttamente** — i NAT mobili
non possono essere forati e il fallback al relay tiene su il traffico. Entrambi i casi
sono una verifica valida per la Fase 4: qualunque percorso venga usato,
`received=count` deve valere.

## Usare TUN su una rete reale

Il percorso hole/relay funziona esattamente allo stesso modo; basta dare a ogni client
un indirizzo overlay:

```sh
# lato A
bin/agent up --name a --keyfile key.a \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up

# lato B
bin/agent up --name b --keyfile key.b \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19502 \
  --tun utun10 --tun-ip 10.62.0.2 --tun-peer a=10.61.0.1
sudo ifconfig utun10 10.62.0.2/24 up

# ping sulla macchina B attraverso l'overlay:
ping -c 3 10.61.0.1
```

(Su Linux si usano `/dev/net/tun` + `ip addr add ... dev meshlink0`; i dettagli
e le note sulle host route macOS sono in `docs/it/TUN.md`.)

## Pre-verifica locale (basta root, nessun VPS)

```sh
make tun-demo        # apre due utun, fa passare l'ICMP attraverso il tunnel con le host route
```

## Risoluzione dei problemi

| Symptom | Possible cause | Fix |
|---|---|---|
| STUN endpoint `127.0.0.1` | `--data 127.0.0.1:...` was used | `--data 0.0.0.0:19501` |
| Handshake timeout (control) | `--coord-pubkey` wrong/missing | Copy the `<hex>` from the server log |
| `ping`: no response | 19200/19201/19205 closed | Open the VPS security group |
| `path=relay` but packet loss | inbound UDP from relay to client closed | Allow inbound UDP on 19501/19502 in the local firewall on machines A/B |
| TUN ping 100% loss | `<peer>` overlay address inconsistent | `-tun-peer` must be symmetric on both sides |

## Nota di sicurezza

0.0.0.0/0 è aperto per la verifica; in seguito relay/coordinator dovrebbero essere
spostati in una whitelist o sotto controllo degli accessi nell'ambito del framework
dei "rischi accettati" della sezione 6 di `docs/it/THREAT_MODEL.md`
(rate-limiting/signature pinning del relay è già attivo nel codice).
