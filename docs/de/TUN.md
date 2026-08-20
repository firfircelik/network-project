# meshlink TUN (Echter Datentransport)

Ziel von Phase 4 (G6): echten IP-Verkehr über verschlüsselte Sitzungen
transportieren. `agent up` öffnet eine TUN-Schnittstelle (macOS `utunN`,
Linux `/dev/net/tun`), leitet die von der Schnittstelle gelesenen IP-Pakete
gemäß der Overlay-Adresstabelle zur verschlüsselten Sitzung des richtigen
Peers; entschlüsselte Pakete, die von Peers kommen, schreibt es an die
Schnittstelle.

## Verifikation

- **Einzelne Maschine (Root genügt):** `make tun-demo` — zwei utun
  + zwei `agent up` auf einer einzelnen Maschine, ICMP-Verkehr wird mit
  `-host`/`ip route` durch den Tunnel gezwungen und `ping 10.62.0.2` wird
  verifiziert (siehe: `scripts/tun-demo.sh`).
- **Reales Internet:** Clients in zwei verschiedenen Netzwerken +
  Koordinator/Relay auf einem öffentlichen VPS → `docs/de/REALNET.md`.

## Architektur

```
                    ┌──────────────────────────── agent ────────────────────────────┐
  OS routing table  │                                                              │
  dst 10.60.0.2 ──► │ TUN device ──► tun.Router ──(dest IP lookup)──► peer.Send()   │ ─► Noise sessi
    (utun9, dev)    │                    ▲                                           │
                    │                    │          decrypted payloads (p.Recv())    │
                    │                    └──────────── tunnel bridge ────────────────┘ ◄─ Noise session
                    └──────────────────────────────────────────────────────────────┘
```

- `internal/tun`: TUN-Gerätezugriff (`Device`) + IPv4-Routing (`Router`)
  + ein In-Memory-Gerät für Tests (`BufferDevice`).
- `internal/agent/tunbridge.go`: die Brücke zwischen dem Gerät und den
  Peer-Sitzungen.
- Overlay-Adresszuweisungen erfolgen mit `-tun-peer <id>=<ip>`; sobald der
  Name vom Koordinator gelernt wird, wird die Route installiert.

## Einrichtung und Ausführung unter macOS (erfordert Root)

1. Koordinator bauen und starten:

   ```sh
   make build
   bin/coordinator -keyfile bin/coord.key
   ```

   Notieren Sie den Wert `control public key ...: <hex>` in der Ausgabe.

2. Agent-„a"-Seite (utun9):

   ```sh
   bin/agent up --name a --keyfile bin/key.a \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19501 \
     --tun utun9 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
   sudo ifconfig utun9 10.60.0.1/24 up
   ```

3. Agent-„b"-Seite (utun10):

   ```sh
   bin/agent up --name b --keyfile bin/key.b \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19502 \
     --tun utun10 --tun-ip 10.60.0.2 --tun-peer a=10.60.0.1
   sudo ifconfig utun10 10.60.0.2/24 up
   ```

4. Test:

   ```sh
   ping -c 3 10.60.0.2   # on laptop a: ICMP to b passes through the tunnel
   ```

## Einrichtung und Ausführung unter Linux

Gleiche Flags; das TUN-Gerät verwendet `/dev/net/tun` (IFF_TUN|IFF_NO_PI)
über `internal/tun/tun_linux.go`. Wird der Name leer gelassen, öffnet der
Kernel eine freie Schnittstelle als `meshlink%d`:

```sh
sudo ip tuntap add dev meshlink0 mode tun
bin/agent up --name a ... --tun meshlink0 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
sudo ip addr add 10.60.0.1/24 dev meshlink0
sudo ip link set meshlink0 up
```

## Geräteübergreifender Test — Linux + macOS im selben LAN

Zwei getrennte Maschinen, zwei getrennte Betriebssysteme, dasselbe Netzwerk:
Die Agents sehen sich per direktem Hole Punching (`path=direct`) und pingen
sich über das Overlay. Da das Drahtformat in allen Längenfeldern Big-Endian
ist, gibt es keinen Plattformunterschied; nur der Gerätename und der
Schnittstellenbefehl sind OS-spezifisch. Auch hier werden `/32`-Routen
benötigt — andernfalls versucht der Kernel, das Overlay-Ziel über das
Standard-Gateway zu erreichen.

Mac (z. B. `192.168.1.10`): Koordinator + Relay + Agent a

```sh
bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key &
bin/relay -addr 0.0.0.0:19205 &
# read <coord_pub_hex> from the output

bin/agent up --name a --keyfile key.a \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up
sudo route add -host 10.62.0.2 -interface utun9
ping -c 3 10.62.0.2
```

Linux (z. B. `192.168.1.20`): Agent b

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

Wenn auf beiden Seiten `ping` verlustfrei ist und die Zeile
`public endpoint (STUN)` in den Logs die LAN-IP der anderen Maschine zeigt,
ist **das plattformübergreifende Mesh verifiziert (`path=direct`)**. Dasselbe
Rezept gilt für das reale Internet; der einzige Unterschied ist, dass
Koordinator/Relay auf einem öffentlichen VPS laufen (`docs/de/REALNET.md`).

## Grenzen und Details

- Overlay-Adressen werden mit einer statischen `-tun-peer`-Tabelle verwaltet
  (WireGuard-`AllowedIPs`-artig); dynamische Vergabe steht auf der Liste
  „v1.1+".
- Das Routing ist für reines IPv4 (L3 TUN); L2 (TAP)/IPv6 in einer späteren
  Version.
- TUN-Zugriff erfordert Root; Tests laufen ohne Root mit `BufferDevice`, und
  wenn kein echtes Gerät geöffnet werden kann, wird der Test mit `t.Skip`
  übersprungen.
- Ziele, die nicht in der Routingtabelle stehen, werden still verworfen
  (`PktsDropped`); die Zähler `Pings/Routed/Dropped` werden auf `Router`
  geführt.