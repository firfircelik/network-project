# meshlink — NAT-Verifikation im realen Internet (Restposten aus Phase 4)

Die Demo **simuliert** das NAT-Verhalten mit `natbox`
(fullcone/restricted/symmetric). Um die Verifikation abzuschließen, muss
derselbe Ablauf über ein **echtes Netzwerk** gezeigt werden:

- **Direktes Hole Punching (path=direct)** bei mindestens einem Cone-/
  Restricted-Paar,
- **Relay-Fallback (path=relay)**, wenn der direkte Pfad scheitert.

Außerdem wird die TUN-Brücke mit einem echten E2E-Test verifiziert, der Root
erfordert (`make tun-demo`, auf einer einzelnen Maschine).

## Einrichtung — öffentlicher Server (Koordinator + Relay)

Am einfachsten: ein günstiger VPS (Cloud ~5 $/Monat) + zwei verschiedene
Netzwerke auf der Client-Seite (z. B. Heim-WLAN + Tethering über ein
Mobiltelefon).

1. Die Server-Binaries cross-kompilieren (linux/amd64):

   ```sh
   make build
   GOOS=linux GOARCH=amd64 go build -o bin/linux/coordinator ./cmd/coordinator
   GOOS=linux GOARCH=amd64 go build -o bin/linux/relay       ./cmd/relay
   GOOS=linux GOARCH=amd64 go build -o bin/linux/agent       ./cmd/agent
   scp bin/linux/{coordinator,relay,agent} user@vps:/opt/meshlink/
   ```

2. In der Sicherheitsgruppe öffnen: TCP **19200**, UDP **19201**, UDP **19205**
   (0.0.0.0/0; in der Produktion nach Quelle einschränken).

3. Auf dem Server ausführen:

   ```sh
   # koordinatör: ilk çalıştırmada anahtarını üretir ve yazdırır
   bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key
   # relay
   bin/relay -addr 0.0.0.0:19205
   ```

   Notieren Sie den Schlüssel `control public key ...: <hex>` aus der Ausgabe —
   dieser wird den **Clients** als `--coord-pubkey` übergeben.

## Clients — in zwei verschiedenen Netzwerken

4. Die Client-Binaries bauen (pro Maschine): für macOS `GOOS=darwin
   GOARCH=amd64` (oder `arm64`), für Linux `GOOS=linux`.

5. Auf Maschine A (den Datensocket an `0.0.0.0` binden — STUN muss die echte
   Quell-IP sehen; wenn an `127.0.0.1` gebunden wird, kann kein Loch geöffnet
   werden):

   ```sh
   bin/agent up --name a --keyfile key.a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19501
   ```

   Verifikation: Die Zeile `public endpoint (STUN)` im Log muss eine
   **öffentliche** Adresse zeigen (nicht 127.0.0.1). Bei einem Heim-NAT sollte
   dies die WAN-IP sein.

6. Maschine B auf dieselbe Weise mit `--name b --data 0.0.0.0:19502` starten.

7. Von B aus ausführen:

   ```sh
   bin/agent ping --name b --keyfile key.b --peer a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19502 --count 3 --interval 1s
   ```

Erwartete Ergebnisse:

| Szenario | NATs | Erwarteter Pfad |
|---|---|---|
| Zwei Heim-/ADSL-NATs | fullcone / restricted | `direct` |
| Tethering / Mobilfunk | symmetric (oder Financial) | `relay` |
| Gemischt | restricted + symmetric | `relay` |

Wenn `path=relay` erscheint, arbeitet das System **korrekt** — Mobilfunk-NATs
lassen sich nicht per Hole Punching durchdringen und der Relay-Fallback hält
den Verkehr aufrecht. Beide Fälle sind eine gültige Verifikation für Phase 4:
Unabhängig davon, welcher Pfad verwendet wird, muss `received=count` gelten.

## TUN in einem echten Netzwerk verwenden

Der Hole-/Relay-Pfad funktioniert exakt gleich; geben Sie jedem Client
lediglich eine Overlay-Adresse:

```sh
# A tarafı
bin/agent up --name a --keyfile key.a \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up

# B tarafı
bin/agent up --name b --keyfile key.b \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19502 \
  --tun utun10 --tun-ip 10.62.0.2 --tun-peer a=10.61.0.1
sudo ifconfig utun10 10.62.0.2/24 up

# B makinede overlay boyunca ping:
ping -c 3 10.61.0.1
```

(Unter Linux werden `/dev/net/tun` + `ip addr add ... dev meshlink0`
verwendet; Details und Hinweise zu Host-Routen unter macOS stehen in
`docs/de/TUN.md`.)

## Lokale Vorverifikation (Root genügt, kein VPS)

```sh
make tun-demo        # iki utun açar, host route'larla tünelden ICMP geçirir
```

## Fehlerbehebung

| Symptom | Mögliche Ursache | Lösung |
|---|---|---|
| STUN-Endpunkt `127.0.0.1` | `--data 127.0.0.1:...` wurde verwendet | `--data 0.0.0.0:19501` |
| Handshake-Timeout (Kontrolle) | `--coord-pubkey` falsch/fehlt | `<hex>` aus dem Server-Log kopieren |
| `ping`: keine Antwort | 19200/19201/19205 geschlossen | Die VPS-Sicherheitsgruppe öffnen |
| `path=relay`, aber Paketverlust | eingehendes UDP vom Relay zum Client geschlossen | Eingehendes UDP auf 19501/19502 in der lokalen Firewall der Maschinen A/B erlauben |
| TUN-Ping 100 % Verlust | `<peer>`-Overlay-Adresse inkonsistent | `-tun-peer` muss auf beiden Seiten symmetrisch sein |

## Sicherheitshinweis

0.0.0.0/0 ist für die Verifikation geöffnet; danach sollten Relay/Koordinator
im Rahmen der „akzeptierten Risiken" aus Abschnitt 6 von
`docs/de/THREAT_MODEL.md` auf eine Whitelist oder Zugriffskontrolle umgestellt
werden (Ratenlimitierung/Signatur-Pinning des Relays ist im Code bereits
aktiv).