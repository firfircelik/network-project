# meshlink — Architektur

`meshlink` ist ein in Go gebautes Mini-Zero-Trust-Mesh-VPN: eine
verschlüsselte Transportschicht, NAT-Traversal, Transport-Fallback und ein
modularer Client. Während der Entwicklung läuft es vollständig auf localhost —
NAT-Boxen werden simuliert, sodass Hole Punching und Relay-Fallback ohne Root
oder echte Netzwerkhardware demonstriert werden können.

## Komponenten

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

## Datenebene

- Jedes UDP-Datagramm ist ein *Frame*: `[1B type][2B length][payload]`
  (siehe `internal/record`).
- Verschlüsselung: Noise Protocol Framework, **XX-Muster**,
  `DH25519 + ChaCha20-Poly1305 + SHA256`, Prolog `meshlink-v1`
  (siehe `internal/noisework`).
- Identität: jeder Agent hält ein persistentes X25519-Schlüsselpaar. Der
  Koordinator verteilt öffentliche Schlüssel; nach dem XX-Handshake
  **verifizieren** beide Seiten den statischen Schlüssel des Peers gegen den
  beim Koordinator registrierten Schlüssel. Das Relay sieht nie Klartext —
  die Verschlüsselung ist Ende-zu-Ende.
- Rollen: die lexikografisch kleinere Agent-ID ist der Handshake-Initiator,
  sodass sich beide Seiten ohne zusätzliche Signalisierung einig sind
  (`internal/disco`).

## Pfadauswahl

1. **Direkt (P2P):** beide Seiten senden Probes (`type=4`) an den jeweils
   angekündigten Endpunkt, um NAT-Mappings zu öffnen, und führen dann den
   Noise-Handshake aus.
2. **Relay-Fallback:** kann der direkte Handshake innerhalb von
   `disco.DirectAttempt` nicht abgeschlossen werden, wechselt der
   Datenverkehr zum Relay: Frames werden mit `[magic 0x52][src][dst][frame]`
   umhüllt; das Relay leitet Ciphertext anhand der Peer-ID weiter
   (`internal/relay`).
3. **Rückwechsel:** Solange der Agent über das Relay verbunden ist, probt er
   weiterhin den direkten Pfad (`disco.ReestablishInterval`) und führt bei
   Möglichkeit erneut den Handshake über P2P aus.

## NAT-Simulation (`internal/nat`, `cmd/natbox`)

Eine natbox hat einen *öffentlichen* Socket (die Sicht der Außenwelt) und eine
*Innentür* (*inside door*). Agents dahinter verlassen das Netz durch die Tür
(Wrapper `[dst][payload]`). Verhaltensweisen:

- `fullcone`    — ein Mapping pro internem Host; eingehend von jeder Quelle OK.
- `restricted`  — eingehend nur von IPs, die zuvor kontaktiert wurden.
- `symmetric`   — **ein neuer öffentlicher Port pro Ziel**; eingehend nur über
  das exakte Mapping, das der Peer zur Erreichung verwendet hat. Genau das
  lässt klassisches Simultaneous-Open-Hole-Punching scheitern und demonstriert
  das Relay.

## Kontrollebene (`internal/protocol`, `internal/coordinator`)

Agents verbinden sich mit dem `coordinator` (TCP), senden
`register {id, pubkey, endpoints}` und empfangen `peer_list`-Broadcasts mit
jedem registrierten Peer. Der erste Endpunkt ist die über STUN gelernte
öffentliche Adresse; der zweite (optional) ist das Relay. Eine erneute
Registrierung aktualisiert die Endpunkt-Mappings. Der Koordinator beantwortet
außerdem STUN-Binding-Requests auf einem UDP-Port.

## Ping / Erreichbarkeit

Eine etablierte Sitzung überträgt JSON-Nachrichten über Noise:
`{"cmd":"ping","s":seq,"ts":nanos}` → `{"cmd":"pong","s":seq,"ts":nanos}`.
Der Pinger meldet RTT, Verlust und den aktiven Pfad (`direct|relay`).

## Bekannte Einschränkungen (MVP)

- Die Kontrollebene authentifiziert über Noise XX und pinnt den statischen
  Schlüssel des Koordinators, hat aber kein TLS-Zertifikat-Konzept; das
  Vertrauen in den Betreiber erfolgt out-of-band (Schlüsselverteilung).
- Sitzungen wechseln relay→direct, aber nicht direct→relay mitten in der
  Sitzung.
- Overlay-Adressen werden statisch zugewiesen (`-tun-peer`); noch keine
  dynamische Adressvergabe.
- TUN-Unterstützung existiert (`internal/tun`,
  `internal/agent/tunbridge.go`), erfordert aber Root und wird von
  `make demo` nicht ausgeführt; die NAT-Verifikation im realen Internet (über
  den Simulator hinaus) ist ein offener Punkt der Phase 4.

## Verzeichnisübersicht

```
cmd/{coordinator,relay,natbox,agent}   thin binaries
internal/record      frame codec
internal/noisework   Noise XX handshake + session (rekey, replay window)
internal/control     authenticated control connection + framing
internal/stun        RFC 8489 binding client/server
internal/nat         NAT simulator
internal/relay       UDP relay server (name pinning, rate limits)
internal/protocol    control-plane JSON
internal/coordinator control-plane server (Noise-auth, key pinning)
internal/disco       punching policy (timing, roles, path enum)
internal/peer        per-peer session state machine
internal/agent       client glue (keys, STUN, register, receive loop)
internal/tun         TUN device + IPv4 route table (Faz 4)
```
