# meshlink — Code-Review-Bericht

Datum: 2026-08-19 · Umfang: gesamter Quellcode, Tests, Dokumentation,
Makefile, Demo-Skript. Methode: 5-Achsen-Review + Live-Verifikation über
`gofmt` / `go vet` / `go test -race` / `make demo`.

---

## Status

| Punkt | Schweregrad | Status |
|---|---|---|
| H1 — `Peer.Run` hat `p.done` nicht überwacht → Goroutine-Leak | Hoch | ✅ Behoben + Regressionstest |
| H2 — `contactIP` des Restricted-NAT hat sich nicht akkumuliert | Hoch | ✅ Behoben + Multi-Target-Test |
| H3 — Kein Pinning von Koordinator-ID→Pubkey | Mittel/Sicherheit | ✅ Behoben + Test |
| M1 — Quellname des Relays nicht verifiziert | Mittel/Sicherheit | ✅ Behoben (Phase 3: Name→Adresse-Pinning) + Test |
| M2 — `MaxPlaintextLen` überschritt das UDP-Limit | Mittel | ✅ Behoben (65504; Relay-Pfad weiter verengt) |
| M3 — `scripts/demo.sh` war nicht ausführbar | Mittel | ✅ `chmod +x` |
| M4 — Veraltete natbox-Flags in der README | Mittel | ✅ Aktualisiert |
| M5 — Tote Konstante `disco.MaxPunchAttempts` + SPEC „max 10" | Mittel | ✅ Entfernt / dokumentiert |
| D1 — `wg.Add`/`Wait`-Nebenläufigkeit in nat | Niedrig | ✅ `closed`-Guard |
| D2 — Ping-Zusammenfassungspfad beim Start erfasst | Niedrig | ✅ Am Ende des Laufs gelesen |
| D3 — Kontrollverbindung hat keine Schreib-Deadline | Niedrig | ✅ `broadcastWriteDeadline` + Schreib-Mutex |
| D4 — Ping-Sendefehler wurde verschluckt | Niedrig | ✅ Protokolliert |
| D5 — JSON-Decodierungsfehler war still | Niedrig | ✅ Protokolliert |
| D6 — `nat.decodeOutbound`-Test-Shim in der Produktion | Niedrig | ✅ In die Testdatei verschoben |
| D7 — `// indirect`-Kommentare in `go.mod` | Niedrig | ✅ `go mod tidy` |
| D8 — Kopie in `receiveLoop` bei jedem Paket | Niedrig | ✅ Nur der passende Frame wird kopiert |
| Bonus | — | ✅ Totes `peer.maxPlaintext()` entfernt |

## Verifikation

```
gofmt -l .                → boş
go vet ./...              → temiz
go build ./...            → ok
go test -count=1 -race ./... → tümü ok (control/coordinator/peer/nat/agent/tun yeni testler dahil)
make demo                 → phase 1 path=direct PASS · phase 2 path=relay PASS
```

---

## Befunde der vorherigen Sitzung und Auflösungsdetails

### H1 — `Peer.Run` überwacht `p.done` nicht (Goroutine-Leak)
`internal/peer/peer.go` — `Run` wartete nur auf `ctx.Done()`; das von
`Close()` geschlossene `p.done` wurde in der Schleife nicht überwacht und
`p.recv` wurde nie geschlossen (zwei Goroutines, die den `applyPeers`-Prune
dauerhaft leaken). Behebung:

- `p.done` wird jetzt über `doneOnce sync.Once` genau einmal geschlossen.
- Das `defer` von `Run` schließt `recv` unter Lock (keine Nebenläufigkeits-Race
  beim Senden).
- `onData` führt unter Lock einen geschützten (`closed`/`recvClosed`), nicht
  blockierenden Send aus.
- Regressionstest: `internal/peer/peer_test.go` (`TestRunExitsWhenClosed`,
  `TestRunExitsOnCancel`, `TestNoDataAfterClose`).

### H2 — Akkumulation von `contactIP` im Restricted-NAT
`internal/nat/nat.go` — `e.contactIP[ipKey(dst.IP)] = true` fehlte im
Mapping-Refresh-Zweig; der Host verwarf fälschlich eingehenden Verkehr von
IPs, die er später kontaktiert hatte. Regressionstest:
`internal/nat/nat_test.go` → `TestAddressRestrictedMultiTarget`.

### H3 — Schlüssel-Pinning des Koordinators
`internal/coordinator/coordinator.go` — Ein anderer `PubKey` mit derselben ID
löst einen TypeError aus (die Registrierung wird nicht überschrieben); ein
leerer Pubkey wird abgelehnt; eine erneute Registrierung mit demselben
Schlüssel (Endpunkt-Refresh) bleibt möglich. Regressionstest:
`TestRegistrationKeyPinning`.

### M2 — Datagramm-Größenvertrag
- `internal/noisework/noisework.go`: `maxPlaintextLen = 65507 - 3 - 16 = 65504`
  (25535 − IP(20) − UDP(8)-Header; Frame-Header 3; AEAD-Tag 16).
- `internal/relay/relay.go`: `MaxHeaderLen` exportiert (schlimmster Fall 133 B).
- `internal/peer/peer.go`: Das `Send`-Limit auf dem Relay-Pfad ist
  `MaxPlaintextLen - MaxHeaderLen`.
- Test/SPEC/noisework_test angepasst; der 65535-Encoding-Vertrag von `record`
  (ein Codec-Limit, kein einzelnes Paket) bleibt erhalten.

### D8 — Reduzierung der Allokationen in `receiveLoop`
`internal/agent/agent.go` — Eine eigene Frame-Kopie wird nur für den passenden
Frame erstellt; nicht passende (im Leerlauf verworfene) Datagramme werden ohne
Kopieren aus dem gemeinsamen Puffer verworfen. Die Relay-Demultiplexierung
erfolgt weiterhin anhand der Peer-ID.

---

## Zusätzliche Befunde der Phase-3/4-Sitzung

### D9 — Gleichzeitige Kontroll-Schreiber konnten Frames beschädigen (Hoch)
`internal/control` — Zwei `handleClient`-Instanzen konnten gleichzeitig in
dieselbe Client-`*control.Conn` schreiben (Broadcast + persönliche Antwort);
da `WriteMsg` zwei separate `Write`-Aufrufe machte (Längen-Header +
Ciphertext), konnte das Framing unter `-race` beschädigt werden. Behebung:
`Conn.wm sync.Mutex` + atomarer Schreibvorgang aus einem einzelnen Puffer.
`TestRegistrationAndBroadcast` wurde in der Reihenfolge deterministisch
gemacht.

### D10 — Kontroll-Handshake hatte kein Timeout (Mittel)
`internal/control` — Da `Initiate`/`Accept` nicht durch ein `handshakeTimeout`
begrenzt waren, konnten hängende Peers den Akzeptor blockieren. Behebung:
`SetDeadline(handshakeTimeout)` beim Eintritt, nach Erfolg gelöscht.
`TestWrongCoordinatorKey` kehrt nun clientseitig deterministisch zurück.

### Y1 — TUN-Brücke (Phase 4 / G6, teilweise)
`internal/tun` (utun/TUN-Öffnung, IPv4-Weiterleitung per `Router`,
`BufferDevice`) + `internal/agent/tunbridge.go` (Brücke Gerät ⇄ Peer-Sitzung,
`-tun`/`-tun-ip`/`-tun-peer`). Rootlose Unit-Tests:
`internal/tun/tun_test.go`, `internal/agent/tunbridge_test.go`. Das Öffnen
echter Geräte wird in Tests über `t.Skip` übersprungen; die Verifikation im
realen Netzwerk ist ein Restposten aus Phase 4 (`docs/de/TUN.md`).

---

## Bewertung der Testabdeckung

Vorhanden: record, noisework, stun, nat, relay, coordinator, protocol, peer,
control, tun, agent (TUN-Brücke) — sehr gut. Fuzzer: record, relay, nat,
stun, protocol. Offen (v1.1): NAT-Verifikation im realen Internet; Live-E2E-
TUN-Lebenszyklus (erfordert Root).

## Abschluss

Alle zutreffenden Punkte des Berichts wurden behoben und die Verifikation
erfolgte in drei Ebenen (Unit-Test `-race`, `go vet`/`gofmt`,
End-to-End-`make demo`). M1 (Relay-seitige Authentifizierung) wurde in Phase 3
geschlossen; Tests im realen Netzwerk wurden bewusst als Restposten aus Phase 4
belassen.