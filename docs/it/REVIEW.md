# meshlink — Report della code review

Data: 2026-08-19 · Ambito: tutto il sorgente, i test, la documentazione, il Makefile,
lo script demo.
Metodo: review a 5 assi + verifica live tramite `gofmt` / `go vet` / `go test -race` / `make demo`.

---

## Stato

| Item | Severity | Status |
|---|---|---|
| H1 — `Peer.Run` didn't watch `p.done` → goroutine leak | High | ✅ Fixed + regression test |
| H2 — Restricted NAT `contactIP` wasn't accumulating | High | ✅ Fixed + multi-target test |
| H3 — No coordinator ID→pubkey pinning | Medium/security | ✅ Fixed + test |
| M1 — Relay source name unverified | Medium/security | ✅ Fixed (Phase 3: name→address pinning) + test |
| M2 — `MaxPlaintextLen` exceeded the UDP limit | Medium | ✅ Fixed (65504; relay path further narrowed) |
| M3 — `scripts/demo.sh` wasn't executable | Medium | ✅ `chmod +x` |
| M4 — README stale natbox flags | Medium | ✅ Updated |
| M5 — `disco.MaxPunchAttempts` dead constant + SPEC "max 10" | Medium | ✅ Removed / documented |
| D1 — nat `wg.Add`/`Wait` concurrency | Low | ✅ `closed` guard |
| D2 — Ping summary path captured at run start | Low | ✅ Read at end of run |
| D3 — Control conn. has no write deadline | Low | ✅ `broadcastWriteDeadline` + write mutex |
| D4 — Ping send error was being swallowed | Low | ✅ Logged |
| D5 — JSON decoding error was silent | Low | ✅ Logged |
| D6 — `nat.decodeOutbound` test shim in production | Low | ✅ Moved to test file |
| D7 — `go.mod` `// indirect` comments | Low | ✅ `go mod tidy` |
| D8 — `receiveLoop` copy on every packet | Low | ✅ Only matching frame is copied |
| Bonus | — | ✅ Dead `peer.maxPlaintext()` removed |

## Verifica

```
gofmt -l .                → vuoto
go vet ./...              → pulito
go build ./...            → ok
go test -count=1 -race ./... → tutto ok (inclusi i nuovi test di control/coordinator/peer/nat/agent/tun)
make demo                 → phase 1 path=direct PASS · phase 2 path=relay PASS
```

---

## Risultati della sessione precedente e dettagli della risoluzione

### H1 — `Peer.Run` non osserva `p.done` (goroutine leak)
`internal/peer/peer.go` — `Run` aspettava solo su `ctx.Done()`; il `p.done` chiuso da
`Close()` non veniva osservato nel loop e `p.recv` non veniva mai chiuso (due goroutine
che perdevano per sempre la prune di `applyPeers`). Correzione:

- `p.done` ora si chiude esattamente una volta tramite `doneOnce sync.Once`.
- Il defer di `Run` chiude `recv` sotto lock (nessuna race di send concorrente).
- `onData` fa una send protetta (`closed`/`recvClosed`) e non bloccante sotto lock.
- Test di regressione: `internal/peer/peer_test.go` (`TestRunExitsWhenClosed`,
  `TestRunExitsOnCancel`, `TestNoDataAfterClose`).

### H2 — Accumulo di `contactIP` nel NAT restricted
`internal/nat/nat.go` — `e.contactIP[ipKey(dst.IP)] = true` mancava nel ramo di
refresh del mapping; l'host stava erroneamente DROPPando il traffico inbound dagli IP
che aveva contattato in seguito. Test di regressione:
`internal/nat/nat_test.go` → `TestAddressRestrictedMultiTarget`.

### H3 — Pinning della chiave del coordinator
`internal/coordinator/coordinator.go` — Una `PubKey` diversa con lo stesso ID
solleva un TypeError (la registrazione non viene sovrascritta); una pubkey vuota viene
rifiutata; la ri-registrazione con la stessa chiave (refresh degli endpoint) resta
libera. Test di regressione: `TestRegistrationKeyPinning`.

### M2 — Contratto sulla dimensione dei datagrammi
- `internal/noisework/noisework.go`: `maxPlaintextLen = 65507 - 3 - 16 = 65504`
  (25535 − IP(20) − UDP(8) headers; frame hdr 3; AEAD tag 16).
- `internal/relay/relay.go`: `MaxHeaderLen` esportata (worst case 133 B).
- `internal/peer/peer.go`: il limite di `Send` sul percorso relay è
  `MaxPlaintextLen - MaxHeaderLen`.
- Test/SPEC/noisework_test adattati; preservato il contratto di codifica 65535 di
  `record` (un limite del codec, non un singolo pacchetto).

### D8 — Riduzione delle allocazioni in `receiveLoop`
`internal/agent/agent.go` — Una copia dedicata del frame viene fatta solo per il frame
corrispondente; i datagrammi non corrispondenti (scartati come inattivi) vengono
eliminati senza copiarli dal buffer condiviso. Il demux del relay resta per ID del peer.

---

## Risultati aggiuntivi della sessione Fase 3/4

### D9 — Scrittori di controllo concorrenti potevano corrompere i frame (Alto)
`internal/control` — Due istanze `handleClient` potevano scrivere in concorrenza sullo
stesso `*control.Conn` del client (broadcast + risposta personale); poiché `WriteMsg`
eseguiva due chiamate `Write` separate (header di lunghezza + testo cifrato), il framing
poteva corrompersi sotto `-race`. Correzione: `Conn.wm sync.Mutex` + scrittura atomica
su buffer singolo. `TestRegistrationAndBroadcast` è stato reso deterministico
nell'ordinamento.

### D10 — L'handshake di controllo non aveva timeout (Medio)
`internal/control` — Poiché `Initiate`/`Accept` non erano delimitati da un
`handshakeTimeout`, peer bloccati potevano inchiodare l'accettatore. Correzione:
`SetDeadline(handshakeTimeout)` all'ingresso, rimosso dopo il successo.
`TestWrongCoordinatorKey` ora ritorna in modo deterministico sul lato client.

### Y1 — Bridge TUN (Fase 4 / G6, parziale)
`internal/tun` (apertura utun/TUN, forwarding IPv4 `Router`, `BufferDevice`) +
`internal/agent/tunbridge.go` (ponte dispositivo ⇄ sessione peer, `-tun`/`-tun-ip`/
`-tun-peer`). Unit test senza root: `internal/tun/tun_test.go`,
`internal/agent/tunbridge_test.go`. L'apertura del dispositivo reale è saltata nei test
tramite `t.Skip`; la verifica su rete reale è un residuo della Fase 4 (`docs/it/TUN.md`).

---

## Valutazione della copertura dei test

Presenti: record, noisework, stun, nat, relay, coordinator, protocol, peer,
control, tun, agent (tun bridge) — molto buono. Fuzzer: record, relay, nat,
stun, protocol. Aperti (v1.1): verifica NAT su internet reale; lifecycle e2e live del
TUN (richiede root).

## Chiusura

Tutte le voci applicabili del report sono state risolte e la verifica è stata fatta su
tre livelli (unit test `-race`, `go vet`/`gofmt`, end-to-end `make demo`). M1
(autenticazione lato relay) è stata chiusa nella Fase 3; i test su rete reale sono
stati lasciati intenzionalmente come residuo della Fase 4.
