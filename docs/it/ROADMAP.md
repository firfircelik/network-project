# meshlink — Roadmap di produzione (v1)

Stato attuale: **Fase 1–3 completa; Fase 4 parziale** (codice TUN + documentazione
pronti; test NAT su internet reale aperto). Alla fine di ogni fase `gofmt` / `go vet` /
`go test -race` / `make demo` restano verdi.

## Fase 1 — Infrastruttura di fiducia/qualità (obiettivo: G7, G9) — ✅ completa

- ✅ GitHub Actions CI: `.github/workflows/ci.yml` — `gofmt`, `go vet`,
  `go test -race ./...`, `make demo`.
- ✅ Test di fuzz: decoder di `record`, `relay`, `nat`, `stun`, `protocol`
  (input malformato semplice, troncamento, esagerazione dei campi di lunghezza) +
  `make fuzz-smoke`.
- ✅ Letture di controllo con limite: tappo `maxMsgLen` in `control.ReadMsg`,
  lunghezze di handshake limitate a 16 bit; superficie DoS sulla memoria chiusa.
- ✅ Log strutturato: `log/slog` (`level=INFO msg=...`), error/warning/info.
- ✅ Configurazione: validazione dei flag (`--name`/`--keyfile`/`--coord-pubkey`
  obbligatori); quando il file delle chiavi manca viene creato con `0600` e i permessi
  sono preservati. (Configurazione basata su variabili d'ambiente → v1.1+.)

## Fase 2 — Rafforzamento del core del tunnel (obiettivo: G1, G8) — ✅ completa

- ✅ **Finestra anti-replay + tolleranza alla perdita:** nonce esplicito a 64 bit nei
  frame DATA; finestra scorrevole stile WireGuard sul ricevitore (bitmap, 2048
  pacchetti). Record/replay molto vecchi rifiutati; la sessione non si blocca dopo una
  perdita (`internal/noisework`, `internal/peer`).
- ✅ **Rekey periodico:** il messaggio `RekeyEvery` innesca una rotazione delle chiavi;
  entrambe le direzioni allo stesso limite, pacchetti persi tracciati tramite salti di
  epoch.
- ✅ Protezione dall'esaurimento dei nonce (`MaxNonce`), tappo anti-DoS `maxEpochJump`
  e limite di età della sessione.
- ✅ Test: drop, replay, arrivo fuori ordine, nonce obsoleto, gap di rekey
  (`TestDecryptAtLossReorderAndRekey`, `TestRekeyRotatesKeys`,
  `TestRekeyJumpCapped`).

## Fase 3 — Sicurezza di controllo + relay (obiettivo: G2–G5) — ✅ completa

- ✅ **Pinning del nome nel relay:** se cambia l'indirizzo di rete associato a un nome,
  non può essere rivendicato da un altro canale (dirottamento del nome/interruzione
  della consegna chiusi).
- ✅ **Relay rate-limit/quota:** limite pps/byte per indirizzo sorgente + quota per
  nome; superficie di amplificazione ridotta.
- ✅ **Budget di handshake/CPU + timeout di handshake:** limite dello stato di
  handshake concorrente sul lato risponditore e timeout espliciti di
  takeover/decadimento (relay + controllo).
- ✅ **Auth Noise del piano di controllo:** canale di register crittografato con Noise
  XX e chiave del coordinator pinata sul client; associazione nome→chiave verificata
  sul lato coordinator (mancate corrispondenze identità/chiave rifiutate).

## Fase 4 — Trasporto dati reale (TUN) (obiettivo: G6) — 🔶 parziale

- ✅ `internal/tun`: apertura dell'interfaccia utun/TUN, routing IPv4 (`Router`),
  dispositivo di test in memoria (`BufferDevice`); macOS `utun`, Linux `/dev/net/tun`.
- ✅ Bridge agent→tun: `internal/agent/tunbridge.go` — instrada i dati delle sessioni
  crittografate come pacchetti IP (`-tun`, `-tun-ip`,
  `-tun-peer id=ip`).
- ✅ Passi di configurazione dell'indirizzo a livello di OS (richiede root) →
  `docs/it/TUN.md`.
- ⏸ Test NAT su internet reale (oltre il simulatore) — aperto; richiede validazione
  su una rete reale.

## Passi successivi (v1.1+)

- Configurazione basata su variabili d'ambiente; validazione NAT su internet reale
  (residuo della Fase 4).
- Rotazione live della configurazione; key store crittografico/KMS; metriche
  Prometheus; protezione della memoria in chiaro (mlock); timeout di sessione stile
  WireGuard; stato di salute di handshake/funzioni core.
