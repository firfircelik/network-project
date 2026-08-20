# meshlink — Produktions-Roadmap (v1)

Aktueller Status: **Phase 1–3 abgeschlossen; Phase 4 teilweise** (TUN-Code +
Dokumentation fertig; NAT-Test im realen Internet offen). Am Ende jeder Phase
bleiben `gofmt` / `go vet` / `go test -race` / `make demo` grün.

## Phase 1 — Vertrauens-/Qualitätsinfrastruktur (Ziel: G7, G9) — ✅ abgeschlossen

- ✅ GitHub Actions CI: `.github/workflows/ci.yml` — `gofmt`, `go vet`,
  `go test -race ./...`, `make demo`.
- ✅ Fuzz-Tests: Decoder von `record`, `relay`, `nat`, `stun`, `protocol`
  (einfache fehlerhafte Eingaben, Abschneiden, Übertreibung der
  Längenfelder) + `make fuzz-smoke`.
- ✅ Begrenzte Kontroll-Reads: `control.ReadMsg` mit `maxMsgLen`-Obergrenze,
  Handshake-Längen mit 16-Bit-Obergrenze; Memory-DoS-Fläche geschlossen.
- ✅ Strukturierte Protokollierung: `log/slog` (`level=INFO msg=...`),
  error/warning/info.
- ✅ Konfiguration: Flag-Validierung (`--name`/`--keyfile`/`--coord-pubkey`
  erforderlich); wenn die Schlüsseldatei fehlt, wird sie mit `0600` erstellt
  und die Berechtigungen bleiben erhalten.
  (Konfiguration über Umgebungsvariablen → v1.1+.)

## Phase 2 — Härtung des Tunnelkerns (Ziel: G1, G8) — ✅ abgeschlossen

- ✅ **Replay-Fenster + Verlusttoleranz:** explizite 64-Bit-Nonce in
  DATA-Frames; WireGuard-artiges Schiebefenster beim Empfänger (Bitmap,
  2048 Pakete). Sehr alte Datensätze/Replays werden abgelehnt; die Sitzung
  hängt nach Verlusten nicht (`internal/noisework`, `internal/peer`).
- ✅ **Periodisches Rekeying:** `RekeyEvery` Nachrichten lösen eine
  Schlüsselrotation aus; beide Richtungen bei derselben Grenze, verlorene
  Pakete werden über Epochensprünge verfolgt.
- ✅ Nonce-Erschöpfungs-Guard (`MaxNonce`), `maxEpochJump`-DoS-Obergrenze und
  Sitzungsalterslimit.
- ✅ Tests: Verlust, Replay, nicht geordnete Ankunft, veraltete Nonce,
  Rekey-Lücke (`TestDecryptAtLossReorderAndRekey`, `TestRekeyRotatesKeys`,
  `TestRekeyJumpCapped`).

## Phase 3 — Sicherheit von Kontrolle + Relay (Ziel: G2–G5) — ✅ abgeschlossen

- ✅ **Relay-Namens-Pinning:** Wenn sich die an einen Namen gebundene
  Netzwerkadresse ändert, kann der Name nicht von einem anderen Kanal
  beansprucht werden (Namens-Hijacking/Zustellungsstörung geschlossen).
- ✅ **Ratenlimit/Kontingent des Relays:** PPS/Byte-Limit pro Quelladresse +
  Kontingent pro Name; Amplifikationsfläche verkleinert.
- ✅ **Handshake-/CPU-Budget + Handshake-Timeout:** Limit für gleichzeitigen
  Handshake-Zustand auf der Responder-Seite und explizite Übernahme-/
  Verfalls-Timeouts (Relay + Kontrolle).
- ✅ **Noise-Authentifizierung der Kontrollebene:** Register-Kanal mit Noise XX
  verschlüsselt und Koordinator-Schlüssel beim Client gepinnt;
  Name→Schlüssel-Bindung wird auf der Koordinatorenseite verifiziert
  (Identitäts-/Schlüssel-Mismatches abgelehnt).

## Phase 4 — Echter Datentransport (TUN) (Ziel: G6) — 🔶 teilweise

- ✅ `internal/tun`: Öffnen von utun/TUN-Schnittstellen, IPv4-Routing
  (`Router`), In-Memory-Testgerät (`BufferDevice`); macOS `utun`,
  Linux `/dev/net/tun`.
- ✅ Agent→tun-Brücke: `internal/agent/tunbridge.go` — leitet verschlüsselte
  Sitzungsdaten als IP-Pakete weiter (`-tun`, `-tun-ip`,
  `-tun-peer id=ip`).
- ✅ Schritte zur OS-Adresskonfiguration (erfordert Root) → `docs/de/TUN.md`.
- ⏸ NAT-Test im realen Internet (über den Simulator hinaus) — offen;
  erfordert Validierung in einem echten Netzwerk.

## Nächste Schritte (v1.1+)

- Konfiguration über Umgebungsvariablen; NAT-Validierung im realen Internet
  (Restposten aus Phase 4).
- Live-Konfigurationsrotation; kryptografischer Schlüsselspeicher/KMS;
  Prometheus-Metriken; Klartext-Speicherschutz (mlock); WireGuard-artige
  Sitzungs-Timeouts; Health-Status von Handshake-/Kernfunktionen.