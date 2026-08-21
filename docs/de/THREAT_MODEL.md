# meshlink — Bedrohungsmodell (v0.x → v1.0)

Datum: 2026-08-19
Dieses Dokument ist der Eckpfeiler des Übergangs vom MVP zur
Produktionsrealität. Der aktuelle Code ist eine **Demo/MVP**; dieses Modell
listet explizit auf, welche Kontrollen fehlen.

---

## 1. Umfang und Werte (Assets)

Das System besteht aus vier Komponenten: **agent** (Client), **coordinator**
(Kontrollebene: Registrierung + STUN), **relay** (Transport der Datenebene)
und der optionalen **TUN-Brücke** (echter IP-Datentransport, erfordert Root).
Die Demo enthält außerdem **natbox**, die echte NAT-Geräte nachahmt — in der
Produktion ist sie nicht vorhanden.

Werte (Assets):

| Asset | Vertraulichkeit | Integrität | Verfügbarkeit |
|---|---|---|---|
| Statischer X25519-Schlüssel des Agents | Hoch | Hoch | — |
| Sitzungsdaten (Ende-zu-Ende-Klartext) | Hoch | Hoch | Mittel |
| Koordinatoren-Registry (Name→Schlüssel, Endpunkt) | Mittel | Hoch | Hoch |
| Relay-Nachrichtenfluss | Mittel (Richtungs-/Identitäts-Metadaten) | Hoch | Hoch |
| STUN-Antworten (XOR-MAPPED-ADDRESS) | Niedrig | Hoch | Niedrig |

## 2. Vertrauensgrenzen

```
 [güvenilir]                   [yarı güvenilir / ağa düşman]          [güvenilir]
 agent A ──coord/STUN──▶ coordinator ◀──coord/STUN── agent B
     │                                                            │
     └─────Noise (E2E)──▶ relay (ciphertext only) ◀──Noise──────┘
```

- Der **Agent-Kern** ist vollständig vertrauenswürdig; **coordinator und
  relay** sind „netzwerkexponiert, Transport ist heilig" (sie können die Daten
  nicht sehen, weil Noise E2E ist).
- Der **Netzwerkpfad** (Internet/NATs) gilt als vollständig feindlich.
- **natbox** ist ein Demo-Artefakt; um sie wird keine
  Produktions-Vertrauensgrenze gezogen.
- Der Kontrollkanal ist jetzt Noise-authentifiziert; die Authentizität des
  Koordinators wird beim Client über einen gepinnten Schlüssel verifiziert
  (Phase 3).

## 3. Bedrohungen (STRIDE)

### 3.1 T1 — Nicht privilegierter Netzwerkangreifer (Datenpfad)
- **Replay:** erneutes Senden aufgezeichneter DATA-Ciphertexte. Das
  WireGuard-artige Schiebefenster (2048) beim Empfänger lehnt alte Nonces und
  Duplikate ab → **entschärft** (Phase 2).
- **Rekey-Zustands-DoS:** ein gefälschtes Datagramm mit einer wilden Nonce,
  das die Einweg-Epochenschlüssel vor der Authentifizierung vorschiebt und die
  Empfangsrichtung bis zum nächsten Re-Handshake sperrt. `DecryptAt` leitet den
  Epochenschlüssel-Kandidaten jetzt auf einem Wegwerf-Cipher-State ab und
  übernimmt den Rekey erst nach bestandener AEAD-Prüfung → **entschärft**.
- **Halboffener-Handshake-DoS:** ein verlorenes HS3 ließ den Responder bis zur
  24-h-Sitzungslaufzeit halboffen. Der Initiator sendet HS3 jetzt erneut, bis
  der Responder mit authentifizierten Daten antwortet; doppelte HS1 senden das
  gecachte HS2 erneut statt den Responder zurückzusetzen, und veralteter
  halboffener Zustand wird nach 10 s Timeout geräumt → **entschärft**.
- **UDP-DoS/Reflexion:** Amplifikation durch Beanspruchen eines Namens beim
  Relay; Pakete mit gefälschten Quelladressen. Name→Adresse-Pinning +
  PPS/Byte-Limits pro Quelle + Kontingent pro Name sind aktiv →
  **entschärft** (Phase 3).
- **Handshake-Flut:** CPU-Erschöpfung über HS1 (jede Anfrage erzeugt neuen
  Handshake-Zustand). Der Responder hat ein Budget für gleichzeitige
  Handshakes + ein Handshake-Timeout → **entschärft** (Phase 3).
- **STUN-Spoofing:** Einschleusen eines falschen Endpunkts — die
  Txid-Verifikation existiert und die Schlüsselverifikation stellt die Sitzung
  wieder her → **entschärft**.

### 3.2 T2 — Schurken-Agent (bösartiger Client, der sich registrieren kann)
- **Namens-Hijacking:** Registrieren des Namens „a" vor dem legitimen „a" und
  Blockieren des Pings. Schlüssel-Pinning + Ablehnung von Identitäts-/
  Schlüssel-Mismatch beim Koordinator → **entschärft** (Phase 3).
- **Falsche Relay-Behauptung:** Senden von Paketen an das Relay mit fremder
  srcID. Name→Adresse-Pinning verhindert das → **entschärft** (Phase 3, das
  alte M1 wird geschlossen).
- **Fehlleitung mit gefälschtem Endpunkt:** den Koordinator mit einem
  schlechten Endpunkt zuspammen; andere Agents verifizieren den Schlüssel
  während des Handshakes, proben aber die falsche Adresse → **teilweise
  entschärft** (der Kontrollkanal ist Noise-authentifiziert,
  Registrierungsänderungen sind im unverschlüsselten Netzwerk nicht mehr
  möglich).

### 3.3 T3 — Angreifer als Koordinator-/Relay-Betreiber
- Der Kontrollkanal war unverschlüsselt/ohne TLS → geschlossen durch einen
  Noise-authentifizierten Kontrollkanal + Pinning des Koordinator-Pubkeys →
  **entschärft** (Phase 3).
- Das Relay führt die Name→Adresse-Tabelle; ein Betreiber kann einen
  Teilnehmer austauschen oder den Datenfluss beobachten (Metadaten: wer spricht
  mit wem zu welcher Zeit). E2E-Noise behebt das nicht;
  Metadaten-Privatsphäre ist eine separate Anforderung → **dokumentierte
  Akzeptanz**.

### 3.4 T4 — Lokaler Betrieb
- Schlüsseldatei: `0600`-Berechtigungen sind **gut**; der Klartext-
  Privatschlüssel → Festplattenverschlüsselung/KMS ist jedoch eine
  Produktionsanforderung.
- Schlüssel + Klartext in Memory-Dump/Core-Dump → in der Produktion sollten
  mlock/Guard in Betracht gezogen werden (post-v1).

## 4. Aktuelle Gegenmaßnahmen (implementiert)

- Noise XX + DH25519 + ChaCha20-Poly1305 + SHA256; bidirektionale
  Verifikation des statischen Schlüssels (mit vom Koordinator verteiltem
  Pubkey, optional).
- Schlüssel-Pinning: Der Koordinator lehnt eine Registrierung mit demselben
  Namen + einem anderen Schlüssel ab; das Relay-Pinning Name→Adresse
  verhindert Zustellungsstörungen.
- Noise-authentifizierter Kontrollkanal: Registrierungs-/Kontrollverkehr ist
  verschlüsselt und kann nicht ausgetauscht werden.
- Datenebene: Schiebefenster (2048) zur Replay-Ablehnung, periodisches
  Rekeying, Nonce-Erschöpfungs-Guard + `maxEpochJump`-DoS-Obergrenze,
  Sitzungsalterslimit.
- Ratenlimit/Kontingent des Relays (PPS/Byte pro Quelle, Kontingent pro Name);
  Handshake-Budget + Timeout (Relay und Kontrolle).
- STUN-Txid-Verifikation.
- Größenlimits in der Kommunikation (Kontrolle `maxMsgLen`,
  Relay/NAT-Umschlag), Prüfung der Frame-Gültigkeit.
- Datagramm-Größenvertrag (65507-3-8-16 = 65480 Klartext-Obergrenze, der Relay-Pfad ist
  zusätzlich verengt).
- Schreib-Deadline für Koordinatoren-Broadcasts; begrenzte Kontroll-Reads.
- `-race`-saubere Unit-Tests; Parser-Fuzzer; End-to-End-Demo; CI-Workflow.

## 5. Bekannte Lücken (Produktionsblocker)

| # | Lücke | Auswirkung | Status |
|---|---|---|---|
| G1 | — (Replay-Fenster + Rekeying) | — | ✅ Phase 2 |
| G2 | — (Relay-Namens-Pinning) | — | ✅ Phase 3 |
| G3 | — (Kontroll-Noise-Auth) | — | ✅ Phase 3 |
| G4 | — (Ratenlimit/Kontingent des Relays) | — | ✅ Phase 3 |
| G5 | — (Handshake-Budget/Timeout) | — | ✅ Phase 3 |
| G6 | TUN-Lebenszyklus + Verifikation im realen Netzwerk | NAT-Tests im realen Netzwerk für den VPN-Einsatz sind offen | 🔶 Phase 4 teilweise |
| G7 | — (Fuzz, CI, Health-Logs) | — | ✅ Phase 1 |
| G8 | — (Rekeying, Replay-Fenster) | — | ✅ Phase 2 |
| G9 | Konfiguration über Umgebungsvariablen; Metriken/Prometheus | Betriebliche Vorhersagbarkeit | 🔶 v1.1+ |

## 6. Akzeptierte Risiken (MVP)

- **Vertrauen in Kontrollebenen-Metadaten:** Dass der Koordinator-/Relay-
  Betreiber Informationen darüber sieht, „wer mit wem wann spricht", wird
  trotz E2E-Verschlüsselung akzeptiert.
- **Parallelität/DTLS:** Die UDP-Datenebene verwendet kein DTLS;
  Energie-/Metadatenanalyse ist theoretisch möglich (Akzeptanz nach dem
  WireGuard-Modell).
- Die **natbox-Simulation** deckt nicht die Vielfalt realer Internet-NATs ab
  (Cone/Cone, Carrier-Grade usw.); Tests im realen Netzwerk sind ein
  Restposten aus Phase 4.

## 7. Abschlusskriterien (Roadmap-Zuordnung)

Phase 1 → G7, G9; Phase 2 → G1, G8; Phase 3 → G2–G5; Phase 4 → G6.
Am Ende jeder Phase werden Tests + Dokumentation aktualisiert; diese Tabelle
wird ebenfalls aktualisiert.