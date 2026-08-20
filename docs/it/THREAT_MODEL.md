# meshlink — Modello delle minacce (v0.x → v1.0)

Data: 2026-08-19
Questo documento è la pietra angolare della transizione dal MVP al realismo
di produzione. Il codice attuale è una **demo/MVP**; questo modello elenca
esplicitamente quali controlli mancano.

---

## 1. Ambito e beni

Il sistema è composto da quattro componenti: **agent** (client), **coordinator**
(piano di controllo: registrazione + STUN), **relay** (trasporto del data plane) e
l'opzionale **bridge TUN** (trasporto dati IP reale, richiede root). La demo include
anche **natbox**, che imita i dispositivi NAT reali — non è presente in produzione.

Beni:

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Agent X25519 static key | High | High | — |
| Session data (end-to-end plaintext) | High | High | Medium |
| Coordinator registry (name→key, endpoint) | Medium | High | High |
| Relay message flow | Medium (direction/identity metadata) | High | High |
| STUN responses (XOR-MAPPED-ADDRESS) | Low | High | Low |

## 2. Confini di fiducia

```
 [güvenilir]                   [yarı güvenilir / ağa düşman]          [güvenilir]
 agent A ──coord/STUN──▶ coordinator ◀──coord/STUN── agent B
     │                                                            │
     └─────Noise (E2E)──▶ relay (ciphertext only) ◀──Noise──────┘
```

- **Il core dell'agent** è completamente fidato; **coordinator e relay** sono
  "esposti alla rete, il trasporto è sacro" (non possono vedere i dati perché
  Noise è E2E).
- Il **percorso di rete** (internet/NAT) è considerato interamente ostile.
- **natbox** è un artefatto demo; attorno ad esso non viene tracciato alcun confine
  di fiducia di produzione.
- Il canale di controllo è ora autenticato con Noise; l'autenticità del coordinator
  è verificata sul client tramite una chiave pinata (Fase 3).

## 3. Minacce (STRIDE)

### 3.1 T1 — Attaccante di rete senza privilegi (percorso dati)
- **Replay:** ritrasmissione di testo cifrato DATA registrato. La finestra scorrevole
  stile WireGuard (2048) sul ricevitore rifiuta nonce vecchi e duplicati
  → **mitigata** (Fase 2).
- **DoS UDP/riflessione:** amplificazione rivendicando un nome presso il relay;
  pacchetti con indirizzi sorgente falsificati. Il pinning nome→indirizzo + i limiti
  pps/byte per sorgente + la quota per nome sono attivi → **mitigata** (Fase 3).
- **Inondazione di handshake:** esaurimento della CPU tramite HS1 (ogni richiesta
  crea un nuovo stato di handshake). Il risponditore ha un budget di handshake
  concorrenti + timeout di handshake → **mitigata** (Fase 3).
- **Spoofing STUN:** iniezione di un endpoint errato — esiste la verifica del txid e
  la verifica delle chiavi recupera la sessione → **mitigata**.

### 3.2 T2 — Agent canaglia (client dannoso che può registrarsi)
- **Dirottamento del nome:** registrare il nome "a" prima dell'"a" legittimo e
  bloccare il ping. Pinning delle chiavi + rifiuto della mancata corrispondenza
  identità/chiave presso il coordinator → **mitigata** (Fase 3).
- **Rivendicazione falsa al relay:** inviare pacchetti al relay con lo srcID di
  qualcun altro. Il pinning nome→indirizzo lo impedisce → **mitigata** (Fase 3,
  chiude la vecchia M1).
- **Indirizzamento errato con endpoint fasullo:** bombardare il coordinator con un
  endpoint sbagliato; gli altri agent verificano la chiave durante l'handshake ma
  provano l'indirizzo sbagliato → **parzialmente mitigata** (il canale di controllo
  è autenticato con Noise, le modifiche alla registrazione non sono più possibili
  sulla rete non crittografata).

### 3.3 T3 — Attaccante operatore di coordinator / relay
- Il canale di controllo era non crittografato/senza TLS → chiuso con un canale di
  controllo autenticato con Noise + pinning della pubkey del coordinator →
  **mitigata** (Fase 3).
- Il relay mantiene la tabella nome→indirizzo; un operatore può scambiare un abbonato
  o osservare il flusso (metadati: chi parla con chi e a che ora). Noise E2E non
  risolve questo; la privacy dei metadati è un requisito separato →
  **accettazione documentata**.

### 3.4 T4 — Operatività locale
- File delle chiavi: i permessi `0600` sono **buoni**; tuttavia la chiave privata in
  chiaro → la crittografia del disco/KMS è un requisito di produzione.
- Chiave + testo in chiaro in memory dump / core dump → mlock/guard dovrebbero essere
  considerati in produzione (post-v1).

## 4. Mitigazioni attuali (implementate)

- Noise XX + DH25519 + ChaCha20-Poly1305 + SHA256; verifica bidirezionale delle chiavi
  statiche (con pubkey distribuita dal coordinator, opzionale).
- Pinning delle chiavi: il coordinator rifiuta una registrazione con lo stesso nome +
  una chiave diversa; il pinning nome→indirizzo del relay impedisce l'interruzione
  della consegna.
- Canale di controllo autenticato con Noise: il traffico di registrazione/controllo è
  crittografato e non può essere scambiato.
- Data plane: rifiuto dei replay con finestra scorrevole (2048), rekey periodico,
  protezione dall'esaurimento dei nonce + tappo anti-DoS `maxEpochJump`, limite di
  età della sessione.
- Relay rate-limit/quota (pps/byte per sorgente, quota per nome); budget di handshake
  + timeout (relay e controllo).
- Verifica del txid STUN.
- Limiti di dimensione nella comunicazione (`maxMsgLen` di controllo, envelope
  relay/nat), controllo di validità dei frame.
- Contratto sulla dimensione dei datagrammi (tetto plaintext 65507-3-16, il percorso
  relay è ulteriormente ristretto).
- Write deadline per le broadcast del coordinator; letture di controllo con limite.
- Unit test puliti con `-race`; fuzzer dei parser; demo end-to-end; workflow CI.

## 5. Gap noti (bloccanti per la produzione)

| # | Gap | Impact | Status |
|---|---|---|---|
| G1 | — (replay window + rekey) | — | ✅ Phase 2 |
| G2 | — (relay name pinning) | — | ✅ Phase 3 |
| G3 | — (control Noise-auth) | — | ✅ Phase 3 |
| G4 | — (relay rate-limit/quota) | — | ✅ Phase 3 |
| G5 | — (handshake budget/timeout) | — | ✅ Phase 3 |
| G6 | TUN lifecycle + real-network verification | Real-network NAT testing for VPN use is open | 🔶 Phase 4 partial |
| G7 | — (fuzz, CI, health logs) | — | ✅ Phase 1 |
| G8 | — (rekey, replay window) | — | ✅ Phase 2 |
| G9 | Environment-variable config; metrics/Prometheus | Operational predictability | 🔶 v1.1+ |

## 6. Rischi accettati (MVP)

- **Fiducia nei metadati del piano di controllo:** l'informazione "chi parla con chi
  e quando" vista dall'operatore di coordinator/relay è accettata nonostante la
  crittografia E2E.
- **Parallelismo / DTLS:** il data plane UDP non usa DTLS; l'analisi
  energetica/dei metadati è teoricamente possibile (accettazione del modello
  WireGuard).
- La **simulazione natbox** non copre la diversità dei NAT reali di internet
  (Cone/Cone, carrier-grade, ecc.); il test su rete reale è un residuo della Fase 4.

## 7. Controlli di chiusura (mappatura della roadmap)

Fase 1 → G7, G9; Fase 2 → G1, G8; Fase 3 → G2–G5; Fase 4 → G6.
Alla fine di ogni fase vengono aggiornati test + documentazione; anche questa
tabella viene aggiornata.
