# meshlink — Rapport de revue de code

Date : 2026-08-19 · Périmètre : tout le code source, les tests, la documentation, le Makefile, le script de démo.
Méthode : revue sur 5 axes + vérification en direct via `gofmt` / `go vet` / `go test -race` / `make demo`.

---

## Statut

| Élément | Gravité | Statut |
|---|---|---|
| H1 — `Peer.Run` ne surveillait pas `p.done` → fuite de goroutine | Haute | ✅ Corrigé + test de régression |
| H2 — `contactIP` du NAT restricted ne s'accumulait pas | Haute | ✅ Corrigé + test multi-cibles |
| H3 — Aucun épinglage ID→pubkey du coordinateur | Moyenne/sécurité | ✅ Corrigé + test |
| M1 — Nom source du relais non vérifié | Moyenne/sécurité | ✅ Corrigé (phase 3 : épinglage nom→adresse) + test |
| M2 — `MaxPlaintextLen` dépassait la limite UDP | Moyenne | ✅ Corrigé (65504 ; chemin relais encore resserré) |
| M3 — `scripts/demo.sh` n'était pas exécutable | Moyenne | ✅ `chmod +x` |
| M4 — flags natbox obsolètes dans le README | Moyenne | ✅ Mis à jour |
| M5 — constante morte `disco.MaxPunchAttempts` + « max 10 » de la SPEC | Moyenne | ✅ Supprimé / documenté |
| D1 — concurrence nat `wg.Add`/`Wait` | Faible | ✅ garde `closed` |
| D2 — chemin de résumé du ping capturé au démarrage de l'exécution | Faible | ✅ Lu à la fin de l'exécution |
| D3 — la connexion de contrôle n'a pas de délai d'écriture | Faible | ✅ `broadcastWriteDeadline` + mutex d'écriture |
| D4 — l'erreur d'envoi du ping était avalée | Faible | ✅ Journalisée |
| D5 — l'erreur de décodage JSON était silencieuse | Faible | ✅ Journalisée |
| D6 — simili de test `nat.decodeOutbound` en production | Faible | ✅ Déplacé dans le fichier de test |
| D7 — commentaires `// indirect` de `go.mod` | Faible | ✅ `go mod tidy` |
| D8 — copie de `receiveLoop` à chaque paquet | Faible | ✅ Seule la trame correspondante est copiée |
| Bonus | — | ✅ `peer.maxPlaintext()` mort supprimé |

## Vérification

```
gofmt -l .                → vide
go vet ./...              → propre
go build ./...            → ok
go test -count=1 -race ./... → tout ok (y compris les nouveaux tests control/coordinator/peer/nat/agent/tun)
make demo                 → phase 1 path=direct PASS · phase 2 path=relay PASS
```

---

## Constats de la session précédente et détails de résolution

### H1 — `Peer.Run` ne surveille pas `p.done` (fuite de goroutine)
`internal/peer/peer.go` — `Run` n'attendait que `ctx.Done()` ; le `p.done` fermé par
`Close()` n'était pas surveillé dans la boucle et `p.recv` n'était jamais fermé (deux goroutines
fuyaient l'élagage `applyPeers` pour toujours). Correctif :

- `p.done` se ferme désormais exactement une fois via `doneOnce sync.Once`.
- le `defer` de `Run` ferme `recv` sous verrou (pas de course d'envoi concurrent).
- `onData` fait un envoi non bloquant sous verrou, gardé (`closed`/`recvClosed`).
- Test de régression : `internal/peer/peer_test.go` (`TestRunExitsWhenClosed`,
  `TestRunExitsOnCancel`, `TestNoDataAfterClose`).

### H2 — Accumulation de `contactIP` du NAT restricted
`internal/nat/nat.go` — `e.contactIP[ipKey(dst.IP)] = true` manquait dans la
branche de rafraîchissement du mapping ; l'hôte rejetait (DROP) à tort le trafic entrant provenant d'IP
qu'il avait contactées ensuite. Test de régression :
`internal/nat/nat_test.go` → `TestAddressRestrictedMultiTarget`.

### H3 — Épinglage de clé du coordinateur
`internal/coordinator/coordinator.go` — un `PubKey` différent avec le même ID
lève un TypeError (l'inscription n'est pas écrasée) ; un pubkey vide est
rejeté ; la ré-inscription avec la même clé (rafraîchissement d'endpoint) reste libre.
Test de régression : `TestRegistrationKeyPinning`.

### M2 — Contrat de taille de datagramme
- `internal/noisework/noisework.go` : `maxPlaintextLen = 65507 - 3 - 16 = 65504`
  (25535 − en-têtes IP(20) − UDP(8) ; en-tête de trame 3 ; tag AEAD 16).
- `internal/relay/relay.go` : `MaxHeaderLen` exporté (pire cas 133 o).
- `internal/peer/peer.go` : la limite de `Send` sur le chemin relais est `MaxPlaintextLen - MaxHeaderLen`.
- Test/SPEC/noisework_test adaptés ; le contrat d'encodage 65535 de `record` (une limite
  de codec, pas un paquet unique) est préservé.

### D8 — Réduction des allocations de `receiveLoop`
`internal/agent/agent.go` — une copie de trame dédiée n'est faite que pour la trame
correspondante ; les datagrammes non correspondants (abandonnés à l'inactivité) sont rejetés sans copie depuis
le tampon partagé. Le démultiplexage du relais reste par ID de pair.

---

## Constats supplémentaires de la session phases 3/4

### D9 — Les écrivains de contrôle concurrents pouvaient corrompre les trames (Haute)
`internal/control` — deux instances `handleClient` pouvaient écrire simultanément sur
le même `*control.Conn` du client (diffusion + réponse personnelle) ; comme `WriteMsg`
faisait deux appels `Write` séparés (en-tête de longueur + texte chiffré), le trame pouvait
se corrompre sous `-race`. Correctif : `Conn.wm sync.Mutex` + écriture atomique dans un tampon unique.
`TestRegistrationAndBroadcast` est devenu déterministe dans l'ordre.

### D10 — Le handshake de contrôle n'avait pas de délai (Moyenne)
`internal/control` — comme `Initiate`/`Accept` n'étaient pas bornés par un
`handshakeTimeout`, des pairs bloqués pouvaient verrouiller l'accepteur. Correctif :
`SetDeadline(handshakeTimeout)` à l'entrée, effacé après succès.
`TestWrongCoordinatorKey` retourne désormais de façon déterministe côté client.

### Y1 — Pont TUN (phase 4 / G6, partielle)
`internal/tun` (ouverture utun/TUN, transfert IPv4 `Router`, `BufferDevice`) +
`internal/agent/tunbridge.go` (pont dispositif ⇄ session de pair, `-tun`/`-tun-ip`/
`-tun-peer`). Tests unitaires sans root : `internal/tun/tun_test.go`,
`internal/agent/tunbridge_test.go`. L'ouverture du dispositif réel est ignorée dans les tests via
`t.Skip` ; la vérification sur réseau réel est un reliquat de la phase 4 (`docs/fr/TUN.md`).

---

## Évaluation de la couverture de test

Présents : record, noisework, stun, nat, relay, coordinator, protocol, peer,
control, tun, agent (pont tun) — très bon. Fuzzers : record, relay, nat,
stun, protocol. Ouverts (v1.1) : vérification NAT sur le vrai internet ; cycle de vie TUN
e2e réel (requiert root).

## Conclusion

Tous les éléments applicables du rapport ont été résolus et la vérification a été faite en
trois couches (test unitaire `-race`, `go vet`/`gofmt`, bout en bout `make demo`). M1
(authentification côté relais) a été fermé en phase 3 ; les tests sur réseau réel ont été
volontairement laissés comme reliquat de la phase 4.
