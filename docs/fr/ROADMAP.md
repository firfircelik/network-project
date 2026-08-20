# meshlink — Feuille de route de production (v1)

Statut actuel : **Phases 1–3 terminées ; Phase 4 partielle** (code TUN + documentation
prêtes ; test NAT sur le vrai internet ouvert). À la fin de chaque phase `gofmt` / `go vet` /
`go test -race` / `make demo` restent au vert.

## Phase 1 — Infrastructure de confiance/qualité (objectif : G7, G9) — ✅ terminée

- ✅ CI GitHub Actions : `.github/workflows/ci.yml` — `gofmt`, `go vet`,
  `go test -race ./...`, `make demo`.
- ✅ Tests de fuzz : décodeurs `record`, `relay`, `nat`, `stun`, `protocol`
  (entrée malformée simple, troncature, exagération des champs de longueur) + `make fuzz-smoke`.
- ✅ Lectures de contrôle bornées : plafond `maxMsgLen` de `control.ReadMsg`, longueurs de
  handshake plafonnées à 16 bits ; surface de DoS mémoire fermée.
- ✅ Journalisation structurée : `log/slog` (`level=INFO msg=...`), erreur/avertissement/info.
- ✅ Config : validation des flags (`--name`/`--keyfile`/`--coord-pubkey` requis) ;
  quand le fichier de clé manque, il est créé avec `0600` et les permissions sont préservées.
  (Configuration par variables d'environnement → v1.1+.)

## Phase 2 — Durcissement du cœur du tunnel (objectif : G1, G8) — ✅ terminée

- ✅ **Fenêtre anti-rejeu + tolérance aux pertes :** nonce explicite de 64 bits dans les trames DATA ;
  fenêtre glissante de type WireGuard au récepteur (bitmap, 2048 paquets). Les enregistrements
  très anciens/rejeux sont rejetés ; la session ne se bloque pas après une perte
  (`internal/noisework`, `internal/peer`).
- ✅ **Rekey périodique :** un nombre `RekeyEvery` de messages déclenche une rotation de clé ; les deux
  directions à la même limite, les paquets perdus suivis via des sauts d'époque.
- ✅ Garde d'épuisement des nonces (`MaxNonce`), plafond anti-DoS `maxEpochJump` et limite
  d'âge de session.
- ✅ Tests : chute, rejeu, arrivée hors ordre, nonce obsolète, écart de rekey
  (`TestDecryptAtLossReorderAndRekey`, `TestRekeyRotatesKeys`,
  `TestRekeyJumpCapped`).

## Phase 3 — Sécurité du contrôle + du relais (objectif : G2–G5) — ✅ terminée

- ✅ **Épinglage de nom du relais :** si l'adresse réseau liée à un nom change, elle
  ne peut pas être revendiquée depuis un autre canal (détournement de nom / perturbation de remise fermés).
- ✅ **Limite de débit/quota du relais :** limite pps/octets par adresse source + quota par
  nom ; surface d'amplification réduite.
- ✅ **Budget de handshake/CPU + délai de handshake :** limite d'état de handshakes simultanés
  côté répondant et délais explicites de prise en charge/expiration
  (relais + contrôle).
- ✅ **Auth Noise du plan de contrôle :** canal register chiffré avec Noise XX et
  clé du coordinateur épinglée côté client ; liaison nom→clé vérifiée côté
  coordinateur (incohérences identité/clé rejetées).

## Phase 4 — Transport de données réel (TUN) (objectif : G6) — 🔶 partielle

- ✅ `internal/tun` : ouverture d'interface utun/TUN, routage IPv4 (`Router`),
  dispositif de test en mémoire (`BufferDevice`) ; macOS `utun`, Linux `/dev/net/tun`.
- ✅ Pont agent→tun : `internal/agent/tunbridge.go` — routage des données de session
  chiffrées en paquets IP (`-tun`, `-tun-ip`,
  `-tun-peer id=ip`).
- ✅ Étapes de configuration des adresses OS (requiert root) → `docs/fr/TUN.md`.
- ⏸ Test NAT sur le vrai internet (au-delà du simulateur) — ouvert ; requiert une validation
  sur un réseau réel.

## Prochaines étapes (v1.1+)

- Configuration par variables d'environnement ; validation NAT sur le vrai internet (reliquat de la phase 4).
- Rotation de configuration à chaud ; magasin de clés cryptographiques/KMS ; métriques Prometheus ;
  protection de la mémoire en clair (mlock) ; délais de session de type WireGuard ;
  statut de santé des fonctions de handshake/noyau.
