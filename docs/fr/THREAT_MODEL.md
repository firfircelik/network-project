# meshlink — Modèle de menaces (v0.x → v1.0)

Date : 2026-08-19
Ce document est la pierre angulaire de la transition du MVP vers un réalisme
de production. Le code actuel est une **démo/MVP** ; ce modèle liste
explicitement les contrôles qui manquent.

---

## 1. Portée et actifs

Le système se compose de quatre composants : **agent** (client), **coordinateur**
(plan de contrôle : inscription + STUN), **relais** (transport du plan de données) et le
**pont TUN** optionnel (transport de données IP réel, requiert root). La démo inclut aussi
**natbox**, qui imite les véritables dispositifs NAT — il n'est pas présent en
production.

Actifs :

| Actif | Confidentialité | Intégrité | Disponibilité |
|---|---|---|---|
| Clé statique X25519 de l'agent | Haute | Haute | — |
| Données de session (texte clair de bout en bout) | Haute | Haute | Moyenne |
| Registre du coordinateur (nom→clé, endpoint) | Moyenne | Haute | Haute |
| Flux de messages du relais | Moyenne (métadonnées de direction/identité) | Haute | Haute |
| Réponses STUN (XOR-MAPPED-ADDRESS) | Faible | Haute | Faible |

## 2. Frontières de confiance

```
 [güvenilir]                   [yarı güvenilir / ağa düşman]          [güvenilir]
 agent A ──coord/STUN──▶ coordinator ◀──coord/STUN── agent B
     │                                                            │
     └─────Noise (E2E)──▶ relay (ciphertext only) ◀──Noise──────┘
```

- **Le cœur de l'agent** est entièrement fiable ; **coordinateur et relais** sont « exposés au réseau,
  le transport est sacré » (ils ne peuvent pas voir les données car Noise est de bout en bout).
- Le **chemin réseau** (internet/NAT) est considéré comme entièrement hostile.
- **natbox** est un artefact de démo ; aucune frontière de confiance de production n'est tracée autour de lui.
- Le canal de contrôle est désormais authentifié par Noise ; l'authenticité du coordinateur
  est vérifiée côté client via une clé épinglée (phase 3).

## 3. Menaces (STRIDE)

### 3.1 T1 — Attaquant réseau sans privilèges (chemin de données)
- **Rejeu :** retransmission d'un texte chiffré DATA enregistré. La fenêtre glissante
  de type WireGuard (2048) côté récepteur rejette les nonces anciens et les doublons
  → **atténué** (phase 2).
- **Déni de service/reflexion UDP :** amplification en revendiquant un nom auprès du relais ; des paquets
  avec adresses sources usurpées. L'épinglage nom→adresse + les limites pps/octets
  par source + le quota par nom sont actifs → **atténué** (phase 3).
- **Inondation de handshake :** épuisement du CPU via HS1 (chaque requête crée un nouvel état de
  handshake). Le répondant a un budget de handshakes simultanés + un délai de handshake →
  **atténué** (phase 3).
- **Usurpation STUN :** injection d'un endpoint erroné — la vérification de txid existe et
  la vérification de clé récupère la session → **atténué**.

### 3.2 T2 — Agent malveillant (client hostile pouvant s'inscrire)
- **Détournement de nom :** enregistrer le nom « a » avant le « a » légitime et
  bloquer le ping. Épinglage de clé + rejet des incohérences identité/clé au
  coordinateur → **atténué** (phase 3).
- **Fausse revendication de relais :** envoyer des paquets au relais avec le srcID de quelqu'un d'autre.
  L'épinglage nom→adresse l'empêche → **atténué** (phase 3, l'ancien M1 se ferme).
- **Mauvaise orientation avec endpoint fallacieux :** inonder le coordinateur d'un mauvais
  endpoint ; les autres agents vérifient la clé pendant le handshake mais sondent la mauvaise
  adresse → **partiellement atténué** (le canal de contrôle est authentifié par Noise,
  les modifications d'inscription ne sont plus possibles sur le réseau non chiffré).

### 3.3 T3 — Attaquant opérateur du coordinateur / du relais
- Le canal de contrôle était non chiffré/sans TLS → fermé avec un canal de contrôle authentifié
  par Noise + épinglage de la clé publique du coordinateur → **atténué** (phase 3).
- Le relais conserve la table nom→adresse ; un opérateur peut échanger un abonné ou
  observer le flux (métadonnées : qui parle à qui et quand). Le Noise de bout en bout ne
  règle pas cela ; la confidentialité des métadonnées est une exigence distincte → **acceptation documentée**.

### 3.4 T4 — Opération locale
- Fichier de clé : les permissions `0600` sont **bonnes** ; cependant, la clé privée en clair → le
  chiffrement de disque/KMS est une exigence de production.
- Clé + texte clair dans un dump mémoire / core dump → mlock/garde devrait être envisagé
  en production (post-v1).

## 4. Mesures d'atténuation actuelles (implémentées)

- Noise XX + DH25519 + ChaCha20-Poly1305 + SHA256 ; vérification bilatérale de la clé statique
  (avec la clé publique distribuée par le coordinateur, optionnelle).
- Épinglage de clé : le coordinateur rejette une inscription avec le même nom + une
  clé différente ; l'épinglage nom→adresse du relais empêche la perturbation de remise.
- Canal de contrôle authentifié par Noise : le trafic d'inscription/contrôle est chiffré
  et ne peut pas être échangé.
- Plan de données : fenêtre glissante (2048) de rejet de rejeu, rekey périodique, garde d'épuisement
  des nonces + plafond anti-DoS `maxEpochJump`, limite d'âge de session.
- Limite de débit/quota du relais (pps/octets par source, quota par nom) ; budget de handshake
  + délai (relais et contrôle).
- Vérification du txid STUN.
- Limites de taille dans les communications (contrôle `maxMsgLen`, enveloppes relais/nat), vérification
  de la validité des trames.
- Contrat de taille de datagramme (plafond de texte clair 65507-3-16, le chemin relais est
  en plus resserré).
- Délai d'écriture de diffusion du coordinateur ; lectures de contrôle bornées.
- Tests unitaires propres sous `-race` ; fuzzers d'analyseurs ; démo de bout en bout ; workflow CI.

## 5. Lacunes connues (bloqueurs de production)

| # | Lacune | Impact | Statut |
|---|---|---|---|
| G1 | — (fenêtre anti-rejeu + rekey) | — | ✅ Phase 2 |
| G2 | — (épinglage de nom du relais) | — | ✅ Phase 3 |
| G3 | — (auth Noise du contrôle) | — | ✅ Phase 3 |
| G4 | — (limite de débit/quota du relais) | — | ✅ Phase 3 |
| G5 | — (budget/délai de handshake) | — | ✅ Phase 3 |
| G6 | Cycle de vie TUN + vérification sur réseau réel | Le test NAT sur réseau réel pour l'usage VPN reste ouvert | 🔶 Phase 4 partielle |
| G7 | — (fuzz, CI, journaux de santé) | — | ✅ Phase 1 |
| G8 | — (rekey, fenêtre anti-rejeu) | — | ✅ Phase 2 |
| G9 | Configuration par variables d'environnement ; métriques/Prometheus | Prévisibilité opérationnelle | 🔶 v1.1+ |

## 6. Risques acceptés (MVP)

- **Confiance dans les métadonnées du plan de contrôle :** le fait que l'opérateur du coordinateur/relais voie
  « qui parle à qui quand » est accepté malgré le chiffrement de bout en bout.
- **Parallélisme / DTLS :** le plan de données UDP n'utilise pas DTLS ; l'analyse énergétique/métadonnées
  est théoriquement possible (acceptation du modèle WireGuard).
- La **simulation natbox** ne couvre pas la diversité des NAT réels d'internet
  (Cone/Cone, grade opérateur, etc.) ; les tests sur réseau réel sont un reliquat de la phase 4.

## 7. Contrôles de clôture (mise en correspondance avec la feuille de route)

Phase 1 → G7, G9 ; Phase 2 → G1, G8 ; Phase 3 → G2–G5 ; Phase 4 → G6.
À la fin de chaque phase, les tests et la documentation sont mis à jour ; ce tableau
l'est aussi.
