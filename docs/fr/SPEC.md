# SPEC — meshlink v1 (MVP)

Mini VPN maillé zéro confiance. Monorepo Go. Tout peut être testé sur
localhost sans root, en utilisant le simulateur NAT (`natbox`).

## Structure des modules et des dossiers

```
module meshlink  (go 1.26)

cmd/
  coordinator/main.go    # serveur de contrôle (inscription TCP + STUN UDP, sessions Noise)
  relay/main.go          # serveur de relais UDP (épinglage de nom + limite de débit/quota)
  natbox/main.go         # simulateur NAT
  agent/main.go          # client (démon `up` + `ping` à usage unique)
internal/
  record/                # trame du plan de données
  noisework/             # handshake Noise XX + session (rekey, fenêtre anti-rejeu)
  control/               # connexion de contrôle authentifiée + trame (auth Noise)
  stun/                  # client+serveur STUN
  nat/                   # cœur natbox (simulateur NAT)
  relay/                 # cœur du serveur de relais
  protocol/              # messages JSON du plan de contrôle
  coordinator/           # cœur du coordinateur (épinglage nom/clé)
  peer/                  # gestionnaire de sessions
  disco/                 # ouverture de trou + sélection de chemin
  agent/                 # cœur du client (y compris le pont TUN)
  tun/                   # dispositif TUN + table de routes IPv4
docs/
  ARCHITECTURE.md
  SPEC.md
scripts/
  demo.sh
Makefile
```

## Répartition des ports (par défaut, démo)

| Composant | Port |
|---|---|
| coordinateur TCP (contrôle) | 19200 |
| coordinateur UDP (STUN) | 19201 |
| relais UDP | 19205 |
| natbox-1 public / porte intérieure | 19301 / 19401 |
| natbox-2 public / porte intérieure | 19302 / 19402 |
| agent a (données) | 19501 |
| agent b (données) | 19502 |

## Dépendance

Seulement `github.com/flynn/noise v1.1.0`. (x/crypto, x/sys transitifs.)

## 1. Format sur le fil — plan de données (datagramme UDP = une seule trame)

Trame : `[1B type][2B length BE][payload]`, longueur <= 65535.

| type | nom | signification |
|---|---|---|
| 1 | HS1 | message 1 Noise XX (initiateur → répondant) |
| 2 | HS2 | message 2 Noise XX (répondant → initiateur) |
| 3 | HS3 | message 3 Noise XX (initiateur → répondant) |
| 4 | PROBE | sonde vide (ouverture de trou / mapping NAT) |
| 5 | DATA | message de transport Noise chiffré : `[8B nonce BE][ciphertext]` (AEAD) |
| 7 | RELAY | agent → relais : `[magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame]` ; relais → agent est de même ré-enveloppé avec le même en-tête (le récepteur sépare ainsi l'identité source pour plusieurs pairs) |

Tous les champs de longueur/endpoint sont en big-endian. Le paquet `record` implémente ce contrat.

## 2. Format sur le fil — plan de contrôle (agent ↔ coordinateur, TCP, trames authentifiées Noise)

Le canal de contrôle (à partir de la phase 3) est authentifié avec Noise XX : le client
épingle la clé statique du coordinateur ; chaque partie connectée vérifie la clé
`Session.PeerStatic()` de l'autre. Une fois le handshake terminé, chaque message est
envoyé sous la forme `[4B length BE][ciphertext]` ; le contenu du texte chiffré est une seule
ligne de JSON (se termine par `\n`). Le plafond de longueur est borné par `maxMsgLen`.

Les messages de handshake circulent sous la forme `[2B length BE][Noise message]` (non chiffrés,
mais signés — le mélange d'authentification propre de Noise) et sont bornés par
`handshakeTimeout`.

Agent → Coor:
```json
{"type":"register","id":"a","pubkey":"<hex32>","endpoints":["127.0.0.1:19301","127.0.0.1:19205"]}
```
- `endpoints[0]` : endpoint UDP public appris via STUN (plan de données).
- `endpoints[1]` (optionnel) : si un endpoint de relais est utilisé.

Coor → Agent:
```json
{"type":"hello","id":"a"}
{"type":"peer_list","peers":[{"id":"a","pubkey":"<hex32>","endpoints":["..."]}]}
{"type":"error","msg":"..."}
```

Comportement : après chaque register, le coordinateur envoie `peer_list` à TOUS les pairs (y compris l'émetteur).
`peer_list` est un tableau vide s'il n'y a aucun pair.

## 3. Crypto

- Motif : **Noise XX** (`noise.HandshakeXX`), CipherSuite : `DH25519 + CipherChaChaPoly + HashSHA256`.
- Prologue : `meshlink-v1` (identique des deux côtés).
- Attribution des rôles : si `id_a < id_b` (octet par octet) alors `a` est initiateur, `b` répondant.
- Authentification post-handshake : chaque côté **doit vérifier** que sa valeur `Session.PeerStatic()`
  correspond à la clé publique du pair reçue du coordinateur.
- Données de transport : `CipherState.WriteMessage` → texte chiffré ; type de trame DATA.
- Plan de données (phase 2) : nonce explicite de 64 bits + fenêtre glissante de type WireGuard côté
  récepteur (bitmap de 2048 bits) — rejet des nonces dupliqués/obsolètes, tolérance aux pertes.
- Rekey périodique : rotation des clés tous les `RekeyEvery` messages (défaut 2^20) ;
  plafond anti-DoS `maxEpochJump` ; garde d'épuisement des nonces et limite d'âge de session.
- Keepalive : trame DATA vide après 10 s de silence (mapping NAT + vivacité).

## 4. Contrats d'API des paquets

### internal/record
```go
const (
    TypeHS1   byte = 1
    TypeHS2   byte = 2
    TypeHS3   byte = 3
    TypeProbe byte = 4
    TypeData  byte = 5
    TypeRelay byte = 7
)
const HeaderLen = 3
func Frame(t byte, payload []byte) []byte                    // t ++ u16be(len) ++ payload
func Parse(datagram []byte) (t byte, payload []byte, err error) // une seule trame ; erreur : ErrTooShort, ErrOversized, ErrTrailing
func ReadFrame(r io.Reader) (t byte, payload []byte, err error) // pour un flux (TCP) : lire HeaderLen puis le payload
```
Erreurs : `var ErrTooShort`, `var ErrOversized`, `var ErrTrailing`. Test : roundtrip, payload 0, payload 65535, datagramme corrompu.

### internal/noisework
```go
const KeySize = 32
const DefaultRekeyEvery uint64 = 1 << 20  // nombre de messages pour la rotation de clé dans chaque direction
const MaxNonce = ^uint64(0) - 1           // garde d'épuisement des nonces (réserve de rekey)
type Keypair struct { Public, Private []byte }  // 32 octets bruts, toujours réalloués
func GenerateKeypair() (*Keypair, error)
func LoadOrCreateKeyfile(path string) (*Keypair, error)  // lit un fichier hex ; le crée en 0600 sinon
func (k *Keypair) PublicHex() string
func ParsePublicKeyHex(s string) ([]byte, error)

type Session struct { peerStatic, channelBinding []byte }  // champs non exportés
func (s *Session) Send(plaintext []byte) (uint64, []byte, error)
    // nonce DATA + texte chiffré ; le nonce est transporté explicitement en tête de trame (8B BE).
    // un nonce exigeant un rekey au-delà de maxEpochJump est rejeté (plafond anti-DoS).
func (s *Session) Encrypt(plaintext []byte) ([]byte, error)     // canal de contrôle : envoi séquentiel
func (s *Session) DecryptAt(nonce uint64, ciphertext []byte) ([]byte, error)  // canal de données : nonce explicite
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error)    // canal de contrôle : réception séquentielle
func (s *Session) PeerStatic() []byte
func (s *Session) ChannelBinding() []byte
func (s *Session) MaxPlaintextLen() int  // texte clair maximal d'un seul datagramme : 65507 (UDP IPv4 max) - 3 (en-tête de trame) - 16 (tag AEAD) = 65504 ; sur le chemin relais, réduit en outre de la taille de l'en-tête relais

type Initiator struct{}
func NewInitiator(myStatic *Keypair, peerStatic []byte, prologue []byte) (*Initiator, error)
func (i *Initiator) Message1() ([]byte, error)
func (i *Initiator) ReadMessage2(msg2 []byte) (*Session, error)
func (i *Initiator) WriteMessage3() ([]byte, error)   // XX : msg3 contient le statique de l'initiateur

type Responder struct{}
func NewResponder(myStatic *Keypair, prologue []byte) (*Responder, error)
func (r *Responder) ReadMessage1(msg1 []byte) error
func (r *Responder) Message2() ([]byte, error)
func (r *Responder) ReadMessage3(msg3 []byte) (*Session, error)
```
Contrat : `PeerStatic()` est renseigné une fois le handshake terminé ; nil avant cela. Clé statique erronée/message corrompu →
erreur. Rekey : l'émetteur et le récepteur appliquent la même règle d'époque ; dépasser `maxEpochJump` est rejeté,
les paquets perdus sont tolérés via les sauts d'époque. Test : boucle initiateur/répondant + plusieurs
Encrypt/Decrypt + erreur de message tamponné + correspondance peerStatic + nonce perdu/hors ordre + rotations
de rekey + rejet de nonce obsolète.

### internal/stun
```go
func EncodeBindingRequest(txid [12]byte) []byte   // RFC 8489 : type 0x0001 len 0 cookie + txid
func NewTransactionID() [12]byte
func DecodeXORMappedAddress(pkt []byte) (*net.UDPAddr, error) // réponse 0x0101 ; vérifier le cookie
func ResolvePublicAddr(conn *net.UDPConn, server *net.UDPAddr, timeout time.Duration) (*net.UDPAddr, error)
    // envoyer la requête via conn, lire la réponse, retourner XOR-MAPPED-ADDRESS.
    // conn reste le même socket (la cohérence du mapping NAT est critique).
func HandleBindingRequest(pkt []byte, src *net.UDPAddr) ([]byte, error)
    // côté serveur : produire une réponse de binding contenant XOR-MAPPED-ADDRESS pour src.
```
Test : aller-retour serveur↔client sur une véritable connexion UDP ; erreur de paquet tronqué ; erreur de cookie invalide.

### internal/nat
```go
type Behavior int
const (
    BehaviorFullCone         Behavior = iota // le mapping est conservé pour chaque dst, l'entrant est libre de toute src
    BehaviorAddressRestricted                 // entrant : mapping existe ET l'IP source du paquet a déjà été ciblée
    BehaviorSymmetric                         // mapping par (insideHost, dstIP, dstPort) ; entrant : correspondance exacte requise
)
func ParseBehavior(s string) (Behavior, error)  // « fullcone », « restricted », « symmetric » (casse indifférente)

type Config struct {
    Name        string
    Behavior    Behavior
    PublicAddr  *net.UDPAddr // adresse du « dispositif NAT » accessible de l'extérieur (endpoint reflété)
    InsideDoor  *net.UDPAddr // porte de sortie de l'hôte intérieur : les paquets OUTBOUND de l'agent y sont envoyés
    PrivateHost *net.UDPAddr // le véritable socket de données de l'hôte intérieur : l'entrant y est transmis
}
type Box struct{}
func New(cfg Config) (*Box, error)
func (b *Box) Run(ctx context.Context) error   // bloque ; écoute sur public et inside door
func (b *Box) Close() error
func (b *Box) Public() *net.UDPAddr            // retourne cfg.PublicAddr
func (b *Box) Stats() Stats
type Stats struct { Outbound, Inbound, Dropped uint64; Mappings int }
```
Contrat de comportement :
- Sortant : un paquet arrivant à la porte intérieure avec src == PrivateHost → créer un mapping, réécrire src en PublicAddr,
  envoyer vers le vrai dst via le PublicSocket. Enveloppe : `[0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`.
- Entrant : un paquet arrivant au PublicSocket → selon les règles du comportement, transmettre à PrivateHost si applicable. La
  remise se fait dans une enveloppe portant la véritable adresse source externe : `[0x53][u16 src_len][src][frame]` (src =
  l'adresse PublicSocket de l'hôte externe). Les adresses sources ne pouvant pas être usurpées sur loopback, l'agent n'associe
  un pair qu'à partir de cette source externe ; les réponses STUN et les trames sont traitées de même en ouvrant la même enveloppe.
- Expiration du mapping : 30 s (les tests peuvent passer `0` = pour toujours — vous pouvez ajouter `MappingTTL time.Duration` à Config ; 0 = n'expire jamais).
Test : roundtrip fullcone client↔externe ; symmetric : entrant accepté après un sortant vers le même dst, entrant REJETÉ vers un
dst différent ; restricted : entrant REJETÉ depuis une IP src sans mapping.

### internal/relay
```go
const Magic byte = 0x52
const MaxNameLen = 64
type Config struct {
    Addr *net.UDPAddr          // adresse d'écoute ; port 0 éphémère (Addr() indique le vrai port)
    PinGrace time.Duration     // durée d'épinglage nom→adresse (défaut 30 s ; 0 = défaut, <0 = pas d'épinglage)
    MaxPPS int                 // limite pps par adresse source (défaut 300 ; <0 = désactivée)
    MaxBytesPS int             // limite octets/s par adresse source (défaut 128 KiB/s ; <0 = désactivée)
    NameQuotaBytes int         // quota d'octets/s transmis par nom de destination (défaut 256 KiB/s ; <0 = désactivé)
}
type Server struct{}
func New(cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) Addr() *net.UDPAddr
func (s *Server) Stats() Stats
type Stats struct {
    Wrapped, Forwarded, Dropped uint64
    PinnedDropped uint64  // rejeté car le nom source est épinglé à une autre adresse (G2)
    RateLimited   uint64  // paquets dépassant le budget de débit/quota (G4)
}
```
Comportement (phase 3) : l'adresse `peers[srcID]` est **épinglée** à chaque paquet ; si le même nom
apparaît depuis une autre adresse dans `PinGrace`, le paquet est rejeté (`PinnedDropped++`,
le vol de nom / la perturbation de remise est fermé — G2). Si `Peers[dstID]` existe, transmettre la
trame là ; lorsque le budget pps/octets par adresse source ou le quota d'octets par nom de destination
est dépassé, `RateLimited++` (la surface d'amplification rétrécit — G4). Le datagramme transmis
est ré-enveloppé avec le même en-tête de relais
(`[0x52][u16 src_len][src][u16 dst_len][dst][frame]`), de sorte que N pairs partageant un unique socket
de relais peuvent distinguer l'identité source d'un paquet livré.
Le relais ne voit jamais les données chiffrées (Noise de bout en bout).
Test : deux « agents » échangent des trames via le relais avec des connexions UDP localhost ; rejet de dst inconnu ; erreur d'en-tête corrompu ;
rejet de violation d'épinglage ; indicateurs de limite de débit/quota.

### internal/protocol (plan de contrôle)
```go
type Message struct {                    // un seul struct, Type string
    Type      string `json:"type"`
    ID        string `json:"id,omitempty"`
    PubKey    string `json:"pubkey,omitempty"`
    Endpoints []string `json:"endpoints,omitempty"`
    Peers     []PeerInfo `json:"peers,omitempty"`
    Msg       string `json:"msg,omitempty"`
}
type PeerInfo struct {
    ID        string   `json:"id"`
    PubKey    string   `json:"pubkey"`
    Endpoints []string `json:"endpoints"`
}
const ( TypeRegister="register"; TypeHello="hello"; TypePeerList="peer_list"; TypeError="error" )
func EncodeLine(v any) ([]byte, error)            // JSON + "\n"
func DecodeLine(b []byte) (*Message, error)
```
Test : roundtrip register/peer_list.

### internal/control (connexion de contrôle)
```go
type Conn struct{...}          // connexion TCP tramée, authentifiée par Noise-XX
func Initiate(conn net.Conn, myKP *Keypair, peerStatic []byte) (*Conn, error)
    // côté client : épingle la clé statique du coordinateur/pair ; borné par handshakeTimeout
func Accept(conn net.Conn, myKP *Keypair) (peerStatic []byte, c *Conn, err error)
    // côté serveur ; retourne la clé statique du pair (mise en correspondance avec l'inscription)
func (c *Conn) WriteMsg(plaintext []byte) error   // [4B longueur BE][ciphertext] ; écrivains simultanés mutexés
func (c *Conn) ReadMsg() ([]byte, error)          // plafond de longueur maxMsgLen ; canal de session optionnel
func (c *Conn) Close() error
```
Les deux côtés **doivent vérifier** `PeerStatic()` (agent : la clé du coordinateur,
coordinateur : le pubkey du register — si la clé/signature ne correspond pas, TypeError/rejet de session).

### internal/coordinator
```go
type Config struct {
    CtrlAddr string // « ip:port » écoute TCP (plan de contrôle)
    StunAddr string // « ip:port » écoute UDP (STUN)
    Keyfile  string // chemin de la clé statique du coordinateur (hex ; créée en 0600 si absente)
}
type Server struct{}
func New(cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error   // TCP + STUN UDP simultanément
func (s *Server) Close() error
func (s *Server) PublicKeyHex() string            // valeur de --coord-pubkey des agents
func (s *Server) Addrs() (ctrl, stun net.Addr)
```
- Chaque client est authentifié via `control.Accept` ; le pubkey du register est accepté tant qu'il
  correspond à la clé statique de la session Noise ; une seconde inscription du même nom avec une clé
  différente est rejetée (épinglage de nom).
- STUN : utiliser `stun.HandleBindingRequest`, envoyer la réponse à src.
- Après le register, `peer_list` est diffusé à tous les pairs connectés (les écritures sont
  protégées par mutex — les diffusions simultanées n'entrelacent pas les trames).
Test : deux requêtes register → peer_list des deux côtés ; rejet d'inscription avec mauvaise clé ;
TypeError en cas d'inscription usurpée (pubkey/clé de session incohérents).

## 5. Intégration (agent, disco, peer — principales écritures de l'agent)

Comportement de l'agent (en bref, le contrat d'intégration) :
- Si `--nat <door>` est fourni, tous les paquets sortants vont à la porte ; sinon DIRECTEMENT à dst.
- STUN : requête de binding vers le STUN du coordinateur via le socket de données (à travers la porte) → endpoint public.
- register : nom + pubkey + endpoints [public, relay].
- peer_list → pour chaque pair : attribution de rôle ; PROBE (période de 500 ms) → HS1 (initiateur) →
  HS2/HS3 → données. Si le handshake direct échoue en 3 s → chemin RELAY (enveloppe + sonde + handshake).
- Message ping en JSON dans une trame DATA : `{"cmd":"ping","s":<seq>,"ts":<unixnano>}` →
  `{"cmd":"pong","s":<seq>,"ts":<unixnano>}`. Le RTT, les pertes et le chemin (direct|relay) sont rapportés.
- Démon (`up`) : traite les messages DATA des pairs (réponses pong/ping), keepalive périodique.

## 6. Règles de qualité

- `go vet` propre, `gofmt` appliqué, erreurs enveloppées avec `fmt.Errorf("...: %w")`.
- Utiliser `net.ListenPacket("udp", "127.0.0.1:0")` avec un port éphémère dans les tests (pas de conflits de ports).
- Les tests ne requièrent pas de root ni d'utilisation du réseau réel (localhost).
- Chaque paquet a un commentaire de documentation `// Package ...` ; les imports croisés entre paquets sont interdits : record/noisework/stun/nat/relay/protocol/coordinator sont indépendants entre eux. Seuls les paquets principaux et les paquets d'intégration importent les autres.
- Annulation via `context.Context` ; Run(ctx) s'arrête proprement quand ctx est annulé.
