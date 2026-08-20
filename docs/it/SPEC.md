# SPEC — meshlink v1 (MVP)

Mini VPN mesh zero-trust. Monorepo Go. Tutto può essere testato su
localhost senza root, usando il simulatore NAT (`natbox`).

## Struttura di moduli e cartelle

```
module meshlink  (go 1.26)

cmd/
  coordinator/main.go    # server di controllo (registrazione TCP + STUN UDP, sessioni Noise)
  relay/main.go          # server relay UDP (pinning dei nomi + limiti di velocità/quota)
  natbox/main.go         # simulatore NAT
  agent/main.go          # client (daemon `up` + `ping` one-shot)
internal/
  record/                # framing del data plane
  noisework/             # handshake Noise XX + sessione (rekey, finestra anti-replay)
  control/               # connessione di controllo autenticata + framing (auth Noise)
  stun/                  # client+server STUN
  nat/                   # core di natbox (simulatore NAT)
  relay/                 # core del server relay
  protocol/              # messaggi JSON del piano di controllo
  coordinator/           # core del coordinator (pinning nomi/chiavi)
  peer/                  # gestore delle sessioni
  disco/                 # hole punching + selezione del percorso
  agent/                 # core del client (incluso il bridge TUN)
  tun/                   # dispositivo TUN + tabella di routing IPv4
docs/
  ARCHITECTURE.md
  SPEC.md
scripts/
  demo.sh
Makefile
```

## Layout delle porte (default, demo)

| Component | Port |
|---|---|
| coordinator TCP (control) | 19200 |
| coordinator UDP (STUN) | 19201 |
| relay UDP | 19205 |
| natbox-1 public / inside door | 19301 / 19401 |
| natbox-2 public / inside door | 19302 / 19402 |
| agent a (data) | 19501 |
| agent b (data) | 19502 |

## Dipendenza

Solo `github.com/flynn/noise v1.1.0`. (x/crypto, x/sys transitivi.)

## 1. Formato wire — data plane (datagramma UDP = frame singolo)

Frame: `[1B type][2B length BE][payload]`, length <= 65535.

| type | name | meaning |
|---|---|---|
| 1 | HS1 | Noise XX message 1 (initiator → responder) |
| 2 | HS2 | Noise XX message 2 (responder → initiator) |
| 3 | HS3 | Noise XX message 3 (initiator → responder) |
| 4 | PROBE | empty probe (hole punching / NAT mapping) |
| 5 | DATA | encrypted Noise transport message: `[8B nonce BE][ciphertext]` (AEAD) |
| 7 | RELAY | agent → relay: `[magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`; relay → agent is likewise re-wrapped with the same header (the receiver thus separates the source identity for multiple peers) |

Tutti i campi di lunghezza/endpoint sono big-endian. Il pacchetto `record` implementa
questo contratto.

## 2. Formato wire — piano di controllo (agent ↔ coordinator, TCP, framing con auth Noise)

Il canale di controllo (dalla Fase 3 in poi) è autenticato con Noise XX: il client
fissa la chiave statica del coordinator; ciascuna delle parti connesse verifica la
chiave `Session.PeerStatic()` dell'altra. Dopo il completamento dell'handshake, ogni
messaggio viene inviato come `[4B length BE][ciphertext]`; il contenuto del testo
cifrato è una singola riga di JSON (termina con `\n`). Il limite di lunghezza è
delimitato da `maxMsgLen`.

I messaggi di handshake scorrono come `[2B length BE][Noise message]` (non crittografati,
ma non senza firma — il mix di autenticazione proprio di Noise) e sono delimitati da
`handshakeTimeout`.

Agent → Coor:
```json
{"type":"register","id":"a","pubkey":"<hex32>","endpoints":["127.0.0.1:19301","127.0.0.1:19205"]}
```
- `endpoints[0]`: endpoint udp pubblico appreso via STUN (data plane).
- `endpoints[1]` (opzionale): se viene usato un endpoint relay.

Coor → Agent:
```json
{"type":"hello","id":"a"}
{"type":"peer_list","peers":[{"id":"a","pubkey":"<hex32>","endpoints":["..."]}]}
{"type":"error","msg":"..."}
```

Comportamento: dopo ogni register, il coordinator invia `peer_list` a TUTTI i peer
(incluso il mittente). `peer_list` è un array vuoto se non ci sono peer.

## 3. Crittografia

- Pattern: **Noise XX** (`noise.HandshakeXX`), CipherSuite: `DH25519 + CipherChaChaPoly + HashSHA256`.
- Prologo: `meshlink-v1` (identico su entrambi i lati).
- Assegnazione dei ruoli: se `id_a < id_b` (confronto byte per byte) allora `a` è
  l'iniziatore, `b` il risponditore.
- Autenticazione post-handshake: ciascun lato **deve verificare** che il proprio valore
  `Session.PeerStatic()` corrisponda alla pubkey del peer ricevuta dal coordinator.
- Dati di trasporto: `CipherState.WriteMessage` → testo cifrato; tipo di frame DATA.
- Data plane (Fase 2): nonce esplicito a 64 bit + finestra scorrevole stile WireGuard
  sul ricevitore (bitmap da 2048 bit) — rifiuto dei nonce duplicati/obsoleti,
  tolleranza alla perdita.
- Rekey periodico: rotazione delle chiavi ogni `RekeyEvery` (default 2^20) messaggi;
  tappo anti-DoS `maxEpochJump`; protezione contro l'esaurimento dei nonce e limite
  di età della sessione.
- Keepalive: frame DATA vuoto dopo 10 s di silenzio (mapping NAT + liveness).

## 4. Contratti API dei pacchetti

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
func Parse(datagram []byte) (t byte, payload []byte, err error) // frame singolo; error: ErrTooShort, ErrOversized, ErrTrailing
func ReadFrame(r io.Reader) (t byte, payload []byte, err error) // per stream (TCP): leggi HeaderLen poi il payload
```
Errori: `var ErrTooShort`, `var ErrOversized`, `var ErrTrailing`. Test: roundtrip,
payload 0, payload 65535, datagramma corrotto.

### internal/noisework
```go
const KeySize = 32
const DefaultRekeyEvery uint64 = 1 << 20  // numero di messaggi per la rotazione delle chiavi in ogni direzione
const MaxNonce = ^uint64(0) - 1           // protezione dall'esaurimento dei nonce (riserva per il rekey)
type Keypair struct { Public, Private []byte }  // 32 byte raw, sempre riallocati
func GenerateKeypair() (*Keypair, error)
func LoadOrCreateKeyfile(path string) (*Keypair, error)  // legge il file hex; se manca lo crea con 0600
func (k *Keypair) PublicHex() string
func ParsePublicKeyHex(s string) ([]byte, error)

type Session struct { peerStatic, channelBinding []byte }  // campi non esportati
func (s *Session) Send(plaintext []byte) (uint64, []byte, error)
    // nonce DATA + testo cifrato; il nonce è trasportato esplicitamente all'inizio del frame (8B BE).
    // i nonce che richiedono un rekey oltre maxEpochJump vengono rifiutati (tappo anti-DoS).
func (s *Session) Encrypt(plaintext []byte) ([]byte, error)     // canale di controllo: invio sequenziale
func (s *Session) DecryptAt(nonce uint64, ciphertext []byte) ([]byte, error)  // canale dati: nonce esplicito
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error)    // canale di controllo: ricezione sequenziale
func (s *Session) PeerStatic() []byte
func (s *Session) ChannelBinding() []byte
func (s *Session) MaxPlaintextLen() int  // plaintext massimo per singolo datagramma: 65507 (UDP IPv4 max) - 3 (hdr frame) - 16 (tag AEAD) = 65504; sul percorso relay diminuisce ulteriormente dell'header del relay

type Initiator struct{}
func NewInitiator(myStatic *Keypair, peerStatic []byte, prologue []byte) (*Initiator, error)
func (i *Initiator) Message1() ([]byte, error)
func (i *Initiator) ReadMessage2(msg2 []byte) (*Session, error)
func (i *Initiator) WriteMessage3() ([]byte, error)   // XX: msg3 = contiene la statica dell'iniziatore

type Responder struct{}
func NewResponder(myStatic *Keypair, prologue []byte) (*Responder, error)
func (r *Responder) ReadMessage1(msg1 []byte) error
func (r *Responder) Message2() ([]byte, error)
func (r *Responder) ReadMessage3(msg3 []byte) (*Session, error)
```
Contratto: `PeerStatic()` è popolato al completamento dell'handshake; nil prima di
allora. Statics errata/messaggio corrotto → errore. Rekey: sia mittente che ricevitore
applicano la stessa regola delle epoch; il superamento di `maxEpochJump` viene rifiutato,
i pacchetti persi sono tollerati tramite salti di epoch. Test: loop
iniziatore/risponditore + più Encrypt/Decrypt + errore per messaggio in buffer +
corrispondenza peerStatic + nonce perso/fuori ordine + rotazioni rekey + rifiuto dei
nonce obsoleti.

### internal/stun
```go
func EncodeBindingRequest(txid [12]byte) []byte   // RFC 8489: type 0x0001 len 0 cookie + txid
func NewTransactionID() [12]byte
func DecodeXORMappedAddress(pkt []byte) (*net.UDPAddr, error) // risposta 0x0101; verifica il cookie
func ResolvePublicAddr(conn *net.UDPConn, server *net.UDPAddr, timeout time.Duration) (*net.UDPAddr, error)
    // invia la request sulla conn, legge la risposta, restituisce XOR-MAPPED-ADDRESS.
    // la conn resta la stessa socket (la coerenza del mapping NAT è critica).
func HandleBindingRequest(pkt []byte, src *net.UDPAddr) ([]byte, error)
    // lato server: produce una binding response con XOR-MAPPED-ADDRESS per src.
```
Test: roundtrip server↔client su una conn UDP reale; errore per pacchetto troncato;
errore per cookie non valido.

### internal/nat
```go
type Behavior int
const (
    BehaviorFullCone         Behavior = iota // il mapping è conservato per ogni dst, inbound libero da ogni src
    BehaviorAddressRestricted                 // inbound: mapping presente E l'IP di src del pkt già contattato
    BehaviorSymmetric                         // mapping per (insideHost, dstIP, dstPort); inbound richiede corrispondenza esatta
)
func ParseBehavior(s string) (Behavior, error)  // "fullcone","restricted","symmetric" (senza distinzione maiuscole/minuscole)

type Config struct {
    Name        string
    Behavior    Behavior
    PublicAddr  *net.UDPAddr // indirizzo del "dispositivo NAT" visto dall'esterno (endpoint riflesso)
    InsideDoor  *net.UDPAddr // porta di uscita dell'host interno: i pacchetti OUTBOUND dell'agent vengono inviati qui
    PrivateHost *net.UDPAddr // socket dati reale dell'host interno: il traffico inbound viene inoltrato qui
}
type Box struct{}
func New(cfg Config) (*Box, error)
func (b *Box) Run(ctx context.Context) error   // bloccante; ascolta su public e inside door
func (b *Box) Close() error
func (b *Box) Public() *net.UDPAddr            // restituisce cfg.PublicAddr
func (b *Box) Stats() Stats
type Stats struct { Outbound, Inbound, Dropped uint64; Mappings int }
```
Contratto di comportamento:
- Outbound: un pacchetto che arriva all'inside door con src == PrivateHost → crea un
  mapping, riscrive src in PublicAddr, lo invia al dst reale attraverso la PublicSocket.
  Envelope: `[0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`.
- Inbound: un pacchetto che arriva alla PublicSocket → secondo le regole del comportamento,
  viene inoltrato a PrivateHost se applicabile. La consegna avviene dentro un envelope che
  trasporta il reale indirizzo sorgente esterno: `[0x53][u16 src_len][src][frame]`
  (src = indirizzo PublicSocket dell'host esterno). Poiché gli indirizzi sorgente non possono
  essere falsificati su loopback, l'agent associa un peer solo da questa sorgente esterna;
  le risposte STUN e i frame vengono ugualmente processati aprendo lo stesso envelope.
- Scadenza del mapping: 30 s (i test possono passare `0` = per sempre — puoi aggiungere
  `MappingTTL time.Duration` a Config; 0 = mai scadere).
Test: roundtrip fullcone client↔esterno; symmetric: inbound accettato dopo un outbound
verso la stessa dst, DROP dell'inbound verso una dst diversa; restricted: DROP
dell'inbound da un IP sorgente senza mapping.

### internal/relay
```go
const Magic byte = 0x52
const MaxNameLen = 64
type Config struct {
    Addr *net.UDPAddr          // indirizzo di ascolto; porta 0 effimera (Addr() comunica la porta reale)
    PinGrace time.Duration     // durata del pin nome→indirizzo (default 30s; 0 = default, <0 = nessun pin)
    MaxPPS int                 // limite pps per indirizzo sorgente (default 300; <0 = disattivato)
    MaxBytesPS int             // limite byte/s per indirizzo sorgente (default 128 KiB/s; <0 = disattivato)
    NameQuotaBytes int         // quota byte/s inoltrati per nome di destinazione (default 256 KiB/s; <0 = disattivato)
}
type Server struct{}
func New(cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) Addr() *net.UDPAddr
func (s *Server) Stats() Stats
type Stats struct {
    Wrapped, Forwarded, Dropped uint64
    PinnedDropped uint64  // rifiutati perché il nome sorgente è pinato a un altro indirizzo (G2)
    RateLimited   uint64  // pacchetti che superano il budget di rate/quota (G4)
}
```
Comportamento (Fase 3): l'indirizzo `peers[srcID]` è **pinato** per ogni pacchetto;
se lo stesso nome appare da un altro indirizzo entro `PinGrace`, il pacchetto viene
rifiutato (`PinnedDropped++`, il furto di nomi/l'interruzione della consegna è chiusa —
G2). Se `Peers[dstID]` esiste, inoltra il frame lì; quando il budget pps/byte per
indirizzo sorgente o la quota byte per nome di destinazione viene superato,
`RateLimited++` (la superficie di amplificazione si riduce — G4). Il datagramma
inoltrato viene ri-incapsulato con lo stesso header del relay
(`[0x52][u16 src_len][src][u16 dst_len][dst][frame]`), così N peer che condividono
una singola socket del relay possono distinguere l'identità sorgente di un pacchetto
consegnato. Il relay non vede mai i dati crittografati (Noise end-to-end).
Test: due "agent" si scambiano frame attraverso il relay con conn UDP su localhost;
drop per dst sconosciuta; errore per header corrotto; drop per violazione del pin;
flag rate-limit/quota.

### internal/protocol (piano di controllo)
```go
type Message struct {                    // singola struct, Type string
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
Test: roundtrip register/peer_list.

### internal/control (connessione di controllo)
```go
type Conn struct{...}          // connessione TCP framata e autenticata con Noise-XX
func Initiate(conn net.Conn, myKP *Keypair, peerStatic []byte) (*Conn, error)
    // lato client: fissa la chiave statica del coordinator/peer; delimitata da handshakeTimeout
func Accept(conn net.Conn, myKP *Keypair) (peerStatic []byte, c *Conn, err error)
    // lato server; restituisce la chiave statica del peer (da confrontare con la registrazione)
func (c *Conn) WriteMsg(plaintext []byte) error   // [4B lunghezza BE][ciphertext]; scrittori concorrenti con mutex
func (c *Conn) ReadMsg() ([]byte, error)          // limite di lunghezza maxMsgLen; canale di sessione opzionale
func (c *Conn) Close() error
```
Entrambi i lati **devono verificare** `PeerStatic()` (agent: la chiave del coordinator,
coordinator: la pubkey di register — se chiave/firma non corrisponde,
TypeError/rifiuto della sessione).

### internal/coordinator
```go
type Config struct {
    CtrlAddr string // "ip:port" in ascolto TCP (piano di controllo)
    StunAddr string // "ip:port" in ascolto UDP (STUN)
    Keyfile  string // percorso della chiave statica del coordinator (hex; se manca viene creata con 0600)
}
type Server struct{}
func New(cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error   // TCP + STUN UDP contemporaneamente
func (s *Server) Close() error
func (s *Server) PublicKeyHex() string            // il valore --coord-pubkey degli agent
func (s *Server) Addrs() (ctrl, stun net.Addr)
```
- Ogni client è autenticato tramite `control.Accept`; la pubkey in register è accettata
  finché corrisponde alla chiave statica della sessione Noise; una seconda registrazione
  dello stesso nome con una chiave diversa viene rifiutata (pinning del nome).
- STUN: usa `stun.HandleBindingRequest`, invia la risposta a src.
- Dopo register, `peer_list` viene trasmessa in broadcast a tutti i peer connessi
  (le scritture sono protette da mutex — le broadcast concorrenti non intercalano i frame).
Test: due richieste register → peer_list su entrambi i lati; rifiuto di register con
chiave errata; registrazione falsificata (mancata corrispondenza pubkey/chiave di
sessione) TypeError.

## 5. Integrazione (agent, disco, peer — principali scritture dell'agent)

Comportamento dell'agent (in breve, il contratto di integrazione):
- Se è presente `--nat <door>`, tutti i pacchetti outbound vanno al door; altrimenti
  DIRETTAMENTE a dst.
- STUN: binding request allo STUN del coordinator sulla socket dati (attraverso il
  door) → endpoint pubblico.
- register: nome + pubkey + endpoint [pubblico, relay].
- peer_list → per ogni peer: assegnazione del ruolo; PROBE (periodo 500 ms) → HS1
  (iniziatore) → HS2/HS3 → dati. Se l'handshake diretto fallisce entro 3 s → percorso
  RELAY (incapsulamento + probe + handshake).
- Messaggio di ping come JSON dentro un frame DATA: `{"cmd":"ping","s":<seq>,"ts":<unixnano>}` →
  `{"cmd":"pong","s":<seq>,"ts":<unixnano>}`. Vengono riportati RTT, perdita e percorso
  (direct|relay).
- Daemon (`up`): processa i messaggi DATA dei peer (risposte pong/ping), keepalive
  periodico.

## 6. Regole di qualità

- `go vet` pulito, `gofmt` applicato, errori avvolti con `fmt.Errorf("...: %w")`.
- Usa `net.ListenPacket("udp", "127.0.0.1:0")` con una porta effimera nei test (nessun
  conflitto di porte).
- I test non richiedono root né uso di rete reale (localhost).
- Ogni pacchetto ha un commento doc `// Package ...`; le importazioni tra pacchetti sono
  vietate: record/noisework/stun/nat/relay/protocol/coordinator sono indipendenti. Solo i
  pacchetti main e i pacchetti di integrazione importano gli altri.
- Cancellazione tramite `context.Context`; Run(ctx) si arresta pulitamente quando ctx
  è cancellato.
