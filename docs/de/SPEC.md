# SPEC — meshlink v1 (MVP)

Mini-Zero-Trust-Mesh-VPN. Go-Monorepo. Alles kann ohne Root über localhost
getestet werden, mit dem NAT-Simulator (`natbox`).

## Modul- und Ordnerstruktur

```
module meshlink  (go 1.26)

cmd/
  coordinator/main.go    # control server (TCP registration + UDP STUN, Noise sessions)
  relay/main.go          # UDP relay server (name pinning + rate-limit/quota)
  natbox/main.go         # NAT simulator
  agent/main.go          # client (daemon `up` + one-shot `ping`)
internal/
  record/                # data-plane framing
  noisework/             # Noise XX handshake + session (rekey, replay window)
  control/               # authenticated control connection + framing (Noise-auth)
  stun/                  # STUN client+server
  nat/                   # natbox core (NAT simulator)
  relay/                 # relay server core
  protocol/              # control-plane JSON messages
  coordinator/           # coordinator core (name/key pinning)
  peer/                  # session manager
  disco/                 # hole punching + path selection
  agent/                 # client core (including TUN bridge)
  tun/                   # TUN device + IPv4 route table
docs/
  ARCHITECTURE.md
  SPEC.md
scripts/
  demo.sh
Makefile
```

## Port-Layout (Standard, Demo)

| Komponente | Port |
|---|---|
| Koordinator-TCP (Kontrolle) | 19200 |
| Koordinator-UDP (STUN) | 19201 |
| Relay-UDP | 19205 |
| natbox-1 public / Innentür | 19301 / 19401 |
| natbox-2 public / Innentür | 19302 / 19402 |
| Agent a (Daten) | 19501 |
| Agent b (Daten) | 19502 |

## Abhängigkeiten

Nur `github.com/flynn/noise v1.1.0`. (x/crypto, x/sys transitiv.)

## 1. Drahtformat — Datenebene (UDP-Datagramm = einzelner Frame)

Frame: `[1B type][2B length BE][payload]`, Länge <= 65535.

| Typ | Name | Bedeutung |
|---|---|---|
| 1 | HS1 | Noise-XX-Nachricht 1 (Initiator → Responder) |
| 2 | HS2 | Noise-XX-Nachricht 2 (Responder → Initiator) |
| 3 | HS3 | Noise-XX-Nachricht 3 (Initiator → Responder) |
| 4 | PROBE | leerer Probe (Hole Punching / NAT-Mapping) |
| 5 | DATA | verschlüsselte Noise-Transportnachricht: `[8B nonce BE][ciphertext]` (AEAD) |
| 7 | RELAY | Agent → Relay: `[magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`; Relay → Agent wird ebenso mit demselben Header neu umhüllt (der Empfänger trennt so die Quellidentität für mehrere Peers) |

Alle Längen-/Endpunktfelder sind Big-Endian. Das Paket `record` implementiert
diesen Vertrag.

## 2. Drahtformat — Kontrollebene (Agent ↔ Koordinator, TCP, Noise-auth gerahmt)

Der Kontrollkanal (ab Phase 3) wird mit Noise XX authentifiziert: Der Client
pinnt den statischen Schlüssel des Koordinators; jede verbundene Partei
verifiziert den `Session.PeerStatic()`-Schlüssel der anderen. Nach Abschluss
des Handshakes wird jede Nachricht als `[4B length BE][ciphertext]` gesendet;
der Inhalt des Ciphertexts ist eine einzelne JSON-Zeile (endet mit `\n`). Die
Längenobergrenze ist durch `maxMsgLen` begrenzt.

Handshake-Nachrichten laufen als `[2B length BE][Noise message]`
(unverschlüsselt, aber nicht unsigniert — Noises eigene
Authentifizierungsmischung) und sind durch `handshakeTimeout` begrenzt.

Agent → Koordinator:
```json
{"type":"register","id":"a","pubkey":"<hex32>","endpoints":["127.0.0.1:19301","127.0.0.1:19205"]}
```
- `endpoints[0]`: über STUN gelernter öffentlicher UDP-Endpunkt (Datenebene).
- `endpoints[1]` (optional): wenn ein Relay-Endpunkt verwendet wird.

Koordinator → Agent:
```json
{"type":"peer_list","peers":[{"id":"a","pubkey":"<hex32>","endpoints":["..."]}]}
{"type":"query_result","count":2,"total":5,"up":123,"peers":[...]}
{"type":"error","msg":"..."}
```

Verhalten: Nach jeder Registrierung sendet der Koordinator `peer_list` an ALLE
Peers (einschließlich des Absenders). Wenn es keine Peers gibt, ist
`peer_list` ein leeres Array.

## 3. Kryptografie

- Muster: **Noise XX** (`noise.HandshakeXX`), CipherSuite:
  `DH25519 + CipherChaChaPoly + HashSHA256`.
- Prolog: `meshlink-v1` (auf beiden Seiten identisch).
- Rollenzuweisung: Wenn `id_a < id_b` (byteweise), ist `a` Initiator und `b`
  Responder.
- Authentifizierung nach dem Handshake: Jede Seite **muss verifizieren**, dass
  ihr `Session.PeerStatic()`-Wert mit dem vom Koordinator empfangenen
  Peer-Pubkey übereinstimmt.
- Transportdaten: `CipherState.WriteMessage` → Ciphertext; Frame-Typ DATA.
- Datenebene (Phase 2): explizite 64-Bit-Nonce + WireGuard-artiges
  Schiebefenster auf Empfängerseite (2048-Bit-Bitmap) — Ablehnung
  doppelter/veralteter Nonces, Verlusttoleranz.
- Periodisches Rekeying: Schlüsselrotation alle `RekeyEvery` (Standard 2^20)
  Nachrichten; `maxEpochJump`-DoS-Obergrenze; Nonce-Erschöpfungs-Guard und
  Sitzungsalterslimit. Das empfängerseitige Rekey ist
  **authentifizierungsgeschützt**: der Epochenschlüssel-Kandidat wird auf einem
  Wegwerf-Cipher-State abgeleitet und erst übernommen, wenn die AEAD-Prüfung des
  Frames besteht; ein nicht authentifiziertes Datagramm kann die Einweg-Epochen-
  schlüssel daher nicht vorschieben und die Empfangsrichtung sperren.
- Handshake-Zuverlässigkeit: HS3 (die einzige Handshake-Nachricht ohne
  eingebaute Wiederholung) wird vom Initiator erneut gesendet, bis der Responder
  mit einem authentifizierten DATA-Frame antwortet; ein doppeltes HS1 bei
  halboffenem Responder sendet das gecachte HS2 erneut statt den Handshake
  zurückzusetzen, und veralteter halboffener Zustand wird nach 10 s Timeout
  geräumt.
- Keepalive: leerer DATA-Frame nach 10 s Stille (NAT-Mapping +
  Erreichbarkeit).

## 4. API-Verträge der Pakete

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
func Parse(datagram []byte) (t byte, payload []byte, err error) // tek frame; error: ErrTooShort, ErrOversized, ErrTrailing
func ReadFrame(r io.Reader) (t byte, payload []byte, err error) // stream (TCP) için, HeaderLen oku sonra payload
```
Fehler: `var ErrTooShort`, `var ErrOversized`, `var ErrTrailing`. Test:
Roundtrip, 0-Payload, 65535-Payload, beschädigtes Datagramm.

### internal/noisework
```go
const KeySize = 32
const DefaultRekeyEvery uint64 = 1 << 20  // her yönde anahtar dönüş mesaj sayısı
const MaxNonce = ^uint64(0) - 1           // nonce tükenme guard'ı (rekey rezervi)
type Keypair struct { Public, Private []byte }  // raw 32 bayt, her zaman yeniden tahsis
func GenerateKeypair() (*Keypair, error)
func LoadOrCreateKeyfile(path string) (*Keypair, error)  // hex dosya okur; yoksa 0600 ile üretir
func (k *Keypair) PublicHex() string
func ParsePublicKeyHex(s string) ([]byte, error)

type Session struct { peerStatic, channelBinding []byte }  // unexported alanlar
func (s *Session) Send(plaintext []byte) (uint64, []byte, error)
    // DATA nonce'u + ciphertext; nonce açıkça frame başında taşınır (8B BE).
    // maxEpochJump üstünde rekey gerektiren nonce reddedilir (DoS kapağı).
func (s *Session) Encrypt(plaintext []byte) ([]byte, error)     // kontrol kanalı: sıralı send
func (s *Session) DecryptAt(nonce uint64, ciphertext []byte) ([]byte, error)  // veri kanalı: explicit nonce
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error)    // kontrol kanalı: sıralı recv
func (s *Session) PeerStatic() []byte
func (s *Session) ChannelBinding() []byte
func (s *Session) MaxPlaintextLen() int  // en büyük tek-datagram plaintext'i: 65507 (max IPv4 UDP) - 3 (frame hdr) - 8 (açık nonce) - 16 (AEAD tag) = 65480; relay yolunda ayrıca relay başlığı kadar azalır

type Initiator struct{}
func NewInitiator(myStatic *Keypair, peerStatic []byte, prologue []byte) (*Initiator, error)
func (i *Initiator) Message1() ([]byte, error)
func (i *Initiator) ReadMessage2(msg2 []byte) (*Session, error)
func (i *Initiator) WriteMessage3() ([]byte, error)   // XX: msg3 = initiator statik içerir

type Responder struct{}
func NewResponder(myStatic *Keypair, prologue []byte) (*Responder, error)
func (r *Responder) ReadMessage1(msg1 []byte) error
func (r *Responder) Message2() ([]byte, error)
func (r *Responder) ReadMessage3(msg3 []byte) (*Session, error)
```
Vertrag: `PeerStatic()` ist gefüllt, sobald der Handshake abgeschlossen ist;
davor nil. Falsche statische/beschädigte Nachricht → Fehler. Rekeying: Sender
und Empfänger wenden dieselbe Epochenregel an; das Überschreiten von
`maxEpochJump` wird abgelehnt, verlorene Pakete werden über Epochensprünge
toleriert. Test: Initiator/Responder-Schleife + mehrere Encrypt/Decrypt +
Fehler bei gepufferter Nachricht + PeerStatic-Übereinstimmung + verlorene/
nicht geordnete Nonce + Rekey-Rotationen + Ablehnung veralteter Nonces.

### internal/stun
```go
func EncodeBindingRequest(txid [12]byte) []byte   // RFC 8489: type 0x0001 len 0 cookie + txid
func NewTransactionID() [12]byte
func DecodeXORMappedAddress(pkt []byte) (*net.UDPAddr, error) // 0x0101 response; cookie doğrula
func ResolvePublicAddr(conn *net.UDPConn, server *net.UDPAddr, timeout time.Duration) (*net.UDPAddr, error)
    // conn üzerinden request gönder, response oku, XOR-MAPPED-ADDRESS döndür.
    // conn aynı socket kalacak (NAT mapping tutarlılığı kritik).
func HandleBindingRequest(pkt []byte, src *net.UDPAddr) ([]byte, error)
    // sunucu tarafı: src için XOR-MAPPED-ADDRESS içeren binding response üret.
```
Test: Server↔Client-Roundtrip über eine echte UDP-Verbindung; Fehler bei
abgeschnittenem Paket; Fehler bei ungültigem Cookie.

### internal/nat
```go
type Behavior int
const (
    BehaviorFullCone         Behavior = iota // mapping her dst için korunur, inbound her src'den serbest
    BehaviorAddressRestricted                 // inbound: mapping var VE pkt src IP daha önce hedeflenmiş
    BehaviorSymmetric                         // mapping (insideHost, dstIP, dstPort) başına; inbound tam eşleşme şart
)
func ParseBehavior(s string) (Behavior, error)  // "fullcone","restricted","symmetric" (durum farkı yok)

type Config struct {
    Name        string
    Behavior    Behavior
    PublicAddr  *net.UDPAddr // dışarıdan erişilen "NAT cihazı" adresi (reflected endpoint)
    InsideDoor  *net.UDPAddr // iç hostun ödeme kapısı: agent OUTBOUND paketleri buraya gönderir
    PrivateHost *net.UDPAddr // iç hostun gerçek data socket'i: inbound buraya iletilir
}
type Box struct{}
func New(cfg Config) (*Box, error)
func (b *Box) Run(ctx context.Context) error   // bloklar; public ve inside door'da dinler
func (b *Box) Close() error
func (b *Box) Public() *net.UDPAddr            // cfg.PublicAddr döner
func (b *Box) Stats() Stats
type Stats struct { Outbound, Inbound, Dropped uint64; Mappings int }
```
Verhaltensvertrag:
- Outbound: Ein Paket, das an der Innentür mit src == PrivateHost ankommt →
  ein Mapping erstellen, src auf PublicAddr umschreiben und über den
  PublicSocket an das echte Ziel senden. Umschlag:
  `[0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`.
- Inbound: Ein Paket, das am PublicSocket ankommt → je nach Verhaltensregeln
  an PrivateHost weiterleiten, sofern zutreffend. Die Zustellung erfolgt in
  einem Umschlag mit der echten externen Quelladresse:
  `[0x53][u16 src_len][src][frame]` (src = die PublicSocket-Adresse des
  externen Hosts). Da Quelladressen über Loopback nicht gefälscht werden
  können, ordnet der Agent einen Peer nur dieser externen Quelle zu;
  STUN-Antworten und Frames werden ebenfalls durch Öffnen desselben Umschlags
  verarbeitet.
- Mapping-Ablauf: 30 s (Tests dürfen `0` übergeben = für immer — Sie dürfen
  `MappingTTL time.Duration` zu Config hinzufügen; 0 = läuft nie ab).
Test: Fullcone-Client↔externer Roundtrip; symmetric: Inbound nach Outbound zum
selben Ziel akzeptiert, Inbound DROP zu einem anderen Ziel; restricted: Inbound
DROP von einer src-IP ohne Mapping.

### internal/relay
```go
const Magic byte = 0x52
const MaxNameLen = 64
type Config struct {
    Addr *net.UDPAddr          // dinleme adresi; port 0 ephemeral (Addr() gerçek portu söyler)
    PinGrace time.Duration     // isim→adres pin süresi (varsayılan 30s; 0 = varsayılan, <0 = pin yok)
    MaxPPS int                 // kaynak adres başına pps limiti (varsayılan 300; <0 = kapalı)
    MaxBytesPS int             // kaynak adres başına byte/s limiti (varsayılan 128 KiB/s; <0 = kapalı)
    NameQuotaBytes int         // hedef isim başına forwarded byte/s kotası (varsayılan 256 KiB/s; <0 = kapalı)
}
type Server struct{}
func New(cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) Addr() *net.UDPAddr
func (s *Server) Stats() Stats
type Stats struct {
    Wrapped, Forwarded, Dropped uint64
    PinnedDropped uint64  // kaynak ismi başka adrese pinli olduğu için reddedilen (G2)
    RateLimited   uint64  // rate/kota bütçesini aşan paketler (G4)
}
```
Verhalten (Phase 3): Die Adresse `peers[srcID]` wird pro Paket **gepinnt**;
erscheint derselbe Name innerhalb von `PinGrace` von einer anderen Adresse,
wird das Paket abgelehnt (`PinnedDropped++`, Namensdiebstahl/
Zustellungsstörung ist geschlossen — G2). Existiert `Peers[dstID]`, wird der
Frame dorthin weitergeleitet; wenn das PPS/Byte-Budget pro Quelladresse oder
das Byte-Kontingent pro Zielnamen überschritten wird, wird `RateLimited++`
(die Amplifikationsfläche schrumpft — G4). Das weitergeleitete Datagramm wird
mit demselben Relay-Header neu umhüllt
(`[0x52][u16 src_len][src][u16 dst_len][dst][frame]`), sodass N Peers, die
sich einen einzigen Relay-Socket teilen, die Quellidentität eines zugestellten
Pakets unterscheiden können. Das Relay sieht nie die verschlüsselten Daten
(Ende-zu-Ende-Noise).
Test: Zwei „Agents" tauschen Frames über das Relay mit lokalen
UDP-Verbindungen aus; Drop bei unbekanntem Ziel; Fehler bei beschädigtem
Header; Drop bei Pin-Verletzung; Ratenlimit-/Kontingent-Flags.

### internal/protocol (Kontrollebene)
```go
type Message struct {                    // tek struct, Type string
    Type      string `json:"type"`
    ID        string `json:"id,omitempty"`
    PubKey    string `json:"pubkey,omitempty"`
    Endpoints []string `json:"endpoints,omitempty"`
    Peers     []PeerInfo `json:"peers,omitempty"`
    Msg       string `json:"msg,omitempty"`
    Count     int   `json:"count,omitempty"` // nur query_result
    Total     int   `json:"total,omitempty"` // nur query_result
    Up        int64 `json:"up,omitempty"`    // nur query_result
}
type PeerInfo struct {
    ID        string   `json:"id"`
    PubKey    string   `json:"pubkey"`
    Endpoints []string `json:"endpoints"`
}
const ( TypeRegister="register"; TypePeerList="peer_list"; TypeQuery="query"; TypeQueryResult="query_result"; TypeError="error" )
const MaxControlLine = 64 << 10          // Obergrenze für eine einzelne Kontrollnachricht (Speicher-DoS-Deckel)
var ErrControlLineTooLong                // Zeile überschreitet MaxControlLine
func EncodeLine(v any) ([]byte, error)            // JSON + "\n"
func DecodeLine(b []byte) (*Message, error)
func ReadLine(r *bufio.Reader) ([]byte, error)    // liest die Zeile ohne Akkumulation; ErrControlLineTooLong bei Überlänge
```
Test: register/peer_list-Roundtrip.

### internal/control (Kontrollverbindung)
```go
type Conn struct{...}          // Noise-XX ile doğrulanmış, çerçeveli TCP bağlantısı
func Initiate(conn net.Conn, myKP *Keypair, peerStatic []byte) (*Conn, error)
    // istemci tarafı: koordinatör/peer statik anahtarını sabitler; handshakeTimeout sınırlı
func Accept(conn net.Conn, myKP *Keypair) (peerStatic []byte, c *Conn, err error)
    // sunucu tarafı; peer static anahtarı döner (kayıtla eşleştirilir)
func (c *Conn) WriteMsg(plaintext []byte) error   // [4B uzunluk BE][ciphertext]; eşzamanlı yazıcılar mutex'li
func (c *Conn) ReadMsg() ([]byte, error)          // uzunluk tavanı maxMsgLen; opsiyonel session kanal
func (c *Conn) Close() error
```
Beide Seiten **müssen** `PeerStatic()` verifizieren (Agent: der Schlüssel des
Koordinators, Koordinator: der Register-Pubkey — stimmen Schlüssel/Signatur
nicht überein, erfolgt TypeError/Sitzungsablehnung).

### internal/coordinator
```go
type Config struct {
    CtrlAddr string // "ip:port" TCP dinleme (kontrol düzlemi)
    StunAddr string // "ip:port" UDP dinleme (STUN)
    Keyfile  string // koordinatör statik anahtarının yolu (hex; yoksa 0600 ile üretilir)
}
type Server struct{}
func New(cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error   // TCP + STUN UDP aynı anda
func (s *Server) Close() error
func (s *Server) PublicKeyHex() string            // agent'ların --coord-pubkey değeri
func (s *Server) Addrs() (ctrl, stun net.Addr)
```
- Jeder Client wird über `control.Accept` authentifiziert; der Pubkey in
  register wird akzeptiert, solange er mit dem statischen Schlüssel der
  Noise-Sitzung übereinstimmt; eine zweite Registrierung desselben Namens mit
  einem anderen Schlüssel wird abgelehnt (Namens-Pinning).
- STUN: `stun.HandleBindingRequest` verwenden, die Antwort an src senden.
- Nach register wird `peer_list` an alle verbundenen Peers gebroadcastet
  (Schreibvorgänge sind mutex-geschützt — gleichzeitige Broadcasts
  verschachteln keine Frames).
Test: zwei register-Anfragen → peer_list auf beiden Seiten; Ablehnung der
Registrierung mit falschem Schlüssel; TypeError bei gefälschter Registrierung
(Pubkey/Session-Key-Mismatch).

## 5. Integration (agent, disco, peer — Haupt-Agent-Implementierung)

Agent-Verhalten (in Kürze, der Integrationsvertrag):
- Wenn `--nat <door>` angegeben ist, gehen alle ausgehenden Pakete an die Tür;
  andernfalls DIREKT an dst.
- STUN: Binding-Request an den STUN des Koordinators über den Datensocket
  (durch die Tür) → öffentlicher Endpunkt.
- register: Name + Pubkey + [öffentliche, Relay]-Endpunkte.
- peer_list → für jeden Peer: Rollenzuweisung; PROBEs (500-ms-Periode) → HS1
  (Initiator) → HS2/HS3 → Daten. Scheitert der direkte Handshake innerhalb von
  3 s → RELAY-Pfad (umhüllen + probe + Handshake).
- Ping-Nachricht als JSON in einem DATA-Frame:
  `{"cmd":"ping","s":<seq>,"ts":<unixnano>}` →
  `{"cmd":"pong","s":<seq>,"ts":<unixnano>}`. RTT, Verlust und Pfad
  (direct|relay) werden gemeldet.
- Daemon (`up`): verarbeitet DATA-Nachrichten von Peers (Pong/Ping-Antworten),
  periodisches Keepalive.

## 6. Qualitätsregeln

- `go vet` sauber, `gofmt` angewendet, Fehler mit `fmt.Errorf("...: %w")`
  umhüllt.
- In Tests `net.ListenPacket("udp", "127.0.0.1:0")` mit einem ephemeren Port
  verwenden (keine Portkonflikte).
- Tests benötigen kein Root und keine echte Netzwerknutzung (localhost).
- Jedes Paket hat einen `// Package ...`-Dokumentationskommentar;
  paketübergreifende Imports sind verboten: record/noisework/stun/nat/relay/
  protocol/coordinator sind voneinander unabhängig. Nur Main-Pakete und
  Integrationspakete importieren die anderen.
- Abbruch über `context.Context`; Run(ctx) fährt sauber herunter, wenn ctx
  abgebrochen wird.