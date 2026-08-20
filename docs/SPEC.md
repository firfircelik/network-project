# SPEC — meshlink v1 (MVP)

Mini zero-trust mesh VPN. Go monorepo. Her şey localhost üzerinde
root gerektirmeden, NAT simülatörü (`natbox`) ile test edilebilir.

## Modül ve klasör yapısı

```
module meshlink  (go 1.26)

cmd/
  coordinator/main.go    # kontrol sunucusu (TCP kayıt + UDP STUN, Noise oturumları)
  relay/main.go          # UDP röle sunucusu (isim pinleme + rate-limit/kota)
  natbox/main.go         # NAT simülatörü
  agent/main.go          # istemci (daemon `up` + tek seferlik `ping`)
internal/
  record/                # data-plane çerçeveleme
  noisework/             # Noise XX handshake + oturum (rekey, replay penceresi)
  control/               # doğrulanmış kontrol bağlantısı + çerçeveleme (Noise-auth)
  stun/                  # STUN istemci+sunucu
  nat/                   # natbox çekirdeği (NAT simülatörü)
  relay/                 # röle sunucusu çekirdeği
  protocol/              # kontrol düzlemi JSON mesajları
  coordinator/           # koordinatör çekirdeği (isim/anahtar pinleme)
  peer/                  # oturum yöneticisi
  disco/                 # hole punching + yol seçimi
  agent/                 # istemci çekirdeği (TUN köprüsü dahil)
  tun/                   # TUN aygıtı + IPv4 rota tablosu
docs/
  ARCHITECTURE.md
  SPEC.md
scripts/
  demo.sh
Makefile
```

## Port düzenleri (varsayılan, demo)

| Bileşen | Port |
|---|---|
| coordinator TCP (control) | 19200 |
| coordinator UDP (STUN) | 19201 |
| relay UDP | 19205 |
| natbox-1 public / inside door | 19301 / 19401 |
| natbox-2 public / inside door | 19302 / 19402 |
| agent a (data) | 19501 |
| agent b (data) | 19502 |

## Bağımlılık

Sadece `github.com/flynn/noise v1.1.0`. (x/crypto, x/sys transitif.)

## 1. Wire format — data plane (UDP datagram = tek frame)

Frame: `[1B type][2B length BE][payload]`, length <= 65535.

| type | ad | anlam |
|---|---|---|
| 1 | HS1 | Noise XX mesaj 1 (initiator → responder) |
| 2 | HS2 | Noise XX mesaj 2 (responder → initiator) |
| 3 | HS3 | Noise XX mesaj 3 (initiator → responder) |
| 4 | PROBE | boş probe (hole punching / NAT mapping) |
| 5 | DATA | şifreli Noise transport mesajı: `[8B nonce BE][ciphertext]` (AEAD) |
| 7 | RELAY | agent → röle: `[magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`; röle → agent da aynı başlıkla yeniden sarılır (alıcı çoklu eş için kaynak kimliğini böyle ayırır) |

Tüm uzunluk/endpoint alanları big-endian. `record` paketi bu sözleşmeyi uygular.

## 2. Wire format — kontrol düzlemi (agent ↔ coordinator, TCP, Noise-auth çerçeveli)

Kontrol kanalı (Faz 3'ten itibaren) Noise XX ile doğrulanır: istemci,
koordinatörün statik anahtarını sabitler; bağlanan her taraf diğerinin
`Session.PeerStatic()` anahtarını doğrular. El sıkışma tamamlandıktan sonra her
mesaj `[4B uzunluk BE][ciphertext]` olarak gönderilir; ciphertext'in içi bir
satır JSON'dur (`\n` ile biter). Uzunluk tavanı `maxMsgLen` ile sınırlıdır.

Handshake mesajları `[2B uzunluk BE][Noise mesajı]` (şifresiz, imzasız değil —
Noise'ın kendi kimlik doğrulama karışımı) olarak akar ve `handshakeTimeout` ile
sınırlanır.

Agent → Coor:
```json
{"type":"register","id":"a","pubkey":"<hex32>","endpoints":["127.0.0.1:19301","127.0.0.1:19205"]}
```
- `endpoints[0]`: STUN ile öğrenilen public udp endpoint (data plane).
- `endpoints[1]` (opsiyonel): röle endpoint kullanılıyorsa.

Coor → Agent:
```json
{"type":"hello","id":"a"}
{"type":"peer_list","peers":[{"id":"a","pubkey":"<hex32>","endpoints":["..."]}]}
{"type":"error","msg":"..."}
```

Davranış: her register sonrası koordinatör TÜM eşlere `peer_list` gönderir (gönderen dahil).
`peer_list` hiç eş yoksa boş dizi olur.

## 3. Kripto

- Pattern: **Noise XX** (`noise.HandshakeXX`), CipherSuite: `DH25519 + CipherChaChaPoly + HashSHA256`.
- Prologue: `meshlink-v1` (her iki taraf aynı).
- Rol tayini: `id_a < id_b` (bytewise) ise `a` initiator, `b` responder.
- Handshake bittikten sonra kimlik doğrulama: her taraf `Session.PeerStatic()` değerinin,
  koordinatörden aldığı peer pubkey ile eşleştiğini **doğrulamak zorundadır**.
- Transport verisi: `CipherState.WriteMessage` → ciphertext; frame tipi DATA.
- Veri düzlemi (Faz 2): açık 64-bit nonce + alıcıda WireGuard tarzı kayar
  pencere (2048 bit bitmap) — tekrar/eski nonce reddi, kayıp toleransı.
- Periyodik rekey: her `RekeyEvery` (varsayılan 2^20) mesajda anahtar dönüşü;
  `maxEpochJump` DoS kapağı; nonce tükenme guard'ı ve oturum yaş sınırı.
- Keepalive: 10 sn sessizlikte boş DATA frame (NAT mapping + liveness).

## 4. Paket API sözleşmeleri

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
Hatalar: `var ErrTooShort`, `var ErrOversized`, `var ErrTrailing`. Test: roundtrip, 0-payload, 65535-payload, bozuk datagram.

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
func (s *Session) MaxPlaintextLen() int  // en büyük tek-datagram plaintext'i: 65507 (max IPv4 UDP) - 3 (frame hdr) - 16 (AEAD tag) = 65504; relay yolunda ayrıca relay başlığı kadar azalır

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
Kontrat: `PeerStatic()` handshake tamamlanınca dolu; öncesinde nil. Yanlış statik/bozuk mesaj →
error. Rekey: hem gönderici hem alıcı aynı epoch kuralını uygular; `maxEpochJump` aşımı reddedilir,
kayıp paketler epoch atlamasıyla tolere edilir. Test: initiator/responder döngüsü + çoklu
Encrypt/Decrypt + tamponlı mesaj error + peerStatic eşleşmesi + kayıp/sırasız nonce + rekey
dönüşleri + eski nonce reddi.

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
Test: gerçek UDP conn üzerinden server↔client roundtrip; truncate edilmiş paket error; geçersiz cookie error.

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
Davranış sözleşmesi:
- Outbound: inside door'dan gelen, src == PrivateHost olan paket → mapping oluştur, src'yi PublicAddr'ya
  çevir, gerçek dst'ye PublicSocket üzerinden gönder. Envelope: `[0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`.
- Inbound: PublicSocket'e gelen paket → davranış kurallarına göre, varsa PrivateHost'a ilet. Teslimat,
  gerçek dış kaynak adresini taşıyan bir zarf içinde yapılır: `[0x53][u16 src_len][src][frame]` (src = harici
  hostun PublicSocket adresi). Loopback üzerinde kaynak adres spoof edilemediği için agent, peer'ı yalnızca
  bu dış kaynaktan eşleştirir; STUN yanıtları ve frame'ler de aynı zarfı açarak işlenir.
- Mapping expiration: 30 sn (testler `0` = sonsuz verebilir — Config'e `MappingTTL time.Duration` ekleyebilirsin, 0 = hiç expire etme).
Test: fullcone client↔extern roundtrip; symmetric: aynı dst'ye outbound sonrası inbound kabul, farklı
dst'ye inbound DROP; restricted: mapping olmayan src IP inbound DROP.

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
Davranış (Faz 3): paket başına `peers[srcID]` adresi **pinlenir**; aynı isim
`PinGrace` içinde başka adresten gelirse paket reddedilir (`PinnedDropped++`,
isim kaçırma/teslimat bozma kapanır — G2). `Peers[dstID]` varsa frame'i oraya
iletir; kaynak adresi başına pps/byte bütçesi ve hedef isim başına byte kotası
aşılınca `RateLimited++` (amplification yüzeyi daralır — G4). İletilen datagram
aynı relay başlığıyla yeniden sarılır
(`[0x52][u16 src_len][src][u16 dst_len][dst][frame]`), böylece tek relay
soketini paylaşan N eş, teslim edilen paketin kaynak kimliğini ayırt edebilir.
Relay şifreli veriyi görmez (uçtan uca Noise).
Test: iki "agent" localhost UDP conn ile relay üzerinden frame alışverişi; bilinmeyen dst drop; başlık bozuk error;
pin ihlali drop; rate-limit/kota bayrakları.

### internal/protocol (kontrol düzlemi)
```go
type Message struct {                    // tek struct, Type string
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
Test: register/peer_list roundtrip.

### internal/control (kontrol bağlantısı)
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
Her iki taraf `PeerStatic()`i **doğrulamak zorundadır** (agent: koordinatör anahtarı,
koordinatör: register pubkey — anahtar/imza eşleşmezse TypeError/oturum reddi).

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
- Her istemci `control.Accept` ile doğrulanır; register'daki pubkey, Noise
  oturumunun statik anahtarıyla çakıştığı sürece kabul edilir; aynı isimde
  farklı anahtar ikinci kayıt reddedilir (isim pinleme).
- STUN: `stun.HandleBindingRequest` kullan, src'ye response gönder.
- Register sonrası tüm bağlı eşlere `peer_list` broadcast edilir (yazma
  mutex'li — eşzamanlı broadcast'ler çerçevelemez).
Test: iki register isteği → her iki tarafta peer_list; yanlış-key register reddi;
spoof'lu (pubkey/oturum anahtarı eşleşmeyen) kayıt TypeError.

## 5. Entegrasyon (agent, disco, peer — main agent yazar)

Agent davranışı (kısaca, entegre sözleşme):
- `--nat <door>` verilirse tüm outbound paketler door'a gider; aksi halde DİREKT dst'ye.
- STUN: data socket üzerinden (door üzerinden) koordinatör STUN'una binding request → public endpoint.
- register: name + pubkey + [public, relay] endpoints.
- peer_list → her peer için: role tayini; PROBE'lar (500ms periyot) → HS1 (initiator) →
  HS2/HS3 → veri. Direct handshake 3 sn içinde başarısızsa → RELAY yolu (wrap + probe + handshake).
- Ping mesajı DATA framesi içinde JSON: `{"cmd":"ping","s":<seq>,"ts":<unixnano>}` →
  `{"cmd":"pong","s":<seq>,"ts":<unixnano>}`. RTT, kayıp, yol (direct|relay) rapor edilir.
- Daemon (`up`): peer'lardan gelen DATA mesajlarını işler (pong/ping yanıtlar), periyodik keepalive.

## 6. Kalite kuralları

- `go vet` temiz, `gofmt` uygulanmış, hatalar `fmt.Errorf("...: %w")` ile sarmalanmış.
- `net.ListenPacket("udp", "127.0.0.1:0")` testlerde ephemeral port kullan (port çakışması yok).
- Testler root gerektirmez, gerçek ağ kullanımı yok (localhost).
- Her paket `// Package ...` doc yorumu içerir; paketler arası import yasak: record/noisework/stun/nat/relay/protocol/coordinator hançer bağımsız. Sadece main'ler ve entegrasyon paketleri diğerlerini import eder.
- `context.Context` ile iptal; Run(ctx) ctx iptalinde temiz kapanır.