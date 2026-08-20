# SPEC — meshlink v1 (MVP)

Mini sıfır-güven mesh VPN. Go monorepo. Her şey, NAT simülatörü (`natbox`)
kullanılarak root gerektirmeden localhost üzerinde test edilebilir.

## Modül ve klasör yapısı

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

## Port yerleşimi (varsayılan, demo)

| Bileşen | Port |
|---|---|
| koordinatör TCP (kontrol) | 19200 |
| koordinatör UDP (STUN) | 19201 |
| relay UDP | 19205 |
| natbox-1 public / iç kapı | 19301 / 19401 |
| natbox-2 public / iç kapı | 19302 / 19402 |
| agent a (veri) | 19501 |
| agent b (veri) | 19502 |

## Bağımlılık

Yalnızca `github.com/flynn/noise v1.1.0`. (x/crypto, x/sys geçişli.)

## 1. Hat formatı — veri düzlemi (UDP datagram = tek çerçeve)

Çerçeve: `[1B type][2B length BE][payload]`, uzunluk <= 65535.

| type | name | anlam |
|---|---|---|
| 1 | HS1 | Noise XX mesajı 1 (başlatıcı → yanıtlayıcı) |
| 2 | HS2 | Noise XX mesajı 2 (yanıtlayıcı → başlatıcı) |
| 3 | HS3 | Noise XX mesajı 3 (başlatıcı → yanıtlayıcı) |
| 4 | PROBE | boş yoklama (delik delme / NAT eşlemesi) |
| 5 | DATA | şifreli Noise taşıma mesajı: `[8B nonce BE][ciphertext]` (AEAD) |
| 7 | RELAY | ajan → relay: `[magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`; relay → ajan da aynı başlıkla yeniden sarılır (alıcı böylece birden çok eş için kaynak kimliğini ayırır) |

Tüm uzunluk/uç nokta alanları big-endian'dır. `record` paketi bu sözleşmeyi
uygular.

## 2. Hat formatı — kontrol düzlemi (ajan ↔ koordinatör, TCP, Noise-auth çerçeveli)

Kontrol kanalı (Faz 3'ten itibaren) Noise XX ile kimliği doğrulanır: istemci
koordinatörün statik anahtarını sabitler; bağlı her taraf diğerinin
`Session.PeerStatic()` anahtarını doğrular. El sıkışma tamamlandıktan sonra her
mesaj `[4B length BE][ciphertext]` olarak gönderilir; ciphertext'in içeriği tek
satır JSON'dur (`\n` ile biter). Uzunluk tavanı `maxMsgLen` ile sınırlıdır.

El sıkışma mesajları `[2B length BE][Noise message]` olarak akar (şifresiz,
imzasız değil — Noise'in kendi kimlik doğrulama karışımı) ve
`handshakeTimeout` ile sınırlıdır.

Ajan → Coor:
```json
{"type":"register","id":"a","pubkey":"<hex32>","endpoints":["127.0.0.1:19301","127.0.0.1:19205"]}
```
- `endpoints[0]`: STUN ile öğrenilen public UDP uç noktası (veri düzlemi).
- `endpoints[1]` (isteğe bağlı): bir relay uç noktası kullanılıyorsa.

Coor → Ajan:
```json
{"type":"hello","id":"a"}
{"type":"peer_list","peers":[{"id":"a","pubkey":"<hex32>","endpoints":["..."]}]}
{"type":"error","msg":"..."}
```

Davranış: her kayıttan sonra koordinatör `peer_list`'i TÜM eşlere gönderir
(gönderen dahil). Hiç eş yoksa `peer_list` boş bir dizidir.

## 3. Kripto

- Desen: **Noise XX** (`noise.HandshakeXX`), CipherSuite: `DH25519 + CipherChaChaPoly + HashSHA256`.
- Prolog: `meshlink-v1` (her iki tarafta aynı).
- Rol ataması: `id_a < id_b` ise (bayt bazında) `a` başlatıcı, `b` yanıtlayıcıdır.
- El sıkışma sonrası kimlik doğrulama: her taraf, `Session.PeerStatic()` değerinin
  koordinatörden alınan eş pubkey'i ile eşleştiğini **doğrulamalıdır**.
- Taşıma verisi: `CipherState.WriteMessage` → ciphertext; çerçeve tipi DATA.
- Veri düzlemi (Faz 2): açık 64-bit nonce + alıcıda WireGuard tarzı kayan
  pencere (2048-bit bitmap) — yinelenen/bayat nonce reddi, kayıp toleransı.
- Periyodik rekey: her `RekeyEvery` (varsayılan 2^20) mesajda anahtar dönüşü;
  `maxEpochJump` DoS kapağı; nonce tükenme koruması ve oturum yaş sınırı.
- Keepalive: 10 s sessizlikten sonra boş DATA çerçevesi (NAT eşlemesi + canlılık).

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
Hatalar: `var ErrTooShort`, `var ErrOversized`, `var ErrTrailing`. Test: gidiş-dönüş,
0-payload, 65535-payload, bozuk datagram.

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
Sözleşme: `PeerStatic()` el sıkışma tamamlandığında doldurulur; öncesinde nil'dir.
Yanlış statik/bozuk mesaj → hata. Rekey: gönderen ve alıcı aynı epoch kuralını
uygular; `maxEpochJump` aşımı reddedilir, kaybolan paketler epoch atlamalarıyla
tolere edilir. Test: başlatıcı/yanıtlayıcı döngüsü + birden çok Encrypt/Decrypt +
tamponlanmış mesaj hatası + peerStatic eşleşmesi + kayıp/sıra dışı nonce + rekey
dönüşleri + bayat-nonce reddi.

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
Test: gerçek bir UDP bağlantısı üzerinde sunucu↔istemci gidiş-dönüşü;
kırpılmış-paket hatası; geçersiz-cookie hatası.

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
- Çıkış (outbound): iç kapıya src == PrivateHost ile gelen bir paket → bir eşleme
  oluştur, src'yi PublicAddr olarak yeniden yaz, PublicSocket üzerinden gerçek
  hedefe gönder. Zarf: `[0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`.
- Giriş (inbound): PublicSocket'e gelen bir paket → davranış kurallarına göre,
  uygunsa PrivateHost'a ilet. Teslim, gerçek dış kaynak adresini taşıyan bir zarf
  içinde yapılır: `[0x53][u16 src_len][src][frame]` (src = dış hostun PublicSocket
  adresi). Loopback üzerinde kaynak adresleri taklit edilemediğinden ajan bir eşi
  yalnızca bu dış kaynaktan eşleştirir; STUN yanıtları ve çerçeveler de aynı zarf
  açılarak işlenir.
- Eşleme süresi dolumu: 30 s (testler `0` geçebilir = sonsuza kadar — Config'e
  `MappingTTL time.Duration` ekleyebilirsiniz; 0 = asla süresi dolmaz).
Test: fullcone istemci↔dış gidiş-dönüşü; symmetric: aynı hedefe outbound'tan sonra
inbound kabul edilir, farklı bir hedefe inbound DROP; restricted: eşlemesi olmayan
bir src IP'den inbound DROP.

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
Davranış (Faz 3): `peers[srcID]` adresi paket başına **sabitlenir**; aynı isim
`PinGrace` içinde başka bir adresten görünürse paket reddedilir
(`PinnedDropped++`, isim hırsızlığı/teslimat bozma kapatılır — G2).
`Peers[dstID]` varsa çerçeveyi oraya ilet; kaynak-adres başına pps/byte bütçesi
veya hedef-isim başına byte kotası aşılırsa `RateLimited++` (amplifikasyon yüzeyi
küçülür — G4). İletilen datagram aynı relay başlığıyla yeniden sarılır
(`[0x52][u16 src_len][src][u16 dst_len][dst][frame]`), böylece tek bir relay
soketini paylaşan N eş, teslim edilen bir paketin kaynak kimliğini ayırt
edebilir. Relay şifreli veriyi asla görmez (uçtan uca Noise).
Test: iki "ajan" localhost UDP bağlantılarıyla relay üzerinden çerçeve alışverişi
yapar; bilinmeyen-hedef düşüşü; bozuk-başlık hatası; pin-ihlali düşüşü;
rate-limit/kota bayrakları.

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
Test: register/peer_list gidiş-dönüşü.

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
Her iki taraf da `PeerStatic()`'i **doğrulamalıdır** (ajan: koordinatörün anahtarı,
koordinatör: register pubkey'i — anahtar/imza eşleşmezse TypeError/oturum reddi).

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
- Her istemci `control.Accept` ile kimlik doğrulanır; register'daki pubkey, Noise
  oturumunun statik anahtarıyla eşleştiği sürece kabul edilir; aynı ismin farklı
  bir anahtarla ikinci kez kaydı reddedilir (isim sabitleme).
- STUN: `stun.HandleBindingRequest` kullanın, yanıtı src'ye gönderin.
- Kayıttan sonra `peer_list` bağlı tüm eşlere yayınlanır (yazımlar mutex ile
  korunur — eşzamanlı yayınlar çerçeveleri iç içe geçirmez).
Test: iki register isteği → iki tarafta da peer_list; yanlış-anahtarlı kayıt reddi;
sahte kayıt (pubkey/oturum anahtarı uyuşmazlığı) TypeError.

## 5. Entegrasyon (agent, disco, peer — ana ajan yazıları)

Ajan davranışı (kısaca, entegrasyon sözleşmesi):
- `--nat <door>` verildiyse tüm giden paketler kapıya gider; aksi halde DOĞRUDAN hedefe.
- STUN: veri soketi üzerinden (kapı üzerinden) koordinatör STUN'una binding isteği
  → public uç nokta.
- register: isim + pubkey + [public, relay] uç noktaları.
- peer_list → her eş için: rol ataması; PROBE'lar (500 ms periyot) → HS1 (başlatıcı) →
  HS2/HS3 → veri. Doğrudan el sıkışma 3 s içinde başarısız olursa → RELAY yolu
  (sar + probe + el sıkışma).
- DATA çerçevesi içinde JSON olarak ping mesajı: `{"cmd":"ping","s":<seq>,"ts":<unixnano>}` →
  `{"cmd":"pong","s":<seq>,"ts":<unixnano>}`. RTT, kayıp ve yol (direct|relay) raporlanır.
- Daemon (`up`): eşlerden gelen DATA mesajlarını (pong/ping yanıtları) işler, periyodik keepalive.

## 6. Kalite kuralları

- `go vet` temiz, `gofmt` uygulanmış, hatalar `fmt.Errorf("...: %w")` ile sarılmış.
- Testlerde geçici (ephemeral) bir portla `net.ListenPacket("udp", "127.0.0.1:0")`
  kullanın (port çakışması yok).
- Testler root ve gerçek ağ kullanımı gerektirmez (localhost).
- Her paketin `// Package ...` dokümantasyon yorumu vardır; paketler arası içe
  aktarımlar yasaktır: record/noisework/stun/nat/relay/protocol/coordinator
  birbirinden bağımsızdır. Yalnızca main paketleri ve entegrasyon paketleri
  diğerlerini içe aktarır.
- İptal `context.Context` üzerinden; ctx iptal edildiğinde Run(ctx) temiz biçimde kapanır.
