# SPEC — meshlink v1 (MVP)

Mini zero-trust mesh VPN. Go monorepo. Everything can be tested over
localhost without root, using the NAT simulator (`natbox`).

## Module and folder structure

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

## Port layout (default, demo)

| Component | Port |
|---|---|
| coordinator TCP (control) | 19200 |
| coordinator UDP (STUN) | 19201 |
| relay UDP | 19205 |
| natbox-1 public / inside door | 19301 / 19401 |
| natbox-2 public / inside door | 19302 / 19402 |
| agent a (data) | 19501 |
| agent b (data) | 19502 |

## Dependency

Only `github.com/flynn/noise v1.1.0`. (x/crypto, x/sys transitive.)

## 1. Wire format — data plane (UDP datagram = single frame)

Frame: `[1B type][2B length BE][payload]`, length <= 65535.

| type | name | meaning |
|---|---|---|
| 1 | HS1 | Noise XX message 1 (initiator → responder) |
| 2 | HS2 | Noise XX message 2 (responder → initiator) |
| 3 | HS3 | Noise XX message 3 (initiator → responder) |
| 4 | PROBE | empty probe (hole punching / NAT mapping) |
| 5 | DATA | encrypted Noise transport message: `[8B nonce BE][ciphertext]` (AEAD) |
| 7 | RELAY | agent → relay: `[magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`; relay → agent is likewise re-wrapped with the same header (the receiver thus separates the source identity for multiple peers) |

All length/endpoint fields are big-endian. The `record` package implements this contract.

## 2. Wire format — control plane (agent ↔ coordinator, TCP, Noise-auth framed)

The control channel (from Phase 3 onward) is authenticated with Noise XX: the client
pins the coordinator's static key; each connected party verifies the other's
`Session.PeerStatic()` key. After the handshake completes, every message is
sent as `[4B length BE][ciphertext]`; the contents of the ciphertext are a single
line of JSON (ends with `\n`). The length cap is bounded by `maxMsgLen`.

Handshake messages flow as `[2B length BE][Noise message]` (unencrypted, not unsigned —
Noise's own authentication mix) and are bounded by
`handshakeTimeout`.

Agent → Coor:
```json
{"type":"register","id":"a","pubkey":"<hex32>","endpoints":["127.0.0.1:19301","127.0.0.1:19205"]}
```
- `endpoints[0]`: public udp endpoint learned via STUN (data plane).
- `endpoints[1]` (optional): if a relay endpoint is used.

Coor → Agent:
```json
{"type":"peer_list","peers":[{"id":"a","pubkey":"<hex32>","endpoints":["..."]}]}
{"type":"query_result","count":2,"total":5,"up":123,"peers":[...]}
{"type":"error","msg":"..."}
```

Agent → Coor (additionally):
```json
{"type":"query"}
```
`query` asks for a registry snapshot (`query_result` answers it with the peer
list plus count/total/uptime).

Behavior: after every register, the coordinator sends `peer_list` to ALL peers (including the sender).
`peer_list` is an empty array if there are no peers.

## 3. Crypto

- Pattern: **Noise XX** (`noise.HandshakeXX`), CipherSuite: `DH25519 + CipherChaChaPoly + HashSHA256`.
- Prologue: `meshlink-v1` (identical on both sides).
- Role assignment: if `id_a < id_b` (bytewise) then `a` is initiator, `b` responder.
- Post-handshake authentication: each side **must verify** that its `Session.PeerStatic()` value
  matches the peer pubkey received from the coordinator.
- Transport data: `CipherState.WriteMessage` → ciphertext; frame type DATA.
- Data plane (Phase 2): explicit 64-bit nonce + WireGuard-style sliding window on the
  receiver (2048-bit bitmap). The window is **two-phase**: `Check` never mutates,
  and a nonce is committed only after the frame's AEAD authentication succeeds —
  an unauthenticated datagram with a wild nonce cannot slide the window away from
  honest frames. Duplicate/stale nonce rejection with reorder/loss tolerance.
- Periodic rekey: key rotation every `RekeyEvery` (default 2^20) messages;
  `maxEpochJump` DoS cap; nonce-exhaustion guard. Reorder tolerance spans frames
  *within* a rekey epoch; a frame lagging a full epoch cannot be recovered because
  epoch keys advance one-way (deterministic drop — documented behavior). The
  receive-side rekey is **authentication-gated**: the candidate epoch key is
  derived on a throwaway cipher state and committed only after the frame's AEAD
  check passes, so an unauthenticated datagram cannot advance the one-way epoch
  keys and lock the receive direction.
- Session age limit: a session's key material is dropped and the tunnel
  re-handshakes after 24 h (`sessionMaxAge`), rotating keys on an absolute timer
  as well as by message count.
- Handshake reliability: HS3 (the only handshake message without a built-in
  retry) is re-emitted by the initiator until the responder answers with an
  authenticated DATA frame; a duplicate HS1 received while the responder is
  half-open retransmits the cached HS2 instead of resetting the handshake, and
  half-open responder state is cleared after a 10 s timeout.
- Keepalive: empty DATA frame after 10 s of silence (NAT mapping + liveness).

## 4. Package API contracts

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
Errors: `var ErrTooShort`, `var ErrOversized`, `var ErrTrailing`. Test: roundtrip, 0-payload, 65535-payload, corrupted datagram.

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
Contract: `PeerStatic()` is populated once the handshake completes; nil before that. Wrong static/corrupted message →
error. Rekey: both sender and receiver apply the same epoch rule; exceeding `maxEpochJump` is rejected,
lost packets are tolerated via epoch jumps. Test: initiator/responder loop + multiple
Encrypt/Decrypt + buffered-message error + peerStatic match + lost/out-of-order nonce + rekey
rotations + stale-nonce rejection.

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
Test: server↔client roundtrip over a real UDP conn; truncated-packet error; invalid-cookie error.

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
Behavior contract:
- Outbound: a packet arriving at the inside door with src == PrivateHost → create a mapping, rewrite src to PublicAddr,
  send to the real dst over the PublicSocket. Envelope: `[0x52][u16 src_len][src][u16 dst_len][dst][inner frame]`.
- Inbound: a packet arriving at the PublicSocket → per the behavior rules, forward to PrivateHost if applicable. Delivery
  is done inside an envelope carrying the real external source address: `[0x53][u16 src_len][src][frame]` (src = the
  external host's PublicSocket address). Since source addresses cannot be spoofed over loopback, the agent matches a peer
  only from this external source; STUN responses and frames are likewise processed by opening the same envelope.
- Mapping expiration: 30 s (tests may pass `0` = forever — you may add `MappingTTL time.Duration` to Config; 0 = never expire).
Test: fullcone client↔extern roundtrip; symmetric: inbound accepted after outbound to the same dst, inbound DROP to a
different dst; restricted: inbound DROP from a src IP with no mapping.

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
Behavior (Phase 3): the address `peers[srcID]` is **pinned** per packet; if the same name
appears from another address within `PinGrace`, the packet is rejected (`PinnedDropped++`,
name stealing/delivery disruption is closed — G2). If `Peers[dstID]` exists, forward the
frame there; when the per-source-address pps/byte budget or the per-destination-name byte
quota is exceeded, `RateLimited++` (the amplification surface shrinks — G4). The forwarded
datagram is re-wrapped with the same relay header
(`[0x52][u16 src_len][src][u16 dst_len][dst][frame]`), so N peers sharing a single relay
socket can distinguish the source identity of a delivered packet.
The relay never sees the encrypted data (end-to-end Noise).
Test: two "agents" exchange frames over the relay with localhost UDP conns; unknown-dst drop; corrupted-header error;
pin-violation drop; rate-limit/quota flags.

### internal/protocol (control plane)
```go
type Message struct {                    // tek struct, Type string
    Type      string `json:"type"`
    ID        string `json:"id,omitempty"`
    PubKey    string `json:"pubkey,omitempty"`
    Endpoints []string `json:"endpoints,omitempty"`
    Peers     []PeerInfo `json:"peers,omitempty"`
    Msg       string `json:"msg,omitempty"`
    Count     int   `json:"count,omitempty"` // query_result only
    Total     int   `json:"total,omitempty"` // query_result only
    Up        int64 `json:"up,omitempty"`    // query_result only
}
type PeerInfo struct {
    ID        string   `json:"id"`
    PubKey    string   `json:"pubkey"`
    Endpoints []string `json:"endpoints"`
}
const ( TypeRegister="register"; TypePeerList="peer_list"; TypeQuery="query"; TypeQueryResult="query_result"; TypeError="error" )
const MaxControlLine = 64 << 10          // tek satır kontrol mesajı tavanı (bellek DoS kapağı)
var ErrControlLineTooLong                // MaxControlLine aşan satır
func EncodeLine(v any) ([]byte, error)            // JSON + "\n"
func DecodeLine(b []byte) (*Message, error)
func ReadLine(r *bufio.Reader) ([]byte, error)    // satırı biriktirmeden okur; uzun satırda ErrControlLineTooLong
```
Test: register/peer_list roundtrip.

### internal/control (control connection)
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
Both sides **must verify** `PeerStatic()` (agent: the coordinator's key,
coordinator: the register pubkey — if the key/signature does not match, TypeError/session rejection).

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
- Every client is authenticated via `control.Accept`; the pubkey in register is accepted as long as it
  matches the Noise session's static key; a second registration of the same name with a different
  key is rejected (name pinning).
- STUN: use `stun.HandleBindingRequest`, send the response to src.
- After register, `peer_list` is broadcast to all connected peers (writes are
  mutex-protected — concurrent broadcasts do not interleave frames).
Test: two register requests → peer_list on both sides; wrong-key register rejection;
spoofed registration (pubkey/session key mismatch) TypeError.

## 5. Integration (agent, disco, peer — main agent writes)

Agent behavior (in brief, the integration contract):
- If `--nat <door>` is given, all outbound packets go to the door; otherwise DIRECTLY to dst.
- STUN: binding request to the coordinator STUN over the data socket (through the door) → public endpoint.
- register: name + pubkey + [public, relay] endpoints.
- peer_list → for each peer: role assignment; PROBEs (500 ms period) → HS1 (initiator) →
  HS2/HS3 → data. If the direct handshake fails within 3 s → RELAY path (wrap + probe + handshake).
- Ping message as JSON inside a DATA frame: `{"cmd":"ping","s":<seq>,"ts":<unixnano>}` →
  `{"cmd":"pong","s":<seq>,"ts":<unixnano>}`. RTT, loss, and path (direct|relay) are reported.
- Daemon (`up`): processes DATA messages from peers (pong/ping replies), periodic keepalive.

## 6. Quality rules

- `go vet` clean, `gofmt` applied, errors wrapped with `fmt.Errorf("...: %w")`.
- Use `net.ListenPacket("udp", "127.0.0.1:0")` with an ephemeral port in tests (no port conflicts).
- Tests require no root and no real network usage (localhost).
- Every package has a `// Package ...` doc comment; cross-package imports are forbidden: record/noisework/stun/nat/relay/protocol/coordinator are dagger-independent. Only main packages and integration packages import the others.
- Cancellation via `context.Context`; Run(ctx) shuts down cleanly when ctx is cancelled.
