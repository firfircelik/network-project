// Package noisework implements the meshlink transport-layer cryptography:
// a Noise XX handshake using DH25519 + CipherChaChaPoly + HashSHA256, and an
// authenticated transport session on top of it.
//
// The handshake is driven by two role machines. The initiator knows the
// responder's static public key in advance, while the responder learns the
// initiator's static key from the final handshake message. Identity is
// verified once a side has observed its peer's static key, matching the
// meshlink contract that PeerStatic is filled once the handshake completes.
package noisework

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// LoadOrCreateKeyfile loads a private key from path (hex-encoded), generating
// and persisting a fresh one with 0600 permissions when the file does not
// exist. This is the coordinator's own key management; agents persist theirs
// through the same format in the agent package.
func LoadOrCreateKeyfile(path string) (*Keypair, error) {
	if path == "" {
		return nil, errors.New("noisework: keyfile path is required")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		// Trim surrounding whitespace so a file written with a trailing
		// newline (e.g. via echo) still parses.
		priv, perr := hex.DecodeString(strings.TrimSpace(string(data)))
		if perr == nil && len(priv) == KeySize {
			kp, kerr := keypairFromPrivate(priv)
			if kerr == nil {
				return kp, nil
			}
		}
		// The file exists but does not hold a usable key: fail loudly rather
		// than silently rotating this node's long-term identity (which would
		// break coordinator/agent key pinning).
		return nil, fmt.Errorf("noisework: existing keyfile %s is corrupt: %w", path, err)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("noisework: read keyfile %s: %w", path, err)
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(kp.Private)), 0o600); err != nil {
		return nil, fmt.Errorf("noisework: persist keypair %s: %w", path, err)
	}
	return kp, nil
}

// keypairFromPrivate reconstructs a Keypair from a raw private scalar by
// deriving the public key.
func keypairFromPrivate(priv []byte) (*Keypair, error) {
	if len(priv) != KeySize {
		return nil, errors.New("noisework: invalid private key length")
	}
	var dst, src [32]byte
	copy(src[:], priv)
	curve25519.ScalarBaseMult(&dst, &src)
	return &Keypair{Public: dst[:], Private: clone(priv)}, nil
}

// KeySize is the size in bytes of a Curve25519 public or private key.
const KeySize = 32

// Wire-size budget: meshlink delivers every frame inside exactly one UDP
// datagram. The largest single IPv4 UDP payload is 65507 bytes (65535 minus the
// 20-byte IP and 8-byte UDP headers); record.Frame then reserves 3 bytes for
// its [type][length] header, every DATA frame carries an explicit 8-byte
// transport nonce so the receiver can accept lossy/out-of-order delivery, and
// Noise adds a 16-byte ChaCha20-Poly1305 tag. maxPlaintextLen is therefore the
// largest plaintext a single datagram can carry, which is smaller than the
// 65535-byte framing contract of record.
const (
	maxUDPPayload   = 65507 // 65535 - IP(20) - UDP(8)
	frameHeader     = 3     // record.HeaderLen: [type][len BE]
	nonceLen        = 8     // explicit 64-bit transport nonce in every DATA frame
	aeadTag         = 16    // ChaCha20-Poly1305 tag
	maxPlaintextLen = maxUDPPayload - frameHeader - nonceLen - aeadTag
)

// DefaultRekeyEvery is the number of messages per direction after which the
// data key rotates deterministically (epoch = nonce / DefaultRekeyEvery). Both
// sides apply the same number of Rekey operations to the same cipher state, so
// a lost packet does not desynchronize the schedule. 2^20 bounds the amount of
// data protected under one key while keeping per-message overhead at zero.
const DefaultRekeyEvery uint64 = 1 << 20

// maxEpochJump bounds how many rekey operations a single frame may trigger.
// The send path advances at most one epoch per message in normal operation and
// a receive path crossing one boundary needs exactly one more rekey; a frame
// whose nonce demands a bigger jump is rejected instead of burned CPU, so one
// datagram cannot force an unbounded rekey loop. Sessions that fall more than
// maxEpochJump*DefaultRekeyEvery messages behind are re-established instead.
const maxEpochJump = 64

// MaxNonce is the largest transport nonce a session may use (mirrors
// flynn/noise.MaxNonce, which reserves one value for rekey bookkeeping).
const MaxNonce = ^uint64(0) - 1

// Handshake phases for the initiator and responder role machines.
const (
	phaseStart    = iota // role created, nothing exchanged yet
	phaseMessage1        // initiator sent msg1 / responder read msg1
	phaseMessage2        // initiator read msg2 / responder sent msg2
	phaseComplete        // msg3 processed, handshake finished
)

// newCipherSuite returns the meshlink Noise cipher suite.
func newCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// Keypair holds a raw Curve25519 keypair. Public and Private are always
// freshly allocated slices of KeySize bytes.
type Keypair struct {
	Public  []byte
	Private []byte
}

// GenerateKeypair creates a new random Curve25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	dk, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("noisework: generate keypair: %w", err)
	}
	return &Keypair{
		Public:  clone(dk.Public),
		Private: clone(dk.Private),
	}, nil
}

// PublicHex returns the public key as a 64-character lowercase hex string.
func (k *Keypair) PublicHex() string {
	if k == nil || k.Public == nil {
		return ""
	}
	return hex.EncodeToString(k.Public)
}

// ParsePublicKeyHex decodes a public key from exactly 64 hex characters into
// a fresh KeySize-byte slice.
func ParsePublicKeyHex(s string) ([]byte, error) {
	if len(s) != KeySize*2 {
		return nil, fmt.Errorf("noisework: public key hex must be %d characters, got %d", KeySize*2, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("noisework: invalid public key hex: %w", err)
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("noisework: decoded public key has %d bytes, want %d", len(b), KeySize)
	}
	return b, nil
}

// Session is an established Noise transport session. Encrypt/Send send an
// authenticated message to the remote peer using the send CipherState and
// Decrypt/DecryptAt receive one using the recv CipherState. Every message is
// stamped with an explicit 64-bit nonce; the receiving side tracks those
// nonces with a replay window (see internal/peer) and may decrypt out of
// order because DecryptAt seeks the recv CipherState to the frame's nonce.
// Keys rotate deterministically at every DefaultRekeyEvery-th message, which
// needs no extra protocol messages and tolerates lost frames. Reorder
// tolerance spans frames *within a rekey epoch*; a frame lagging one full
// epoch behind cannot be recovered because epoch keys advance one-way (the
// previous epoch's key material is gone once a newer epoch has been seen).
type Session struct {
	peerStatic     []byte
	channelBinding []byte
	send           *noise.CipherState
	recv           *noise.CipherState
	sendCount      uint64    // nonce of the next send
	recvCount      uint64    // expected nonce for the in-order Decrypt form
	sendEpoch      uint64    // rekeys already applied to send
	recvEpoch      uint64    // rekeys already applied to recv
	rekeyEvery     uint64    // message count between key rotations (0 = default)
	start          time.Time // when the handshake completed (age-based rotation)
}

// Send authenticates and encrypts plaintext for the remote peer, applying any
// scheduled key rotation first. It returns the nonce the receiver must use to
// decrypt the frame plus the ciphertext (which includes the 16-byte
// ChaCha20-Poly1305 tag). A session whose handshake has not completed yet
// returns an error.
func (s *Session) Send(plaintext []byte) (uint64, []byte, error) {
	if s == nil || s.send == nil {
		return 0, nil, errors.New("noisework: session not ready (handshake incomplete)")
	}
	if s.sendCount > MaxNonce {
		return 0, nil, fmt.Errorf("noisework: send nonce exhausted: %w", noise.ErrMaxNonce)
	}
	if !s.rekeySendTo(s.sendCount) {
		return 0, nil, fmt.Errorf("noisework: send nonce %d demands too large a rekey jump", s.sendCount)
	}
	s.send.SetNonce(s.sendCount)
	ct, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return 0, nil, fmt.Errorf("noisework: encrypt: %w", err)
	}
	n := s.sendCount
	s.sendCount++
	return n, ct, nil
}

// Encrypt is the in-order convenience form of Send; it discards the explicit
// nonce and is intended for callers that only ever decrypt in order.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	_, ct, err := s.Send(plaintext)
	return ct, err
}

// DecryptAt authenticates and decrypts ciphertext that was produced at the
// given wire nonce. The recv CipherState is rekeyed deterministically to the
// nonce's epoch and then seeks to the exact nonce, so frames may arrive
// reordered or with gaps. A session whose handshake has not completed yet
// returns an error.
func (s *Session) DecryptAt(nonce uint64, ciphertext []byte) ([]byte, error) {
	if s == nil || s.recv == nil {
		return nil, errors.New("noisework: session not ready (handshake incomplete)")
	}
	if nonce > MaxNonce {
		return nil, fmt.Errorf("noisework: decrypt nonce out of range: %w", noise.ErrMaxNonce)
	}
	if !s.rekeyRecvTo(nonce) {
		return nil, fmt.Errorf("noisework: decrypt nonce %d demands too large a rekey jump", nonce)
	}
	s.recv.SetNonce(nonce)
	pt, err := s.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("noisework: decrypt: %w", err)
	}
	return pt, nil
}

// Decrypt is the in-order convenience form of DecryptAt: it opens ciphertext
// produced by the next expected nonce and advances the in-order counter.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	if s == nil || s.recv == nil {
		return nil, errors.New("noisework: session not ready (handshake incomplete)")
	}
	n := s.recvCount
	if n > MaxNonce {
		return nil, fmt.Errorf("noisework: recv nonce exhausted: %w", noise.ErrMaxNonce)
	}
	pt, err := s.DecryptAt(n, ciphertext)
	if err != nil {
		return nil, err
	}
	s.recvCount = n + 1
	return pt, nil
}

// rekeySendTo applies Rekey until the send state matches the epoch of nonce,
// refusing jumps larger than maxEpochJump. It returns false when the gap is
// too big; the caller treats that as a framing/DoS error.
func (s *Session) rekeySendTo(nonce uint64) bool {
	ep := epochOf(nonce, s.rekeyEvery)
	for s.sendEpoch < ep {
		if ep-s.sendEpoch > maxEpochJump {
			return false
		}
		s.send.Rekey()
		s.sendEpoch++
	}
	return true
}

// rekeyRecvTo mirrors rekeySendTo for the receive cipher state.
func (s *Session) rekeyRecvTo(nonce uint64) bool {
	ep := epochOf(nonce, s.rekeyEvery)
	for s.recvEpoch < ep {
		if ep-s.recvEpoch > maxEpochJump {
			return false
		}
		s.recv.Rekey()
		s.recvEpoch++
	}
	return true
}

// epochOf returns the rekey epoch a nonce belongs to. A zero rekeyEvery falls
// back to the package default so hand-constructed sessions cannot hit a
// divide-by-zero.
func epochOf(nonce, rekeyEvery uint64) uint64 {
	if rekeyEvery == 0 {
		rekeyEvery = DefaultRekeyEvery
	}
	return nonce / rekeyEvery
}

// PeerStatic returns the remote peer's static public key. It is only known
// once the handshake has completed; before that it returns nil.
func (s *Session) PeerStatic() []byte {
	if s == nil || s.peerStatic == nil {
		return nil
	}
	return clone(s.peerStatic)
}

// ChannelBinding returns the handshake transcript hash, which identifies the
// session. It is non-empty once the handshake has completed and is identical
// on both sides; before that it returns nil.
func (s *Session) ChannelBinding() []byte {
	if s == nil || s.channelBinding == nil {
		return nil
	}
	return clone(s.channelBinding)
}

// MaxPlaintextLen returns the largest plaintext that fits inside a single IPv4
// UDP datagram after the frame header and the ChaCha20-Poly1305 tag: the Noise
// ciphertext must never exceed the wire budget (record's 65535-byte framing
// contract is a codec limit, not a one-datagram limit).
func (s *Session) MaxPlaintextLen() int {
	return maxPlaintextLen
}

// Age returns how long this session has been established (0 before the
// handshake completes). Callers use it to rotate keys on an absolute timer.
func (s *Session) Age() time.Duration {
	if s == nil || s.start.IsZero() {
		return 0
	}
	return time.Since(s.start)
}

// Initiator drives the initiator half of the Noise XX handshake:
// msg1 = e, msg2 = e,ee,s,es, msg3 = s,se.
type Initiator struct {
	hs       *noise.HandshakeState
	expected []byte // responder static key supplied by the caller
	session  *Session
	phase    int
}

// NewInitiator starts the initiator side of an XX handshake towards the peer
// that owns peerStatic. prologue must be identical on both sides. The caller
// provides myStatic as its own static keypair.
func NewInitiator(myStatic *Keypair, peerStatic []byte, prologue []byte) (*Initiator, error) {
	if myStatic == nil || len(myStatic.Private) != KeySize || len(myStatic.Public) != KeySize {
		return nil, errors.New("noisework: invalid initiator static keypair")
	}
	if len(peerStatic) != KeySize {
		return nil, fmt.Errorf("noisework: peer static key must be %d bytes, got %d", KeySize, len(peerStatic))
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   newCipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      clone(prologue),
		StaticKeypair: noise.DHKey{Private: clone(myStatic.Private), Public: clone(myStatic.Public)},
		// The XX pattern has no pre-message, so PeerStatic must NOT be passed
		// to the handshake config: flynn/noise rejects re-reading a
		// pre-configured peer static when message 2 is processed. The
		// responder's key is instead verified explicitly in ReadMessage2.
	})
	if err != nil {
		return nil, fmt.Errorf("noisework: initiator handshake state: %w", err)
	}
	return &Initiator{
		hs:       hs,
		expected: clone(peerStatic),
		phase:    phaseStart,
	}, nil
}

// Message1 produces the first XX handshake message (e) to send to the
// responder.
func (i *Initiator) Message1() ([]byte, error) {
	if i == nil || i.hs == nil {
		return nil, errors.New("noisework: initiator handshake is closed")
	}
	if i.phase != phaseStart {
		return nil, fmt.Errorf("noisework: Message1 called at phase %d, want %d", i.phase, phaseStart)
	}
	msg, _, _, err := i.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noisework: initiator write message 1: %w", err)
	}
	i.phase = phaseMessage1
	return msg, nil
}

// ReadMessage2 processes the second XX handshake message (e, ee, s, es) from
// the responder and verifies that the responder's static key matches the
// peerStatic passed to NewInitiator. The returned Session is finalized by
// WriteMessage3, which must be called next.
func (i *Initiator) ReadMessage2(msg2 []byte) (*Session, error) {
	if i == nil || i.hs == nil {
		return nil, errors.New("noisework: initiator handshake is closed")
	}
	if i.phase != phaseMessage1 {
		return nil, fmt.Errorf("noisework: ReadMessage2 called at phase %d, want %d", i.phase, phaseMessage1)
	}
	if _, _, _, err := i.hs.ReadMessage(nil, msg2); err != nil {
		return nil, fmt.Errorf("noisework: initiator read message 2: %w", err)
	}
	if got := i.hs.PeerStatic(); !bytes.Equal(got, i.expected) {
		return nil, errors.New("noisework: responder static key does not match expected peer")
	}
	i.phase = phaseMessage2
	i.session = &Session{rekeyEvery: DefaultRekeyEvery}
	return i.session, nil
}

// WriteMessage3 produces the final XX handshake message (s, se), completes the
// handshake and finalizes the Session returned by ReadMessage2 so that it can
// be used for transport.
func (i *Initiator) WriteMessage3() ([]byte, error) {
	if i == nil || i.hs == nil {
		return nil, errors.New("noisework: initiator handshake is closed")
	}
	if i.phase != phaseMessage2 {
		return nil, fmt.Errorf("noisework: WriteMessage3 called at phase %d, want %d", i.phase, phaseMessage2)
	}
	msg, sendCs, recvCs, err := i.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noisework: initiator write message 3: %w", err)
	}
	if sendCs == nil || recvCs == nil {
		return nil, errors.New("noisework: initiator write message 3 returned no cipher states")
	}
	if i.session == nil {
		i.session = &Session{rekeyEvery: DefaultRekeyEvery}
	}
	// Split() returns the initiator→responder state first, then the
	// responder→initiator state.
	i.session.send = sendCs
	i.session.recv = recvCs
	i.session.peerStatic = clone(i.hs.PeerStatic())
	i.session.channelBinding = clone(i.hs.ChannelBinding())
	i.session.start = time.Now()
	i.phase = phaseComplete
	return msg, nil
}

// Responder drives the responder half of the Noise XX handshake.
type Responder struct {
	hs      *noise.HandshakeState
	session *Session
	phase   int
}

// NewResponder starts the responder side of an XX handshake. prologue must be
// identical to the initiator's.
func NewResponder(myStatic *Keypair, prologue []byte) (*Responder, error) {
	if myStatic == nil || len(myStatic.Private) != KeySize || len(myStatic.Public) != KeySize {
		return nil, errors.New("noisework: invalid responder static keypair")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   newCipherSuite(),
		Pattern:       noise.HandshakeXX,
		Prologue:      clone(prologue),
		StaticKeypair: noise.DHKey{Private: clone(myStatic.Private), Public: clone(myStatic.Public)},
	})
	if err != nil {
		return nil, fmt.Errorf("noisework: responder handshake state: %w", err)
	}
	return &Responder{hs: hs, phase: phaseStart}, nil
}

// ReadMessage1 processes the first XX handshake message (e) from the
// initiator.
func (r *Responder) ReadMessage1(msg1 []byte) error {
	if r == nil || r.hs == nil {
		return errors.New("noisework: responder handshake is closed")
	}
	if r.phase != phaseStart {
		return fmt.Errorf("noisework: ReadMessage1 called at phase %d, want %d", r.phase, phaseStart)
	}
	if _, _, _, err := r.hs.ReadMessage(nil, msg1); err != nil {
		return fmt.Errorf("noisework: responder read message 1: %w", err)
	}
	r.phase = phaseMessage1
	return nil
}

// Message2 produces the second XX handshake message (e, ee, s, es) to send to
// the initiator.
func (r *Responder) Message2() ([]byte, error) {
	if r == nil || r.hs == nil {
		return nil, errors.New("noisework: responder handshake is closed")
	}
	if r.phase != phaseMessage1 {
		return nil, fmt.Errorf("noisework: Message2 called at phase %d, want %d", r.phase, phaseMessage1)
	}
	msg, _, _, err := r.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noisework: responder write message 2: %w", err)
	}
	r.phase = phaseMessage2
	return msg, nil
}

// ReadMessage3 processes the final XX handshake message (s, se), completes
// the handshake and returns the established Session.
func (r *Responder) ReadMessage3(msg3 []byte) (*Session, error) {
	if r == nil || r.hs == nil {
		return nil, errors.New("noisework: responder handshake is closed")
	}
	if r.phase != phaseMessage2 {
		return nil, fmt.Errorf("noisework: ReadMessage3 called at phase %d, want %d", r.phase, phaseMessage2)
	}
	_, initSend, initRecv, err := r.hs.ReadMessage(nil, msg3)
	if err != nil {
		return nil, fmt.Errorf("noisework: responder read message 3: %w", err)
	}
	if initSend == nil || initRecv == nil {
		return nil, errors.New("noisework: responder read message 3 returned no cipher states")
	}
	r.session = &Session{
		// The first split state (initSend) carries initiator→responder data.
		send:           initRecv,
		recv:           initSend,
		peerStatic:     clone(r.hs.PeerStatic()),
		channelBinding: clone(r.hs.ChannelBinding()),
		rekeyEvery:     DefaultRekeyEvery,
		start:          time.Now(),
	}
	r.phase = phaseComplete
	return r.session, nil
}

// clone returns a fresh copy of b, or nil when b is nil.
func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
