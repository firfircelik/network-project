// Package peer implements per-peer sessions: UDP hole punching, the Noise XX
// handshake over the active path, direct↔relay path selection and encrypted
// data I/O on top of a Noise session.
package peer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"meshlink/internal/disco"
	"meshlink/internal/noisework"
	"meshlink/internal/record"
	"meshlink/internal/relay"
)

// Prologue is the Noise prologue shared by every meshlink peer.
const Prologue = "meshlink-v1"

// nonceWireLen is the size of the explicit 64-bit transport nonce prepended
// to every DATA frame payload (matches noisework's encoder).
const nonceWireLen = 8

// hs1MaxPerSec is the responder's per-peer handshake CPU budget: at most this
// many HS1 messages are processed per second per peer. Anything beyond that is
// dropped, so an attacker flooding HS1 frames cannot make a victim burn
// unbounded Noise CPU while the session is mid-handshake (G5).
const hs1MaxPerSec = 8

// sessionMaxAge forces a re-handshake (and fresh key material) after a session
// has lived this long, so keys are rotated on an absolute timer as well as by
// message count (SPEC §3 "session age limit").
const sessionMaxAge = 24 * time.Hour

// Transport abstracts how the owning agent emits datagrams.
type Transport interface {
	// SendDirect sends a framed datagram to dst, egressing through the
	// agent's own NAT if one is configured.
	SendDirect(dst *net.UDPAddr, frame []byte) error
	// SendRelay sends a framed datagram to peerID through the relay server.
	SendRelay(peerID string, frame []byte) error
	// RelayAddr returns the relay server address, or nil if none configured.
	RelayAddr() *net.UDPAddr
}

// Peer tracks a single remote peer.
type Peer struct {
	ID       string
	DirectEP *net.UDPAddr

	myKp       *noisework.Keypair
	peerStatic []byte // public key registered with the coordinator
	initiator  bool
	send       Transport

	mu          sync.Mutex
	mode        disco.Path // path the handshake is currently attempted on
	path        disco.Path // path established data is flowing over
	responder   *noisework.Responder
	initiatorHS *noisework.Initiator
	hs1Frame    []byte // cached TypeHS1 frame; resent verbatim on HS1 retries
	sess        *noisework.Session
	replay      *replayWindow // DATA nonce acceptance gate for the current session
	established bool
	sessSince   time.Time // when the current session was installed (age rotation)
	phaseStart  time.Time
	lastHS1     time.Time
	lastSent    time.Time
	closed      bool
	recvClosed  bool

	hsBurstStart time.Time // G5: responder handshake CPU budget window
	hsBurstCount int

	doneOnce sync.Once
	done     chan struct{}
	recv     chan []byte
}

// New creates a peer session. myID is used to derive the handshake role.
func New(myID, id string, peerStatic []byte, directEP *net.UDPAddr, myKp *noisework.Keypair, send Transport) *Peer {
	return &Peer{
		ID:         id,
		DirectEP:   directEP,
		myKp:       myKp,
		peerStatic: peerStatic,
		initiator:  disco.RoleIsInitiator(myID, id),
		send:       send,
		mode:       disco.PathNone,
		path:       disco.PathNone,
		replay:     newReplayWindow(replayWindowSizeBits),
		done:       make(chan struct{}),
		recv:       make(chan []byte, 64),
	}
}

// Close stops the peer's background loop and releases its channel.
func (p *Peer) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.doneOnce.Do(func() { close(p.done) })
}

// Recv returns the channel of decrypted payloads from this peer.
func (p *Peer) Recv() <-chan []byte { return p.recv }

// Established reports whether an authenticated session exists.
func (p *Peer) Established() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.established
}

// RemoteStatic reports the authenticated peer static key (raw bytes).
func (p *Peer) RemoteStatic() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sess == nil {
		return nil
	}
	return p.sess.PeerStatic()
}

// Path reports the path established data flows over.
func (p *Peer) Path() disco.Path {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.path
}

// WaitEstablished blocks until the session is established or ctx is done.
func (p *Peer) WaitEstablished(ctx context.Context) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		if p.Established() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for session with %s: %w", p.ID, ctx.Err())
		case <-p.done:
			return errors.New("peer closed before session established")
		case <-t.C:
		}
	}
}

func (p *Peer) attemptFor(mode disco.Path) time.Duration {
	if mode == disco.PathRelay {
		return disco.RelayAttempt
	}
	return disco.DirectAttempt
}

// Run drives hole punching, keepalive and (re)establishment until ctx is done
// or the peer is closed.
func (p *Peer) Run(ctx context.Context) {
	// Closing p.done must happen exactly once no matter which side (Run or
	// Close) wins the race; `recv` is closed under the lock so onData cannot
	// send to a concurrently closing channel.
	defer func() {
		p.doneOnce.Do(func() { close(p.done) })
		p.mu.Lock()
		if !p.recvClosed {
			p.recvClosed = true
			close(p.recv)
		}
		p.mu.Unlock()
	}()

	p.mu.Lock()
	switch {
	case p.DirectEP != nil:
		p.mode = disco.PathDirect
	case p.send.RelayAddr() != nil:
		p.mode = disco.PathRelay
	default:
		p.mu.Unlock()
		return
	}
	p.phaseStart = time.Now()
	p.mu.Unlock()

	ticker := time.NewTicker(disco.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			established := p.established
			mode := p.mode
			path := p.path
			lastHS1 := p.lastHS1
			lastSent := p.lastSent
			phaseStart := p.phaseStart
			sessSince := p.sessSince
			p.mu.Unlock()

			if established && time.Since(sessSince) > sessionMaxAge {
				// Age-based key rotation: drop the key material and
				// re-establish the session from scratch.
				p.forceRehandshake()
				continue
			}

			switch {
			case !established:
				if err := p.punch(mode); err != nil {
					continue
				}
				if time.Since(phaseStart) > p.attemptFor(mode) {
					p.switchMode(mode)
				}
			case path == disco.PathRelay && p.initiator && p.DirectEP != nil:
				if mode == disco.PathDirect {
					// A roaming probe is in flight: give it a full direct
					// attempt window, then revert to the relay instead of
					// abandoning the working path over one lost HS1.
					if time.Since(phaseStart) > disco.DirectAttempt {
						p.abandonRoaming()
					}
				} else if time.Since(lastHS1) > disco.ReestablishInterval {
					p.retryDirect()
				}
				if time.Since(lastSent) > disco.KeepaliveInterval {
					if err := p.Send([]byte{}); err != nil {
						continue
					}
				}
			default:
				// established: keepalive keeps NAT mappings and liveness.
				if time.Since(lastSent) > disco.KeepaliveInterval {
					if err := p.Send([]byte{}); err != nil {
						continue
					}
				}
			}
		}
	}
}

// punch emits a probe, and HS1 if we are the initiator, on the given mode.
func (p *Peer) punch(mode disco.Path) error {
	p.mu.Lock()
	now := time.Now()
	if p.initiator && now.Sub(p.lastHS1) >= disco.HS1ResendInterval {
		// The HS1 frame (and its freshly generated Noise ephemeral) is created
		// exactly once per handshake attempt and resent verbatim on retries,
		// so the responder always sees a consistent handshake state.
		if p.hs1Frame == nil {
			hs, err := noisework.NewInitiator(p.myKp, p.peerStatic, []byte(Prologue))
			if err != nil {
				p.mu.Unlock()
				return err
			}
			msg1, err := hs.Message1()
			if err != nil {
				p.mu.Unlock()
				return err
			}
			p.initiatorHS = hs
			p.hs1Frame = record.Frame(record.TypeHS1, msg1)
		}
		p.lastHS1 = now
		frame := p.hs1Frame
		src := p.addressFor(mode)
		p.mu.Unlock()
		return p.sendFrame(mode, src, frame)
	}
	addr := p.addressFor(mode)
	p.mu.Unlock()
	frame := record.Frame(record.TypeProbe, nil)
	return p.sendFrame(mode, addr, frame)
}

// addressFor returns the destination address used on a path for HS/DATA.
func (p *Peer) addressFor(mode disco.Path) *net.UDPAddr {
	if mode == disco.PathRelay {
		return p.send.RelayAddr()
	}
	return p.DirectEP
}

// sendFrame emits a raw frame on the given mode/path.
func (p *Peer) sendFrame(mode disco.Path, addr *net.UDPAddr, frame []byte) error {
	if mode == disco.PathRelay {
		return p.send.SendRelay(p.ID, frame)
	}
	if addr == nil {
		return errors.New("no direct endpoint")
	}
	return p.send.SendDirect(addr, frame)
}

// switchMode alternates the handshake attempt between direct and relay.
func (p *Peer) switchMode(current disco.Path) {
	p.mu.Lock()
	switch current {
	case disco.PathDirect:
		if p.send.RelayAddr() != nil {
			p.mode = disco.PathRelay
			p.initiatorHS = nil
			p.hs1Frame = nil
			p.responder = nil
			p.phaseStart = time.Now()
		}
	case disco.PathRelay:
		if p.DirectEP != nil {
			p.mode = disco.PathDirect
			p.initiatorHS = nil
			p.hs1Frame = nil
			p.responder = nil
			p.phaseStart = time.Now()
		}
	}
	p.mu.Unlock()
}

// retryDirect starts a fresh direct handshake attempt while established on
// the relay path, so the session can roam back to P2P when possible.
func (p *Peer) retryDirect() {
	p.mu.Lock()
	hs, err := noisework.NewInitiator(p.myKp, p.peerStatic, []byte(Prologue))
	if err != nil {
		p.mu.Unlock()
		return
	}
	msg1, err := hs.Message1()
	if err != nil {
		p.mu.Unlock()
		return
	}
	p.initiatorHS = hs
	p.responder = nil
	p.mode = disco.PathDirect
	p.lastHS1 = time.Now()
	p.phaseStart = time.Now()
	p.mu.Unlock()
	frame := record.Frame(record.TypeHS1, msg1)
	_ = p.send.SendDirect(p.DirectEP, frame)
}

// abandonRoaming reverts a relay→direct roaming attempt back to the relay path
// after the direct probe timed out. The established relay session is untouched,
// so data keeps flowing while direct is re-probed on the next cadence.
func (p *Peer) abandonRoaming() {
	p.mu.Lock()
	if p.mode != disco.PathDirect {
		p.mu.Unlock()
		return
	}
	p.mode = disco.PathRelay
	p.initiatorHS = nil
	p.hs1Frame = nil
	p.responder = nil
	p.phaseStart = time.Now()
	p.mu.Unlock()
}

// forceRehandshake tears down the current key material so Run re-establishes
// the session (age-based rotation; keepalive/nonce-exhaustion recovery).
func (p *Peer) forceRehandshake() {
	p.mu.Lock()
	p.sess = nil
	p.replay = newReplayWindow(replayWindowSizeBits)
	p.established = false
	p.initiatorHS = nil
	p.hs1Frame = nil
	p.responder = nil
	p.phaseStart = time.Now()
	p.mu.Unlock()
}

// SetDirectEP updates the advertised direct endpoint, e.g. when the control
// plane reports a changed public address after a NAT remap. Lock-held reads in
// Run and receiveLoop observe the pointer under p.mu; DirectEP itself is read
// from locked contexts, so replacing the pointer value here is safe.
func (p *Peer) SetDirectEP(ep *net.UDPAddr) {
	p.mu.Lock()
	p.DirectEP = ep
	p.mu.Unlock()
}

// handleFrameByPath routes a frame to the correct path logic.
func (p *Peer) handleFrameByPath(src *net.UDPAddr, path disco.Path, typ byte, payload []byte) {
	switch typ {
	case record.TypeProbe:
		// Probes only open NAT mappings; nothing to do.
	case record.TypeHS1:
		if p.initiator {
			return
		}
		p.onHS1(payload, path)
	case record.TypeHS2:
		if !p.initiator {
			return
		}
		p.onHS2(payload, path)
	case record.TypeHS3:
		if p.initiator {
			return
		}
		p.onHS3(payload, path)
	case record.TypeData:
		p.onData(payload)
	default:
	}
}

// HandleFrame processes an incoming datagram from a peer.
func (p *Peer) HandleFrame(src *net.UDPAddr, frame []byte) {
	typ, payload, err := record.Parse(frame)
	if err != nil {
		return
	}
	path := disco.PathDirect
	ra := p.send.RelayAddr()
	if ra != nil && src != nil && src.String() == ra.String() {
		path = disco.PathRelay
	}
	p.handleFrameByPath(src, path, typ, payload)
}

func (p *Peer) onHS1(msg []byte, path disco.Path) {
	p.mu.Lock()
	// G5: bound the CPU cost an attacker can impose with a flood of HS1
	// frames aimed at this peer.
	now := time.Now()
	if now.Sub(p.hsBurstStart) >= time.Second {
		p.hsBurstStart = now
		p.hsBurstCount = 0
	}
	p.hsBurstCount++
	if p.hsBurstCount > hs1MaxPerSec {
		p.mu.Unlock()
		return
	}
	alreadyEstablished := p.established
	if alreadyEstablished && p.path != disco.PathRelay {
		p.mu.Unlock()
		return // refuse re-handshake over an already-established direct session
	}
	if p.responder == nil {
		r, err := noisework.NewResponder(p.myKp, []byte(Prologue))
		if err != nil {
			p.mu.Unlock()
			return
		}
		p.responder = r
	}
	if err := p.responder.ReadMessage1(msg); err != nil {
		p.responder = nil
		p.mu.Unlock()
		return
	}
	msg2, err := p.responder.Message2()
	if err != nil {
		p.mu.Unlock()
		return
	}
	p.mode = path
	p.phaseStart = time.Now()
	frame := record.Frame(record.TypeHS2, msg2)
	dst := p.DirectEP
	p.mu.Unlock()
	_ = p.sendFrame(path, dst, frame)
}

func (p *Peer) onHS2(msg []byte, path disco.Path) {
	p.mu.Lock()
	if p.initiatorHS == nil {
		p.mu.Unlock()
		return
	}
	sess, err := p.initiatorHS.ReadMessage2(msg)
	if err != nil {
		p.initiatorHS = nil
		p.hs1Frame = nil
		p.mu.Unlock()
		return
	}
	msg3, err := p.initiatorHS.WriteMessage3()
	if err != nil {
		p.initiatorHS = nil
		p.hs1Frame = nil
		p.mu.Unlock()
		return
	}
	p.setSessionLocked(sess, path)
	frame := record.Frame(record.TypeHS3, msg3)
	dst := p.DirectEP
	p.mu.Unlock()
	_ = p.sendFrame(path, dst, frame)
}

func (p *Peer) onHS3(msg []byte, path disco.Path) {
	p.mu.Lock()
	if p.responder == nil {
		p.mu.Unlock()
		return
	}
	sess, err := p.responder.ReadMessage3(msg)
	if err != nil {
		p.responder = nil
		p.mu.Unlock()
		return
	}
	p.setSessionLocked(sess, path)
	p.mu.Unlock()
}

// setSessionLocked authenticates the peer static key and installs the session.
func (p *Peer) setSessionLocked(sess *noisework.Session, path disco.Path) {
	if len(sess.PeerStatic()) != 32 {
		return
	}
	if string(sess.PeerStatic()) != string(p.peerStatic) {
		return // peer identity mismatch: refuse session
	}
	// A re-handshake installs a brand-new session whose counters restart from
	// zero, so the replay window must never carry over state from the old key.
	if p.sess != sess {
		p.sess = sess
		p.replay = newReplayWindow(replayWindowSizeBits)
	}
	p.established = true
	p.path = path
	// Continue holding the current mode so handshake traffic keeps flowing
	// on the same path.
	p.mode = path
	p.sessSince = time.Now()
	p.lastSent = time.Now()
}

func (p *Peer) onData(payload []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.recvClosed {
		return
	}
	sess := p.sess
	if sess == nil {
		return
	}
	// Every DATA frame leads with its explicit 64-bit nonce; without one the
	// frame cannot be positioned or gated against replay.
	if len(payload) < 8 {
		return
	}
	nonce := binary.BigEndian.Uint64(payload[:8])
	// The replay gate is a two-phase check: the window is only committed for a
	// nonce whose frame AUTHENTICATED successfully, so a spoofed datagram with
	// a wild nonce cannot slide the window and kill the session.
	if p.replay == nil || !p.replay.Check(nonce) {
		return // replayed or outside the sliding window
	}
	plain, err := sess.DecryptAt(nonce, payload[8:])
	if err != nil {
		return
	}
	p.replay.Commit(nonce)
	if len(plain) > 0 {
		// Non-blocking send while holding the lock: the channel can only be
		// closed under the same lock, so a concurrent Run-defer close cannot
		// race a send on this buffered channel.
		select {
		case p.recv <- plain:
		default: // drop if the consumer is congested
		}
	}
}

// sendEncryptedLocked encrypts and emits payload on the established path.
func (p *Peer) sendEncryptedLocked(payload []byte) error {
	sess := p.sess
	if sess == nil {
		return errors.New("no session")
	}
	// The Noise+frame bound already fits a single UDP datagram on the direct
	// path; relayed frames additionally carry the relay header, so the plaintext
	// budget must shrink by its worst-case size.
	limit := sess.MaxPlaintextLen()
	if p.path == disco.PathRelay {
		limit -= relay.MaxHeaderLen
	}
	if len(payload) > limit {
		return fmt.Errorf("payload too large for %s frame (%d > %d bytes)", p.path, len(payload), limit)
	}
	nonce, cipher, err := sess.Send(payload)
	if err != nil {
		return err
	}
	wire := make([]byte, nonceWireLen, nonceWireLen+len(cipher))
	binary.BigEndian.PutUint64(wire, nonce)
	wire = append(wire, cipher...)
	frame := record.Frame(record.TypeData, wire)
	p.lastSent = time.Now()
	return p.sendFrame(p.path, p.DirectEP, frame)
}

// Send encrypts and sends payload over the established session.
func (p *Peer) Send(payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sendEncryptedLocked(payload)
}

// SendJSON marshals v and sends it over the session.
func (p *Peer) SendJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.Send(b)
}
