package peer

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshlink/internal/disco"
	"meshlink/internal/noisework"
	"meshlink/internal/record"
	"meshlink/internal/relay"
)

// hsTransport is a peer.Transport that records every emitted frame and
// optionally delivers it straight to a linked peer's HandleFrame, so two
// peers can run a real handshake over an in-memory "network".
type hsTransport struct {
	mu     sync.Mutex
	target func() *Peer // nil = record only, no delivery
	src    *net.UDPAddr
	relay  *net.UDPAddr
	drop   func(typ byte) bool
	frames [][]byte
}

func (t *hsTransport) SendDirect(dst *net.UDPAddr, frame []byte) error {
	t.mu.Lock()
	t.frames = append(t.frames, append([]byte(nil), frame...))
	drop := len(frame) > 0 && t.drop != nil && t.drop(frame[0])
	target := t.target
	t.mu.Unlock()
	if drop || target == nil {
		return nil
	}
	if p := target(); p != nil {
		p.HandleFrame(t.src, append([]byte(nil), frame...))
	}
	return nil
}

func (t *hsTransport) SendRelay(peerID string, frame []byte) error {
	return t.SendDirect(nil, frame)
}

func (t *hsTransport) RelayAddr() *net.UDPAddr { return t.relay }

func (t *hsTransport) count(typ byte) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, f := range t.frames {
		if len(f) > 0 && f[0] == typ {
			n++
		}
	}
	return n
}

func (t *hsTransport) last(typ byte) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.frames) - 1; i >= 0; i-- {
		if len(t.frames[i]) > 0 && t.frames[i][0] == typ {
			return t.frames[i]
		}
	}
	return nil
}

// newHSPair builds an initiator ("a")/responder ("b") peer pair wired
// together through in-memory transports. dropA2B/dropB2A may drop frames by
// type to simulate loss.
func newHSPair(t *testing.T, dropA2B, dropB2A func(byte) bool) (*Peer, *Peer, *hsTransport, *hsTransport) {
	t.Helper()
	kpA, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	kpB, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	epA := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001}
	epB := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40002}
	trA := &hsTransport{src: epA, drop: dropA2B}
	trB := &hsTransport{src: epB, drop: dropB2A}
	pa := New("a", "b", kpB.Public, epB, kpA, trA)
	pb := New("b", "a", kpA.Public, epA, kpB, trB)
	trA.target = func() *Peer { return pb }
	trB.target = func() *Peer { return pa }
	if !pa.initiator || pb.initiator {
		t.Fatalf("role derivation broken: a.initiator=%v b.initiator=%v", pa.initiator, pb.initiator)
	}
	return pa, pb, trA, trB
}

// TestPeerHandshakeEstablishesAndCarriesData drives the full HS1→HS2→HS3
// state machine between two Run loops and then moves data both ways.
func TestPeerHandshakeEstablishesAndCarriesData(t *testing.T) {
	pa, pb, _, _ := newHSPair(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pa.Run(ctx)
	go pb.Run(ctx)
	defer pa.Close()
	defer pb.Close()

	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := pa.WaitEstablished(wctx); err != nil {
		t.Fatalf("initiator never established: %v", err)
	}
	if err := pb.WaitEstablished(wctx); err != nil {
		t.Fatalf("responder never established: %v", err)
	}
	if pa.Path() != disco.PathDirect || pb.Path() != disco.PathDirect {
		t.Fatalf("paths = %v/%v, want direct/direct", pa.Path(), pb.Path())
	}

	if err := pa.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mustRecv(t, pb, []byte("ping"))
	if err := pb.Send([]byte("pong")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mustRecv(t, pa, []byte("pong"))
}

// TestPeerHS3LossRecoveredByRetransmit is the regression test for the
// half-open session bug: when the single HS3 is lost, the responder used to
// stay half-open until the 24 h age rotation. The initiator must now
// re-emit HS3 until the responder answers.
func TestPeerHS3LossRecoveredByRetransmit(t *testing.T) {
	var drops int32 = 1 // drop exactly the first HS3
	dropFirstHS3 := func(typ byte) bool {
		return typ == record.TypeHS3 && atomic.AddInt32(&drops, -1) >= 0
	}
	pa, pb, trA, _ := newHSPair(t, dropFirstHS3, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pa.Run(ctx)
	go pb.Run(ctx)
	defer pa.Close()
	defer pb.Close()

	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := pa.WaitEstablished(wctx); err != nil {
		t.Fatalf("initiator never established: %v", err)
	}
	if err := pb.WaitEstablished(wctx); err != nil {
		t.Fatalf("responder never established despite HS3 retransmission: %v", err)
	}
	if got := trA.count(record.TypeHS3); got < 2 {
		t.Fatalf("HS3 sent %d times, want at least 2 (one lost + one recovered)", got)
	}

	// Data must flow after the recovered handshake.
	if err := pa.Send([]byte("after-recovery")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mustRecv(t, pb, []byte("after-recovery"))
}

// TestPeerDuplicateHS1RetransmitsHS2 verifies that a duplicate HS1 received
// while the responder is half-open retransmits the cached HS2 instead of
// resetting the responder (which would orphan the initiator's HS3), and that
// a *different* HS1 only restarts the handshake after the timeout.
func TestPeerDuplicateHS1RetransmitsHS2(t *testing.T) {
	kpA, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	kpB, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	epA := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001}
	trB := &hsTransport{src: epA}
	pb := New("b", "a", kpA.Public, epA, kpB, trB)

	init, err := noisework.NewInitiator(kpA, kpB.Public, []byte(Prologue))
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	msg1, err := init.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}

	pb.onHS1(msg1, disco.PathDirect)
	hs2First := trB.last(record.TypeHS2)
	if hs2First == nil {
		t.Fatal("no HS2 emitted for the first HS1")
	}

	// A duplicate of the accepted HS1 must retransmit the identical cached
	// HS2 and keep the responder state alive.
	pb.onHS1(msg1, disco.PathDirect)
	hs2Second := trB.last(record.TypeHS2)
	if !bytes.Equal(hs2First, hs2Second) {
		t.Fatal("duplicate HS1 produced a different HS2 (responder was reset)")
	}
	if trB.count(record.TypeHS2) != 2 {
		t.Fatalf("HS2 count = %d, want 2 (original + retransmission)", trB.count(record.TypeHS2))
	}
	pb.mu.Lock()
	respAlive := pb.responder != nil
	pb.mu.Unlock()
	if !respAlive {
		t.Fatal("duplicate HS1 cleared the half-open responder state")
	}

	// A different HS1 within the timeout is ignored: the half-open attempt
	// gets its chance to finish before being replaced.
	init2, err := noisework.NewInitiator(kpA, kpB.Public, []byte(Prologue))
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	msg1Other, err := init2.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	pb.onHS1(msg1Other, disco.PathDirect)
	if got := trB.count(record.TypeHS2); got != 2 {
		t.Fatalf("different HS1 within timeout changed HS2 count to %d, want 2", got)
	}

	// Finish the original handshake: the responder must accept HS3.
	_, msg2Payload, err := record.Parse(hs2First)
	if err != nil {
		t.Fatalf("Parse(hs2): %v", err)
	}
	if _, err := init.ReadMessage2(msg2Payload); err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}
	msg3, err := init.WriteMessage3()
	if err != nil {
		t.Fatalf("WriteMessage3: %v", err)
	}
	pb.onHS3(msg3, disco.PathDirect)
	if !pb.Established() {
		t.Fatal("responder did not establish after HS3")
	}

	// After the timeout a different HS1 may restart the handshake.
	pb2 := New("b", "a", kpA.Public, epA, kpB, trB)
	pb2.onHS1(msg1, disco.PathDirect)
	before := trB.count(record.TypeHS2)
	pb2.mu.Lock()
	pb2.hs2SentAt = time.Now().Add(-responderHandshakeTimeout - time.Second)
	pb2.mu.Unlock()
	pb2.onHS1(msg1Other, disco.PathDirect)
	if got := trB.count(record.TypeHS2); got != before+1 {
		t.Fatalf("stale half-open state was not replaceable: HS2 count %d, want %d", got, before+1)
	}
}

// TestPeerHS1Budget verifies the G5 CPU budget: duplicate HS1 retransmissions
// are cheap (cached HS2) but still consume the per-second budget, and beyond
// it everything is dropped.
func TestPeerHS1Budget(t *testing.T) {
	kpA, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	kpB, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	epA := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001}
	trB := &hsTransport{src: epA}
	pb := New("b", "a", kpA.Public, epA, kpB, trB)

	init, err := noisework.NewInitiator(kpA, kpB.Public, []byte(Prologue))
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	msg1, err := init.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	for i := 0; i < hs1MaxPerSec*3; i++ {
		pb.onHS1(msg1, disco.PathDirect)
	}
	if got := trB.count(record.TypeHS2); got != hs1MaxPerSec {
		t.Fatalf("HS2 count = %d, want exactly the budget %d", got, hs1MaxPerSec)
	}
}

// TestPeerSpoofedEpochJumpDoesNotLockSession is the data-plane regression
// test for the rekey DoS: an unauthenticated datagram whose nonce points one
// epoch ahead must not advance the one-way epoch keys; the next legitimate
// frame must still decrypt.
func TestPeerSpoofedEpochJumpDoesNotLockSession(t *testing.T) {
	initKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	respKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	sInit, sResp := handshakePair(t, initKP, respKP)
	p := newInstallPeer(t, respKP, initKP, sResp)
	src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	// Spoofed DATA frame: fresh nonce one full rekey epoch ahead, garbage
	// ciphertext. It passes the replay gate (fresh) but must fail AEAD
	// without mutating the session's receive state.
	spoof := make([]byte, 8+32)
	putBE := func(n uint64) {
		for i := 7; i >= 0; i-- {
			spoof[i] = byte(n)
			n >>= 8
		}
	}
	putBE(noisework.DefaultRekeyEvery) // epoch 1
	p.HandleFrame(src, record.Frame(record.TypeData, spoof))
	mustNotRecv(t, p)

	// The session's receive direction must still be alive at epoch 0.
	p.HandleFrame(src, dataFrame(t, sInit, []byte("still alive")))
	mustRecv(t, p, []byte("still alive"))
}

// TestPeerSendSizeLimits covers the plaintext budget enforced before
// encryption, including the relay path's extra header allowance.
func TestPeerSendSizeLimits(t *testing.T) {
	initKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	respKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	sInit, sResp := handshakePair(t, initKP, respKP)
	_ = sInit
	p := newInstallPeer(t, respKP, initKP, sResp)
	p.SetDirectEP(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})

	max := sResp.MaxPlaintextLen()
	if err := p.Send(make([]byte, max)); err != nil {
		t.Fatalf("Send at the direct limit failed: %v", err)
	}
	if err := p.Send(make([]byte, max+1)); err == nil {
		t.Fatal("Send over the direct limit succeeded, want error")
	}

	// Relay path: the budget shrinks by the worst-case relay header.
	_, sResp2 := handshakePair(t, initKP, respKP)
	p.mu.Lock()
	p.setSessionLocked(sResp2, disco.PathRelay)
	p.mu.Unlock()
	relayLimit := max - relay.MaxHeaderLen
	if err := p.Send(make([]byte, relayLimit)); err != nil {
		t.Fatalf("Send at the relay limit failed: %v", err)
	}
	if err := p.Send(make([]byte, relayLimit+1)); err == nil {
		t.Fatal("Send over the relay limit succeeded, want error")
	}
}

// TestPeerConcurrentSendRecvSetEP hammers the send, receive and
// endpoint-update paths at once; the race detector must stay quiet.
func TestPeerConcurrentSendRecvSetEP(t *testing.T) {
	initKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	respKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	sInit, sResp := handshakePair(t, initKP, respKP)
	p := newInstallPeer(t, respKP, initKP, sResp)
	p.SetDirectEP(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})

	frames := make([][]byte, 32)
	for i := range frames {
		frames[i] = dataFrame(t, sInit, []byte{byte(i)})
	}
	src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	ep1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2}
	ep2 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = p.Send([]byte("x"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			p.HandleFrame(src, frames[i%len(frames)])
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				p.SetDirectEP(ep1)
			} else {
				p.SetDirectEP(ep2)
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	p.Close()
}
