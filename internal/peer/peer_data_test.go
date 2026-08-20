package peer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"meshlink/internal/disco"
	"meshlink/internal/noisework"
	"meshlink/internal/record"
)

// handshakePair runs a complete XX handshake between initKP and respKP and
// returns both finalized sessions. sInit.Send produces frames that only
// sResp.DecryptAt can open (initiator→responder direction).
func handshakePair(t *testing.T, initKP, respKP *noisework.Keypair) (*noisework.Session, *noisework.Session) {
	t.Helper()
	init, err := noisework.NewInitiator(initKP, respKP.Public, []byte(Prologue))
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	resp, err := noisework.NewResponder(respKP, []byte(Prologue))
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	msg1, err := init.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	if err := resp.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	msg2, err := resp.Message2()
	if err != nil {
		t.Fatalf("Message2: %v", err)
	}
	sInit, err := init.ReadMessage2(msg2)
	if err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}
	msg3, err := init.WriteMessage3()
	if err != nil {
		t.Fatalf("WriteMessage3: %v", err)
	}
	sResp, err := resp.ReadMessage3(msg3)
	if err != nil {
		t.Fatalf("ReadMessage3: %v", err)
	}
	return sInit, sResp
}

// dataFrame encrypts payload with sess and wraps it in a complete framed DATA
// datagram exactly as Peer.Send would emit it.
func dataFrame(t *testing.T, sess *noisework.Session, payload []byte) []byte {
	t.Helper()
	nonce, ct, err := sess.Send(payload)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	wire := make([]byte, 8, 8+len(ct))
	binary.BigEndian.PutUint64(wire, nonce)
	wire = append(wire, ct...)
	return record.Frame(record.TypeData, wire)
}

// newInstallPeer builds the "b" peer (whose peer key is initKP.Public) with
// the given established session — the session whose recv state matches frames
// produced by the initiator side of the same handshake.
func newInstallPeer(t *testing.T, myKP, initKP *noisework.Keypair, sess *noisework.Session) *Peer {
	t.Helper()
	p := New("b", "a", initKP.Public, nil, myKP, &fakeTransport{})
	p.mu.Lock()
	p.setSessionLocked(sess, disco.PathDirect)
	p.mu.Unlock()
	if !p.Established() {
		t.Fatal("session did not install")
	}
	return p
}

// mustRecv reads exactly one payload from the peer channel and compares it to
// want.
func mustRecv(t *testing.T, p *Peer, want []byte) {
	t.Helper()
	select {
	case got := <-p.Recv():
		if string(got) != string(want) {
			t.Fatalf("received %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

// mustNotRecv asserts no payload arrives until the timeout.
func mustNotRecv(t *testing.T, p *Peer) {
	t.Helper()
	select {
	case got := <-p.Recv():
		t.Fatalf("unexpected payload delivered: %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPeerDataDeliveryRejectReplay(t *testing.T) {
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

	f0 := dataFrame(t, sInit, []byte("m0"))
	f1 := dataFrame(t, sInit, []byte("m1"))
	f2 := dataFrame(t, sInit, []byte("m2"))
	src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	// Out-of-order delivery must reach the consumer in arrival order.
	for _, f := range [][]byte{f1, f0, f2} {
		p.HandleFrame(src, f)
	}
	mustRecv(t, p, []byte("m1"))
	mustRecv(t, p, []byte("m0"))
	mustRecv(t, p, []byte("m2"))

	// Replaying any delivered frame must be dropped silently.
	p.HandleFrame(src, f1)
	p.HandleFrame(src, f0)
	mustNotRecv(t, p)
}

func TestPeerDataGarbledFramesIgnored(t *testing.T) {
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

	// Short payload (no nonce), tampered ciphertext, and non-frames.
	p.HandleFrame(src, []byte{record.TypeData, 0x00, 0x02, 0xAA, 0xBB})
	f := dataFrame(t, sInit, []byte("tamper me"))
	f[len(f)-1] ^= 0xFF
	p.HandleFrame(src, f)
	p.HandleFrame(src, []byte("not a frame"))
	mustNotRecv(t, p)

	// The session survives all of that and still delivers valid frames.
	p.HandleFrame(src, dataFrame(t, sInit, []byte("still alive")))
	mustRecv(t, p, []byte("still alive"))
}

// TestPeerDataFreshSessionResetsWindow verifies that installing a new session
// (re-handshake) resets the replay window so its fresh counter can start over
// from zero after the old session has consumed low nonces.
func TestPeerDataFreshSessionResetsWindow(t *testing.T) {
	initKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	respKP, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	s1Init, s1Resp := handshakePair(t, initKP, respKP)
	p := newInstallPeer(t, respKP, initKP, s1Resp)
	src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	// Old session consumes nonces 0..1.
	p.HandleFrame(src, dataFrame(t, s1Init, []byte("old0")))
	p.HandleFrame(src, dataFrame(t, s1Init, []byte("old1")))
	mustRecv(t, p, []byte("old0"))
	mustRecv(t, p, []byte("old1"))

	// A brand-new handshake between the same identities installs a fresh
	// session; its first frame can use nonce 0 again.
	s2Init, s2Resp := handshakePair(t, initKP, respKP)
	p.mu.Lock()
	p.setSessionLocked(s2Resp, disco.PathDirect)
	p.mu.Unlock()

	p.HandleFrame(src, dataFrame(t, s2Init, []byte("new0")))
	p.HandleFrame(src, dataFrame(t, s2Init, []byte("new1")))
	mustRecv(t, p, []byte("new0"))
	mustRecv(t, p, []byte("new1"))
	mustNotRecv(t, p) // nothing else may follow
}
