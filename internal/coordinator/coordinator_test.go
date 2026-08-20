package coordinator

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshlink/internal/control"
	"meshlink/internal/noisework"
	"meshlink/internal/protocol"
)

// startServer spins up a coordinator on ephemeral ports with a fresh keyfile.
func startServer(t *testing.T) (*Server, net.Addr, net.Addr) {
	t.Helper()
	s, err := New(Config{
		CtrlAddr: "127.0.0.1:0",
		StunAddr: "127.0.0.1:0",
		Keyfile:  filepath.Join(t.TempDir(), "coord.key"),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = s.Run(ctx)
		cancel()
	}()
	ctrl, stun := s.Addrs()
	t.Cleanup(func() {
		cancel()
		s.Close()
	})
	return s, ctrl, stun
}

// client is a noise-authenticated control connection to the coordinator.
type client struct {
	ctrl *control.Conn
	kp   *noisework.Keypair
}

func mustKey(t *testing.T) *noisework.Keypair {
	t.Helper()
	kp, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

// connect opens a fresh encrypted control session authenticated with kp.
func connect(t *testing.T, s *Server, ctrlAddr net.Addr, kp *noisework.Keypair) *client {
	t.Helper()
	pub, err := noisework.ParsePublicKeyHex(s.PublicKeyHex())
	if err != nil {
		t.Fatalf("coordinator pubkey: %v", err)
	}
	raw, err := net.Dial("tcp", ctrlAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c, err := control.Initiate(raw, kp, pub)
	if err != nil {
		t.Fatalf("control handshake: %v", err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return &client{ctrl: c, kp: kp}
}

func (c *client) send(m protocol.Message) {
	line, err := protocol.EncodeLine(m)
	if err != nil {
		panic(err)
	}
	if err := c.ctrl.WriteMsg(line); err != nil {
		panic(err)
	}
}

func (c *client) recv(t *testing.T) protocol.Message {
	t.Helper()
	plain, err := c.ctrl.ReadMsg()
	if err != nil {
		t.Fatalf("control read: %v", err)
	}
	msg, err := protocol.DecodeLine(plain)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg == nil {
		t.Fatal("nil control message")
	}
	return *msg
}

func TestRegistrationAndBroadcast(t *testing.T) {
	s, ctrlAddr, _ := startServer(t)

	kpA := mustKey(t)
	kpB := mustKey(t)
	connA := connect(t, s, ctrlAddr, kpA)
	connB := connect(t, s, ctrlAddr, kpB)

	// Both clients are connected before anyone registers, so every
	// registration broadcast reaches both of them in order.
	connB.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "b", PubKey: kpB.PublicHex(),
		Endpoints: []string{"127.0.0.1:19302"},
	})
	lb0 := connB.recv(t)
	if lb0.Type != protocol.TypePeerList || len(lb0.Peers) != 1 || lb0.Peers[0].ID != "b" {
		t.Fatalf("B unexpected first list: %+v", lb0)
	}
	la0 := connA.recv(t)
	if len(la0.Peers) != 1 || la0.Peers[0].ID != "b" {
		t.Fatalf("A missed B's registration: %+v", la0)
	}

	// A registers; both receive the two-peer list.
	connA.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "a", PubKey: kpA.PublicHex(),
		Endpoints: []string{"127.0.0.1:19301"},
	})
	la := connA.recv(t)
	if len(la.Peers) != 2 {
		t.Fatalf("A expected 2 peers, got %+v", la.Peers)
	}
	lb := connB.recv(t)
	if len(lb.Peers) != 2 {
		t.Fatalf("B expected 2 peers, got %+v", lb.Peers)
	}

	// Registrations must come from an authenticated identity whose static key
	// equals the register pubkey.
	connA.send(protocol.Message{Type: protocol.TypeRegister, ID: "spoof", PubKey: kpB.PublicHex()})
	if lm := connA.recv(t); lm.Type != protocol.TypeError {
		t.Fatalf("spoofed identity accepted, got %+v", lm)
	}
}

func TestRegistrationKeyPinning(t *testing.T) {
	s, ctrlAddr, _ := startServer(t)

	// First registration for ID "a" binds it to kpA.
	kpA := mustKey(t)
	connA := connect(t, s, ctrlAddr, kpA)
	connA.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "a", PubKey: kpA.PublicHex(),
		Endpoints: []string{"127.0.0.1:19301"},
	})
	if la := connA.recv(t); la.Type != protocol.TypePeerList {
		t.Fatalf("A expected peer_list, got %+v", la)
	}

	// A different authenticated identity (kpB) trying to take over "a" with
	// its own key must be refused by the key pin.
	kpB := mustKey(t)
	connB := connect(t, s, ctrlAddr, kpB)
	connB.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "a", PubKey: kpB.PublicHex(),
		Endpoints: []string{"127.0.0.1:19399"},
	})
	if lb := connB.recv(t); lb.Type != protocol.TypeError {
		t.Fatalf("B expected TypeError for key mismatch, got %+v", lb)
	}

	// The pin cheats nothing: an identity claiming "a" with a borrowed kpA key
	// still fails because the handshake bound this connection to kpB.
	connB.send(protocol.Message{Type: protocol.TypeRegister, ID: "a", PubKey: kpA.PublicHex()})
	if lb := connB.recv(t); lb.Type != protocol.TypeError {
		t.Fatalf("B expected TypeError for identity mismatch, got %+v", lb)
	}

	// Re-registration over a fresh connection whose identity is kpA itself is
	// still accepted (same pinned key).
	connC := connect(t, s, ctrlAddr, kpA)
	connC.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "a", PubKey: kpA.PublicHex(),
		Endpoints: []string{"127.0.0.1:19302"},
	})
	if lc := connC.recv(t); lc.Type != protocol.TypePeerList {
		t.Fatalf("C expected peer_list after re-register, got %+v", lc)
	}

	// No pubkey at all must be refused.
	kpD := mustKey(t)
	connD := connect(t, s, ctrlAddr, kpD)
	connD.send(protocol.Message{Type: protocol.TypeRegister, ID: "c", PubKey: kpD.PublicHex()[:0]})
	if ld := connD.recv(t); ld.Type != protocol.TypeError {
		t.Fatalf("D expected TypeError for missing pubkey, got %+v", ld)
	}
}

func TestRegistrationPrunedOnDisconnect(t *testing.T) {
	s, ctrlAddr, _ := startServer(t)

	kpA := mustKey(t)
	connA := connect(t, s, ctrlAddr, kpA)
	connA.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "a", PubKey: kpA.PublicHex(),
		Endpoints: []string{"127.0.0.1:19301"},
	})
	if la := connA.recv(t); la.Type != protocol.TypePeerList {
		t.Fatalf("A expected peer_list, got %+v", la)
	}
	s.mu.RLock()
	_, regged := s.registrations["a"]
	s.mu.RUnlock()
	if !regged {
		t.Fatal("registration for 'a' missing after register")
	}

	// Disconnect A; the registry must release the name so it cannot keep
	// being advertised with a dead endpoint forever.
	_ = connA.ctrl.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.RLock()
		_, present := s.registrations["a"]
		s.mu.RUnlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("registration 'a' not pruned after disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A fresh connection with the same identity can re-register cleanly.
	connA2 := connect(t, s, ctrlAddr, kpA)
	connA2.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "a", PubKey: kpA.PublicHex(),
		Endpoints: []string{"127.0.0.1:19301"},
	})
	if la := connA2.recv(t); la.Type != protocol.TypePeerList {
		t.Fatalf("A2 expected peer_list after re-register, got %+v", la)
	}
}

func TestRegistrationValidation(t *testing.T) {
	s, ctrlAddr, _ := startServer(t)
	kp := mustKey(t)
	conn := connect(t, s, ctrlAddr, kp)

	// Overlong ID.
	conn.send(protocol.Message{
		Type: protocol.TypeRegister, ID: strings.Repeat("x", maxIDLen+1), PubKey: kp.PublicHex(),
	})
	if lm := conn.recv(t); lm.Type != protocol.TypeError {
		t.Fatalf("expected TypeError for overlong ID, got %+v", lm)
	}
	// Too many endpoints.
	conn.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "ok", PubKey: kp.PublicHex(),
		Endpoints: []string{"1.1.1.1:1", "2.2.2.2:2", "3.3.3.3:3"},
	})
	if lm := conn.recv(t); lm.Type != protocol.TypeError {
		t.Fatalf("expected TypeError for too many endpoints, got %+v", lm)
	}
	// Overlong endpoint.
	conn.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "ok", PubKey: kp.PublicHex(),
		Endpoints: []string{strings.Repeat("e", maxEndpointLen+1)},
	})
	if lm := conn.recv(t); lm.Type != protocol.TypeError {
		t.Fatalf("expected TypeError for overlong endpoint, got %+v", lm)
	}
	// A well-formed register still succeeds after all the refusals.
	conn.send(protocol.Message{
		Type: protocol.TypeRegister, ID: "ok", PubKey: kp.PublicHex(),
		Endpoints: []string{"127.0.0.1:19301"},
	})
	if lm := conn.recv(t); lm.Type != protocol.TypePeerList {
		t.Fatalf("expected peer_list after valid register, got %+v", lm)
	}
}

func TestSTUNEndpoint(t *testing.T) {
	_, _, stunAddr := startServer(t)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	ua, err := net.ResolveUDPAddr("udp", stunAddr.String())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := conn.WriteTo([]byte("garbage-not-stun"), ua); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Only a well-formed request gets a response; garbage should yield nothing.
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	_, _, err = conn.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected no response to garbage")
	}
}
