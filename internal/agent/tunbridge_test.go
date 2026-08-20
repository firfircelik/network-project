package agent

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"meshlink/internal/noisework"
	"meshlink/internal/peer"
	"meshlink/internal/tun"
)

type bridgeSink struct {
	ch chan []byte
}

func (s *bridgeSink) Send(p []byte) error {
	select {
	case s.ch <- append([]byte(nil), p...):
	default:
	}
	return nil
}

func newBridgeSink() *bridgeSink {
	return &bridgeSink{ch: make(chan []byte, 16)}
}

func ipv4Pkt(src, dst string, payload []byte) []byte {
	sa := netip.MustParseAddr(src).As4()
	da := netip.MustParseAddr(dst).As4()
	total := 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45 // v4, IHL 5
	b[2] = byte(total >> 8)
	b[3] = byte(total)
	copy(b[12:16], sa[:])
	copy(b[16:20], da[:])
	copy(b[20:], payload)
	return b
}

func newTestBridge(t *testing.T) *tunBridge {
	t.Helper()
	b := &tunBridge{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		dev:    tun.NewBufferDevice("utun0", 1500),
		router: tun.NewRouter(),
		ipByPeer: map[string]netip.Addr{
			"b": netip.MustParseAddr("10.60.0.2"),
		},
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestTunBridgeOutboundAndInbound(t *testing.T) {
	b := newTestBridge(t)
	s := newBridgeSink()
	b.setPeerSink("b", s)

	// Outbound: an IP packet targeting the peer's overlay address must reach
	// the peer's send path untouched.
	pkt := ipv4Pkt("10.60.0.1", "10.60.0.2", []byte("x"))
	if !b.router.RoutePacket(pkt) {
		t.Fatal("known destination not routed")
	}
	select {
	case got := <-s.ch:
		if !reflect.DeepEqual(got, pkt) {
			t.Fatalf("sink mismatch: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet never reached the sink")
	}

	// Inbound: a decrypted peer payload must surface on the device.
	if err := b.inbound(pkt); err != nil {
		t.Fatalf("inbound: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := b.dev.Read(buf)
	if err != nil {
		t.Fatalf("device read: %v", err)
	}
	if !reflect.DeepEqual(buf[:n], pkt) {
		t.Fatal("inbound packet mismatch")
	}

	// Detached peer: traffic for its address is dropped.
	b.setPeerSink("b", nil)
	if b.router.RoutePacket(pkt) {
		t.Fatal("routed after peer detach")
	}
}

func TestTunBridgeRunSmoke(t *testing.T) {
	b := newTestBridge(t)
	s := newBridgeSink()
	b.setPeerSink("b", s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.run(ctx) }()

	pkt := ipv4Pkt("10.60.0.1", "10.60.0.2", []byte("y"))
	if _, err := b.dev.Write(pkt); err != nil {
		t.Fatalf("device write: %v", err)
	}
	select {
	case got := <-s.ch:
		if !reflect.DeepEqual(got, pkt) {
			t.Fatalf("routed mismatch: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet never routed by the run loop")
	}
}

// TestBridgeFastPathPayload checks that in TUN mode a non-ping payload is
// treated as an IP packet and written to the device, while nothing is
// attempted for keepalives.
func TestBridgeFastPathPayload(t *testing.T) {
	b := newTestBridge(t)
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), bridge: b}

	pkt := ipv4Pkt("10.60.0.1", "10.60.0.2", nil)
	a.handlePeerPayload(nil, pkt)
	buf := make([]byte, 1500)
	n, err := b.dev.Read(buf)
	if err != nil {
		t.Fatalf("device read: %v", err)
	}
	if !reflect.DeepEqual(buf[:n], pkt) {
		t.Fatal("payload not written to device")
	}
}

// testTransport is a no-op peer transport for tests that do not send frames.
type testTransport struct{}

func (testTransport) SendDirect(*net.UDPAddr, []byte) error { return nil }
func (testTransport) SendRelay(string, []byte) error        { return nil }
func (testTransport) RelayAddr() *net.UDPAddr               { return nil }

// TestAttachBridgeWiresExistingPeers ensures peers discovered before the TUN
// device was opened still get their outbound routes installed.
func TestAttachBridgeWiresExistingPeers(t *testing.T) {
	b := newTestBridge(t) // ipByPeer: b -> 10.60.0.2

	kp, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	peerStatic, err := hex.DecodeString(kp.PublicHex())
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	a := &Agent{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		mu:    sync.Mutex{},
		peers: make(map[string]*peer.Peer),
	}
	a.peers["b"] = peer.New("a", "b", peerStatic,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, kp, testTransport{})

	a.attachBridge(b)

	if !b.router.HasRoute(netip.MustParseAddr("10.60.0.2")) {
		t.Fatal("route for pre-existing peer not installed after attachBridge")
	}
}

// TestTunBridgeDropPeerRemovesRoute verifies that pruning a peer detaches its
// sink from the router.
func TestTunBridgeDropPeerRemovesRoute(t *testing.T) {
	b := newTestBridge(t)
	s := newBridgeSink()
	b.setPeerSink("b", s)
	if !b.router.HasRoute(netip.MustParseAddr("10.60.0.2")) {
		t.Fatal("route missing after setPeerSink")
	}
	b.setPeerSink("b", nil)
	if b.router.HasRoute(netip.MustParseAddr("10.60.0.2")) {
		t.Fatal("route still present after detach")
	}
}
