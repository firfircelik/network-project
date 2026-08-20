package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

const testReadTimeout = 2 * time.Second

// startBox wires a Box around a freshly bound "inside client" socket (the
// private host) and starts its Run loop. The box binds ephemeral public and
// door ports.
func startBox(t *testing.T, behavior Behavior) (*Box, net.PacketConn, context.CancelFunc) {
	t.Helper()
	inside, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind inside client: %v", err)
	}
	t.Cleanup(func() { _ = inside.Close() })
	box, err := New(Config{
		Behavior:    behavior,
		PublicAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, // ephemeral port
		InsideDoor:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, // ephemeral port
		PrivateHost: inside.LocalAddr().(*net.UDPAddr),
		MappingTTL:  0,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = box.Run(ctx) }()
	return box, inside, cancel
}

func dialPeer(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("bind peer %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

// buildEnvelope builds the interior-door outbound envelope for the given
// destination address string and inner frame.
func buildEnvelope(src, dst string, inner []byte) []byte {
	b := []byte{outboundMagic}
	b = binary.BigEndian.AppendUint16(b, uint16(len(src)))
	b = append(b, src...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(dst)))
	b = append(b, dst...)
	b = append(b, inner...)
	return b
}

// decodeOutbound decodes a door envelope into destination and inner frame (a
// test helper; production code always receives the full source name too).
func decodeOutbound(pkt []byte) (dst *net.UDPAddr, inner []byte, err error) {
	_, dst, inner, err = UnwrapOutbound(pkt)
	return dst, inner, err
}

func readFrom(t *testing.T, conn net.PacketConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(testReadTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 65536)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	return buf[:n], addr.(*net.UDPAddr)
}

func expectNoData(t *testing.T, conn net.PacketConn, d time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 65536)
	n, _, err := conn.ReadFrom(buf)
	if err == nil {
		t.Fatalf("expected no datagram, received %q", buf[:n])
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return
	}
	t.Fatalf("unexpected read error: %v", err)
}

// readFromInside reads a datagram delivered to the private host and unwraps
// the box inbound envelope, asserting the external source was preserved.
func readFromInside(t *testing.T, conn net.PacketConn, wantSrc string) []byte {
	t.Helper()
	raw, _ := readFrom(t, conn)
	src, payload, err := UnwrapInbound(raw)
	if err != nil {
		t.Fatalf("unwrap inbound envelope: %v", err)
	}
	if wantSrc != "" && src.String() != wantSrc {
		t.Fatalf("inbound external source %s, want %s", src, wantSrc)
	}
	return payload
}

func TestParseBehavior(t *testing.T) {
	cases := []struct {
		in   string
		want Behavior
	}{
		{"fullcone", BehaviorFullCone},
		{"FULLCONE", BehaviorFullCone},
		{"restricted", BehaviorAddressRestricted},
		{"Restricted", BehaviorAddressRestricted},
		{"symmetric", BehaviorSymmetric},
		{"SYMMETRIC", BehaviorSymmetric},
	}
	for _, c := range cases {
		got, err := ParseBehavior(c.in)
		if err != nil {
			t.Fatalf("ParseBehavior(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseBehavior(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := ParseBehavior("bogus"); err == nil {
		t.Fatal("ParseBehavior(bogus) succeeded")
	}
}

func TestFullConeRoundtrip(t *testing.T) {
	box, inside, cancel := startBox(t, BehaviorFullCone)
	defer cancel()

	ext := dialPeer(t, "127.0.0.1:0")
	door := box.doorConn.LocalAddr().(*net.UDPAddr)
	pub := box.Public()

	// Outbound: inside client -> door -> external peer, source rewritten to
	// the box public address.
	inner := []byte("hello-from-inside")
	env := buildEnvelope(box.cfg.PrivateHost.String(), ext.LocalAddr().String(), inner)
	if _, err := inside.(*net.UDPConn).WriteToUDP(env, door); err != nil {
		t.Fatalf("outbound write: %v", err)
	}
	got, src := readFrom(t, ext)
	if string(got) != "hello-from-inside" {
		t.Fatalf("external peer got %q, want %q", got, inner)
	}
	if !src.IP.Equal(pub.IP) || src.Port != pub.Port {
		t.Fatalf("external peer saw source %s, want %s", src, pub)
	}

	// Inbound: external peer replies to box public -> inside client.
	reply := []byte("reply-from-outside")
	if _, err := ext.WriteToUDP(reply, pub); err != nil {
		t.Fatalf("inbound write: %v", err)
	}
	if got := readFromInside(t, inside, ext.LocalAddr().String()); string(got) != "reply-from-outside" {
		t.Fatalf("inside client got %q, want %q", got, reply)
	}

	st := box.Stats()
	if st.Outbound < 1 || st.Inbound < 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if st.Dropped != 0 {
		t.Fatalf("unexpected drops: %+v", st)
	}
}

func TestSymmetricDropsUnmappedInbound(t *testing.T) {
	box, inside, cancel := startBox(t, BehaviorSymmetric)
	defer cancel()

	extA := dialPeer(t, "127.0.0.1:0") // contacted peer
	extB := dialPeer(t, "127.0.0.1:0") // different addr: same IP, different port
	door := box.doorConn.LocalAddr().(*net.UDPAddr)

	// Outbound to A establishes the exact (private host, A) mapping. The
	// forwarded frame's source is the mapping's dedicated ephemeral socket.
	env := buildEnvelope(box.cfg.PrivateHost.String(), extA.LocalAddr().String(), []byte("s-in"))
	if _, err := inside.(*net.UDPConn).WriteToUDP(env, door); err != nil {
		t.Fatalf("outbound write: %v", err)
	}
	_, ephem := readFrom(t, extA) // consume the forwarded inner frame
	if ephem.Port == 0 {
		t.Fatalf("expected an ephemeral public port for symmetric mapping, got %s", ephem)
	}

	// Inbound from A (exact source match) is admitted.
	if _, err := extA.WriteToUDP([]byte("s-ack"), ephem); err != nil {
		t.Fatalf("reply from A: %v", err)
	}
	if got := readFromInside(t, inside, extA.LocalAddr().String()); string(got) != "s-ack" {
		t.Fatalf("inside client got %q, want %q", got, "s-ack")
	}

	// Inbound from B (same IP, different port) must be dropped.
	before := box.Stats()
	if _, err := extB.WriteToUDP([]byte("s-bogus"), ephem); err != nil {
		t.Fatalf("probe from B: %v", err)
	}
	expectNoData(t, inside, 300*time.Millisecond)
	after := box.Stats()
	if after.Dropped <= before.Dropped {
		t.Fatalf("B's probe was not counted as dropped: before=%+v after=%+v", before, after)
	}
	if after.Inbound != 1 {
		t.Fatalf("inbound count = %d, want 1", after.Inbound)
	}
}

func TestAddressRestrictedInbound(t *testing.T) {
	box, inside, cancel := startBox(t, BehaviorAddressRestricted)
	defer cancel()

	extA := dialPeer(t, "127.0.0.1:0")  // contacted peer
	extA2 := dialPeer(t, "127.0.0.1:0") // same IP, different port
	door := box.doorConn.LocalAddr().(*net.UDPAddr)
	pub := box.Public()

	// Outbound to A: records 127.0.0.1 as a contacted destination IP.
	env := buildEnvelope(box.cfg.PrivateHost.String(), extA.LocalAddr().String(), []byte("r-in"))
	if _, err := inside.(*net.UDPConn).WriteToUDP(env, door); err != nil {
		t.Fatalf("outbound write: %v", err)
	}
	readFrom(t, extA)

	// Inbound from the same IP but a different port is admitted.
	if _, err := extA2.WriteToUDP([]byte("r-same-ip"), pub); err != nil {
		t.Fatalf("write from same IP: %v", err)
	}
	if got := readFromInside(t, inside, extA2.LocalAddr().String()); string(got) != "r-same-ip" {
		t.Fatalf("inside client got %q, want %q", got, "r-same-ip")
	}

	// Inbound from a different IP is dropped. macOS only assigns 127.0.0.1
	// to lo0, so if 127.0.0.2 cannot be bound we exercise the drop path
	// directly with a synthesized foreign source address.
	before := box.Stats().Dropped
	if extB, err := net.ListenPacket("udp", "127.0.0.2:0"); err == nil {
		defer extB.Close()
		if _, err := extB.(net.PacketConn).WriteTo([]byte("r-other-ip"), pub); err != nil {
			t.Fatalf("write from other IP: %v", err)
		}
		expectNoData(t, inside, 300*time.Millisecond)
	} else {
		box.handleInbound(box.fixedConn, []byte("r-other-ip"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000})
	}
	if after := box.Stats().Dropped; after <= before {
		t.Fatalf("other-IP packet was not dropped: before=%d after=%d", before, after)
	}
}

// TestAddressRestrictedMultiTarget is the regression test for the contact-IP
// accumulation bug: an address-restricted box must whitelist every IP the
// private host has contacted over time, not only the first one.
func TestAddressRestrictedMultiTarget(t *testing.T) {
	box, inside, cancel := startBox(t, BehaviorAddressRestricted)
	defer cancel()

	extA := dialPeer(t, "127.0.0.1:0")
	door := box.doorConn.LocalAddr().(*net.UDPAddr)

	// First contact: real outbound to 127.0.0.1 through the door.
	env := buildEnvelope(box.cfg.PrivateHost.String(), extA.LocalAddr().String(), []byte("r-a"))
	if _, err := inside.(*net.UDPConn).WriteToUDP(env, door); err != nil {
		t.Fatalf("outbound write: %v", err)
	}
	readFrom(t, extA)

	// The private host then contacts a second destination IP (synthesized:
	// a routable test-net address that needs no listener for UDP writes).
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 7000}
	env2 := buildEnvelope(box.cfg.PrivateHost.String(), other.String(), []byte("r-b"))
	box.handleOutbound(env2, box.cfg.PrivateHost)

	// Inbound from that second IP must now be admitted.
	before := box.Stats()
	box.handleInbound(box.fixedConn, []byte("r-b2"), &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 7000})
	if got := readFromInside(t, inside, "203.0.113.7:7000"); string(got) != "r-b2" {
		t.Fatalf("inside client got %q, want %q", got, "r-b2")
	}
	if after := box.Stats(); after.Inbound <= before.Inbound {
		t.Fatalf("inbound from a contacted second IP was not admitted: before=%+v after=%+v", before, after)
	}

	// A never-contacted IP stays rejected.
	before = box.Stats()
	box.handleInbound(box.fixedConn, []byte("r-unknown"), &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 9000})
	expectNoData(t, inside, 300*time.Millisecond)
	if after := box.Stats(); after.Dropped <= before.Dropped {
		t.Fatalf("untouched-IP inbound was not dropped: before=%+v after=%+v", before, after)
	}
}

func TestMappingTTLExpiry(t *testing.T) {
	inside := dialPeer(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	box, err := New(Config{
		Behavior:    BehaviorFullCone,
		PublicAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		InsideDoor:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		PrivateHost: inside.LocalAddr().(*net.UDPAddr),
		MappingTTL:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}
	go func() { _ = box.Run(ctx) }()

	ext := dialPeer(t, "127.0.0.1:0")
	door := box.doorConn.LocalAddr().(*net.UDPAddr)
	pub := box.Public()

	env := buildEnvelope(box.cfg.PrivateHost.String(), ext.LocalAddr().String(), []byte("ttl-in"))
	if _, err := inside.WriteToUDP(env, door); err != nil {
		t.Fatalf("outbound write: %v", err)
	}
	readFrom(t, ext)

	time.Sleep(300 * time.Millisecond)
	if st := box.Stats(); st.Mappings != 0 {
		t.Fatalf("expected mappings to expire, still %d", st.Mappings)
	}

	before := box.Stats()
	if _, err := ext.WriteToUDP([]byte("ttl-late"), pub); err != nil {
		t.Fatalf("late inbound write: %v", err)
	}
	expectNoData(t, inside, 300*time.Millisecond)
	after := box.Stats()
	if after.Dropped <= before.Dropped {
		t.Fatalf("late inbound packet was not dropped: before=%+v after=%+v", before, after)
	}
}

func TestDecodeOutboundErrors(t *testing.T) {
	if _, _, err := decodeOutbound([]byte{0x00}); err == nil {
		t.Fatal("bad magic accepted")
	}
	if _, _, err := decodeOutbound([]byte{outboundMagic, 0x00, 0x01, 'x'}); err == nil {
		t.Fatal("truncated envelope accepted")
	}
	if _, _, err := decodeOutbound([]byte{outboundMagic, 0x00, 0x00, 0x00, 0x00}); err == nil {
		t.Fatal("empty source name accepted")
	}
}
