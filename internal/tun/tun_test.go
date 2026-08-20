package tun

import (
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
)

// sink captures packets handed to it.
type sink struct {
	got   [][]byte
	fail  bool
	calls int
}

func (s *sink) Send(p []byte) error {
	s.calls++
	if s.fail {
		return errors.New("boom")
	}
	s.got = append(s.got, append([]byte(nil), p...))
	return nil
}

// ipv4 builds a minimal well-formed single-datagram IPv4 packet.
func ipv4(src, dst string, payload []byte) []byte {
	sa := netip.MustParseAddr(src).As4()
	da := netip.MustParseAddr(dst).As4()
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45 // v4, IHL 5
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	copy(pkt[12:16], sa[:])
	copy(pkt[16:20], da[:])
	copy(pkt[20:], payload)
	return pkt
}

func TestBufferDeviceRoundtrip(t *testing.T) {
	d := NewBufferDevice("utun0", 1500)
	defer d.Close()
	if d.Name() != "utun0" || d.MTU() != 1500 {
		t.Fatalf("meta mismatch: %s/%d", d.Name(), d.MTU())
	}
	msg := []byte("hello")
	if n, err := d.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	buf := make([]byte, 1500)
	n, err := d.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !reflect.DeepEqual(buf[:n], msg) {
		t.Fatalf("roundtrip mismatch: %q", buf[:n])
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := d.Read(buf); err != io.EOF {
		t.Fatalf("Read after Close = %v, want io.EOF", err)
	}
}

func TestRouterForwardsKnownDestination(t *testing.T) {
	r := NewRouter()
	s := &sink{}
	r.SetRoute(netip.MustParseAddr("10.60.0.2"), s)

	pkt := ipv4("10.60.0.1", "10.60.0.2", []byte("payload"))
	if !r.RoutePacket(pkt) {
		t.Fatal("route missed a configured destination")
	}
	if len(s.got) != 1 || !reflect.DeepEqual(s.got[0], pkt) {
		t.Fatalf("sink got %d packets: %v", len(s.got), s.got)
	}
	if r.PktsIn != 1 || r.PktsRouted != 1 || r.PktsDropped != 0 {
		t.Fatalf("counters: in=%d routed=%d dropped=%d", r.PktsIn, r.PktsRouted, r.PktsDropped)
	}
}

func TestRouterDropsUnknownDest(t *testing.T) {
	r := NewRouter()
	r.SetRoute(netip.MustParseAddr("10.60.0.2"), &sink{})
	if r.RoutePacket(ipv4("10.60.0.1", "10.60.0.9", nil)) {
		t.Fatal("routed to unknown destination")
	}
	if r.PktsDropped != 1 {
		t.Fatalf("dropped = %d, want 1", r.PktsDropped)
	}
}

func TestRouterDropsMalformed(t *testing.T) {
	r := NewRouter()
	r.SetRoute(netip.MustParseAddr("10.60.0.2"), &sink{})
	cases := [][]byte{
		nil,
		{0x40},                                   // v4 but truncated
		make([]byte, 20),                         // total length field zero
		{0x60, 0, 0, 0},                          // IPv6
		ipv4("10.60.0.1", "10.60.0.2", nil)[:10], // truncated
	}
	for _, c := range cases {
		if r.RoutePacket(c) {
			t.Fatalf("malformed packet routed: %v", c)
		}
	}
	// Malformed datagrams are offered but never counted as valid traffic: they
	// only bump the drop counter (PktsIn counts valid IPv4 datagrams offered).
	if r.PktsIn != 0 || r.PktsRouted != 0 || r.PktsDropped != uint64(len(cases)) {
		t.Fatalf("counters: in=%d routed=%d dropped=%d", r.PktsIn, r.PktsRouted, r.PktsDropped)
	}
}

func TestRouterRouteRemoval(t *testing.T) {
	r := NewRouter()
	dst := netip.MustParseAddr("10.60.0.2")
	r.SetRoute(dst, &sink{})
	r.SetRoute(dst, nil)
	if r.RoutePacket(ipv4("10.60.0.1", "10.60.0.2", nil)) {
		t.Fatal("routed after route removal")
	}
	// IPv6 routes are never installed.
	ip6 := netip.MustParseAddr("fd00::1")
	r.SetRoute(ip6, &sink{})
	if len(r.routes) != 0 {
		t.Fatalf("IPv6 route installed: %v", r.routes)
	}
}

func TestRouterSendErrorCountsDropped(t *testing.T) {
	r := NewRouter()
	s := &sink{fail: true}
	r.SetRoute(netip.MustParseAddr("10.60.0.2"), s)
	if r.RoutePacket(ipv4("10.60.0.1", "10.60.0.2", nil)) {
		t.Fatal("routed despite sink error")
	}
	if r.PktsDropped != 1 || r.PktsRouted != 0 {
		t.Fatalf("counters after sink error: routed=%d dropped=%d", r.PktsRouted, r.PktsDropped)
	}
}

// TestOpenSkipsWithoutPrivilege exercises the real device opener; it passes
// silently wherever root/TUN access is unavailable and asserts success when
// it is.
func TestOpenSkipsWithoutPrivilege(t *testing.T) {
	dev, err := Open("", 1500)
	if err != nil {
		t.Skip("TUN device unavailable in this environment: ", err)
	}
	if dev.Name() == "" || dev.MTU() <= 0 {
		t.Fatalf("bad device meta: %+v", dev)
	}
	_ = dev.Close()
}
