package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

const testReadTimeout = 2 * time.Second

func TestWrapParseRoundtrip(t *testing.T) {
	frame := []byte{0x05, 0x00, 0x03, 'h', 'i'}
	pkt, err := WrapPacket("alice", "bob", frame)
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if len(pkt) == 0 || pkt[0] != Magic {
		t.Fatalf("bad packet header")
	}
	src, dst, got, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if src != "alice" || dst != "bob" {
		t.Fatalf("got src=%q dst=%q, want alice/bob", src, dst)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("frame mismatch: %q vs %q", got, frame)
	}
}

func TestWrapPacketValidation(t *testing.T) {
	frame := []byte("x")
	if _, err := WrapPacket("", "bob", frame); err == nil {
		t.Fatal("empty source name accepted")
	}
	if _, err := WrapPacket("alice", "", frame); err == nil {
		t.Fatal("empty destination name accepted")
	}
	long := strings.Repeat("x", MaxNameLen+1)
	if _, err := WrapPacket(long, "bob", frame); err == nil {
		t.Fatal("oversized source name accepted")
	}
	if _, err := WrapPacket("alice", long, frame); err == nil {
		t.Fatal("oversized destination name accepted")
	}
}

func TestParsePacketErrors(t *testing.T) {
	good, err := WrapPacket("a", "b", []byte("payload"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}

	if _, _, _, err := ParsePacket(good[:0]); err == nil {
		t.Fatal("empty packet accepted")
	}
	bad := append([]byte(nil), good...)
	bad[0] = 0x00
	if _, _, _, err := ParsePacket(bad); err == nil {
		t.Fatal("bad magic accepted")
	}
	cases := [][]byte{
		good[:3],                                  // too short for a full header+names
		{Magic, 0x00, 0x00, 0x00, 0x01, 'b'},      // empty source name
		{Magic, 0x00, 0x01, 'a', 0x00, 0x03, 'b'}, // destination name truncated
		{Magic, 0x00, 0x41, 'a', 'a', 'a', 'a'},   // source name > MaxNameLen
	}
	for i, c := range cases {
		if _, _, _, err := ParsePacket(c); err == nil {
			t.Fatalf("malformed packet %d accepted", i)
		}
	}
}

func TestServerForwarding(t *testing.T) {
	srv, err := New(Config{Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}}) // ephemeral port
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	x := dialConn(t, "127.0.0.1:0")
	y := dialConn(t, "127.0.0.1:0")
	relayAddr := srv.Addr()

	// Register Y first from Y's own socket (its registration packet is
	// dropped: X is not known yet).
	reg, err := WrapPacket("y", "who", []byte("reg"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := y.WriteToUDP(reg, relayAddr); err != nil {
		t.Fatalf("register write: %v", err)
	}

	// X -> Y: Y receives the inner frame re-wrapped with the relay header
	// (source name preserved for multi-peer demultiplexing).
	ping := []byte("inner-ping")
	pp, err := WrapPacket("x", "y", ping)
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := x.WriteToUDP(pp, relayAddr); err != nil {
		t.Fatalf("X->Y write: %v", err)
	}
	src, dst, got, err := ParsePacket(readFrom(t, y))
	if err != nil {
		t.Fatalf("Y received malformed relay packet: %v", err)
	}
	if src != "x" || dst != "y" {
		t.Fatalf("Y packet headers src=%q dst=%q, want x/y", src, dst)
	}
	if !bytes.Equal(got, ping) {
		t.Fatalf("Y received %q, want %q", got, ping)
	}

	// Y -> X: X receives the exact inner frame.
	pong := []byte("inner-pong")
	pp2, err := WrapPacket("y", "x", pong)
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := y.WriteToUDP(pp2, relayAddr); err != nil {
		t.Fatalf("Y->X write: %v", err)
	}
	src, dst, got, err = ParsePacket(readFrom(t, x))
	if err != nil {
		t.Fatalf("X received malformed relay packet: %v", err)
	}
	if src != "y" || dst != "x" {
		t.Fatalf("X packet headers src=%q dst=%q, want y/x", src, dst)
	}
	if !bytes.Equal(got, pong) {
		t.Fatalf("X received %q, want %q", got, pong)
	}

	// Unknown destination name is dropped.
	ub, err := WrapPacket("x", "nobody", []byte("lost"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := x.WriteToUDP(ub, relayAddr); err != nil {
		t.Fatalf("unknown-dst write: %v", err)
	}
	expectNoData(t, y, 300*time.Millisecond)

	st := srv.Stats()
	if st.Wrapped < 4 {
		t.Fatalf("Wrapped = %d, want >= 4", st.Wrapped)
	}
	if st.Forwarded != 2 {
		t.Fatalf("Forwarded = %d, want 2", st.Forwarded)
	}
	if st.Dropped < 2 {
		t.Fatalf("Dropped = %d, want >= 2", st.Dropped)
	}

	cancel()
	_ = srv.Close() // unblock Run promptly if the watcher already ran
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(testReadTimeout):
		t.Fatal("Run did not stop after cancel")
	}
}

// TestServerNamePinning verifies the G2 name-hijack gate: while a name's pin
// is fresh, packets claiming the name from a different address are dropped;
// once the pin lapses, a legitimate rebind is allowed.
func TestServerNamePinning(t *testing.T) {
	cfg := Config{
		Addr:           &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		PinGrace:       150 * time.Millisecond,
		MaxPPS:         -1, // disable rate budgets; this test targets the pin
		MaxBytesPS:     -1,
		NameQuotaBytes: -1,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	relayAddr := srv.Addr()
	x := dialConn(t, "127.0.0.1:0")
	y := dialConn(t, "127.0.0.1:0")
	imp := dialConn(t, "127.0.0.1:0") // different address, tries to take over "x"

	// Register y so forwarding has a target.
	reg, err := WrapPacket("y", "who", []byte("reg"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := y.WriteToUDP(reg, relayAddr); err != nil {
		t.Fatalf("register y: %v", err)
	}

	// X pins its name from x's socket.
	pp, err := WrapPacket("x", "y", []byte("hello"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := x.WriteToUDP(pp, relayAddr); err != nil {
		t.Fatalf("x write: %v", err)
	}
	if got, want := inner(t, readFrom(t, y)), "hello"; got != want {
		t.Fatalf("y received %q, want %q", got, want)
	}

	// Attacker on a different address claiming "x" while the pin is fresh is
	// silently dropped.
	evil, err := WrapPacket("x", "y", []byte("evil"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := imp.WriteToUDP(evil, relayAddr); err != nil {
		t.Fatalf("imp write: %v", err)
	}
	expectNoData(t, y, 300*time.Millisecond)
	if st := srv.Stats(); st.PinnedDropped == 0 {
		t.Fatalf("PinnedDropped = 0, want >= 1")
	}

	// Once the pin lapses the new address may rebind the name.
	time.Sleep(220 * time.Millisecond)
	if _, err := imp.WriteToUDP(evil, relayAddr); err != nil {
		t.Fatalf("imp rebind write: %v", err)
	}
	if got, want := inner(t, readFrom(t, y)), "evil"; got != want {
		t.Fatalf("y received %q, want %q", got, want)
	}
}

// TestServerRateLimit verifies the per-source datagram budget (G4): once a
// source exhausts its pps allowance within a second, further packets are
// dropped without being forwarded.
func TestServerRateLimit(t *testing.T) {
	cfg := Config{
		Addr:           &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		MaxPPS:         2,
		MaxBytesPS:     -1,
		NameQuotaBytes: -1,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	relayAddr := srv.Addr()
	x := dialConn(t, "127.0.0.1:0")
	y := dialConn(t, "127.0.0.1:0")

	reg, err := WrapPacket("y", "who", []byte("reg"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := y.WriteToUDP(reg, relayAddr); err != nil {
		t.Fatalf("register y: %v", err)
	}

	// A burst of five datagrams from x: only two fit the pps budget.
	for i := 0; i < 5; i++ {
		pp, err := WrapPacket("x", "y", []byte("burst"))
		if err != nil {
			t.Fatalf("WrapPacket: %v", err)
		}
		if _, err := x.WriteToUDP(pp, relayAddr); err != nil {
			t.Fatalf("x write %d: %v", i, err)
		}
	}
	if inner(t, readFrom(t, y)) != "burst" {
		t.Fatalf("first delivery mismatch")
	}
	if inner(t, readFrom(t, y)) != "burst" {
		t.Fatalf("second delivery mismatch")
	}
	expectNoData(t, y, 300*time.Millisecond)

	st := srv.Stats()
	if st.Forwarded != 2 {
		t.Fatalf("Forwarded = %d, want 2", st.Forwarded)
	}
	if st.RateLimited != 3 {
		t.Fatalf("RateLimited = %d, want 3", st.RateLimited)
	}
}

// TestServerGlobalBudget verifies the across-all-sources budget (G4):
// per-source budgets cannot cap a flood of many distinct spoofed sources, so
// the global pps budget bounds total relay work.
func TestServerGlobalBudget(t *testing.T) {
	cfg := Config{
		Addr:             &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		MaxPPS:           -1, // per-source disabled; only the global budget bites
		MaxBytesPS:       -1,
		NameQuotaBytes:   -1,
		GlobalMaxPPS:     3,
		GlobalMaxBytesPS: -1,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	relayAddr := srv.Addr()
	x := dialConn(t, "127.0.0.1:0")
	y := dialConn(t, "127.0.0.1:0")

	reg, err := WrapPacket("y", "who", []byte("reg"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := y.WriteToUDP(reg, relayAddr); err != nil {
		t.Fatalf("register y: %v", err)
	}

	// A burst of eight frames from x: the per-source budget is disabled, so
	// only the global cap can stop the flood. The y registration above already
	// consumed one datagram from the global budget.
	for i := 0; i < 8; i++ {
		pp, err := WrapPacket("x", "y", []byte("flood"))
		if err != nil {
			t.Fatalf("WrapPacket: %v", err)
		}
		if _, err := x.WriteToUDP(pp, relayAddr); err != nil {
			t.Fatalf("x write %d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if inner(t, readFrom(t, y)) != "flood" {
			t.Fatalf("delivery %d mismatch", i)
		}
	}
	expectNoData(t, y, 300*time.Millisecond)

	st := srv.Stats()
	if st.Forwarded != 2 {
		t.Fatalf("Forwarded = %d, want 2", st.Forwarded)
	}
	if st.RateLimited != 6 {
		t.Fatalf("RateLimited = %d, want 6", st.RateLimited)
	}
}

// TestServerNameQuota verifies the per-destination-name byte quota (G4):
// beyond the configured bytes/second a destination stops receiving, so one
// name cannot balloon relay bandwidth.
func TestServerNameQuota(t *testing.T) {
	cfg := Config{
		Addr:           &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		MaxPPS:         -1,
		MaxBytesPS:     -1,
		NameQuotaBytes: 16, // two 6-byte frames fit, the third does not
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	relayAddr := srv.Addr()
	x := dialConn(t, "127.0.0.1:0")
	y := dialConn(t, "127.0.0.1:0")

	reg, err := WrapPacket("y", "who", []byte("reg"))
	if err != nil {
		t.Fatalf("WrapPacket: %v", err)
	}
	if _, err := y.WriteToUDP(reg, relayAddr); err != nil {
		t.Fatalf("register y: %v", err)
	}

	for i := 0; i < 3; i++ {
		pp, err := WrapPacket("x", "y", []byte("payload"))
		if err != nil {
			t.Fatalf("WrapPacket: %v", err)
		}
		if _, err := x.WriteToUDP(pp, relayAddr); err != nil {
			t.Fatalf("x write %d: %v", i, err)
		}
	}
	if inner(t, readFrom(t, y)) != "payload" {
		t.Fatalf("first delivery mismatch")
	}
	if inner(t, readFrom(t, y)) != "payload" {
		t.Fatalf("second delivery mismatch")
	}
	expectNoData(t, y, 300*time.Millisecond)

	st := srv.Stats()
	if st.Forwarded != 2 {
		t.Fatalf("Forwarded = %d, want 2", st.Forwarded)
	}
	if st.RateLimited != 1 {
		t.Fatalf("RateLimited = %d, want 1", st.RateLimited)
	}
}

func dialConn(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("bind %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

func readFrom(t *testing.T, conn net.PacketConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(testReadTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 65536)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	return buf[:n]
}

// inner unwraps one relayed datagram and returns its inner frame payload.
func inner(t *testing.T, pkt []byte) string {
	t.Helper()
	_, _, frame, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("received malformed relay packet: %v", err)
	}
	return string(frame)
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
