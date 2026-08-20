package nat

import (
	"net"
	"testing"
)

// FuzzUnwrapOutbound exercises the door envelope decoder; it must never panic.
func FuzzUnwrapOutbound(f *testing.F) {
	f.Add([]byte{outboundMagic, 0x00, 0x01, 'a', 0x00, 0x01, '1', 0x05, 0x00, 0x01, 'x'})
	f.Add([]byte{})
	f.Add([]byte{outboundMagic})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = UnwrapOutbound(data)
	})
}

// FuzzUnwrapInbound exercises the box delivery envelope decoder; it must never
// panic.
func FuzzUnwrapInbound(f *testing.F) {
	f.Add([]byte{inboundMagic, 0x00, 0x09, '1', '2', '7', '.', '0', '.', '0', '.', '1'})
	f.Add([]byte{})
	f.Add([]byte{inboundMagic})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = UnwrapInbound(data)
	})
}

// FuzzWrapInbound ensures WrapInbound output always unwraps cleanly.
func FuzzWrapInbound(f *testing.F) {
	f.Add("127.0.0.1:1234", []byte("payload"))
	f.Fuzz(func(t *testing.T, src string, payload []byte) {
		if _, err := net.ResolveUDPAddr("udp", src); err != nil {
			return
		}
		addr, _ := net.ResolveUDPAddr("udp", src)
		env := WrapInbound(addr, payload)
		got, inner, err := UnwrapInbound(env)
		if err != nil {
			t.Fatalf("UnwrapInbound(WrapInbound(%q)): %v", src, err)
		}
		if got.String() != addr.String() || len(inner) != len(payload) {
			t.Fatalf("roundtrip mismatch for %q", src)
		}
	})
}
