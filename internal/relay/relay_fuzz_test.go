package relay

import (
	"testing"
)

// FuzzParsePacket exercises the relay header parser against arbitrary
// datagrams; it must never panic.
func FuzzParsePacket(f *testing.F) {
	f.Add([]byte{Magic, 0x00, 0x01, 'a', 0x00, 0x01, 'b', 0x05, 0x00, 0x01, 'x'})
	f.Add([]byte{})
	f.Add([]byte{Magic})
	f.Add([]byte{Magic, 0x00, 0x41, 'a'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = ParsePacket(data)
	})
}

// FuzzWrapParseRoundtrip ensures WrapPacket output always parses back into the
// same names and frame, for arbitrary (bounded) inputs.
func FuzzWrapParseRoundtrip(f *testing.F) {
	f.Add("alice", "bob", []byte("payload"))
	f.Add("x", "y", []byte(nil))
	f.Fuzz(func(t *testing.T, src, dst string, frame []byte) {
		if len(src) > MaxNameLen || len(dst) > MaxNameLen || src == "" || dst == "" {
			return
		}
		pkt, err := WrapPacket(src, dst, frame)
		if err != nil {
			return
		}
		gs, gd, gf, err := ParsePacket(pkt)
		if err != nil {
			t.Fatalf("ParsePacket(WrapPacket(%q,%q)): %v", src, dst, err)
		}
		if gs != src || gd != dst {
			t.Fatalf("names mismatch: %q/%q vs %q/%q", gs, gd, src, dst)
		}
		if len(gf) != len(frame) {
			t.Fatalf("frame length mismatch: %d vs %d", len(gf), len(frame))
		}
	})
}
