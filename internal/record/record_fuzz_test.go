package record

import (
	"bytes"
	"testing"
)

// FuzzParse exercises the frame parser against arbitrary datagrams. The
// parser must reject everything without panicking or aliasing.
func FuzzParse(f *testing.F) {
	f.Add(Frame(TypeData, []byte("hello")))
	f.Add([]byte{TypeProbe})
	f.Add([]byte{})
	f.Add([]byte{TypeData, 0x00, 0x10, 0xAA, 0xBB})
	f.Add(make([]byte, 3))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Parse(data)
	})
}

// FuzzFrameParseRoundtrip feeds Frame output back into Parse for a range of
// payload sizes; a roundtrip must always succeed.
func FuzzFrameParseRoundtrip(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("meshlink"))
	f.Add(bytes.Repeat([]byte{1}, 4096))
	f.Fuzz(func(t *testing.T, payload []byte) {
		fr := Frame(TypeData, payload)
		typ, got, err := Parse(fr)
		if err != nil {
			t.Fatalf("Parse(Frame(%d bytes)): %v", len(payload), err)
		}
		if typ != TypeData || !bytes.Equal(got, payload) {
			t.Fatalf("roundtrip mismatch: %d vs %d bytes", len(got), len(payload))
		}
	})
}

// FuzzReadFrame streams arbitrary frames out of a reader; it must only ever
// return a framing error (never panic).
func FuzzReadFrame(f *testing.F) {
	f.Add(Frame(TypeData, []byte("abc")))
	f.Add([]byte{TypeData, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadFrame(bytes.NewReader(data))
	})
}
