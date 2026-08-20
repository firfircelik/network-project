package record

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestFrameRoundTrip covers Frame/Parse round trips for nil, empty, small and
// maximum-length (65535) payloads.
func TestFrameRoundTrip(t *testing.T) {
	large := make([]byte, maxPayloadLen)
	for i := range large {
		large[i] = byte(i)
	}
	cases := []struct {
		name    string
		typ     byte
		payload []byte
	}{
		{"zero payload", TypeProbe, nil},
		{"empty payload", TypeData, []byte{}},
		{"single byte", TypeHS1, []byte{0x01}},
		{"handshake payload", TypeHS2, []byte("noise xx message 2")},
		{"max 65535", TypeRelay, large},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Frame(tc.typ, tc.payload)
			if len(f) != HeaderLen+len(tc.payload) {
				t.Fatalf("Frame length = %d, want %d", len(f), HeaderLen+len(tc.payload))
			}
			typ, payload, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if typ != tc.typ {
				t.Fatalf("Parse type = %d, want %d", typ, tc.typ)
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Fatalf("Parse payload mismatch: got %d bytes, want %d", len(payload), len(tc.payload))
			}
		})
	}
}

// TestParseRejectsBrokenDatagrams exercises the three exported sentinel
// errors.
func TestParseRejectsBrokenDatagrams(t *testing.T) {
	t.Run("too short header", func(t *testing.T) {
		for _, n := range []int{0, 1, 2} {
			if _, _, err := Parse(make([]byte, n)); !errors.Is(err, ErrTooShort) {
				t.Fatalf("Parse(%d bytes) error = %v, want ErrTooShort", n, err)
			}
		}
	})

	t.Run("oversized length", func(t *testing.T) {
		// The length field claims a 16-byte payload but only 2 bytes follow.
		truncated := []byte{TypeData, 0x00, 0x10, 0xAA, 0xBB}
		if _, _, err := Parse(truncated); !errors.Is(err, ErrOversized) {
			t.Fatalf("Parse(truncated) error = %v, want ErrOversized", err)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		extra := append(Frame(TypeData, []byte{1, 2, 3}), 0xFF)
		if _, _, err := Parse(extra); !errors.Is(err, ErrTrailing) {
			t.Fatalf("Parse(extra) error = %v, want ErrTrailing", err)
		}
	})

	t.Run("empty datagram", func(t *testing.T) {
		if _, _, err := Parse(nil); !errors.Is(err, ErrTooShort) {
			t.Fatalf("Parse(nil) error = %v, want ErrTooShort", err)
		}
	})
}

// TestParseDoesNotAlias ensures the returned payload cannot corrupt the frame
// it was parsed from.
func TestParseDoesNotAlias(t *testing.T) {
	original := []byte("do not touch me")
	f := Frame(TypeData, original)
	_, payload, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 0xFF
	if f[HeaderLen] != original[0] {
		t.Fatalf("Parse returned an aliasing slice: frame byte = %d, want %d", f[HeaderLen], original[0])
	}
}

// TestReadFrame streams several frames (including a 65535-byte payload) out of
// a bytes.Buffer and then confirms a clean io.EOF at the stream end.
func TestReadFrame(t *testing.T) {
	var buf bytes.Buffer
	frames := [][]byte{
		Frame(TypeHS1, []byte("hello")),
		Frame(TypeHS2, nil),
		Frame(TypeData, bytes.Repeat([]byte("meshlink"), 731)),
		Frame(TypeRelay, make([]byte, maxPayloadLen)),
	}
	for _, f := range frames {
		buf.Write(f)
	}
	for i, want := range frames {
		typ, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame frame %d: %v", i, err)
		}
		if got := Frame(typ, payload); !bytes.Equal(got, want) {
			t.Fatalf("ReadFrame frame %d mismatch: got %d bytes, want %d", i, len(got), len(want))
		}
	}
	if _, _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrame at clean end error = %v, want io.EOF", err)
	}
}

// TestReadFrameTruncatedHeader ensures a stream that ends mid-header reports
// the underlying error instead of hanging or returning garbage.
func TestReadFrameTruncatedHeader(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewBuffer([]byte{TypeData, 0x00}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFrame(2 bytes) error = %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestFrameOversizePanics guards the uint16 length field: an 8 KiB+ payload
// cannot be encoded, so Frame must panic instead of silently wrapping.
func TestFrameOversizePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Frame(big payload) did not panic")
		}
	}()
	Frame(TypeData, make([]byte, maxPayloadLen+1))
}
