// Package record implements the meshlink data-plane framing contract.
//
// Every UDP datagram carries exactly one frame of the form
//
//	[1B type][2B length BE][payload]
//
// where the length field is the payload length in bytes, big-endian, and at
// most 65535. This package only implements the framing; the type constants it
// exports are shared across the meshlink modules.
package record

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame type identifiers used in the data plane (see SPEC §1).
const (
	TypeHS1   byte = 1 // Noise XX message 1 (initiator → responder)
	TypeHS2   byte = 2 // Noise XX message 2 (responder → initiator)
	TypeHS3   byte = 3 // Noise XX message 3 (initiator → responder)
	TypeProbe byte = 4 // empty probe (hole punching / NAT mapping)
	TypeData  byte = 5 // encrypted Noise transport message (AEAD, increasing nonce)
	TypeRelay byte = 7 // agent → relay: [magic][src][dst][inner frame]
)

// HeaderLen is the fixed size in bytes of the frame header.
const HeaderLen = 3

// maxPayloadLen is the largest payload a single frame can carry. The length
// field is a big-endian uint16, so 65535 is the natural maximum.
const maxPayloadLen = 65535

// Errors returned by Parse and ReadFrame.
var (
	// ErrTooShort reports a datagram with fewer than HeaderLen bytes.
	ErrTooShort = errors.New("record: datagram shorter than header")
	// ErrOversized reports a length field that claims more payload bytes than
	// the datagram actually contains (the frame is truncated).
	ErrOversized = errors.New("record: length field exceeds payload bytes")
	// ErrTrailing reports extra bytes after the frame payload.
	ErrTrailing = errors.New("record: trailing bytes after payload")
)

// Frame builds a single frame for the given type and payload:
//
//	[1B type][2B length BE][payload]
func Frame(t byte, payload []byte) []byte {
	frame := make([]byte, HeaderLen+len(payload))
	frame[0] = t
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(payload)))
	copy(frame[3:], payload)
	return frame
}

// Parse validates that datagram contains exactly one full frame and returns
// its type and payload. It reports ErrTooShort when the datagram is shorter
// than the header, ErrOversized when the length field promises more payload
// bytes than are present, and ErrTrailing when bytes follow the payload. The
// returned payload is a fresh allocation.
func Parse(datagram []byte) (t byte, payload []byte, err error) {
	if len(datagram) < HeaderLen {
		return 0, nil, ErrTooShort
	}
	t = datagram[0]
	n := int(binary.BigEndian.Uint16(datagram[1:3]))
	if n > len(datagram)-HeaderLen {
		return 0, nil, ErrOversized
	}
	if len(datagram) > HeaderLen+n {
		return 0, nil, ErrTrailing
	}
	payload = make([]byte, n)
	copy(payload, datagram[HeaderLen:HeaderLen+n])
	return t, payload, nil
}

// ReadFrame reads one frame from a stream: it reads HeaderLen header bytes and
// then the payload declared by the length field. This is the stream (TCP)
// variant of Parse. A clean EOF at a frame boundary is reported (wrapped) as
// io.EOF.
func ReadFrame(r io.Reader) (t byte, payload []byte, err error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("record: read header: %w", err)
	}
	t = hdr[0]
	n := int(binary.BigEndian.Uint16(hdr[1:3]))
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("record: read payload: %w", err)
	}
	return t, payload, nil
}
