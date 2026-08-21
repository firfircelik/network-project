package protocol

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestRegisterRoundtrip(t *testing.T) {
	line, err := EncodeLine(Message{
		Type:      TypeRegister,
		ID:        "a",
		PubKey:    "abc123",
		Endpoints: []string{"127.0.0.1:19301", "127.0.0.1:19205"},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := DecodeLine(line)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Type != TypeRegister || msg.ID != "a" || msg.PubKey != "abc123" {
		t.Fatalf("roundtrip mismatch: %+v", msg)
	}
	if len(msg.Endpoints) != 2 || msg.Endpoints[1] != "127.0.0.1:19205" {
		t.Fatalf("endpoints mismatch: %v", msg.Endpoints)
	}
}

func TestPeerListRoundtrip(t *testing.T) {
	line, err := EncodeLine(Message{
		Type: TypePeerList,
		Peers: []PeerInfo{
			{ID: "a", PubKey: "k1", Endpoints: []string{"127.0.0.1:1"}},
			{ID: "b", PubKey: "k2", Endpoints: []string{"127.0.0.1:2"}},
		},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := DecodeLine(line)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg.Peers) != 2 || msg.Peers[1].ID != "b" {
		t.Fatalf("peers mismatch: %+v", msg.Peers)
	}
}

func TestDecodeEmpty(t *testing.T) {
	if _, err := DecodeLine(nil); err == nil {
		t.Fatal("expected error for empty line")
	}
	if _, err := DecodeLine([]byte("not json\n")); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestQueryResultRoundtrip(t *testing.T) {
	line, err := EncodeLine(Message{
		Type:  TypeQueryResult,
		Count: 2,
		Total: 7,
		Up:    42,
		Peers: []PeerInfo{
			{ID: "a", PubKey: "k1", Endpoints: []string{"127.0.0.1:1"}},
			{ID: "b", PubKey: "k2", Endpoints: []string{"127.0.0.1:2"}},
		},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := DecodeLine(line)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Type != TypeQueryResult || msg.Count != 2 || msg.Total != 7 || msg.Up != 42 {
		t.Fatalf("snapshot fields mismatch: %+v", msg)
	}
	if len(msg.Peers) != 2 || msg.Peers[0].ID != "a" {
		t.Fatalf("peers mismatch: %+v", msg.Peers)
	}
	// Query messages must omit the snapshot fields (omitempty) so a query is
	// as small as a register.
	qline, err := EncodeLine(Message{Type: TypeQuery})
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	qmsg, err := DecodeLine(qline)
	if err != nil {
		t.Fatalf("decode query: %v", err)
	}
	if qmsg.Type != TypeQuery || qmsg.Count != 0 || qmsg.Total != 0 || qmsg.Up != 0 {
		t.Fatalf("query decode mismatch: %+v", qmsg)
	}
}

func TestTrailingNewlineTolerated(t *testing.T) {
	msg, err := DecodeLine([]byte(`{"type":"register","id":"x","pubkey":"abc"}` + "\n"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Type != TypeRegister || msg.ID != "x" || msg.PubKey != "abc" {
		t.Fatalf("mismatch: %+v", msg)
	}
}

func TestReadLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("one\ntwo\n"))
	line, err := ReadLine(r)
	if err != nil || string(line) != "one\n" {
		t.Fatalf("ReadLine 1: line=%q err=%v", line, err)
	}
	line, err = ReadLine(r)
	if err != nil || string(line) != "two\n" {
		t.Fatalf("ReadLine 2: line=%q err=%v", line, err)
	}
}

func TestReadLineTooLong(t *testing.T) {
	// A single line far beyond the limit must be rejected without unbounded
	// buffering.
	r := bufio.NewReader(strings.NewReader(strings.Repeat("x", MaxControlLine*2) + "\n"))
	if _, err := ReadLine(r); !errors.Is(err, ErrControlLineTooLong) {
		t.Fatalf("ReadLine(long) error = %v, want ErrControlLineTooLong", err)
	}
}

func FuzzDecodeLine(f *testing.F) {
	f.Add([]byte(`{"type":"register","id":"a","pubkey":"ab","endpoints":["1.2.3.4:9"]}`))
	f.Add([]byte(`{"type":"peer_list","peers":[{"id":"a"}]}`))
	f.Add([]byte("not json"))
	f.Add([]byte{})
	f.Add([]byte(`{"type":"error","msg":"oops"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeLine(b) // must never panic
	})
}
