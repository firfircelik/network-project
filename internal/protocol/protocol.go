// Package protocol defines the control-plane messages exchanged between an
// agent and the coordinator, encoded as newline-delimited JSON.
package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Message types.
const (
	// TypeRegister tells the coordinator a peer exists (agent -> coordinator).
	TypeRegister = "register"
	// TypePeerList carries the full set of known peers (coordinator -> agent).
	TypePeerList = "peer_list"
	// TypeQuery asks the coordinator for a registry snapshot (agent ->
	// coordinator). Only authenticated control sessions may query.
	TypeQuery = "query"
	// TypeQueryResult carries the registry snapshot requested by TypeQuery
	// (coordinator -> agent).
	TypeQueryResult = "query_result"
	// TypeError carries a control-plane error.
	TypeError = "error"

	// MaxControlLine bounds a single newline-delimited control message so a
	// misbehaving peer cannot force the reader to buffer an unbounded line
	// (memory DoS). A register message is a few hundred bytes; 64 KiB is far
	// above any legitimate use.
	MaxControlLine = 64 << 10
)

// ErrControlLineTooLong reports a control line exceeding MaxControlLine.
var ErrControlLineTooLong = errors.New("protocol: control line exceeds limit")

// PeerInfo describes one registered peer.
type PeerInfo struct {
	ID        string   `json:"id"`
	PubKey    string   `json:"pubkey"`
	Endpoints []string `json:"endpoints"`
}

// Message is the union of all control-plane messages.
type Message struct {
	Type      string     `json:"type"`
	ID        string     `json:"id,omitempty"`
	PubKey    string     `json:"pubkey,omitempty"`
	Endpoints []string   `json:"endpoints,omitempty"`
	Peers     []PeerInfo `json:"peers,omitempty"`
	Msg       string     `json:"msg,omitempty"`

	// Registry snapshot fields, present only in TypeQueryResult:
	// Count is the number of peers currently registered, Total counts every
	// registration served since the coordinator started, and Up is the
	// coordinator uptime in seconds.
	Count int   `json:"count,omitempty"`
	Total int   `json:"total,omitempty"`
	Up    int64 `json:"up,omitempty"`
}

// EncodeLine marshals v to JSON and appends a trailing newline.
func EncodeLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal control message: %w", err)
	}
	return append(b, '\n'), nil
}

// DecodeLine parses a single JSON line into a Message.
func DecodeLine(b []byte) (*Message, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty control line")
	}
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshal control line %q: %w", b, err)
	}
	return &m, nil
}

// ReadLine reads one newline-terminated line from r. A line longer than
// MaxControlLine is consumed but never buffered (memory stays bounded) and
// ErrControlLineTooLong is returned, which callers treat as a reason to drop
// the connection.
func ReadLine(r *bufio.Reader) ([]byte, error) {
	var total int
	for {
		line, err := r.ReadSlice('\n')
		total += len(line)
		if total > MaxControlLine {
			return nil, ErrControlLineTooLong
		}
		if err == nil {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return line, err
		}
		// Buffer filled without a newline: continue scanning and count the
		// discarded chunks; the line itself is never accumulated.
	}
}
