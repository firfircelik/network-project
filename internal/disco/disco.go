// Package disco contains the hole-punching policy: path enum, timing
// constants and the deterministic role split used per pair of peers.
package disco

import "time"

// Path identifies which data path a peer session is currently using.
type Path int

const (
	// PathNone means no path has been selected yet.
	PathNone Path = iota
	// PathDirect is the P2P UDP path (traverses NATs via hole punching).
	PathDirect
	// PathRelay is the path through the relay server (fallback).
	PathRelay
)

func (p Path) String() string {
	switch p {
	case PathDirect:
		return "direct"
	case PathRelay:
		return "relay"
	default:
		return "none"
	}
}

// Timing and policy constants for path discovery.
const (
	// ProbeInterval is how often probe/HS frames are emitted while punching.
	ProbeInterval = 500 * time.Millisecond
	// DirectAttempt is how long the direct path is tried before falling back.
	DirectAttempt = 3 * time.Second
	// RelayAttempt is how long the relay path is tried before retrying direct.
	RelayAttempt = 3 * time.Second
	// KeepaliveInterval is the idle time before an empty encrypted frame is sent.
	KeepaliveInterval = 10 * time.Second
	// ReestablishInterval is how often, once on relay, we probe the direct path.
	ReestablishInterval = 10 * time.Second
	// HS1ResendInterval controls how often the initiator re-sends HS1.
	HS1ResendInterval = 500 * time.Millisecond
)

// RoleIsInitiator reports whether myID should act as the Noise XX handshake
// initiator when connecting to peerID. The lexicographically smaller ID
// initiates, so both sides derive the same role without extra signalling.
func RoleIsInitiator(myID, peerID string) bool { return myID < peerID }
