package disco

import "testing"

// TestRoleIsInitiatorSymmetric verifies the deterministic role split: for any
// pair exactly one side initiates, and both sides derive the same answer from
// their own viewpoint.
func TestRoleIsInitiatorSymmetric(t *testing.T) {
	pairs := [][2]string{
		{"a", "b"},
		{"alice", "bob"},
		{"node-1", "node-2"},
		{"zzz", "aaa"},
		{"same-prefix-1", "same-prefix-2"},
	}
	for _, pr := range pairs {
		a, b := pr[0], pr[1]
		if RoleIsInitiator(a, b) == RoleIsInitiator(b, a) {
			t.Fatalf("pair (%q,%q): both sides agree on the initiator role", a, b)
		}
	}
	// Equal IDs never initiate against themselves (degenerate but must not
	// panic or claim both roles).
	if RoleIsInitiator("x", "x") {
		t.Fatal("equal IDs must not initiate")
	}
}

// TestPathString pins the human-readable path names used in logs and status
// output.
func TestPathString(t *testing.T) {
	cases := map[Path]string{
		PathNone:   "none",
		PathDirect: "direct",
		PathRelay:  "relay",
		Path(99):   "none",
	}
	for p, want := range cases {
		if got := p.String(); got != want {
			t.Fatalf("Path(%d).String() = %q, want %q", int(p), got, want)
		}
	}
}

// TestTimingConstantsSanity guards the timing policy against accidental
// inversions that would silently break the handshake cadence (e.g. a probe
// interval longer than an attempt window, or a keepalive shorter than the
// probe interval).
func TestTimingConstantsSanity(t *testing.T) {
	if ProbeInterval <= 0 {
		t.Fatal("ProbeInterval must be positive")
	}
	if DirectAttempt < 2*ProbeInterval || RelayAttempt < 2*ProbeInterval {
		t.Fatal("attempt windows must span several probes")
	}
	if HS1ResendInterval < ProbeInterval {
		t.Fatal("HS1 resend must not fire faster than the probe cadence")
	}
	if KeepaliveInterval <= ProbeInterval {
		t.Fatal("keepalive interval must exceed the probe interval")
	}
	if ReestablishInterval <= DirectAttempt {
		t.Fatal("re-establish interval must exceed a full direct attempt")
	}
}
