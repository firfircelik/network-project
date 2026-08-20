package peer

import "testing"

func TestReplayWindowBasic(t *testing.T) {
	w := newReplayWindow(8)
	seq := []uint64{0, 1, 2, 3}
	for _, n := range seq {
		if !w.Accept(n) {
			t.Fatalf("Accept(%d) rejected a fresh nonce", n)
		}
	}
	// Duplicates must be rejected.
	for _, n := range seq {
		if w.Accept(n) {
			t.Fatalf("Accept(%d) accepted a replay", n)
		}
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	w := newReplayWindow(8)
	if !w.Accept(5) {
		t.Fatal("accept 5")
	}
	if !w.Accept(3) {
		t.Fatal("accept 3 out of order")
	}
	if !w.Accept(1) {
		t.Fatal("accept 1 out of order")
	}
	if w.Accept(3) {
		t.Fatal("replayed 3 accepted")
	}
	if !w.Accept(2) {
		t.Fatal("fresh 2 within window rejected")
	}
	// The explicit zero is fresh until a zero has actually been seen.
	if !w.Accept(0) {
		t.Fatal("fresh zero rejected")
	}
	if w.Accept(0) {
		t.Fatal("replayed zero accepted")
	}
}

func TestReplayWindowSlides(t *testing.T) {
	w := newReplayWindow(8)
	// Fill the whole window.
	for n := uint64(0); n < 8; n++ {
		if !w.Accept(n) {
			t.Fatalf("accept %d", n)
		}
	}
	// Jump far ahead; window start slides to 1000-8+1 = 993.
	if !w.Accept(1000) {
		t.Fatal("accept 1000 (jump)")
	}
	// 992 falls out of the window.
	if w.Accept(992) {
		t.Fatal("992 accepted though it slid out")
	}
	// 993..999 were never seen: fresh.
	for n := uint64(993); n < 1000; n++ {
		if !w.Accept(n) {
			t.Fatalf("fresh %d rejected", n)
		}
	}
	// Within-window replays are still rejected.
	if w.Accept(1000) {
		t.Fatal("replayed 1000 accepted")
	}
	if w.Accept(995) {
		t.Fatal("replayed 995 accepted")
	}
}

func TestReplayWindowMassiveJump(t *testing.T) {
	w := newReplayWindow(8)
	if !w.Accept(1) {
		t.Fatal("accept 1")
	}
	if !w.Accept(1 << 40) {
		t.Fatal("accept huge jump")
	}
	// Everything far behind the new window start is too old.
	if w.Accept(1) {
		t.Fatal("1 accepted after huge jump")
	}
	// Frames immediately behind the current max are fresh.
	if !w.Accept(1<<40 - 1) {
		t.Fatal("fresh nonce behind max rejected")
	}
	if w.Accept(1<<40 - 1) {
		t.Fatal("replay just behind max accepted")
	}
}

func TestReplayWindowMonotonic(t *testing.T) {
	w := newReplayWindow(64)
	for n := uint64(100); n < 100+128; n++ {
		if !w.Accept(n) {
			t.Fatalf("monotonic nonce %d rejected", n)
		}
	}
}
