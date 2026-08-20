package peer

// replayWindow is the receiver-side loss/replay gate for DATA frames. Every
// frame carries an explicit 64-bit nonce; the window accepts exactly one
// occurrence of each fresh nonce, tolerates reordering, and drops everything
// that is replayed or that fell out of the trailing window (WireGuard-style
// sliding bitmap). A fresh session resets the window so a re-handshake can
// restart its counter from zero.
//
// The window is updated in two steps: Check reports whether a nonce is fresh
// WITHOUT mutating any state, and Commit records it. The caller must only
// Commit a nonce after the frame's AEAD authentication has succeeded, so an
// unauthenticated datagram with a wild nonce can never slide the window away
// from honest frames (see Peer.onData).
const replayWindowSizeBits = 2048

type replayWindow struct {
	size     uint64
	max      uint64 // highest accepted nonce; 0 means none accepted yet
	start    uint64 // lowest nonce the bitmap currently tracks
	bits     []uint64
	zeroSeen bool
}

func newReplayWindow(size uint64) *replayWindow {
	return &replayWindow{size: size, bits: make([]uint64, (size+63)/64)}
}

// Check reports whether nonce is fresh (not seen, not outside the window).
// It never mutates the window. Combine with Commit after successful
// authentication.
func (w *replayWindow) Check(nonce uint64) bool {
	if nonce == 0 {
		return !w.zeroSeen
	}
	if w.max == 0 {
		return true // first non-zero nonce is always fresh
	}
	if nonce > w.max {
		return true
	}
	if nonce < w.start {
		return false
	}
	return !w.getBit(nonce - w.start)
}

// Commit records nonce as seen. Check must have returned true for it and the
// frame must already be authenticated.
func (w *replayWindow) Commit(nonce uint64) {
	if nonce == 0 {
		w.zeroSeen = true
		return
	}
	if w.max == 0 {
		w.max = nonce
		w.start = windowStart(nonce, w.size)
		clear(w.bits)
		w.setBit(nonce - w.start)
		return
	}
	if nonce > w.max {
		w.advance(nonce)
	}
	w.setBit(nonce - w.start)
}

// Accept is the combined check-and-commit convenience form. It must only be
// used by callers that already authenticated the frame (and by tests); the
// Peer data path calls Check/Commit separately.
func (w *replayWindow) Accept(nonce uint64) bool {
	if !w.Check(nonce) {
		return false
	}
	w.Commit(nonce)
	return true
}

// advance slides the window so that start = nonce minus the window width,
// keeping every previously seen nonce that still falls inside it. It assumes
// nonce > w.max. When the new start equals the old one (small counters) the
// bitmap is kept as-is; only a real slide shifts it, word-wise right
// (O(window/64), no per-bit scan and no re-allocation beyond the destination
// slice). Clears everything when the jump is a full window or wider.
func (w *replayWindow) advance(nonce uint64) {
	newStart := windowStart(nonce, w.size)
	if shift := newStart - w.start; shift > 0 {
		if shift >= w.size {
			clear(w.bits)
		} else {
			dw := shift / 64
			db := shift % 64
			nw := make([]uint64, len(w.bits))
			if db == 0 {
				for wi := int(dw); wi < len(w.bits); wi++ {
					nw[wi-int(dw)] = w.bits[wi]
				}
			} else {
				for wi := int(dw); wi < len(w.bits); wi++ {
					v := w.bits[wi]
					if v == 0 {
						continue
					}
					nw[wi-int(dw)] |= v >> db
					if wi-int(dw)-1 >= 0 {
						nw[wi-int(dw)-1] |= v << (64 - db)
					}
				}
			}
			w.bits = nw
		}
	}
	w.start = newStart
	w.max = nonce
}

// windowStart is the lowest nonce a window whose highest point is `max` still
// covers, clamped to zero for small counters.
func windowStart(max, size uint64) uint64 {
	if max >= size {
		return max - size + 1
	}
	return 0
}

func (w *replayWindow) setBit(idx uint64) {
	w.bits[idx/64] |= 1 << (idx % 64)
}

func (w *replayWindow) getBit(idx uint64) bool {
	return w.bits[idx/64]&(1<<(idx%64)) != 0
}
