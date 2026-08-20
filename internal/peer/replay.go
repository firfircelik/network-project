package peer

// replayWindow is the receiver-side loss/replay gate for DATA frames. Every
// frame carries an explicit 64-bit nonce; the window accepts exactly one
// occurrence of each fresh nonce, tolerates reordering, and drops everything
// that is replayed or that fell out of the trailing window (WireGuard-style
// sliding bitmap). A fresh session resets the window so a re-handshake can
// restart its counter from zero.
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

// Accept records nonce on first sight if it is within the sliding window and
// reports whether the frame may be processed. A nonce beyond the window (too
// old) or one already seen (replay) is rejected.
func (w *replayWindow) Accept(nonce uint64) bool {
	if nonce == 0 {
		if w.zeroSeen {
			return false
		}
		w.zeroSeen = true
		return true
	}
	if w.max == 0 {
		w.max = nonce
		w.start = windowStart(nonce, w.size)
		clear(w.bits)
		w.setBit(nonce - w.start)
		return true
	}
	if nonce > w.max {
		w.advance(nonce)
		w.setBit(nonce - w.start)
		return true
	}
	// nonce within [start, max]: fresh only if the bit is unset.
	if nonce < w.start {
		return false
	}
	if w.getBit(nonce - w.start) {
		return false
	}
	w.setBit(nonce - w.start)
	return true
}

// advance slides the window so that start = nonce minus the window width,
// keeping every previously seen nonce that still falls inside it. It assumes
// nonce > w.max.
func (w *replayWindow) advance(nonce uint64) {
	old := make([]uint64, len(w.bits))
	copy(old, w.bits)
	oldStart := w.start
	clear(w.bits)
	w.start = windowStart(nonce, w.size)
	w.max = nonce
	for wi := range old {
		bits := old[wi]
		if bits == 0 {
			continue
		}
		for b := 0; b < 64; b++ {
			if bits&(1<<uint(b)) == 0 {
				continue
			}
			abs := oldStart + uint64(wi*64+b)
			if abs >= w.start {
				w.setBit(abs - w.start)
			}
		}
	}
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
