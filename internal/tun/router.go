package tun

import (
	"net/netip"
	"sync"
)

// Sink is where an outbound IP packet gets sent: the owning peer's encrypted
// session send path (implemented by *peer.Peer.Send).
type Sink interface {
	Send(payload []byte) error
}

// Router routes plain IPv4 packets from the TUN device to peer sinks by
// destination address, dropping traffic without a route. It is the outbound
// half of the agent's tun bridge and is fully testable without a real device.
type Router struct {
	mu     sync.RWMutex
	routes map[netip.Addr]Sink

	PktsIn      uint64 // valid IPv4 datagrams offered
	PktsRouted  uint64 // datagrams handed to a peer sink
	PktsDropped uint64 // datagrams dropped (unroutable, malformed, send error)
}

// NewRouter returns an empty router.
func NewRouter() *Router {
	return &Router{routes: make(map[netip.Addr]Sink)}
}

// SetRoute installs (or, with a nil sink, removes) the peer sink for dst.
// Only IPv4 destinations are routed.
func (r *Router) SetRoute(dst netip.Addr, s Sink) {
	if !dst.Is4() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == nil {
		delete(r.routes, dst)
		return
	}
	r.routes[dst] = s
}

// HasRoute reports whether a non-nil sink for dst is currently installed.
func (r *Router) HasRoute(dst netip.Addr) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.routes[dst]
	return ok
}

// RoutePacket validates pkt as an IPv4 datagram, looks up its destination in
// the route table and forwards the datagram through the owning peer's session.
// It reports whether the packet was accepted for delivery and updates the
// packet counters.
func (r *Router) RoutePacket(pkt []byte) bool {
	_, dst, ok := parseIPv4(pkt)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.PktsIn++
	if !ok {
		r.PktsDropped++
		return false
	}
	sink, ok := r.routes[dst]
	if !ok {
		r.PktsDropped++
		return false
	}
	if err := sink.Send(pkt); err != nil {
		r.PktsDropped++
		return false
	}
	r.PktsRouted++
	return true
}

// parseIPv4 validates pkt as a complete IPv4 datagram and returns the source
// and destination addresses.
func parseIPv4(pkt []byte) (netip.Addr, netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return netip.Addr{}, netip.Addr{}, false
	}
	total := int(pkt[2])<<8 | int(pkt[3])
	if total < ihl || len(pkt) < total {
		return netip.Addr{}, netip.Addr{}, false
	}
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	return src, dst, true
}
