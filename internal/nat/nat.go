// Package nat implements the natbox core: a UDP-based NAT simulator that runs
// an "inside door" socket (where the private host sends wrapped outbound
// datagrams) and exposes the private host to the outside world through public
// sockets.
//
// Behaviors:
//   - fullcone      : one fixed public port; inbound accepted from any source.
//   - restricted    : fixed public port; inbound accepted only from IPs the
//     private host has contacted before.
//   - symmetric     : a fresh ephemeral public port per destination; inbound is
//     delivered only on the exact (src IP, src port) the private host sent to.
//     This is what makes classic hole punching fail and forces relay fallback.
//
// Agents behind a box wrap every outbound datagram with WrapOutbound; the box
// decodes the envelope, applies the mapping rules and forwards the inner frame
// from the appropriate public socket.
package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Behavior selects the inbound filtering semantics of a Box.
type Behavior int

const (
	// BehaviorFullCone keeps one mapping regardless of destination and accepts
	// inbound traffic from any external source while that mapping exists.
	BehaviorFullCone Behavior = iota
	// BehaviorAddressRestricted behaves like full cone but additionally
	// requires that the inbound source IP was previously contacted.
	BehaviorAddressRestricted
	// BehaviorSymmetric creates one mapping per (destination IP, destination
	// port) tuple; each mapping owns a dedicated ephemeral public port and
	// inbound is accepted only when the exact source matches the mapped
	// destination (classic hole punching fails).
	BehaviorSymmetric
)

const (
	runBufferSize   = 65536
	maxEnvelopeName = 1024
	// cleanupInterval controls how often expired symmetric mappings and their
	// sockets are reaped.
	cleanupInterval = time.Second
)

// outboundMagic is the leading byte of the interior-door outbound envelope.
var outboundMagic byte = 0x52

// inboundMagic is the leading byte of the box -> private host delivery
// envelope. It carries the true external source address, which cannot be
// spoofed over the loopback private link.
var inboundMagic byte = 0x53

// ParseBehavior converts a case-insensitive string to a Behavior.
func ParseBehavior(s string) (Behavior, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fullcone":
		return BehaviorFullCone, nil
	case "restricted":
		return BehaviorAddressRestricted, nil
	case "symmetric":
		return BehaviorSymmetric, nil
	default:
		return 0, fmt.Errorf("nat: unknown behavior %q", s)
	}
}

// Config configures a Box.
type Config struct {
	Name        string
	Behavior    Behavior
	PublicAddr  *net.UDPAddr  // externally reachable NAT address (for fullcone/restricted); symmetric uses its IP only
	InsideDoor  *net.UDPAddr  // host-facing door; agents send outbound envelopes here
	PrivateHost *net.UDPAddr  // real socket of the inside host; inbound is delivered here
	MappingTTL  time.Duration // 0 means mappings never expire
}

// Stats reports Box activity counters.
type Stats struct {
	Outbound uint64
	Inbound  uint64
	Dropped  uint64
	Mappings int
}

// Box is a NAT simulator core.
type Box struct {
	cfg            Config
	doorConn       *net.UDPConn
	fixedConn      *net.UDPConn // nil for symmetric boxes
	privateHostKey string

	mu       sync.Mutex
	mappings map[mappingKey]*mappingEntry
	stats    Stats
	closed   bool // set under mu; stops new symmetric socket readers during shutdown

	wg        sync.WaitGroup
	closeOnce sync.Once
	closeCh   chan struct{}
}

// mappingKey identifies a mapping: for full-cone and address-restricted boxes
// it is the single empty key (one mapping per private host); for symmetric
// boxes it is the (destination IP, destination port) of an outbound flow.
type mappingKey struct {
	dstIP   string
	dstPort int
}

type mappingEntry struct {
	pubConn    *net.UDPConn // symmetric ephemeral socket; nil for fixed boxes
	pubPort    int
	dstIP      string
	dstPort    int
	contactIP  map[string]bool // destination IPs contacted (address-restricted)
	lastSeen   time.Time
	expired    bool
	purgedConn *net.UDPConn // set by cleanup before Close to avoid double close
}

// New binds the inside-door (and, for non-symmetric boxes, the public) socket.
func New(cfg Config) (*Box, error) {
	if cfg.PublicAddr == nil {
		return nil, errors.New("nat: PublicAddr is required")
	}
	if cfg.InsideDoor == nil {
		return nil, errors.New("nat: InsideDoor is required")
	}
	if cfg.PrivateHost == nil {
		return nil, errors.New("nat: PrivateHost is required")
	}
	if cfg.PrivateHost.IP == nil {
		return nil, errors.New("nat: PrivateHost IP is nil")
	}
	door, err := net.ListenPacket("udp", cfg.InsideDoor.String())
	if err != nil {
		return nil, fmt.Errorf("nat: bind inside door %s: %w", cfg.InsideDoor, err)
	}
	doorConn, ok := door.(*net.UDPConn)
	if !ok {
		_ = door.Close()
		return nil, errors.New("nat: ListenPacket did not return a *net.UDPConn")
	}
	b := &Box{
		cfg:            cfg,
		doorConn:       doorConn,
		privateHostKey: addrKey(cfg.PrivateHost),
		mappings:       make(map[mappingKey]*mappingEntry),
		closeCh:        make(chan struct{}),
	}
	if cfg.Behavior != BehaviorSymmetric {
		pub, err := net.ListenPacket("udp", cfg.PublicAddr.String())
		if err != nil {
			_ = door.Close()
			return nil, fmt.Errorf("nat: bind public socket %s: %w", cfg.PublicAddr, err)
		}
		pubConn, ok := pub.(*net.UDPConn)
		if !ok {
			_ = pub.Close()
			_ = door.Close()
			return nil, errors.New("nat: ListenPacket did not return a *net.UDPConn")
		}
		b.fixedConn = pubConn
	}
	return b, nil
}

// Run serves the door and all public sockets until ctx is canceled or Close is
// called, then returns nil.
func (b *Box) Run(ctx context.Context) error {
	if b.doorConn == nil {
		return errors.New("nat: box is not initialized")
	}

	// Outbound: datagrams on the inside door.
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.serveOutbound(ctx)
	}()

	// Inbound on the fixed public socket (non-symmetric boxes).
	if b.fixedConn != nil {
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.serveInboundFixed(ctx)
		}()
	}

	// Periodic cleanup of expired symmetric mappings.
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		tick := time.NewTicker(cleanupInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-b.closeCh:
				return
			case <-tick.C:
				b.cleanup()
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-b.closeCh:
	}
	_ = b.Close()
	b.wg.Wait()
	return nil
}

// Close closes every socket. Subsequent calls are no-ops.
func (b *Box) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closeCh)
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		if e := b.closeConn(b.doorConn); e != nil {
			err = e
		}
		if e := b.closeConn(b.fixedConn); err == nil && e != nil {
			err = e
		}
		b.mu.Lock()
		for k, e := range b.mappings {
			if e.pubConn != nil {
				if ce := b.closeConn(e.pubConn); err == nil && ce != nil {
					err = ce
				}
			}
			delete(b.mappings, k)
		}
		b.mu.Unlock()
	})
	return err
}

// Public returns the address the outside world associates with this NAT device.
// For symmetric boxes this is the base address with port 0 (each destination
// mapping owns its own ephemeral port, learned via STUN at runtime).
func (b *Box) Public() *net.UDPAddr {
	if b.fixedConn != nil {
		return cloneAddr(b.fixedConn.LocalAddr().(*net.UDPAddr))
	}
	return &net.UDPAddr{IP: cloneIP(b.cfg.PublicAddr.IP), Port: 0}
}

// Stats returns a snapshot of the box counters and current mapping count.
// Expired mappings are pruned eagerly so callers observe a consistent view.
func (b *Box) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, e := range b.mappings {
		if e.lastSeenExpired(now, b.cfg.MappingTTL) {
			b.reclaimLocked(k, e)
		}
	}
	return Stats{
		Outbound: b.stats.Outbound,
		Inbound:  b.stats.Inbound,
		Dropped:  b.stats.Dropped,
		Mappings: len(b.mappings),
	}
}

func (b *Box) closeConn(c *net.UDPConn) error {
	if c != nil {
		return c.Close()
	}
	return nil
}

// serveOutbound reads envelopes on the door and forwards them from the
// appropriate public socket.
func (b *Box) serveOutbound(ctx context.Context) {
	buf := make([]byte, runBufferSize)
	for {
		n, src, err := b.doorConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			b.incDropped()
			continue
		}
		b.handleOutbound(buf[:n], src)
	}
}

func (b *Box) serveInboundFixed(ctx context.Context) {
	buf := make([]byte, runBufferSize)
	for {
		n, src, err := b.fixedConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			b.incDropped()
			continue
		}
		b.handleInbound(b.fixedConn, buf[:n], src)
	}
}

// handleOutbound is invoked for datagrams arriving on the inside door. Only
// datagrams sourced from the configured private host are accepted; the
// envelope's destination address is parsed and the inner frame is forwarded
// from the public socket assigned to that flow.
func (b *Box) handleOutbound(pkt []byte, src *net.UDPAddr) {
	if addrKey(src) != b.privateHostKey {
		b.incDropped()
		return
	}
	_, dst, inner, err := UnwrapOutbound(pkt)
	if err != nil {
		b.incDropped()
		return
	}
	conn, err := b.outboundSocket(dst)
	if err != nil {
		b.incDropped()
		return
	}
	if _, err := conn.WriteToUDP(inner, dst); err != nil {
		b.incDropped()
		return
	}
	b.incOutbound()
}

// outboundSocket returns the socket to write an outbound flow through,
// creating/refreshing the mapping as needed.
func (b *Box) outboundSocket(dst *net.UDPAddr) (*net.UDPConn, error) {
	b.mu.Lock()
	now := time.Now()
	key := mappingKey{}
	if b.cfg.Behavior == BehaviorSymmetric {
		key = mappingKey{dstIP: ipKey(dst.IP), dstPort: dst.Port}
	}
	e := b.mappings[key]
	if e != nil && b.cfg.MappingTTL > 0 && now.Sub(e.lastSeen) > b.cfg.MappingTTL {
		// Expired: reclaim the socket and start fresh.
		b.reclaimLocked(key, e)
		e = nil
	}
	if e != nil {
		e.lastSeen = now
		// Address-restricted boxes whitelist every IP the private host has
		// contacted, not just the first one (a mapping refresh is not a new
		// mapping, but the host may be contacting a new destination).
		if b.cfg.Behavior == BehaviorAddressRestricted {
			e.contactIP[ipKey(dst.IP)] = true
		}
	} else {
		e = &mappingEntry{dstIP: key.dstIP, dstPort: key.dstPort, contactIP: nil, lastSeen: now}
		if b.cfg.Behavior != BehaviorSymmetric {
			e.pubConn = b.fixedConn
			e.pubPort = b.fixedPort()
			if b.cfg.Behavior == BehaviorAddressRestricted {
				e.contactIP = map[string]bool{ipKey(dst.IP): true}
			}
		} else {
			// Allocate a fresh ephemeral public socket for this destination.
			if b.closed {
				b.mu.Unlock()
				return nil, errors.New("nat: box is closed")
			}
			pubAddr := &net.UDPAddr{IP: cloneIP(b.cfg.PublicAddr.IP), Port: 0}
			pub, err := net.ListenPacket("udp", pubAddr.String())
			if err != nil {
				b.mu.Unlock()
				return nil, fmt.Errorf("nat: allocate symmetric mapping socket: %w", err)
			}
			pc, ok := pub.(*net.UDPConn)
			if !ok {
				_ = pub.Close()
				b.mu.Unlock()
				return nil, errors.New("nat: ListenPacket did not return *net.UDPConn")
			}
			e.pubConn = pc
			e.pubPort = pc.LocalAddr().(*net.UDPAddr).Port
			e.dstIP = key.dstIP
			e.dstPort = key.dstPort
			// This mapping's socket only ever talks to its own destination, so
			// it doubles as a restricted-style contact filter.
			e.contactIP = map[string]bool{ipKey(dst.IP): true}
			// Start an inbound reader for this socket.
			b.wg.Add(1)
			go func(conn *net.UDPConn) {
				defer b.wg.Done()
				b.serveInboundSymmetric(conn, key)
			}(pc)
		}
		b.mappings[key] = e
	}
	conn := e.pubConn
	b.mu.Unlock()
	if conn == nil {
		return nil, errors.New("nat: no public socket for mapping")
	}
	return conn, nil
}

func (b *Box) fixedPort() int {
	return b.fixedConn.LocalAddr().(*net.UDPAddr).Port
}

// serveInboundSymmetric reads datagrams on a symmetric mapping's dedicated
// socket and delivers them only when the source exactly matches the mapped
// destination.
func (b *Box) serveInboundSymmetric(conn *net.UDPConn, key mappingKey) {
	buf := make([]byte, runBufferSize)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			b.incDropped()
			continue
		}
		b.handleInbound(conn, buf[:n], src)
	}
}

// handleInbound decides whether an inbound packet is admitted under the
// configured behavior and, if so, delivers it to the private host wrapped in
// an inbound envelope carrying the true external source address.
func (b *Box) handleInbound(sock *net.UDPConn, pkt []byte, src *net.UDPAddr) {
	if !b.lookupInbound(sock, src) {
		b.incDropped()
		return
	}
	env := WrapInbound(src, pkt)
	if _, err := sock.WriteToUDP(env, b.cfg.PrivateHost); err != nil {
		b.incDropped()
		return
	}
	b.incInbound()
}

// lookupInbound decides whether an inbound packet from src on socket sock is
// admitted under the configured behavior.
func (b *Box) lookupInbound(sock *net.UDPConn, src *net.UDPAddr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()

	if b.cfg.Behavior == BehaviorSymmetric {
		// Find the mapping owning this socket; deliver only on exact match.
		for _, e := range b.mappings {
			if e.pubConn == sock {
				if e.lastSeenExpired(now, b.cfg.MappingTTL) {
					return false
				}
				return e.dstIP == ipKey(src.IP) && e.dstPort == src.Port
			}
		}
		return false
	}

	e := b.mappings[mappingKey{}]
	if e == nil || e.lastSeenExpired(now, b.cfg.MappingTTL) {
		return false
	}
	switch b.cfg.Behavior {
	case BehaviorAddressRestricted:
		return e.contactIP[ipKey(src.IP)]
	default: // BehaviorFullCone
		return true
	}
}

func (e *mappingEntry) lastSeenExpired(now time.Time, ttl time.Duration) bool {
	return ttl > 0 && now.Sub(e.lastSeen) > ttl
}

// reclaimLocked closes an expired mapping's socket and removes it.
func (b *Box) reclaimLocked(key mappingKey, e *mappingEntry) {
	if e.pubConn != nil && e.pubConn != b.fixedConn {
		_ = e.pubConn.Close()
	}
	delete(b.mappings, key)
}

// cleanup reaps expired mappings and their sockets.
func (b *Box) cleanup() {
	if b.cfg.MappingTTL <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, e := range b.mappings {
		if e.lastSeenExpired(now, b.cfg.MappingTTL) {
			b.reclaimLocked(k, e)
		}
	}
}

func (b *Box) incOutbound() {
	b.mu.Lock()
	b.stats.Outbound++
	b.mu.Unlock()
}

func (b *Box) incInbound() {
	b.mu.Lock()
	b.stats.Inbound++
	b.mu.Unlock()
}

func (b *Box) incDropped() {
	b.mu.Lock()
	b.stats.Dropped++
	b.mu.Unlock()
}

// WrapOutbound encodes a datagram for the inside door:
// [magic 0x52][u16 src_len][src][u16 dst_len][dst][inner frame].
func WrapOutbound(srcID string, dst *net.UDPAddr, frame []byte) ([]byte, error) {
	if srcID == "" {
		return nil, errors.New("nat: empty source name in outbound envelope")
	}
	if len(srcID) > maxEnvelopeName {
		return nil, fmt.Errorf("nat: source name too long (%d bytes)", len(srcID))
	}
	if dst == nil || dst.IP == nil {
		return nil, errors.New("nat: nil destination in outbound envelope")
	}
	dstStr := dst.String()
	if len(dstStr) > maxEnvelopeName {
		return nil, fmt.Errorf("nat: destination address too long (%d bytes)", len(dstStr))
	}
	out := make([]byte, 0, 1+2+len(srcID)+2+len(dstStr)+len(frame))
	out = append(out, outboundMagic)
	out = appendU16(out, uint16(len(srcID)))
	out = append(out, srcID...)
	out = appendU16(out, uint16(len(dstStr)))
	out = append(out, dstStr...)
	out = append(out, frame...)
	return out, nil
}

// UnwrapOutbound decodes a door envelope and returns the source name, the
// destination address and the inner frame.
func UnwrapOutbound(pkt []byte) (srcID string, dst *net.UDPAddr, frame []byte, err error) {
	if len(pkt) < 1+2+1+2+1 {
		return "", nil, nil, errors.New("nat: outbound envelope too short")
	}
	if pkt[0] != outboundMagic {
		return "", nil, nil, fmt.Errorf("nat: bad outbound envelope magic 0x%02x", pkt[0])
	}
	p := pkt[1:]
	srcLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if srcLen == 0 {
		return "", nil, nil, errors.New("nat: empty source name in outbound envelope")
	}
	if srcLen > maxEnvelopeName {
		return "", nil, nil, fmt.Errorf("nat: source name too long (%d bytes)", srcLen)
	}
	if len(p) < srcLen+2 {
		return "", nil, nil, errors.New("nat: truncated source name in outbound envelope")
	}
	srcID = string(p[:srcLen])
	p = p[srcLen:]
	dstLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if dstLen == 0 {
		return "", nil, nil, errors.New("nat: empty destination address in outbound envelope")
	}
	if dstLen > maxEnvelopeName {
		return "", nil, nil, fmt.Errorf("nat: destination address too long (%d bytes)", dstLen)
	}
	if len(p) < dstLen {
		return "", nil, nil, errors.New("nat: truncated destination address in outbound envelope")
	}
	dstStr := string(p[:dstLen])
	dst, err = net.ResolveUDPAddr("udp", dstStr)
	if err != nil {
		return "", nil, nil, fmt.Errorf("nat: invalid destination %q: %w", dstStr, err)
	}
	return srcID, dst, p[dstLen:], nil
}

// WrapInbound encodes a datagram delivered to the private host:
// [magic 0x53][u16 external src addr len][external src addr][payload]. The
// private host uses the external source to route the datagram to its peer.
func WrapInbound(src *net.UDPAddr, payload []byte) []byte {
	s := src.String()
	out := make([]byte, 0, 1+2+len(s)+len(payload))
	out = append(out, inboundMagic)
	out = appendU16(out, uint16(len(s)))
	out = append(out, s...)
	out = append(out, payload...)
	return out
}

// UnwrapInbound decodes a box delivery envelope and returns the external
// source address and the inner payload.
func UnwrapInbound(pkt []byte) (src *net.UDPAddr, payload []byte, err error) {
	if len(pkt) < 1+2+1 {
		return nil, nil, errors.New("nat: inbound envelope too short")
	}
	if pkt[0] != inboundMagic {
		return nil, nil, fmt.Errorf("nat: bad inbound envelope magic 0x%02x", pkt[0])
	}
	srcLen := int(binary.BigEndian.Uint16(pkt[1:3]))
	if srcLen == 0 {
		return nil, nil, errors.New("nat: empty source address in inbound envelope")
	}
	if srcLen > maxEnvelopeName {
		return nil, nil, fmt.Errorf("nat: source address too long (%d bytes)", srcLen)
	}
	p := pkt[3:]
	if len(p) < srcLen {
		return nil, nil, errors.New("nat: truncated source address in inbound envelope")
	}
	as, err := net.ResolveUDPAddr("udp", string(p[:srcLen]))
	if err != nil {
		return nil, nil, fmt.Errorf("nat: invalid inbound source %q: %w", p[:srcLen], err)
	}
	return as, p[srcLen:], nil
}

// appendU16 appends v to out as two big-endian bytes.
func appendU16(out []byte, v uint16) []byte {
	return append(out, byte(v>>8), byte(v))
}

func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	ip := cloneIP(a.IP)
	return &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone}
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func addrKey(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return net.JoinHostPort(ipKey(a.IP), strconv.Itoa(a.Port))
}

func ipKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.String()
	}
	return ""
}
