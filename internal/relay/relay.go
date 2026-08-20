// Package relay implements the meshlink UDP relay server. It demultiplexes
// datagrams wrapped with the RELAY header
// [magic 0x52][u16 src_len][src][u16 dst_len][dst][frame], maps the sender's
// address to its peer name, and forwards the inner frame bytes to the named
// destination's most recent address, without inspecting (encrypted) content.
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Magic is the leading byte of every relayed packet (data-plane type RELAY).
const Magic byte = 0x52

// MaxNameLen is the maximum length in bytes of a relay peer name.
const MaxNameLen = 64

// MaxHeaderLen is the largest relay framing overhead added on top of an inner
// frame: [magic][u16 src_len][src][u16 dst_len][dst] with worst-case names.
const MaxHeaderLen = 1 + 2 + MaxNameLen + 2 + MaxNameLen

// Errors returned by WrapPacket and ParsePacket for malformed input.
var (
	ErrEmptyName   = errors.New("relay: peer name is empty")
	ErrNameTooLong = errors.New("relay: peer name exceeds MaxNameLen")
	ErrShortPacket = errors.New("relay: packet too short")
	ErrBadMagic    = errors.New("relay: invalid magic byte")
	ErrTruncated   = errors.New("relay: truncated packet")
)

// Config configures a relay Server.
type Config struct {
	Addr *net.UDPAddr // listen address; port 0 is allowed and Addr() reports the actual port

	// PinGrace is how long a name's endpoint stays pinned to the first address
	// that claimed it. While a pin is fresh, packets for that name from a
	// different address are dropped (name-hijack / misdirection prevention).
	// After it lapses the name may legitimately rebind, e.g. after a NAT remap
	// or an agent restart. Defaults to 30 seconds.
	PinGrace time.Duration

	// MaxPPS caps inbound datagrams per second per source address and
	// MaxBytesPS caps the payload bytes those datagrams may carry. Together
	// they bound how much one source can make the relay work, shrinking the
	// amplification surface. Zero caps default to 300 pps and 128 KiB/s;
	// a negative value disables that budget.
	MaxPPS     int
	MaxBytesPS int

	// NameQuotaBytes caps the bytes the relay forwards to a single destination
	// name per second so one name cannot balloon outgoing bandwidth
	// (anti-flood). Defaults to 256 KiB/s; a negative value disables it.
	NameQuotaBytes int

	// GlobalMaxPPS caps inbound datagrams per second across ALL sources and
	// GlobalMaxBytesPS caps their payload bytes. Per-source budgets cannot
	// bound a flood of many distinct (spoofed) sources, so these bound the
	// total work a relay performs. Zero caps default to 5000 pps and 8 MiB/s;
	// a negative value disables the respective budget.
	GlobalMaxPPS     int
	GlobalMaxBytesPS int
}

// fillDefaults installs the production-safe budgets where a zero value was
// configured.
func (c *Config) fillDefaults() {
	if c.PinGrace == 0 {
		c.PinGrace = 30 * time.Second
	}
	if c.MaxPPS == 0 {
		c.MaxPPS = 300
	}
	if c.MaxBytesPS == 0 {
		c.MaxBytesPS = 128 << 10
	}
	if c.NameQuotaBytes == 0 {
		c.NameQuotaBytes = 256 << 10
	}
	if c.GlobalMaxPPS == 0 {
		c.GlobalMaxPPS = 5000
	}
	if c.GlobalMaxBytesPS == 0 {
		c.GlobalMaxBytesPS = 8 << 20
	}
}

// pin is a name's endpoint binding. The address may only be replaced once the
// binding has been idle for PinGrace.
type pin struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

// counter is a one-second windowed tally used for rate budgets.
type counter struct {
	start time.Time
	count int
}

// Server is a relay server.
type Server struct {
	conn        *net.UDPConn
	cfg         Config
	mu          sync.Mutex
	pins        map[string]*pin     // name -> pinned endpoint (G2)
	srcRate     map[string]*counter // per-source datagram budget
	srcBytes    map[string]*counter // per-source byte budget
	nameBytes   map[string]*counter // per-destination-name byte quota
	globalRate  counter             // across-all-sources datagram budget
	globalBytes counter             // across-all-sources byte budget
	lastSweep   time.Time
	stats       Stats
	closeOnce   sync.Once
	closeCh     chan struct{}
}

// Stats reports relay activity counters.
type Stats struct {
	Wrapped       uint64 // valid wrapped packets received
	Forwarded     uint64 // packets delivered to a destination peer
	Dropped       uint64 // malformed packets and packets addressed to unknown peers
	PinnedDropped uint64 // packets rejected because the source name is pinned elsewhere (G2)
	RateLimited   uint64 // packets rejected by a rate/quota budget (G4)
}

// New binds the UDP listener and returns a ready Server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == nil {
		return nil, errors.New("relay: Addr is required")
	}
	cfg.fillDefaults()
	pc, err := net.ListenPacket("udp", cfg.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("relay: bind %s: %w", cfg.Addr, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("relay: ListenPacket did not return a *net.UDPConn")
	}
	return &Server{
		conn:      conn,
		cfg:       cfg,
		pins:      make(map[string]*pin),
		srcRate:   make(map[string]*counter),
		srcBytes:  make(map[string]*counter),
		nameBytes: make(map[string]*counter),
		closeCh:   make(chan struct{}),
	}, nil
}

// WrapPacket builds a relay packet:
// [0x52][u16 src_len][src][u16 dst_len][dst][frame].
func WrapPacket(srcID, dstID string, frame []byte) ([]byte, error) {
	if err := validateName(srcID); err != nil {
		return nil, err
	}
	if err := validateName(dstID); err != nil {
		return nil, err
	}
	pkt := make([]byte, 0, 1+2+len(srcID)+2+len(dstID)+len(frame))
	pkt = append(pkt, Magic)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(srcID)))
	pkt = append(pkt, srcID...)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(dstID)))
	pkt = append(pkt, dstID...)
	pkt = append(pkt, frame...)
	return pkt, nil
}

// ParsePacket decodes a relay packet into its source name, destination name
// and inner frame bytes. It errors on a bad magic byte, a truncated packet,
// empty names or names exceeding MaxNameLen.
func ParsePacket(pkt []byte) (srcID, dstID string, frame []byte, err error) {
	if len(pkt) < 1+2+1+2+1 {
		return "", "", nil, ErrShortPacket
	}
	if pkt[0] != Magic {
		return "", "", nil, fmt.Errorf("%w: 0x%02x", ErrBadMagic, pkt[0])
	}
	p := pkt[1:]
	srcLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if srcLen == 0 {
		return "", "", nil, ErrEmptyName
	}
	if srcLen > MaxNameLen {
		return "", "", nil, fmt.Errorf("%w: source name is %d bytes", ErrNameTooLong, srcLen)
	}
	if len(p) < srcLen+2 {
		return "", "", nil, fmt.Errorf("%w: source name", ErrTruncated)
	}
	srcID = string(p[:srcLen])
	p = p[srcLen:]

	dstLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if dstLen == 0 {
		return "", "", nil, ErrEmptyName
	}
	if dstLen > MaxNameLen {
		return "", "", nil, fmt.Errorf("%w: destination name is %d bytes", ErrNameTooLong, dstLen)
	}
	if len(p) < dstLen {
		return "", "", nil, fmt.Errorf("%w: destination name", ErrTruncated)
	}
	dstID = string(p[:dstLen])
	return srcID, dstID, p[dstLen:], nil
}

// Run serves the relay socket until ctx is canceled or Close is called, then
// returns nil.
func (s *Server) Run(ctx context.Context) error {
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closeCh:
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			s.incDropped()
			continue
		}
		s.handlePacket(buf[:n], src)
	}
}

// Close closes the relay socket. Subsequent calls are no-ops.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closeCh)
		if s.conn != nil {
			err = s.conn.Close()
		}
	})
	return err
}

// Addr returns the actual bound address of the relay socket (identical to
// cfg.Addr when the configured port is non-zero).
func (s *Server) Addr() *net.UDPAddr {
	if s.conn == nil {
		return nil
	}
	addr := s.conn.LocalAddr().(*net.UDPAddr)
	return cloneAddr(addr)
}

// Stats returns a snapshot of the relay counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// handlePacket pins the sender under its source name, applies the per-source
// rate budgets, and forwards the inner frame to the destination peer if it is
// known and within its quota. The forwarded datagram is re-wrapped with the
// same relay header so the recipient can demultiplex by source name over a
// single shared relay socket.
func (s *Server) handlePacket(pkt []byte, src *net.UDPAddr) {
	srcID, dstID, frame, err := ParsePacket(pkt)
	if err != nil {
		s.incDropped()
		return
	}
	now := time.Now()
	addr := cloneAddr(src)

	// Pinning, rate budgets and the destination lookup all mutate shared
	// maps, so they run under one lock; the socket write happens after it is
	// released.
	s.mu.Lock()
	// Age out stale entries on EVERY path (drops included): if the sweep only
	// ran on the forwarding path, a flood of dropped packets would still grow
	// the pins/srcRate maps unboundedly.
	s.maybeSweep(now)
	// Bound total relay work across all sources before any per-source logic.
	if !takeGlobal(&s.globalRate, 1, s.cfg.GlobalMaxPPS, now) ||
		!takeGlobal(&s.globalBytes, len(pkt), s.cfg.GlobalMaxBytesPS, now) {
		s.stats.RateLimited++
		s.mu.Unlock()
		return
	}
	if p := s.pins[srcID]; p != nil {
		if addrEqual(p.addr, addr) {
			p.lastSeen = now
		} else if now.Sub(p.lastSeen) > s.cfg.PinGrace {
			// The pin lapsed: a legitimate rebind (NAT remap, restart).
			p.addr = addr
			p.lastSeen = now
		} else {
			// The name is pinned to a different, still-fresh address: this is
			// a hijack attempt, drop it.
			s.stats.PinnedDropped++
			s.mu.Unlock()
			return
		}
	} else {
		s.pins[srcID] = &pin{addr: addr, lastSeen: now}
	}

	srcKey := addr.String()
	if !s.take(&s.srcRate, srcKey, 1, s.cfg.MaxPPS, now) ||
		!s.take(&s.srcBytes, srcKey, len(pkt), s.cfg.MaxBytesPS, now) {
		s.stats.RateLimited++
		s.mu.Unlock()
		return
	}

	s.stats.Wrapped++
	dst, ok := s.pins[dstID]
	if !ok {
		s.stats.Dropped++
		s.mu.Unlock()
		return
	}
	if !s.take(&s.nameBytes, dstID, len(frame), s.cfg.NameQuotaBytes, now) {
		s.stats.RateLimited++
		s.mu.Unlock()
		return
	}
	dstAddr := cloneAddr(dst.addr)
	s.mu.Unlock()

	fwd, err := WrapPacket(srcID, dstID, frame)
	if err != nil {
		s.incDropped()
		return
	}
	if _, err := s.conn.WriteToUDP(fwd, dstAddr); err != nil {
		s.incDropped()
		return
	}
	s.incForwarded()
}

// take draws amount from a windowed per-key budget, resetting the counter's
// window when it expires. A cap <= 0 disables the budget. Returns false when
// the budget is exhausted.
func (s *Server) take(m *map[string]*counter, key string, amount, cap int, now time.Time) bool {
	if cap <= 0 {
		return true
	}
	c := (*m)[key]
	if c == nil || now.Sub(c.start) >= time.Second {
		// Fresh window: bank only the effective cost so a single oversized
		// (and rejected) datagram does not pre-charge the whole next second
		// beyond the cap itself.
		eff := amount
		if eff > cap {
			eff = cap
		}
		(*m)[key] = &counter{start: now, count: eff}
		return amount <= cap
	}
	if c.count+amount > cap {
		return false
	}
	c.count += amount
	return true
}

// takeGlobal draws amount from a single budget shared by every source (unlike
// take, the counter lives in the Server, not in a per-key map). cap <= 0
// disables the budget.
func takeGlobal(c *counter, amount, cap int, now time.Time) bool {
	if cap <= 0 {
		return true
	}
	if now.Sub(c.start) >= time.Second {
		eff := amount
		if eff > cap {
			eff = cap
		}
		c.start = now
		c.count = eff
		return amount <= cap
	}
	if c.count+amount > cap {
		return false
	}
	c.count += amount
	return true
}

// maybeSweep prunes stale rate counters and long-idle pins once the maps grow
// past a threshold, keeping the state size bounded by active senders, not by
// spoofed source addresses.
func (s *Server) maybeSweep(now time.Time) {
	if len(s.srcRate)+len(s.srcBytes)+len(s.nameBytes)+len(s.pins) <= 4096 {
		return
	}
	if now.Sub(s.lastSweep) < time.Second {
		return
	}
	s.lastSweep = now
	for k, c := range s.srcRate {
		if now.Sub(c.start) > 2*time.Second {
			delete(s.srcRate, k)
		}
	}
	for k, c := range s.srcBytes {
		if now.Sub(c.start) > 2*time.Second {
			delete(s.srcBytes, k)
		}
	}
	for k, c := range s.nameBytes {
		if now.Sub(c.start) > 2*time.Second {
			delete(s.nameBytes, k)
		}
	}
	for k, p := range s.pins {
		if now.Sub(p.lastSeen) > 2*s.cfg.PinGrace {
			delete(s.pins, k)
		}
	}
}

// addrEqual reports whether two UDP endpoints are identical.
func addrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Port != b.Port || !a.IP.Equal(b.IP) {
		return false
	}
	return a.Zone == b.Zone
}

func (s *Server) incForwarded() {
	s.mu.Lock()
	s.stats.Forwarded++
	s.mu.Unlock()
}

func (s *Server) incDropped() {
	s.mu.Lock()
	s.stats.Dropped++
	s.mu.Unlock()
}

func validateName(id string) error {
	if id == "" {
		return errors.New("relay: peer name is empty")
	}
	if len(id) > MaxNameLen {
		return fmt.Errorf("relay: peer name too long: %d > %d bytes", len(id), MaxNameLen)
	}
	return nil
}

func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	ip := make(net.IP, len(a.IP))
	copy(ip, a.IP)
	return &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone}
}
