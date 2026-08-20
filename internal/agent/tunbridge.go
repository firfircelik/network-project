package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"meshlink/internal/tun"
)

// tunBridge wires a TUN device to the encrypted peer sessions (Faz 4 / G6):
// IP packets read from the device are routed to the peer whose overlay address
// is their destination (and encrypted by that peer's session), while
// decrypted payloads arriving from peers are written to the device. The
// bridge is optional — the ping/pong demo and core tests run without it.
type tunBridge struct {
	log    *slog.Logger
	dev    tun.Device
	router *tun.Router

	ipByPeer map[string]netip.Addr // configured peer overlay addresses
}

// newTunBridge opens the configured TUN device (requires root) and preloads
// the configured overlay address assignments. A nil result is returned when
// tuning is disabled.
func newTunBridge(log *slog.Logger, cfg Config) (*tunBridge, error) {
	if cfg.TunName == "" {
		return nil, nil
	}
	dev, err := tun.Open(cfg.TunName, cfg.TunMTU)
	if err != nil {
		return nil, fmt.Errorf("open tun: %w", err)
	}
	if cfg.TunIP != "" {
		if _, perr := netip.ParseAddr(cfg.TunIP); perr != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("tun-ip %q: %w", cfg.TunIP, perr)
		}
	}
	b := &tunBridge{
		log:      log,
		dev:      dev,
		router:   tun.NewRouter(),
		ipByPeer: make(map[string]netip.Addr),
	}
	for id, ip := range cfg.TunPeers {
		a, perr := netip.ParseAddr(ip)
		if perr != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("tun-peer %s=%s: %w", id, ip, perr)
		}
		b.ipByPeer[id] = a
	}
	return b, nil
}

// setPeerSink attaches (or, with a nil sink, detaches) a peer's send path so
// outbound traffic for its overlay address is encrypted through it. Peers
// without a configured overlay address are never routed.
func (b *tunBridge) setPeerSink(id string, s tun.Sink) {
	b.router.SetRoute(b.ipByPeer[id], s)
}

// run pumps IP packets from the device into the peer sessions until ctx is
// canceled or the device fails.
func (b *tunBridge) run(ctx context.Context) error {
	defer b.dev.Close()
	buf := make([]byte, b.dev.MTU()+64)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tun read: %w", err)
		}
		if n == 0 {
			continue
		}
		b.router.RoutePacket(buf[:n])
	}
}

// inbound writes one decrypted peer payload (a plain IP packet) to the device.
func (b *tunBridge) inbound(payload []byte) error {
	// Never hand the kernel a packet larger than the device MTU; oversized
	// frames would be silently truncated on write.
	if len(payload) > b.dev.MTU() {
		return fmt.Errorf("tun write: %d bytes exceeds device MTU %d", len(payload), b.dev.MTU())
	}
	if _, err := b.dev.Write(payload); err != nil {
		return fmt.Errorf("tun write: %w", err)
	}
	return nil
}

// Close shuts the device down (idempotent).
func (b *tunBridge) Close() error {
	if b == nil || b.dev == nil {
		return nil
	}
	return b.dev.Close()
}
