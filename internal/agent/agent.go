// Package agent implements the meshlink client: key management, registration
// with the coordinator, STUN discovery, the data-plane receive loop and the
// ping/pong liveness check used to demonstrate the encrypted tunnel.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"meshlink/internal/control"
	"meshlink/internal/nat"
	"meshlink/internal/noisework"
	"meshlink/internal/peer"
	"meshlink/internal/protocol"
	"meshlink/internal/relay"
	"meshlink/internal/stun"
)

// Config configures an Agent.
type Config struct {
	Name        string
	Keyfile     string
	Coordinator string    // TCP host:port of the control plane
	CoordKey    string    // hex public key of the coordinator (control-plane pin)
	StunAddr    string    // UDP host:port of the STUN endpoint (coordinator)
	RelayAddr   string    // UDP host:port of the relay server ("" = disabled)
	DataAddr    string    // local UDP bind address for the data plane
	NatDoor     string    // optional: the local natbox "inside door" to egress through
	LogWriter   io.Writer // where slog output goes (defaults to os.Stdout)

	TunName  string            // TUN device to open (requires root; "" = disabled)
	TunMTU   int               // TUN MTU (default 1500 when enabled)
	TunIP    string            // IPv4 assigned to this agent on the overlay
	TunPeers map[string]string // peerID -> overlay IPv4 to route outbound traffic through
}

// Agent is a meshlink client instance.
type Agent struct {
	cfg   Config
	log   *slog.Logger
	kp    *noisework.Keypair
	conn  *net.UDPConn
	door  *net.UDPAddr
	relay *net.UDPAddr
	pub   *net.UDPAddr // STUN-learned public endpoint

	ctrl       net.Conn
	ctrlConn   *control.Conn
	ctrlCancel context.CancelFunc
	ctrlMu     sync.Mutex // guards ctrl/ctrlConn/ctrlCancel (re-register vs reader loop)

	mu         sync.Mutex
	peers      map[string]*peer.Peer
	peerCancel map[string]context.CancelFunc
	baseCtx    context.Context // agent-wide context peers are derived from

	bridge *tunBridge // optional: TUN device bridge (Faz 4)

	pingMu    sync.Mutex
	pingOut   map[uint64]chan time.Time
	closeOnce sync.Once

	rttMu   sync.Mutex
	lastRTT map[string]time.Duration
	rttHist map[string][]time.Duration // most recent first, capped at rttHistoryDepth

	queryCh chan *protocol.Message // TypeQueryResult deliveries from ctrlReaderLoop
}

// rttHistoryDepth bounds the per-peer RTT history kept for dashboards.
const rttHistoryDepth = 5

// New loads (or creates) the keypair and prepares the data socket.
func New(cfg Config) (*Agent, error) {
	kp, err := noisework.LoadOrCreateKeyfile(cfg.Keyfile)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenPacket("udp", cfg.DataAddr)
	if err != nil {
		return nil, fmt.Errorf("bind data socket: %w", err)
	}
	writer := cfg.LogWriter
	if writer == nil {
		writer = os.Stdout
	}
	a := &Agent{
		cfg:        cfg,
		log:        slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})).With("name", cfg.Name),
		kp:         kp,
		conn:       conn.(*net.UDPConn),
		peers:      make(map[string]*peer.Peer),
		peerCancel: make(map[string]context.CancelFunc),
		pingOut:    make(map[uint64]chan time.Time),
		lastRTT:    make(map[string]time.Duration),
		rttHist:    make(map[string][]time.Duration),
		queryCh:    make(chan *protocol.Message, 1),
	}
	if cfg.NatDoor != "" {
		a.door, err = net.ResolveUDPAddr("udp", cfg.NatDoor)
		if err != nil {
			return nil, fmt.Errorf("resolve nat door: %w", err)
		}
	}
	if cfg.RelayAddr != "" {
		a.relay, err = net.ResolveUDPAddr("udp", cfg.RelayAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve relay: %w", err)
		}
	}
	return a, nil
}

// PublicKey returns the agent's public key as hex (for logs/debug).
func (a *Agent) PublicKey() string { return a.kp.PublicHex() }

// Start performs the one-time setup (STUN discovery, coordinator registration
// and the data-plane receive loop). It is a prerequisite of Ping; Run calls it
// internally too.
func (a *Agent) Start(ctx context.Context) error { return a.setup(ctx) }

func (a *Agent) localAddr() *net.UDPAddr {
	return a.conn.LocalAddr().(*net.UDPAddr)
}

// sendDatagram emits a datagram to dst, egressing through the NAT door when
// configured (the datagram is wrapped for the natbox inside door).
func (a *Agent) sendDatagram(dst *net.UDPAddr, pkt []byte) error {
	if a.door != nil {
		wrapped, err := nat.WrapOutbound(a.cfg.Name, dst, pkt)
		if err != nil {
			return err
		}
		pkt = wrapped
		dst = a.door
	}
	_, err := a.conn.WriteToUDP(pkt, dst)
	return err
}

// resolvePublicEndpoint performs a STUN binding request on the data socket so
// the learned public endpoint maps to the same socket used for punching.
func (a *Agent) resolvePublicEndpoint(ctx context.Context) (*net.UDPAddr, error) {
	stunAddr, err := net.ResolveUDPAddr("udp", a.cfg.StunAddr)
	if err != nil {
		return nil, err
	}
	txid := stun.NewTransactionID()
	req := stun.EncodeBindingRequest(txid)
	if err := a.sendDatagram(stunAddr, req); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(3 * time.Second)
	_ = a.conn.SetReadDeadline(deadline)
	defer a.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 1500)
	for {
		n, _, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("stun: %w", err)
		}
		if a.door != nil {
			_, payload, err := nat.UnwrapInbound(buf[:n])
			if err != nil {
				continue
			}
			copy(buf, payload)
			n = len(payload)
		}
		if n < 20 || buf[0] != 0x01 || buf[1] != 0x01 {
			continue
		}
		// Ensure the response belongs to our transaction.
		if !txidMatches(buf[8:20], txid) {
			continue
		}
		return stun.DecodeXORMappedAddress(buf[:n])
	}
}

func txidMatches(b []byte, txid [12]byte) bool {
	for i := range txid {
		if b[i] != txid[i] {
			return false
		}
	}
	return true
}

// register connects to the coordinator, authenticates it over a Noise control
// session and registers this agent. It returns the initial peer list, then
// streams subsequent peer_list updates to wait.
func (a *Agent) register(ctx context.Context) error {
	coordPub, err := noisework.ParsePublicKeyHex(a.cfg.CoordKey)
	if err != nil {
		return fmt.Errorf("invalid coordinator public key: %w", err)
	}
	a.ctrlMu.Lock()
	if a.ctrl != nil {
		a.ctrl.Close()
		if a.ctrlCancel != nil {
			a.ctrlCancel()
		}
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", a.cfg.Coordinator)
	if err != nil {
		a.ctrlMu.Unlock()
		return fmt.Errorf("dial coordinator: %w", err)
	}
	a.ctrl = conn
	cctx, cancel := context.WithCancel(ctx)
	a.ctrlCancel = cancel

	ctrl, err := control.Initiate(conn, a.kp, coordPub)
	if err != nil {
		a.ctrlCancel = nil
		a.ctrl = nil
		a.ctrlMu.Unlock()
		conn.Close()
		return fmt.Errorf("control handshake: %w", err)
	}
	a.ctrlConn = ctrl
	a.ctrlMu.Unlock()

	msg := protocol.Message{
		Type:      protocol.TypeRegister,
		ID:        a.cfg.Name,
		PubKey:    a.kp.PublicHex(),
		Endpoints: a.publicEndpoints(),
	}
	line, err := protocol.EncodeLine(msg)
	if err != nil {
		return err
	}
	if err := ctrl.WriteMsg(line); err != nil {
		return err
	}
	go a.ctrlReaderLoop(cctx, ctrl)
	return nil
}

func (a *Agent) publicEndpoints() []string {
	eps := []string{a.pub.String()}
	if a.relay != nil {
		eps = append(eps, a.relay.String())
	}
	return eps
}

func (a *Agent) ctrlReaderLoop(ctx context.Context, ctrl *control.Conn) {
	// Close the *local* control connection: on re-registration the caller
	// installs a brand-new connection, and closing the shared a.ctrl field
	// here would tear down the session that just replaced this one.
	defer ctrl.Close()
	for {
		plain, err := ctrl.ReadMsg()
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("control connection lost", "err", err)
			}
			return
		}
		msg, err := protocol.DecodeLine(plain)
		if err != nil || msg == nil {
			continue
		}
		switch msg.Type {
		case protocol.TypePeerList:
			a.applyPeers(msg.Peers)
		case protocol.TypeQueryResult:
			select {
			case a.queryCh <- msg:
			default: // no waiter: drop rather than block the control loop
			}
		case protocol.TypeError:
			a.log.Warn("coordinator error", "msg", msg.Msg)
		}
	}
}

// applyPeers adds newly discovered peers and prunes peers that disappeared.
// Re-registrations also refresh a known peer's direct endpoint so a NAT remap
// or restart is picked up without a new connection.
func (a *Agent) applyPeers(infos []protocol.PeerInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()

	seen := make(map[string]bool, len(infos))
	for _, info := range infos {
		if info.ID == a.cfg.Name {
			continue
		}
		seen[info.ID] = true
		var directEP *net.UDPAddr
		if len(info.Endpoints) > 0 {
			ep, err := net.ResolveUDPAddr("udp", info.Endpoints[0])
			if err != nil {
				a.log.Warn("bad peer endpoint", "peer", info.ID, "err", err)
			} else {
				directEP = ep
			}
		}
		if existing, ok := a.peers[info.ID]; ok {
			// The peer is already tracked: refresh its endpoint mapping and
			// carry on (the session survives across endpoint changes; the next
			// handshake will target the new address).
			if directEP != nil {
				existing.SetDirectEP(directEP)
			}
			continue
		}
		pub, err := noisework.ParsePublicKeyHex(info.PubKey)
		if err != nil {
			a.log.Warn("bad peer pubkey", "peer", info.ID, "err", err)
			continue
		}
		ctx, cancel := context.WithCancel(a.baseCtx)
		np := peer.New(a.cfg.Name, info.ID, pub, directEP, a.kp, a)
		a.peers[info.ID] = np
		a.peerCancel[info.ID] = cancel
		if a.bridge != nil {
			a.bridge.setPeerSink(info.ID, np)
		}
		go func(p *peer.Peer) {
			go a.peerMessageLoop(p)
			p.Run(ctx)
			cancel()
		}(np)
	}
	for id, p := range a.peers {
		if !seen[id] {
			if a.bridge != nil {
				a.bridge.setPeerSink(id, nil)
			}
			if cancel, ok := a.peerCancel[id]; ok {
				cancel()
				delete(a.peerCancel, id)
			}
			p.Close()
			delete(a.peers, id)
		}
	}
}

// peerMessageLoop handles decrypted payloads from a peer.
func (a *Agent) peerMessageLoop(p *peer.Peer) {
	for payload := range p.Recv() {
		a.handlePeerPayload(p, payload)
	}
}

// pingMsg is the JSON payload exchanged between peers for the liveness ping.
type pingMsg struct {
	Cmd string `json:"cmd"`
	S   uint64 `json:"s"`
	Ts  int64  `json:"ts"`
}

// decodePingMsg reports whether payload is a meshlink ping/pong JSON message.
func decodePingMsg(payload []byte) (*pingMsg, bool) {
	var m pingMsg
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, false
	}
	if m.Cmd != "ping" && m.Cmd != "pong" {
		return nil, false
	}
	return &m, true
}

func (a *Agent) handlePeerPayload(p *peer.Peer, payload []byte) {
	if len(payload) == 0 {
		return // keepalive
	}
	if a.bridge != nil {
		// TUN mode: payloads are plain IP packets unless they are the
		// diagnostic ping/pong messages (cheap first-byte check avoids a JSON
		// parse on every packet).
		if len(payload) > 0 && payload[0] == '{' {
			if m, ok := decodePingMsg(payload); ok {
				a.dispatchPing(p, m)
				return
			}
		}
		if err := a.bridge.inbound(payload); err != nil {
			a.log.Warn("tun write failed", "peer", p.ID, "bytes", len(payload), "err", err)
		}
		return
	}
	m, ok := decodePingMsg(payload)
	if !ok {
		a.log.Warn("undecodable peer payload", "peer", p.ID, "bytes", len(payload))
		return
	}
	a.dispatchPing(p, m)
}

func (a *Agent) dispatchPing(p *peer.Peer, m *pingMsg) {
	switch m.Cmd {
	case "ping":
		resp := pingMsg{Cmd: "pong", S: m.S, Ts: m.Ts}
		if err := p.SendJSON(resp); err != nil {
			a.log.Warn("pong send failed", "peer", p.ID, "err", err)
		}
	case "pong":
		a.pingMu.Lock()
		ch := a.pingOut[m.S]
		delete(a.pingOut, m.S)
		a.pingMu.Unlock()
		if ch != nil {
			select {
			case ch <- time.Now():
			default:
			}
		}
	}
}

// dropPing removes a pending ping's waiter so a timed-out or cancelled ping
// cannot leak pingOut entries in a long-running daemon.
func (a *Agent) dropPing(seq uint64) {
	a.pingMu.Lock()
	delete(a.pingOut, seq)
	a.pingMu.Unlock()
}

// PingResult summarises a ping run against a peer.
type PingResult struct {
	Peer        string
	Count       int
	Received    int
	AvgRTT      time.Duration
	Path        string
	Established bool
}

// Ping performs count ping/pong roundtrips against the named peer. The peer
// must be known via the peer list already.
func (a *Agent) Ping(ctx context.Context, target string, count int, interval time.Duration) (*PingResult, error) {
	if err := a.WaitPeers(ctx); err != nil {
		return nil, err
	}
	a.mu.Lock()
	p := a.peers[target]
	a.mu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("no such peer: %s", target)
	}
	if err := p.WaitEstablished(ctx); err != nil {
		return nil, err
	}

	res := &PingResult{Peer: target, Count: count, Established: true}
	var total time.Duration
pingLoop:
	for i := 0; i < count; i++ {
		seq := uint64(time.Now().UnixNano())
		ts := time.Now().UnixNano()
		deadline := time.Now().Add(2 * time.Second)
		if err := p.SendJSON(pingMsg{Cmd: "ping", S: seq, Ts: ts}); err != nil {
			a.log.Warn("ping send failed", "peer", target, "seq", i, "err", err)
		}

		done := make(chan time.Time, 1)
		a.pingMu.Lock()
		a.pingOut[seq] = done
		a.pingMu.Unlock()

		select {
		case <-ctx.Done():
			a.dropPing(seq)
			return res, ctx.Err()
		case got := <-done:
			rtt := got.Sub(time.Unix(0, ts))
			total += rtt
			res.Received++
			a.log.Info("ping result", "peer", target, "seq", i, "rtt", rtt, "path", p.Path())
		case <-time.After(time.Until(deadline)):
			// a lost ping: forget its waiter so the map cannot grow forever
			a.dropPing(seq)
			a.log.Warn("ping lost", "peer", target, "seq", i)
		}
		if interval > 0 && i+1 < count {
			select {
			case <-ctx.Done():
				break pingLoop
			case <-time.After(interval):
			}
		}
	}
	if res.Received > 0 {
		res.AvgRTT = total / time.Duration(res.Received)
	}
	// Report the *final* path: the session may have roamed relay->direct while
	// the ping was running.
	res.Path = p.Path().String()
	return res, nil
}

// WaitPeers blocks until at least one control update has arrived (needed
// before a ping target can exist).
func (a *Agent) WaitPeers(ctx context.Context) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		a.mu.Lock()
		known := len(a.peers)
		a.mu.Unlock()
		if known > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// attachBridge installs the TUN bridge and wires routes for already-known
// peers, so a peer_list that arrived before the device was opened is not lost.
func (a *Agent) attachBridge(b *tunBridge) {
	a.mu.Lock()
	a.bridge = b
	for id, p := range a.peers {
		b.setPeerSink(id, p)
	}
	a.mu.Unlock()
	a.log.Info("tun device open", "dev", b.dev.Name())
}

// Close releases every resource owned by the agent: the data socket, the
// control connection(s), the TUN bridge device and all peer goroutines. It is
// idempotent and safe to call from Run's shutdown path and from tests.
func (a *Agent) Close() {
	a.closeOnce.Do(func() {
		if a.conn != nil {
			a.conn.Close()
		}
		a.ctrlMu.Lock()
		if a.ctrlCancel != nil {
			a.ctrlCancel()
		}
		if a.ctrl != nil {
			a.ctrl.Close()
		}
		a.ctrlMu.Unlock()
		if a.bridge != nil {
			a.bridge.Close()
		}
		a.mu.Lock()
		for id, cancel := range a.peerCancel {
			cancel()
			delete(a.peerCancel, id)
		}
		for _, p := range a.peers {
			p.Close()
		}
		a.mu.Unlock()
	})
}

// Run starts the agent daemon: registration + data-plane receive loop and
// (when configured) the TUN bridge.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.setup(ctx); err != nil {
		return err
	}
	a.log.Info("public endpoint (STUN)", "addr", a.pub)
	a.log.Info("listening", "data", a.localAddr(), "relay", a.relay)

	if a.cfg.TunName != "" {
		b, err := newTunBridge(a.log, a.cfg)
		if err != nil {
			return fmt.Errorf("tun bridge: %w", err)
		}
		a.attachBridge(b)
		go func() {
			if err := b.run(ctx); err != nil && ctx.Err() == nil {
				a.log.Warn("tun bridge stopped", "err", err)
			}
		}()
	}

	// Re-register periodically to refresh endpoint mappings.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.Close()
			return nil
		case <-ticker.C:
			if err := a.register(ctx); err != nil {
				a.log.Warn("re-register failed", "err", err)
			}
		}
	}
}

// setup binds keys, socket, resolves the public endpoint and registers.
func (a *Agent) setup(ctx context.Context) error {
	a.baseCtx = ctx
	a.log.Info("public key", "hex", a.kp.PublicHex())
	pub, err := a.resolvePublicEndpoint(ctx)
	if err != nil {
		return fmt.Errorf("STUN: %w", err)
	}
	a.pub = pub
	if err := a.register(ctx); err != nil {
		return err
	}
	// Give the registration a moment to reach the coordinator's broadcast.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(200 * time.Millisecond):
	}
	// Data-plane receive loop is part of setup so that both `up` and `ping`
	// processes demultiplex inbound frames (handshake replies keep flowing
	// whether this process is the handshake initiator or responder).
	go a.receiveLoop(ctx)
	return nil
}

// receiveLoop demultiplexes incoming datagrams to the right peer session.
func (a *Agent) receiveLoop(ctx context.Context) {
	buf := make([]byte, 65536)
	for {
		n, src, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		extSrc := src
		frame := buf[:n]
		// Behind a natbox the raw source is the box itself; the real external
		// source and payload are carried in the inbound envelope.
		if a.door != nil {
			var payload []byte
			extSrc, payload, err = nat.UnwrapInbound(frame)
			if err != nil {
				continue
			}
			frame = payload
		}
		// Route to the peer whose advertised endpoint (or relay) matches the
		// external source.
		a.mu.Lock()
		var matched *peer.Peer
		ra := a.relay
		if ra != nil && extSrc.String() == ra.String() {
			// Relay frames carry the sender's name in the relay header, so
			// demultiplex by peer ID rather than by address.
			if rid, _, payload, perr := relay.ParsePacket(frame); perr == nil {
				if p, ok := a.peers[rid]; ok {
					matched = p
					frame = payload
				}
			}
		} else {
			for _, p := range a.peers {
				// DirectEndpoint reads the pointer under the peer's own lock;
				// the agent lock alone does not guard it.
				if ep := p.DirectEndpoint(); ep != nil && extSrc.String() == ep.String() {
					matched = p
					break
				}
			}
		}
		a.mu.Unlock()
		if matched != nil {
			// frame aliases the shared receive buffer, so hand the peer its own
			// copy (only done for frames that actually have a consumer).
			matched.HandleFrame(extSrc, append([]byte(nil), frame...))
		}
	}
}

// Transport implementation for peer.Peer -------------------------------

// SendDirect implements peer.Transport, honoring the optional NAT door.
func (a *Agent) SendDirect(dst *net.UDPAddr, frame []byte) error {
	return a.sendDatagram(dst, frame)
}

// SendRelay implements peer.Transport: wraps frame for the relay destination.
func (a *Agent) SendRelay(peerID string, frame []byte) error {
	if a.relay == nil {
		return errors.New("relay not configured")
	}
	pkt, err := relay.WrapPacket(a.cfg.Name, peerID, frame)
	if err != nil {
		return err
	}
	return a.sendDatagram(a.relay, pkt)
}

// RelayAddr implements peer.Transport.
func (a *Agent) RelayAddr() *net.UDPAddr { return a.relay }

// LocalAddr returns the data-plane socket address.
func (a *Agent) LocalAddr() net.Addr { return a.localAddr() }
