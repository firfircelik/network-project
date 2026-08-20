// Package coordinator implements the control-plane server: a TCP endpoint
// that maintains the peer registry and broadcasts peer lists, plus an
// embedded UDP STUN endpoint agents use for NAT endpoint discovery.
package coordinator

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"meshlink/internal/control"
	"meshlink/internal/noisework"
	"meshlink/internal/protocol"
	"meshlink/internal/stun"
)

// Control-plane hardening limits. They keep a single authenticated peer from
// growing the registry or the broadcast frame without bound (whole-mesh DoS).
const (
	// broadcastWriteDeadline bounds how long a control-plane write may block on
	// a client that has stopped reading before the connection is reclaimed.
	broadcastWriteDeadline = 2 * time.Second
	// readIdleTimeout is re-armed before every control read, so a client that
	// handshakes and then goes silent is reclaimed instead of holding a
	// goroutine + buffer forever.
	readIdleTimeout = 90 * time.Second
	// maxIDLen bounds the peer name an authenticated client may register.
	maxIDLen = 64
	// maxEndpointsPerPeer bounds how many endpoints an agent may advertise.
	maxEndpointsPerPeer = 2
	// maxEndpointLen bounds the serialized length of a single endpoint.
	maxEndpointLen = 255
	// maxRegistrations caps the registry, keeping the broadcast peer_list
	// comfortably below the 1 MiB control-message ceiling.
	maxRegistrations = 512
	// maxControlLineLen mirrors control.maxMsgLen (1 MiB): a peer_list that
	// would exceed it is never assembled/broadcast.
	maxControlLineLen = 1 << 20
)

// Registration is a peer's current control-plane record.
type Registration struct {
	ID        string
	PubKey    string
	Endpoints []string
	Owner     net.Conn // the connection that currently owns this ID
}

// Config configures a coordinator server.
type Config struct {
	CtrlAddr string // TCP listen address for the control plane
	StunAddr string // UDP listen address for STUN
	Keyfile  string // path to the coordinator's persisted private key (hex)
}

// Server is a coordinator instance.
type Server struct {
	cfg Config
	log *log.Logger
	kp  *noisework.Keypair // coordinator control-plane identity

	mu            sync.RWMutex
	registrations map[string]*Registration
	clients       map[net.Conn]string        // conn -> peer ID ("" when not registered)
	ctrlConns     map[net.Conn]*control.Conn // conn -> encrypted control session

	ctrlLn   net.Listener
	stunConn *net.UDPConn
	closed   chan struct{}
}

// New creates a coordinator server bound to the configured addresses and
// loads (or creates) the coordinator's control-plane keypair.
func New(cfg Config) (*Server, error) {
	if cfg.Keyfile == "" {
		return nil, fmt.Errorf("coordinator: Keyfile is required")
	}
	kp, err := noisework.LoadOrCreateKeyfile(cfg.Keyfile)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:           cfg,
		log:           log.Default(),
		kp:            kp,
		registrations: make(map[string]*Registration),
		clients:       make(map[net.Conn]string),
		ctrlConns:     make(map[net.Conn]*control.Conn),
		closed:        make(chan struct{}),
	}
	ln, err := net.Listen("tcp", cfg.CtrlAddr)
	if err != nil {
		return nil, fmt.Errorf("listen control: %w", err)
	}
	s.ctrlLn = ln
	uc, err := net.ListenPacket("udp", cfg.StunAddr)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("listen stun: %w", err)
	}
	s.stunConn = uc.(*net.UDPConn)
	return s, nil
}

// PublicKeyHex returns the coordinator control-plane public key (what agents
// pin with their -coord-pubkey).
func (s *Server) PublicKeyHex() string {
	if s == nil || s.kp == nil {
		return ""
	}
	return s.kp.PublicHex()
}

// Addrs returns the bound control and STUN addresses.
func (s *Server) Addrs() (ctrl net.Addr, stun net.Addr) {
	return s.ctrlLn.Addr(), s.stunConn.LocalAddr()
}

// Close shuts the server down cleanly.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	err1 := s.ctrlLn.Close()
	err2 := s.stunConn.Close()
	s.mu.Lock()
	for c := range s.clients {
		c.Close()
	}
	s.mu.Unlock()
	if err1 != nil {
		return err1
	}
	return err2
}

// Run serves the control plane and STUN until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.serveSTUN(ctx)
	}()
	go func() {
		defer wg.Done()
		s.serveControl(ctx, &wg)
	}()

	select {
	case <-ctx.Done():
		s.Close()
	case <-s.closed:
	}
	wg.Wait()
	return nil
}

func (s *Server) serveSTUN(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		n, src, err := s.stunConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-s.closed:
				return
			default:
				continue
			}
		}
		resp, err := stun.HandleBindingRequest(buf[:n], src)
		if err != nil {
			continue
		}
		_, _ = s.stunConn.WriteToUDP(resp, src)
	}
}

func (s *Server) serveControl(ctx context.Context, wg *sync.WaitGroup) {
	for {
		conn, err := s.ctrlLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-s.closed:
				return
			default:
				// Backoff instead of hot-looping: accept errors such as
				// EMFILE/ENFILE are often transient but expensive to spin on.
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleClient(ctx, conn)
		}()
	}
}

// cleanupConn removes a connection (pending, registered or idle) from all
// maps and releases the ID it owned back to the registry.
func (s *Server) cleanupConn(conn net.Conn) {
	if conn == nil {
		return
	}
	s.mu.Lock()
	if id := s.clients[conn]; id != "" {
		if reg := s.registrations[id]; reg != nil && reg.Owner == conn {
			// Only drop the registration when this very conn still owns it;
			// a re-registration from a newer conn supersedes the owner.
			delete(s.registrations, id)
		}
	}
	delete(s.clients, conn)
	delete(s.ctrlConns, conn)
	s.mu.Unlock()
	conn.Close()
}

// evict drops a connection the server decided to reclaim (e.g. a stalled or
// misbehaving write target). The client goroutine observes the closed socket
// and calls cleanupConn, which is idempotent.
func (s *Server) evict(conn net.Conn) {
	if conn == nil {
		return
	}
	s.cleanupConn(conn)
}

// validateRegistration applies the server-side bounds to a register message.
func (s *Server) validateRegistration(msg *protocol.Message) error {
	if msg.ID == "" {
		return fmt.Errorf("id is required")
	}
	if len(msg.ID) > maxIDLen {
		return fmt.Errorf("id exceeds %d bytes", maxIDLen)
	}
	if len(msg.Endpoints) > maxEndpointsPerPeer {
		return fmt.Errorf("too many endpoints")
	}
	for _, ep := range msg.Endpoints {
		if len(ep) > maxEndpointLen {
			return fmt.Errorf("endpoint exceeds %d bytes", maxEndpointLen)
		}
	}
	return nil
}

// handleClient performs the Noise control-plane handshake, then reads
// register messages and broadcasts peer lists over the encrypted session.
func (s *Server) handleClient(ctx context.Context, conn net.Conn) {
	// Track the conn from the start so Close() can abort mid-handshake
	// sockets instead of waiting out the handshake timeout.
	s.mu.Lock()
	s.clients[conn] = ""
	s.mu.Unlock()
	defer s.cleanupConn(conn)

	// G3: the agent authenticates us against our static key; we authenticate
	// the agent's static key — its public identity — from the handshake itself.
	peerStatic, ctrl, err := control.Accept(conn, s.kp)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.ctrlConns[conn] = ctrl
	s.mu.Unlock()

	for {
		// Re-arm the idle deadline so a client that handshakes and then never
		// sends bytes does not squat a goroutine and buffered connection.
		if nc := ctrl.NetConn(); nc != nil {
			_ = nc.SetReadDeadline(time.Now().Add(readIdleTimeout))
		}
		plain, err := ctrl.ReadMsg()
		if err != nil {
			return
		}
		msg, err := protocol.DecodeLine(plain)
		if err != nil || msg == nil {
			continue
		}
		if msg.Type != protocol.TypeRegister {
			continue
		}
		if err := s.validateRegistration(msg); err != nil {
			s.writeMsg(conn, protocol.Message{Type: protocol.TypeError, Msg: err.Error()})
			continue
		}
		// The register's public key must be the identity that the Noise
		// handshake just authenticated, so a name cannot be claimed with a
		// borrowed key over an unrelated connection.
		if hex.EncodeToString(peerStatic) != msg.PubKey {
			s.writeMsg(conn, protocol.Message{Type: protocol.TypeError, Msg: "pubkey does not match the authenticated control identity"})
			continue
		}
		s.mu.Lock()
		// Key pinning: an ID that already exists is bound to the public key it
		// first registered with; re-registration with a different key is
		// refused so an attacker cannot squat an existing peer's name.
		if cur, ok := s.registrations[msg.ID]; ok && cur.PubKey != "" && cur.PubKey != msg.PubKey {
			s.mu.Unlock()
			s.writeMsg(conn, protocol.Message{Type: protocol.TypeError, Msg: "id already registered with a different key"})
			continue
		}
		// Registry cap: bound the broadcast frame and the memory footprint.
		if _, exists := s.registrations[msg.ID]; !exists && len(s.registrations) >= maxRegistrations {
			s.mu.Unlock()
			s.writeMsg(conn, protocol.Message{Type: protocol.TypeError, Msg: "registry full"})
			continue
		}
		s.registrations[msg.ID] = &Registration{
			ID:        msg.ID,
			PubKey:    msg.PubKey,
			Endpoints: msg.Endpoints,
			Owner:     conn,
		}
		s.clients[conn] = msg.ID
		// Broadcast the full current peer list to everybody (including sender).
		peers := make([]protocol.PeerInfo, 0, len(s.registrations))
		for _, r := range s.registrations {
			peers = append(peers, protocol.PeerInfo{
				ID:        r.ID,
				PubKey:    r.PubKey,
				Endpoints: r.Endpoints,
			})
		}
		s.mu.Unlock()

		s.broadcast(protocol.Message{Type: protocol.TypePeerList, Peers: peers})

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// broadcast sends a control message to every connected client. A client that
// fails to swallow its write is evicted so one stalled reader cannot stall
// the whole mesh.
func (s *Server) broadcast(m protocol.Message) {
	line, err := protocol.EncodeLine(m)
	if err != nil {
		return
	}
	if len(line) > maxControlLineLen {
		s.log.Printf("coordinator: dropping broadcast (%d bytes > ceiling)", len(line))
		return
	}
	s.mu.RLock()
	conns := make([]*control.Conn, 0, len(s.ctrlConns))
	for _, c := range s.ctrlConns {
		conns = append(conns, c)
	}
	s.mu.RUnlock()
	for _, c := range conns {
		nc := c.NetConn()
		if nc != nil {
			_ = nc.SetWriteDeadline(time.Now().Add(broadcastWriteDeadline))
		}
		err := c.WriteMsg(line)
		if nc != nil {
			_ = nc.SetWriteDeadline(time.Time{})
		}
		if err != nil {
			s.evict(nc)
		}
	}
}

func (s *Server) writeMsg(conn net.Conn, m protocol.Message) {
	line, err := protocol.EncodeLine(m)
	if err != nil {
		return
	}
	s.mu.RLock()
	ctrl := s.ctrlConns[conn]
	s.mu.RUnlock()
	if ctrl != nil {
		_ = ctrl.WriteMsg(line)
	}
}
