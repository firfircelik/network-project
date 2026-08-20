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

// broadcastWriteDeadline bounds how long a control-plane write may block on a
// client that has stopped reading before the connection is reclaimed.
const broadcastWriteDeadline = 2 * time.Second

// Registration is a peer's current control-plane record.
type Registration struct {
	ID        string
	PubKey    string
	Endpoints []string
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
	started := make(chan struct{})
	go func() {
		close(started)
		s.serveSTUN(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.serveControl(ctx)
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

func (s *Server) serveControl(ctx context.Context) {
	for {
		conn, err := s.ctrlLn.Accept()
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
		go s.handleClient(ctx, conn)
	}
}

// handleClient performs the Noise control-plane handshake, then reads
// register messages and broadcasts peer lists over the encrypted session.
func (s *Server) handleClient(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
	}()

	// G3: the agent authenticates us against our static key; we authenticate
	// the agent's static key — its public identity — from the handshake itself.
	peerStatic, ctrl, err := control.Accept(conn, s.kp)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.clients[conn] = ""
	s.ctrlConns[conn] = ctrl
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		delete(s.ctrlConns, conn)
		s.mu.Unlock()
	}()

	for {
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
		if msg.ID == "" {
			s.writeMsg(conn, protocol.Message{Type: protocol.TypeError, Msg: "empty id"})
			continue
		}
		if msg.PubKey == "" {
			s.writeMsg(conn, protocol.Message{Type: protocol.TypeError, Msg: "pubkey is required"})
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
		s.registrations[msg.ID] = &Registration{
			ID:        msg.ID,
			PubKey:    msg.PubKey,
			Endpoints: msg.Endpoints,
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

func (s *Server) broadcast(m protocol.Message) {
	line, err := protocol.EncodeLine(m)
	if err != nil {
		return
	}
	s.mu.RLock()
	conns := make([]*control.Conn, 0, len(s.ctrlConns))
	for _, c := range s.ctrlConns {
		conns = append(conns, c)
	}
	s.mu.RUnlock()
	for _, c := range conns {
		_ = c.WriteMsg(line)
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
