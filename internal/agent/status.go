package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"meshlink/internal/protocol"
)

// CoordinatorStatus summarises the coordinator's registry snapshot.
type CoordinatorStatus struct {
	Count int   // peers currently registered
	Total int   // registrations served since the coordinator started
	Up    int64 // coordinator uptime in seconds
}

// PeerStatus is a point-in-time snapshot of one peer session.
type PeerStatus struct {
	ID          string
	Established bool
	Path        string          // none / direct / relay
	LastRTT     time.Duration   // last sampled round trip (0 = not sampled yet)
	RTTHistory  []time.Duration // most recent first (protocol order newest->oldest)
	RekeyCount  uint64
	SessionAge  time.Duration
	BytesSent   uint64 // plaintext bytes sent over the tunnel
	BytesRecv   uint64 // plaintext bytes received from the tunnel
	DirectEP    string // advertised direct endpoint ("" = unknown)
}

// Status is a point-in-time snapshot of the agent and its peers. It never
// performs I/O, so it can be rendered on every UI refresh.
type Status struct {
	Name        string
	PubKey      string
	PublicEP    string // STUN-learned public endpoint
	Relay       string // configured relay ("" = disabled)
	Coordinator string // control-plane address
	Registry    CoordinatorStatus
	Peers       []PeerStatus
}

// Status returns a non-blocking snapshot of the agent.
func (a *Agent) Status() Status {
	st := Status{
		Name:        a.cfg.Name,
		PubKey:      a.kp.PublicHex(),
		Coordinator: a.cfg.Coordinator,
	}
	if a.pub != nil {
		st.PublicEP = a.pub.String()
	}
	if a.relay != nil {
		st.Relay = a.relay.String()
	}

	a.mu.Lock()
	ids := make([]string, 0, len(a.peers))
	for id := range a.peers {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	sort.Strings(ids)

	for _, id := range ids {
		a.mu.Lock()
		p := a.peers[id]
		a.mu.Unlock()
		if p == nil {
			continue
		}
		ps := PeerStatus{
			ID:          p.ID,
			Established: p.Established(),
			Path:        p.Path().String(),
			RekeyCount:  p.RekeyCount(),
			SessionAge:  p.SessionAge(),
			BytesSent:   p.BytesSent(),
			BytesRecv:   p.BytesRecv(),
		}
		if ep := p.DirectEndpoint(); ep != nil {
			ps.DirectEP = ep.String()
		}
		a.rttMu.Lock()
		ps.LastRTT = a.lastRTT[id]
		ps.RTTHistory = append([]time.Duration(nil), a.rttHist[id]...)
		a.rttMu.Unlock()
		st.Peers = append(st.Peers, ps)
	}
	return st
}

// QueryCoordinator asks the authenticated control session for a registry
// snapshot and blocks for the reply (or until ctx is done). The caller must
// have registered first (see setup).
func (a *Agent) QueryCoordinator(ctx context.Context) (*protocol.Message, error) {
	a.queryMu.Lock()
	defer a.queryMu.Unlock()

	a.ctrlMu.Lock()
	ctrl := a.ctrlConn
	a.ctrlMu.Unlock()
	if ctrl == nil {
		return nil, errors.New("control session not established")
	}
	for {
		select {
		case <-a.queryCh:
		default:
			goto drained
		}
	}

drained:
	line, err := protocol.EncodeLine(protocol.Message{Type: protocol.TypeQuery})
	if err != nil {
		return nil, err
	}
	if err := ctrl.WriteMsg(line); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-a.queryCh:
		return msg, nil
	}
}

// ProbeRTT performs a single ping round trip against peerID and returns the
// measured RTT. The session must be established (wait up to ctx deadline).
func (a *Agent) ProbeRTT(ctx context.Context, peerID string) (time.Duration, error) {
	a.mu.Lock()
	p := a.peers[peerID]
	a.mu.Unlock()
	if p == nil {
		return 0, fmt.Errorf("no such peer: %s", peerID)
	}
	if err := p.WaitEstablished(ctx); err != nil {
		return 0, err
	}
	seq := uint64(time.Now().UnixNano())
	ts := time.Now().UnixNano()
	if err := p.SendJSON(pingMsg{Cmd: "ping", S: seq, Ts: ts}); err != nil {
		return 0, fmt.Errorf("send ping: %w", err)
	}
	done := make(chan time.Time, 1)
	a.pingMu.Lock()
	a.pingOut[seq] = done
	a.pingMu.Unlock()
	defer a.dropPing(seq)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case got := <-done:
		rtt := got.Sub(time.Unix(0, ts))
		a.recordRTT(peerID, rtt)
		return rtt, nil
	}
}

// recordRTT stores a freshly measured RTT for peerID, updating both the
// latest value and the capped history ring.
func (a *Agent) recordRTT(peerID string, rtt time.Duration) {
	a.rttMu.Lock()
	a.lastRTT[peerID] = rtt
	hist := append([]time.Duration{rtt}, a.rttHist[peerID]...)
	if len(hist) > rttHistoryDepth {
		hist = hist[:rttHistoryDepth]
	}
	a.rttHist[peerID] = hist
	a.rttMu.Unlock()
}
