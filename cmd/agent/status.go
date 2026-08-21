package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"meshlink/internal/agent"
)

// runStatus prints a one-shot snapshot of the agent and the coordinator
// registry, then exits. It is the non-interactive answer to "are my peers
// alive and on which path?". With -json the same snapshot is emitted as a
// single machine-readable JSON document on stdout (logs stay on stderr), so
// scripts and collectors (e.g. HomeNetIQ) can ingest it directly.
func runStatus(ctx context.Context, a *agent.Agent, asJSON bool, probePeer string) error {
	st, qerr := collectStatus(ctx, a, probePeer)
	if asJSON {
		return renderStatusJSON(st, qerr)
	}
	renderStatusText(st, qerr)
	return nil
}

// collectStatus starts the agent, waits briefly for the initial peer list and
// the registry reply, and returns the snapshot. A missing peer list or
// registry reply is not an error — the snapshot still shows the local agent.
func collectStatus(ctx context.Context, a *agent.Agent, probePeer string) (agent.Status, error) {
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := a.Start(sctx); err != nil {
		return agent.Status{}, err
	}
	defer a.Close()

	wctx, wcancel := context.WithTimeout(sctx, 3*time.Second)
	_ = a.WaitPeers(wctx)
	wcancel()

	if probePeer != "" {
		// Warm up the tunnel from THIS instance so the snapshot reports a
		// real path/RTT. Ping waits for establishment internally. A failure
		// is not fatal — the snapshot then shows the peer as unreachable.
		pctx, pcancel := context.WithTimeout(sctx, 8*time.Second)
		_, _ = a.Ping(pctx, probePeer, 1, 0)
		pcancel()
	} else {
		// Without a probe, give handshakes a moment to complete on their own.
		waitEstablished(sctx, a, 8*time.Second)
	}

	// Sample one RTT probe per established peer so rtt_ms / rtt_history in
	// the snapshot are real measurements, not nulls.
	for _, ps := range a.Status().Peers {
		if !ps.Established {
			continue
		}
		rctx, rcancel := context.WithTimeout(sctx, 3*time.Second)
		_, _ = a.ProbeRTT(rctx, ps.ID)
		rcancel()
	}

	qctx, qcancel := context.WithTimeout(sctx, 3*time.Second)
	qm, qerr := a.QueryCoordinator(qctx)
	qcancel()

	st := a.Status()
	if qerr == nil && qm != nil {
		st.Registry = agent.CoordinatorStatus{Count: qm.Count, Total: qm.Total, Up: qm.Up}
	}
	return st, qerr
}

// waitEstablished polls the snapshot until every known peer is established,
// the deadline passes, or ctx is done. Peers that will never establish simply
// run out the clock; the snapshot then shows them as they are.
func waitEstablished(ctx context.Context, a *agent.Agent, max time.Duration) {
	dctx, cancel := context.WithTimeout(ctx, max)
	defer cancel()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		allEst := true
		for _, p := range a.Status().Peers {
			if !p.Established {
				allEst = false
				break
			}
		}
		if allEst {
			return
		}
		select {
		case <-dctx.Done():
			return
		case <-t.C:
		}
	}
}

func renderStatusText(st agent.Status, qerr error) {
	fmt.Printf("name: %s\n", st.Name)
	fmt.Printf("pubkey: %s\n", st.PubKey)
	fmt.Printf("public_endpoint: %s\n", st.PublicEP)
	fmt.Printf("relay: %s\n", st.Relay)
	fmt.Printf("coordinator: %s\n", st.Coordinator)
	fmt.Printf("registry_count: %d\n", st.Registry.Count)
	fmt.Printf("registry_total: %d\n", st.Registry.Total)
	fmt.Printf("registry_up_s: %d\n", st.Registry.Up)
	if qerr != nil {
		fmt.Printf("registry_error: %v\n", qerr)
	}
	for _, p := range st.Peers {
		fmt.Printf("peer %s: established=%v path=%s rtt=%s rekeys=%d age=%s endpoint=%s",
			p.ID, p.Established, p.Path, fmtDur(p.LastRTT), p.RekeyCount, fmtDur(p.SessionAge), p.DirectEP)
		if len(p.RTTHistory) > 0 {
			fmt.Printf(" rtt_hist=%s", joinDurs(p.RTTHistory))
		}
		fmt.Println()
	}
}

// --- JSON rendering ---
//
// Durations are exported as milliseconds/seconds floats instead of Go's
// default nanosecond integers so downstream consumers (Python collectors,
// jq, dashboards) get sane units. rtt_ms is null when never sampled.

type registryJSON struct {
	Count int   `json:"count"`
	Total int   `json:"total"`
	UpS   int64 `json:"up_s"`
}

type peerJSON struct {
	ID           string    `json:"id"`
	Established  bool      `json:"established"`
	Path         string    `json:"path"` // none / direct / relay
	RTTMs        *float64  `json:"rtt_ms"`                   // null = not sampled yet
	RTTHistoryMs []float64 `json:"rtt_history_ms,omitempty"` // newest first
	Rekeys       uint64    `json:"rekeys"`
	AgeS         float64   `json:"age_s"` // 0 = no session installed
	Endpoint     string    `json:"endpoint,omitempty"`
}

type statusJSON struct {
	Name        string       `json:"name"`
	PubKey      string       `json:"pubkey"`
	PublicEP    string       `json:"public_endpoint,omitempty"`
	Relay       string       `json:"relay,omitempty"`
	Coordinator string       `json:"coordinator,omitempty"`
	Registry    registryJSON `json:"registry"`
	RegistryErr string       `json:"registry_error,omitempty"`
	Peers       []peerJSON   `json:"peers"`
}

func msOf(d time.Duration) *float64 {
	if d == 0 {
		return nil
	}
	ms := float64(d) / float64(time.Millisecond)
	return &ms
}

func renderStatusJSON(st agent.Status, qerr error) error {
	out := statusJSON{
		Name:        st.Name,
		PubKey:      st.PubKey,
		PublicEP:    st.PublicEP,
		Relay:       st.Relay,
		Coordinator: st.Coordinator,
		Registry:    registryJSON{Count: st.Registry.Count, Total: st.Registry.Total, UpS: st.Registry.Up},
		Peers:       make([]peerJSON, 0, len(st.Peers)),
	}
	if qerr != nil {
		out.RegistryErr = qerr.Error()
	}
	for _, p := range st.Peers {
		hist := make([]float64, 0, len(p.RTTHistory))
		for _, d := range p.RTTHistory {
			hist = append(hist, float64(d)/float64(time.Millisecond))
		}
		out.Peers = append(out.Peers, peerJSON{
			ID:           p.ID,
			Established:  p.Established,
			Path:         p.Path,
			RTTMs:        msOf(p.LastRTT),
			RTTHistoryMs: hist,
			Rekeys:       p.RekeyCount,
			AgeS:         p.SessionAge.Seconds(),
			Endpoint:     p.DirectEP,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// fmtDur renders a duration tersely ("-" when zero, "1.2ms" / "3s" otherwise).
func fmtDur(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	if d < time.Second {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func joinDurs(ds []time.Duration) string {
	out := ""
	for i, d := range ds {
		if i > 0 {
			out += ","
		}
		out += fmtDur(d)
	}
	return out
}
