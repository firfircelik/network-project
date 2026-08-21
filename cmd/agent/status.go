package main

import (
	"context"
	"fmt"
	"time"

	"meshlink/internal/agent"
)

// runStatus prints a one-shot, machine-readable snapshot of the agent and the
// coordinator registry, then exits. It is the non-interactive answer to "are
// my peers alive and on which path?".
func runStatus(ctx context.Context, a *agent.Agent) error {
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := a.Start(sctx); err != nil {
		return err
	}
	defer a.Close()

	// Give the initial peer_list a moment to arrive; a missing list is not an
	// error, the snapshot still shows the local agent + registry.
	wctx, wcancel := context.WithTimeout(sctx, 5*time.Second)
	_ = a.WaitPeers(wctx)
	wcancel()

	qctx, qcancel := context.WithTimeout(sctx, 5*time.Second)
	qm, qerr := a.QueryCoordinator(qctx)
	qcancel()

	st := a.Status()
	if qerr == nil && qm != nil {
		st.Registry = agent.CoordinatorStatus{Count: qm.Count, Total: qm.Total, Up: qm.Up}
	}

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
	return nil
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
