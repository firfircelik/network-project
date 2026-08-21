package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"meshlink/internal/agent"
)

// runTUI serves a live terminal dashboard: the agent runs in the background
// (registration + control + data plane) while the screen shows the peer table
// with path badges, sampled RTT history and rekey counters, refreshed every
// second. Logs go to stderr so the alternate screen stays clean.
func runTUI(ctx context.Context, a *agent.Agent) error {
	if err := a.Start(ctx); err != nil {
		return err
	}
	defer a.Close()

	header := tview.NewTextView().SetDynamicColors(true)
	help := tview.NewTextView().
		SetText("q / Ctrl+C quit · refreshes every 1s · RTT sampled once per peer per refresh").
		SetTextColor(tcell.ColorGray)
	table := tview.NewTable().SetBorders(true)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 4, 0, false).
		AddItem(table, 0, 1, true).
		AddItem(help, 1, 0, false)

	st := &tuiState{}
	// Ask the coordinator for the registry snapshot in the background.
	go func() {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		qm, err := a.QueryCoordinator(qctx)
		if err == nil && qm != nil {
			st.setRegistry(agent.CoordinatorStatus{Count: qm.Count, Total: qm.Total, Up: qm.Up})
		}
	}()

	app := tview.NewApplication()
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC || event.Rune() == 'q' || event.Rune() == 'Q' {
			app.Stop()
			return nil
		}
		return event
	})
	app.SetRoot(root, true)

	// Stop the app when the process-level signal fires (SIGINT / SIGTERM),
	// even if the terminal never delivers a key event.
	go func() {
		select {
		case <-ctx.Done():
			app.Stop()
		case <-time.After(24 * time.Hour):
			app.Stop()
		}
	}()

	go tuiLoop(ctx, app, a, st, header, table)
	return app.Run()
}

// tuiState carries the async registry snapshot and holds the per-peer probe
// gate so a slow peer is never flooded with overlapping probes.
type tuiState struct {
	mu         sync.Mutex
	registry   agent.CoordinatorStatus
	registryOK bool
	probing    map[string]bool
}

func (s *tuiState) setRegistry(r agent.CoordinatorStatus) {
	s.mu.Lock()
	s.registry = r
	s.registryOK = true
	s.mu.Unlock()
}

func (s *tuiState) snapshot() (agent.CoordinatorStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registry, s.registryOK
}

// tuiLoop samples and redraws the dashboard once per second.
func tuiLoop(ctx context.Context, app *tview.Application, a *agent.Agent, st *tuiState, header *tview.TextView, table *tview.Table) {
	render := func() {
		reg, regOK := st.snapshot()
		snap := a.Status()
		header.SetText(renderHeader(snap, reg, regOK))
		renderTable(table, snap)
		app.Draw()
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	render()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Kick off one RTT probe per established peer, never overlapping a
			// peer that still has a probe in flight.
			for _, p := range a.Status().Peers {
				if !p.Established {
					continue
				}
				st.mu.Lock()
				if st.probing == nil {
					st.probing = make(map[string]bool)
				}
				if st.probing[p.ID] {
					st.mu.Unlock()
					continue
				}
				st.probing[p.ID] = true
				st.mu.Unlock()
				go func(id string) {
					defer func() {
						st.mu.Lock()
						delete(st.probing, id)
						st.mu.Unlock()
					}()
					pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					_, _ = a.ProbeRTT(pctx, id)
				}(p.ID)
			}
			app.QueueUpdateDraw(render)
		}
	}
}

func renderHeader(snap agent.Status, reg agent.CoordinatorStatus, regOK bool) string {
	registry := "coordinator registry: unknown"
	if regOK {
		registry = fmt.Sprintf("coordinator registry: %d peers registered (%d served, up %ds)",
			reg.Count, reg.Total, reg.Up)
	}
	key := snap.PubKey
	if len(key) > 16 {
		key = key[:16] + "…"
	}
	return fmt.Sprintf("[lime]meshlink [-:-:-]name=[aqua]%s[-] · key=%s\n"+
		"public endpoint=[aqua]%s[-] · relay=[aqua]%s[-] · coordinator=[aqua]%s[-]\n%s",
		snap.Name, key, snap.PublicEP, snap.Relay, snap.Coordinator, registry)
}

func renderTable(table *tview.Table, snap agent.Status) {
	headers := []string{"Peer", "Direct EP", "Est.", "Path", "RTT", "RTT history", "Rekeys", "Age"}
	for c, h := range headers {
		table.SetCell(0, c, tview.NewTableCell(h).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false).
			SetBackgroundColor(tcell.ColorGray))
	}
	if len(snap.Peers) == 0 {
		table.SetCell(1, 0, tview.NewTableCell("no known peers yet (waiting for the coordinator peer list)").
			SetTextColor(tcell.ColorGray).SetSelectable(false))
		return
	}
	for r, p := range snap.Peers {
		row := r + 1
		estText, estColor := "no", tcell.ColorRed
		if p.Established {
			estText, estColor = "yes", tcell.ColorGreen
		}
		var pathColor tcell.Color
		switch p.Path {
		case "direct":
			pathColor = tcell.ColorGreen
		case "relay":
			pathColor = tcell.ColorYellow
		default:
			pathColor = tcell.ColorRed
		}
		table.SetCell(row, 0, tview.NewTableCell(p.ID).SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(p.DirectEP).SetSelectable(false))
		table.SetCell(row, 2, tview.NewTableCell(estText).SetTextColor(estColor).SetSelectable(false))
		table.SetCell(row, 3, tview.NewTableCell(p.Path).SetTextColor(pathColor).SetSelectable(false))
		table.SetCell(row, 4, tview.NewTableCell(fmtDur(p.LastRTT)).SetSelectable(false))
		table.SetCell(row, 5, tview.NewTableCell(joinDurs(p.RTTHistory)).SetSelectable(false))
		table.SetCell(row, 6, tview.NewTableCell(fmt.Sprintf("%d", p.RekeyCount)).SetSelectable(false))
		table.SetCell(row, 7, tview.NewTableCell(fmtDur(p.SessionAge)).SetSelectable(false))
	}
}
