package main

import (
	"testing"
	"time"

	"github.com/rivo/tview"

	"meshlink/internal/agent"
)

func TestRenderTableClearsStaleRows(t *testing.T) {
	table := tview.NewTable()
	renderTable(table, agent.Status{
		Peers: []agent.PeerStatus{
			{ID: "peer-1", Path: "direct", LastRTT: 10 * time.Millisecond, RTTHistory: []time.Duration{10 * time.Millisecond}},
			{ID: "peer-2", Path: "relay", LastRTT: 20 * time.Millisecond, RTTHistory: []time.Duration{20 * time.Millisecond}},
		},
	})
	renderTable(table, agent.Status{
		Peers: []agent.PeerStatus{
			{ID: "peer-1", Path: "direct", LastRTT: 10 * time.Millisecond, RTTHistory: []time.Duration{10 * time.Millisecond}},
		},
	})

	if got := table.GetCell(2, 0).Text; got != "" {
		t.Fatalf("stale row remains after shrink: row2 col0 = %q, want empty", got)
	}
}
