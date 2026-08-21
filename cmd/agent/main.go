// Command agent is the meshlink client. It operates in two modes:
//
//	meshlink agent up   --name a ...      run as a daemon, answering pings
//	meshlink agent ping --name b --peer a ...   perform a ping run and exit
//
// All traffic (control, STUN, data) is unencrypted only where specified by
// the protocol; tunnel data is encrypted end-to-end with Noise.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"meshlink/internal/agent"
)

func configFlags(fs *flag.FlagSet) *agent.Config {
	cfg := &agent.Config{}
	fs.StringVar(&cfg.Name, "name", "", "agent name (identity)")
	fs.StringVar(&cfg.Keyfile, "keyfile", "", "path to persisted private key (hex)")
	fs.StringVar(&cfg.Coordinator, "coordinator", "127.0.0.1:19200", "control-plane TCP address")
	fs.StringVar(&cfg.CoordKey, "coord-pubkey", "", "coordinator control-plane public key (hex, required)")
	fs.StringVar(&cfg.StunAddr, "stun", "127.0.0.1:19201", "STUN UDP address")
	fs.StringVar(&cfg.RelayAddr, "relay", "127.0.0.1:19205", "relay UDP address (empty disables)")
	fs.StringVar(&cfg.DataAddr, "data", "127.0.0.1:19501", "local data-plane UDP bind address")
	fs.StringVar(&cfg.NatDoor, "nat", "", "optional natbox inside-door address")
	fs.StringVar(&cfg.TunName, "tun", "", "TUN device to open (e.g. utun9; root required, empty disables)")
	fs.StringVar(&cfg.TunIP, "tun-ip", "", "IPv4 assigned to this agent on the overlay")
	fs.IntVar(&cfg.TunMTU, "tun-mtu", 1500, "TUN MTU")
	fs.Func("tun-peer", "peerID=ipv4 (repeatable, outbound route table)", func(s string) error {
		id, ip, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("tun-peer %q: want peerID=ipv4", s)
		}
		if cfg.TunPeers == nil {
			cfg.TunPeers = make(map[string]string)
		}
		cfg.TunPeers[id] = ip
		return nil
	})
	return cfg
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  meshlink agent up     --name <id> ...      run daemon
  meshlink agent ping   --name <id> --peer <id> [--count N] ...
  meshlink agent status --name <id> ...      print one-shot status snapshot and exit
  meshlink agent tui    --name <id> ...      live terminal dashboard`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var run func() error
	switch os.Args[1] {
	case "up", "ping", "status", "tui":
		fs := flag.NewFlagSet("agent "+os.Args[1], flag.ExitOnError)
		cfg := configFlags(fs)
		mode := os.Args[1]
		if mode == "tui" {
			// slog output would corrupt the terminal dashboard; keep logs on stderr.
			cfg.LogWriter = os.Stderr
		}
		var peerID string
		var count int
		var interval time.Duration
		if mode == "ping" {
			fs.StringVar(&peerID, "peer", "", "peer to ping")
			fs.IntVar(&count, "count", 3, "number of pings")
			fs.DurationVar(&interval, "interval", 0, "delay between pings")
		}
		_ = fs.Parse(os.Args[2:])
		if cfg.Name == "" || cfg.Keyfile == "" || cfg.CoordKey == "" {
			log.Fatal("--name, --keyfile and --coord-pubkey are required")
		}
		if mode != "up" && (cfg.TunName != "" || cfg.TunIP != "" || len(cfg.TunPeers) > 0) {
			log.Fatal("TUN flags (--tun, --tun-ip, --tun-peer) are only valid in 'up' mode")
		}
		a, err := agent.New(*cfg)
		if err != nil {
			log.Fatalf("agent: %v", err)
		}
		run = func() error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			switch mode {
			case "up":
				return a.Run(ctx)
			case "status":
				return runStatus(ctx, a)
			case "tui":
				return runTUI(ctx, a)
			}
			pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
			defer pcancel()
			if peerID == "" {
				return fmt.Errorf("--peer is required for ping")
			}
			if err := a.Start(pctx); err != nil {
				return err
			}
			res, err := a.Ping(pctx, peerID, count, interval)
			if err != nil {
				return err
			}
			fmt.Printf("ping %s: count=%d received=%d avg_rtt=%s path=%s\n",
				res.Peer, res.Count, res.Received, res.AvgRTT, res.Path)
			return nil
		}
	default:
		usage()
		os.Exit(2)
	}
	if err := run(); err != nil {
		log.Fatalf("%v", err)
	}
}
