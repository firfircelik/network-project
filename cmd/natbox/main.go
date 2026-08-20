// Command natbox simulates a NAT device for local development: agents behind
// it egress through the "inside door", and the outside world reaches them at
// the public address. Different behaviors model full-cone, address-restricted
// and symmetric NATs (the latter breaks classic hole punching, forcing the
// relay fallback).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"meshlink/internal/nat"
)

func main() {
	name := flag.String("name", "nat1", "NAT name")
	behavior := flag.String("behavior", "fullcone", "fullcone | restricted | symmetric")
	public := flag.String("public", "127.0.0.1:19301", "public (outside) UDP address of the NAT device")
	door := flag.String("door", "127.0.0.1:19401", "inside door the private host egresses through")
	host := flag.String("host", "127.0.0.1:19501", "private host data address (inbound delivery)")
	flag.Parse()

	beh, err := nat.ParseBehavior(*behavior)
	if err != nil {
		log.Fatalf("behavior: %v", err)
	}
	b, err := nat.New(nat.Config{
		Name:        *name,
		Behavior:    beh,
		PublicAddr:  mustUDPAddr(*public),
		InsideDoor:  mustUDPAddr(*door),
		PrivateHost: mustUDPAddr(*host),
	})
	if err != nil {
		log.Fatalf("natbox: %v", err)
	}
	log.Printf("natbox %s running: public=%s door=%s host=%s", *name, b.Public(), *door, *host)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := b.Run(ctx); err != nil {
		log.Fatalf("run: %v", err)
	}
}

func mustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		log.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}
