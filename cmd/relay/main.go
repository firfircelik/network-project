// Command relay runs the meshlink UDP relay server. It forwards encrypted
// frames between peers by their registered IDs; it never sees plaintext.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"meshlink/internal/relay"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19205", "UDP address to listen on")
	flag.Parse()

	srv, err := relay.New(relay.Config{Addr: mustUDPAddr(*addr)})
	if err != nil {
		log.Fatalf("relay: %v", err)
	}
	log.Printf("relay listening on %s", srv.Addr())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := srv.Run(ctx); err != nil {
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
