// Command coordinator runs the meshlink control plane: TCP peer registry with
// broadcast peer lists, plus a UDP STUN endpoint.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"meshlink/internal/coordinator"
)

func main() {
	ctrl := flag.String("ctrl", "127.0.0.1:19200", "TCP address for the control plane")
	stun := flag.String("stun", "127.0.0.1:19201", "UDP address for STUN")
	keyfile := flag.String("keyfile", "coordinator.key", "path to the persisted control-plane private key (hex)")
	flag.Parse()

	srv, err := coordinator.New(coordinator.Config{CtrlAddr: *ctrl, StunAddr: *stun, Keyfile: *keyfile})
	if err != nil {
		log.Fatalf("coordinator: %v", err)
	}
	c, su := srv.Addrs()
	log.Printf("coordinator listening: control=%s stun=%s", c, su)
	log.Printf("control public key (give agents via -coord-pubkey): %s", srv.PublicKeyHex())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("run: %v", err)
	}
}
