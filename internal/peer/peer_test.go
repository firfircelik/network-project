package peer

import (
	"context"
	"net"
	"testing"
	"time"

	"meshlink/internal/noisework"
)

// fakeTransport is a no-op peer.Transport for lifecycle tests.
type fakeTransport struct{ relay *net.UDPAddr }

func (f *fakeTransport) SendDirect(dst *net.UDPAddr, frame []byte) error { return nil }
func (f *fakeTransport) SendRelay(peerID string, frame []byte) error     { return nil }
func (f *fakeTransport) RelayAddr() *net.UDPAddr                         { return f.relay }

// TestRunExitsWhenClosed is the regression test for the goroutine leak where
// Peer.Run only watched ctx.Done: closing a peer (as the agent does when a peer
// disappears from the peer list) must terminate Run and eventually close the
// recv channel so the payload consumer loop can exit.
func TestRunExitsWhenClosed(t *testing.T) {
	kp, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	p := New("a", "b", kp.Public,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19302}, kp,
		&fakeTransport{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rdone := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(rdone)
	}()

	// Let Run enter its loop, then close the peer from another goroutine.
	time.Sleep(100 * time.Millisecond)
	p.Close()

	select {
	case <-rdone:
		// Run exited promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after Close (goroutine leak)")
	}

	// The recv channel must be closed so `range p.Recv()` terminates.
	for {
		select {
		case _, ok := <-p.Recv():
			if !ok {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("recv channel was never closed")
		}
	}
}

// TestRunExitsOnCancel verifies Run still terminates cleanly when the owning
// context is canceled (the pre-existing exit path).
func TestRunExitsOnCancel(t *testing.T) {
	kp, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	p := New("a", "b", kp.Public,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19302}, kp,
		&fakeTransport{})

	ctx, cancel := context.WithCancel(context.Background())
	rdone := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(rdone)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-rdone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after context cancel")
	}
}

// TestNoDataAfterClose ensures HandleFrame is a no-op once the peer has been
// closed (recv channel may be closed by then; nothing may panic).
func TestNoDataAfterClose(t *testing.T) {
	kp, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	p := New("a", "b", kp.Public,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19302}, kp,
		&fakeTransport{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	p.Close()
	p.HandleFrame(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19302}, []byte("not-a-frame"))
}
