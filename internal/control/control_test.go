package control

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"meshlink/internal/noisework"
)

func mustKP(t *testing.T) *noisework.Keypair {
	t.Helper()
	kp, err := noisework.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

// tcpPair returns a client and server side of a fresh TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			done <- c
		}
	}()
	pc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sc := <-done
	t.Cleanup(func() { _ = pc.Close() })
	t.Cleanup(func() { _ = sc.Close() })
	return pc, sc
}

func TestHandshakeAndMessages(t *testing.T) {
	srvKP := mustKP(t)
	agentKP := mustKP(t)

	pc, sc := tcpPair(t)

	type acceptResult struct {
		peerStatic []byte
		conn       *Conn
		err        error
	}
	acceptDone := make(chan acceptResult, 1)
	go func() {
		peerStatic, c, err := Accept(sc, srvKP)
		acceptDone <- acceptResult{peerStatic, c, err}
	}()

	cli, err := Initiate(pc, agentKP, srvKP.Public)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	res := <-acceptDone
	if res.err != nil {
		t.Fatalf("Accept: %v", res.err)
	}
	if len(res.peerStatic) != 32 {
		t.Fatalf("peerStatic length = %d, want 32", len(res.peerStatic))
	}
	if string(res.peerStatic) != string(agentKP.Public) {
		t.Fatal("accepted peer static key mismatch")
	}

	// Both directions carry plaintext faithfully and authenticated.
	if err := cli.WriteMsg([]byte("register me")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got, err := res.conn.ReadMsg()
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != "register me" {
		t.Fatalf("server got %q", got)
	}

	if err := res.conn.WriteMsg([]byte("hello")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	got, err = cli.ReadMsg()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("client got %q", got)
	}
}

// TestConcurrentWriteMsg hammers a single connection from many goroutines to
// prove the write lock serializes Encrypt+write. Concurrent Encrypt against the
// same Noise session would reuse a (key, nonce) pair — a ChaCha20-Poly1305
// forgery risk — so this must run under -race too.
func TestConcurrentWriteMsg(t *testing.T) {
	srvKP := mustKP(t)
	agentKP := mustKP(t)

	pc, sc := tcpPair(t)
	type acceptResult struct {
		peerStatic []byte
		conn       *Conn
		err        error
	}
	acceptDone := make(chan acceptResult, 1)
	go func() {
		peerStatic, c, err := Accept(sc, srvKP)
		acceptDone <- acceptResult{peerStatic, c, err}
	}()
	cli, err := Initiate(pc, agentKP, srvKP.Public)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	res := <-acceptDone
	if res.err != nil {
		t.Fatalf("Accept: %v", res.err)
	}

	const n = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	writeErr := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			writeErr <- cli.WriteMsg([]byte(fmt.Sprintf("msg-%d", i)))
		}(i)
	}
	close(start)
	wg.Wait()
	close(writeErr)
	for err := range writeErr {
		if err != nil {
			t.Fatalf("concurrent WriteMsg: %v", err)
		}
	}

	// Every message must decrypt intact on the other side; a corrupted
	// frame (from a shared nonce) would fail authentication here. Because
	// lock acquisition order is arbitrary, labels arrive in any order — the
	// reader must still see exactly n distinct, valid messages.
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		got, err := res.conn.ReadMsg()
		if err != nil {
			t.Fatalf("reader message %d: %v", i, err)
		}
		label := string(got)
		if seen[label] {
			t.Fatalf("duplicate frame content %q (nonce reuse?)", label)
		}
		seen[label] = true
	}
	if len(seen) != n {
		t.Fatalf("reader saw %d distinct frames, want %d", len(seen), n)
	}
}

// TestWrongCoordinatorKey verifies a MITM coordinator with a different static
// key cannot establish a control session (agent-side pinning).
func TestWrongCoordinatorKey(t *testing.T) {
	srvKP := mustKP(t)
	impostorKP := mustKP(t)
	agentKP := mustKP(t)

	pc, sc := tcpPair(t)
	go func() {
		// The responder side will fail to complete once the client aborts
		// when the pinned-key check on msg2 fails.
		_, _, _ = Accept(sc, srvKP)
	}()

	// The agent was configured with the real key but connects to the impostor
	// coordinator — the mismatched static key must abort the handshake.
	if _, err := Initiate(pc, agentKP, impostorKP.Public); err == nil {
		t.Fatal("Initiate with wrong pinned key succeeded, want error")
	}
	// Closing the client half releases the acceptor goroutine.
	_ = pc.Close()
}
