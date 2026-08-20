package noisework

import (
	"bytes"
	"strings"
	"testing"
)

var testPrologue = []byte("meshlink-v1")

func mustKeypair(t *testing.T) *Keypair {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

// newTestSides wires up an initiator expecting respKP and a responder using
// respKP, each with the given prologue.
func newTestSides(t *testing.T, initKP, respKP *Keypair, initPrologue, respPrologue []byte) (*Initiator, *Responder) {
	t.Helper()
	init, err := NewInitiator(initKP, respKP.Public, initPrologue)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	resp, err := NewResponder(respKP, respPrologue)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	return init, resp
}

// runHandshake drives a full XX handshake, exchanging message1/2/3 as raw
// byte slices (optionally substituted by mutate) and returns both completed
// sessions, or the first error encountered.
func runHandshake(init *Initiator, resp *Responder, mutate func(step int, msg []byte) []byte) (*Session, *Session, error) {
	msg1, err := init.Message1()
	if err != nil {
		return nil, nil, err
	}
	if mutate != nil {
		msg1 = mutate(1, msg1)
	}
	if err := resp.ReadMessage1(msg1); err != nil {
		return nil, nil, err
	}
	msg2, err := resp.Message2()
	if err != nil {
		return nil, nil, err
	}
	if mutate != nil {
		msg2 = mutate(2, msg2)
	}
	sInit, err := init.ReadMessage2(msg2)
	if err != nil {
		return nil, nil, err
	}
	msg3, err := init.WriteMessage3()
	if err != nil {
		return nil, nil, err
	}
	if mutate != nil {
		msg3 = mutate(3, msg3)
	}
	sResp, err := resp.ReadMessage3(msg3)
	if err != nil {
		return nil, nil, err
	}
	return sInit, sResp, nil
}

// TestGenerateKeypairAndHex covers key generation plus the hex encoding and
// decoding helpers.
func TestGenerateKeypairAndHex(t *testing.T) {
	k, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if len(k.Public) != KeySize {
		t.Fatalf("Public length = %d, want %d", len(k.Public), KeySize)
	}
	if len(k.Private) != KeySize {
		t.Fatalf("Private length = %d, want %d", len(k.Private), KeySize)
	}

	hexPub := k.PublicHex()
	if len(hexPub) != KeySize*2 {
		t.Fatalf("PublicHex length = %d, want %d", len(hexPub), KeySize*2)
	}
	parsed, err := ParsePublicKeyHex(hexPub)
	if err != nil {
		t.Fatalf("ParsePublicKeyHex: %v", err)
	}
	if !bytes.Equal(parsed, k.Public) {
		t.Fatal("parsed public key does not match the original")
	}

	k2 := mustKeypair(t)
	if bytes.Equal(k.Public, k2.Public) {
		t.Fatal("two generated keypairs share the same public key")
	}
}

// TestParsePublicKeyHexErrors covers the size and hex-validity rejections.
func TestParsePublicKeyHexErrors(t *testing.T) {
	cases := []struct {
		name string
		s    string
	}{
		{"empty", ""},
		{"too short", strings.Repeat("ab", 31)},
		{"too long", strings.Repeat("ab", 33)},
		{"odd length", strings.Repeat("ab", 31) + "a"},
		{"invalid hex", strings.Repeat("zz", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if b, err := ParsePublicKeyHex(tc.s); err == nil {
				t.Fatalf("ParsePublicKeyHex(%q) succeeded with %d bytes, want error", tc.s, len(b))
			}
		})
	}
}

// TestHandshakeAndTransport is the main integration test: message1/2/3 are
// exchanged as raw byte slices, sessions expose matching PeerStatic and
// ChannelBinding, and encrypted transport flows both ways over many sizes.
func TestHandshakeAndTransport(t *testing.T) {
	initKP := mustKeypair(t)
	respKP := mustKeypair(t)
	init, resp := newTestSides(t, initKP, respKP, testPrologue, testPrologue)

	msg1, err := init.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	if err := resp.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	msg2, err := resp.Message2()
	if err != nil {
		t.Fatalf("Message2: %v", err)
	}
	sInit, err := init.ReadMessage2(msg2)
	if err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}
	msg3, err := init.WriteMessage3()
	if err != nil {
		t.Fatalf("WriteMessage3: %v", err)
	}
	sResp, err := resp.ReadMessage3(msg3)
	if err != nil {
		t.Fatalf("ReadMessage3: %v", err)
	}

	// Peer static keys: both sides observe the other's public key, and the
	// initiator's equals the key supplied to NewInitiator.
	if got := sInit.PeerStatic(); got == nil {
		t.Fatal("initiator PeerStatic() is nil after handshake")
	} else if !bytes.Equal(got, respKP.Public) {
		t.Fatal("initiator PeerStatic() does not match the responder public key")
	}
	if got := sResp.PeerStatic(); got == nil {
		t.Fatal("responder PeerStatic() is nil after handshake")
	} else if !bytes.Equal(got, initKP.Public) {
		t.Fatal("responder PeerStatic() does not match the initiator public key")
	}

	// Channel binding: non-empty and identical on both sides.
	cbInit := sInit.ChannelBinding()
	cbResp := sResp.ChannelBinding()
	if len(cbInit) == 0 {
		t.Fatal("initiator ChannelBinding() is empty")
	}
	if !bytes.Equal(cbInit, cbResp) {
		t.Fatal("ChannelBinding values differ between peers")
	}

	if got, want := sInit.MaxPlaintextLen(), maxUDPPayload-frameHeader-nonceLen-aeadTag; got != want {
		t.Fatalf("MaxPlaintextLen() = %d, want %d", got, want)
	}

	// Transport round-trips in both directions over several sizes, including
	// messages well beyond 1000 bytes and the maximum plaintext length.
	sizes := []int{0, 1, 32, 100, 1024, 4096, maxPlaintextLen}
	for _, n := range sizes {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i)
		}

		ct, err := sInit.Encrypt(msg)
		if err != nil {
			t.Fatalf("initiator Encrypt(%d bytes): %v", n, err)
		}
		if len(ct) != n+16 {
			t.Fatalf("ciphertext length = %d, want %d", len(ct), n+16)
		}
		pt, err := sResp.Decrypt(ct)
		if err != nil {
			t.Fatalf("responder Decrypt(%d bytes): %v", n, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("initiator→responder roundtrip mismatch for %d bytes", n)
		}

		ct, err = sResp.Encrypt(msg)
		if err != nil {
			t.Fatalf("responder Encrypt(%d bytes): %v", n, err)
		}
		pt, err = sInit.Decrypt(ct)
		if err != nil {
			t.Fatalf("initiator Decrypt(%d bytes): %v", n, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("responder→initiator roundtrip mismatch for %d bytes", n)
		}
	}
}

// TestSessionNotReadyBeforeCompletion verifies the contract that PeerStatic
// and ChannelBinding are nil and Encrypt/Decrypt error until the handshake is
// finished.
func TestSessionNotReadyBeforeCompletion(t *testing.T) {
	initKP := mustKeypair(t)
	respKP := mustKeypair(t)
	init, resp := newTestSides(t, initKP, respKP, testPrologue, testPrologue)

	msg1, err := init.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	if err := resp.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	msg2, err := resp.Message2()
	if err != nil {
		t.Fatalf("Message2: %v", err)
	}
	sInit, err := init.ReadMessage2(msg2)
	if err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}

	if got := sInit.PeerStatic(); got != nil {
		t.Fatalf("PeerStatic() before completion = %x, want nil", got)
	}
	if got := sInit.ChannelBinding(); got != nil {
		t.Fatalf("ChannelBinding() before completion = %x, want nil", got)
	}
	if _, err := sInit.Encrypt([]byte("x")); err == nil {
		t.Fatal("Encrypt before completion succeeded, want error")
	}
	if _, err := sInit.Decrypt([]byte("x")); err == nil {
		t.Fatal("Decrypt before completion succeeded, want error")
	}

	// Completing the handshake finalizes the Session returned by ReadMessage2.
	msg3, err := init.WriteMessage3()
	if err != nil {
		t.Fatalf("WriteMessage3: %v", err)
	}
	sResp, err := resp.ReadMessage3(msg3)
	if err != nil {
		t.Fatalf("ReadMessage3: %v", err)
	}
	if got := sInit.PeerStatic(); !bytes.Equal(got, respKP.Public) {
		t.Fatalf("PeerStatic() after completion = %x, want %x", got, respKP.Public)
	}
	if !bytes.Equal(sInit.ChannelBinding(), sResp.ChannelBinding()) {
		t.Fatal("ChannelBinding mismatch after completion")
	}

	// The finalized session is now usable for transport.
	ct, err := sInit.Encrypt([]byte("done"))
	if err != nil {
		t.Fatalf("Encrypt after completion: %v", err)
	}
	if _, err := sResp.Decrypt(ct); err != nil {
		t.Fatalf("Decrypt after completion: %v", err)
	}
}

// TestTamperedHandshakeMessages verifies that tampered handshake messages
// surface as errors and the handshake never completes.
func TestTamperedHandshakeMessages(t *testing.T) {
	tamper := func(msg []byte) []byte {
		out := make([]byte, len(msg))
		copy(out, msg)
		out[len(out)-1] ^= 0x01
		return out
	}

	cases := []struct {
		name   string
		mutate func(step int, msg []byte) []byte
	}{
		{"tampered message 1", func(step int, msg []byte) []byte {
			if step == 1 {
				return tamper(msg)
			}
			return msg
		}},
		{"tampered message 2", func(step int, msg []byte) []byte {
			if step == 2 {
				return tamper(msg)
			}
			return msg
		}},
		{"tampered message 3", func(step int, msg []byte) []byte {
			if step == 3 {
				return tamper(msg)
			}
			return msg
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			init, resp := newTestSides(t, mustKeypair(t), mustKeypair(t), testPrologue, testPrologue)
			if _, _, err := runHandshake(init, resp, tc.mutate); err == nil {
				t.Fatal("handshake with tampered message succeeded, want error")
			}
		})
	}
}

// TestMismatchedPrologue verifies that peers using different prologues fail
// the handshake.
func TestMismatchedPrologue(t *testing.T) {
	init, resp := newTestSides(t, mustKeypair(t), mustKeypair(t),
		[]byte("prologue-a"), []byte("prologue-b"))
	if _, _, err := runHandshake(init, resp, nil); err == nil {
		t.Fatal("handshake with mismatched prologue succeeded, want error")
	}
}

// TestWrongPeerStatic verifies that an initiator cannot establish a session
// with a responder whose static key differs from the peerStatic it supplied.
func TestWrongPeerStatic(t *testing.T) {
	init, err := NewInitiator(mustKeypair(t), mustKeypair(t).Public, testPrologue)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	resp, err := NewResponder(mustKeypair(t), testPrologue)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	if _, _, err := runHandshake(init, resp, nil); err == nil {
		t.Fatal("handshake with wrong peer static succeeded, want error")
	}
}

// TestWrongSessionDecrypt verifies that ciphertext produced by a session's
// send state cannot be read back with that session's own recv state, and that
// replaying a ciphertext is rejected by the in-order nonce.
func TestWrongSessionDecrypt(t *testing.T) {
	init, resp := newTestSides(t, mustKeypair(t), mustKeypair(t), testPrologue, testPrologue)
	sInit, sResp, err := runHandshake(init, resp, nil)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// Wrong session: ciphertext produced by the initiator's send state cannot
	// be opened by the initiator's own recv state (different keys).
	first, err := sInit.Encrypt([]byte("first"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := sInit.Decrypt(first); err == nil {
		t.Fatal("decrypting own ciphertext with the same session succeeded, want error")
	}

	// The legitimate counterpart of "first" decrypts fine, and replaying it
	// is rejected by the in-order nonce.
	second, err := sInit.Encrypt([]byte("second"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := sResp.Decrypt(first); err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}
	if _, err := sResp.Decrypt(first); err == nil {
		t.Fatal("replayed ciphertext decrypted, want error")
	}
	if _, err := sResp.Decrypt(second); err != nil {
		t.Fatalf("Decrypt(second): %v", err)
	}

	// Wrong session, responder side: ciphertext produced by the responder's
	// send state cannot be opened by its own recv state, but decrypts fine on
	// the initiator.
	r1, err := sResp.Encrypt([]byte("responder secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := sResp.Decrypt(r1); err == nil {
		t.Fatal("decrypting own ciphertext with the same session succeeded, want error")
	}
	if _, err := sInit.Decrypt(r1); err != nil {
		t.Fatalf("initiator Decrypt: %v", err)
	}
}

// TestOutOfOrderHandshakeCalls verifies the role machines reject calls that
// skip or repeat handshake steps.
func TestOutOfOrderHandshakeCalls(t *testing.T) {
	initKP := mustKeypair(t)
	respKP := mustKeypair(t)

	init, resp := newTestSides(t, initKP, respKP, testPrologue, testPrologue)

	msg1, err := init.Message1()
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	if _, err := init.Message1(); err == nil {
		t.Fatal("second Message1 succeeded, want error")
	}
	if _, err := init.WriteMessage3(); err == nil {
		t.Fatal("WriteMessage3 before ReadMessage2 succeeded, want error")
	}

	if err := resp.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	if err := resp.ReadMessage1(msg1); err == nil {
		t.Fatal("second ReadMessage1 succeeded, want error")
	}
	msg2, err := resp.Message2()
	if err != nil {
		t.Fatalf("Message2: %v", err)
	}
	if _, err := resp.Message2(); err == nil {
		t.Fatal("second Message2 succeeded, want error")
	}

	if _, err := init.ReadMessage2(msg2); err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}
	if _, err := init.ReadMessage2(msg2); err == nil {
		t.Fatal("second ReadMessage2 succeeded, want error")
	}
	msg3, err := init.WriteMessage3()
	if err != nil {
		t.Fatalf("WriteMessage3: %v", err)
	}
	if _, err := init.WriteMessage3(); err == nil {
		t.Fatal("second WriteMessage3 succeeded, want error")
	}

	if _, err := resp.ReadMessage3(msg3); err != nil {
		t.Fatalf("ReadMessage3: %v", err)
	}
	if _, err := resp.ReadMessage3(msg3); err == nil {
		t.Fatal("second ReadMessage3 succeeded, want error")
	}
}

// establishSessions runs a complete XX handshake and returns both completed
// sessions.
func establishSessions(t *testing.T) (*Session, *Session) {
	t.Helper()
	init, resp := newTestSides(t, mustKeypair(t), mustKeypair(t), testPrologue, testPrologue)
	sInit, sResp, err := runHandshake(init, resp, nil)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	return sInit, sResp
}

// TestSendNoncesAreOrdered verifies that Send hands out the explicit wire
// nonces in strict order starting at zero.
func TestSendNoncesAreOrdered(t *testing.T) {
	sInit, sResp := establishSessions(t)
	_ = sResp
	for want := uint64(0); want < 8; want++ {
		got, ct, err := sInit.Send([]byte("x"))
		if err != nil {
			t.Fatalf("Send(%d): %v", want, err)
		}
		if got != want {
			t.Fatalf("Send nonce = %d, want %d", got, want)
		}
		if len(ct) != 1+aeadTag {
			t.Fatalf("ciphertext length = %d, want %d", len(ct), 1+aeadTag)
		}
	}
}

// TestSendNonceExhaustion verifies that once the counter passes MaxNonce the
// session refuses to encrypt further.
func TestSendNonceExhaustion(t *testing.T) {
	sInit, _ := establishSessions(t)
	sInit.sendCount = MaxNonce + 1
	if _, _, err := sInit.Send([]byte("gone")); err == nil {
		t.Fatal("Send past MaxNonce succeeded, want error")
	}
}

// TestRekeyJumpCapped verifies the rekey DoS guard: a frame whose nonce demands
// more than maxEpochJump rekey operations is rejected without burning CPU, in
// both directions.
func TestRekeyJumpCapped(t *testing.T) {
	sInit, sResp := establishSessions(t)
	sInit.sendCount = 100 * DefaultRekeyEvery // epoch 100, far beyond the cap
	if _, _, err := sInit.Send([]byte("x")); err == nil {
		t.Fatal("Send ahead of the rekey cap succeeded, want error")
	}
	if _, err := sResp.DecryptAt(100*DefaultRekeyEvery, []byte("x")); err == nil {
		t.Fatal("DecryptAt ahead of the rekey cap succeeded, want error")
	}
}

// TestDecryptAtLossReorderAndRekey exercises the receiver's explicit-nonce
// decrypt path under a tiny rekey boundary: whole messages are dropped,
// frames within one epoch arrive reordered, and the receiver crosses several
// epochs while still opening every delivered frame.
func TestDecryptAtLossReorderAndRekey(t *testing.T) {
	sInit, sResp := establishSessions(t)
	const rekeyEvery = 4
	sInit.rekeyEvery = rekeyEvery
	sResp.rekeyEvery = rekeyEvery

	const n = 10
	type sent struct {
		nonce uint64
		ct    []byte
		msg   []byte
	}
	var msgs [n]sent
	for i := 0; i < n; i++ {
		msg := []byte{byte(i)}
		nonce, ct, err := sInit.Send(msg)
		if err != nil {
			t.Fatalf("Send(%d): %v", i, err)
		}
		msgs[i] = sent{nonce: nonce, ct: ct, msg: msg}
	}

	// Delivery: epoch-0 frames reordered (0,3,2,1), then a jump into
	// epoch 1 at nonce 6 (4 and 5 lost), then the late same-epoch 4 and 5,
	// then epoch 2 at 8 (7 lost). Rekey is driven by each frame's own nonce,
	// so gaps never deadlock the session.
	order := []int{0, 3, 2, 1, 6, 4, 5, 8}
	for _, idx := range order {
		pt, err := sResp.DecryptAt(msgs[idx].nonce, msgs[idx].ct)
		if err != nil || !bytes.Equal(pt, msgs[idx].msg) {
			t.Fatalf("DecryptAt(nonce=%d): err=%v pt=%x want=%x", msgs[idx].nonce, err, pt, msgs[idx].msg)
		}
	}
}

// TestRekeyRotatesKeys verifies the rekey actually changes the active key: a
// frame from an earlier epoch can no longer be opened once the receiver has
// processed messages in a later epoch.
func TestRekeyRotatesKeys(t *testing.T) {
	sInit, sResp := establishSessions(t)
	const rekeyEvery = 2
	sInit.rekeyEvery = rekeyEvery
	sResp.rekeyEvery = rekeyEvery

	c0, err := sInit.Encrypt([]byte("epoch zero"))
	if err != nil {
		t.Fatalf("Encrypt(0): %v", err)
	}
	if _, err := sResp.Decrypt(c0); err != nil {
		t.Fatalf("Decrypt(0): %v", err)
	}
	c1, err := sInit.Encrypt([]byte("epoch zero still"))
	if err != nil {
		t.Fatalf("Encrypt(1): %v", err)
	}
	if _, err := sResp.Decrypt(c1); err != nil {
		t.Fatalf("Decrypt(1): %v", err)
	}

	// Nonce 2 is the first message of epoch 1: both sides rotate their keys
	// before encrypting/decrypting it.
	nonce, c2, err := sInit.Send([]byte("epoch one"))
	if err != nil {
		t.Fatalf("Send(2): %v", err)
	}
	if nonce != 2 {
		t.Fatalf("nonce = %d, want 2", nonce)
	}
	if _, err := sResp.DecryptAt(2, c2); err != nil {
		t.Fatalf("DecryptAt(2): %v", err)
	}

	// The epoch-0 ciphertext can no longer be opened after the rotation.
	if _, err := sResp.DecryptAt(0, c0); err == nil {
		t.Fatal("epoch-0 frame decrypted after rekey, want error")
	}
}
