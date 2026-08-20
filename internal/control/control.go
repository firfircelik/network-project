// Package control secures the meshlink control plane: agents and the
// coordinator establish a Noise XX session over the TCP control socket before
// exchanging any registry messages. The agent authenticates the coordinator
// against the static key it was configured with, and the coordinator learns
// the agent's static key from the handshake, so the register message's public
// key can be bound to the authenticated connection (G3: no plaintext control
// traffic, no name squatting with someone else's key).
package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"meshlink/internal/noisework"
)

// prologue keeps the control-plane transcript distinct from the data plane's,
// so no handshake transcript can be replayed across planes.
var prologue = []byte("meshlink-v1-control")

// maxMsgLen bounds a single control message (framed ciphertext). Control
// messages are JSON registrations and peer lists; 1 MiB is far beyond any
// legitimate payload but keeps the read buffer bounded.
const maxMsgLen = 1 << 20

// writeDeadline bounds a single control write so a stalled client cannot pin
// an open socket forever.
const writeDeadline = 5 * time.Second

// handshakeTimeout bounds the whole Noise handshake, so slow-loris style
// connection squatting on the coordinator cannot hold goroutines open forever.
const handshakeTimeout = 10 * time.Second

// Conn is an encrypted, framed control connection. Messages are exchanged as
// length-prefixed ciphertexts in flight order (TCP is reliable and ordered,
// so the in-order Decrypt form suffices; no explicit nonces are needed here).
type Conn struct {
	nc   net.Conn
	br   *bufio.Reader
	sess *noisework.Session

	wm sync.Mutex // serializes WriteMsg so concurrent broadcasters cannot interleave frames
}

// Initiate runs the initiator side of the control Noise handshake (the agent)
// over conn and returns a ready encrypted Conn. The coordinator's static key
// is pinned by peerStatic, so a MITM cannot impersonate the coordinator.
func Initiate(conn net.Conn, myKP *noisework.Keypair, peerStatic []byte) (*Conn, error) {
	br := bufio.NewReader(conn)
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	init, err := noisework.NewInitiator(myKP, peerStatic, prologue)
	if err != nil {
		return nil, fmt.Errorf("control: initiator: %w", err)
	}
	msg1, err := init.Message1()
	if err != nil {
		return nil, fmt.Errorf("control: message1: %w", err)
	}
	if err := writeRaw(conn, msg1); err != nil {
		return nil, fmt.Errorf("control: write message1: %w", err)
	}
	msg2, err := readRaw(br)
	if err != nil {
		return nil, fmt.Errorf("control: read message2: %w", err)
	}
	sess, err := init.ReadMessage2(msg2)
	if err != nil {
		return nil, fmt.Errorf("control: message2: %w", err)
	}
	msg3, err := init.WriteMessage3()
	if err != nil {
		return nil, fmt.Errorf("control: message3: %w", err)
	}
	if err := writeRaw(conn, msg3); err != nil {
		return nil, fmt.Errorf("control: write message3: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &Conn{nc: conn, br: br, sess: sess}, nil
}

// Accept runs the responder side of the control Noise handshake (the
// coordinator) over conn. It returns the agent's authenticated static key and
// a ready encrypted Conn.
func Accept(conn net.Conn, myKP *noisework.Keypair) (peerStatic []byte, c *Conn, err error) {
	br := bufio.NewReader(conn)
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	resp, err := noisework.NewResponder(myKP, prologue)
	if err != nil {
		return nil, nil, fmt.Errorf("control: responder: %w", err)
	}
	msg1, err := readRaw(br)
	if err != nil {
		return nil, nil, fmt.Errorf("control: read message1: %w", err)
	}
	if err := resp.ReadMessage1(msg1); err != nil {
		return nil, nil, fmt.Errorf("control: message1: %w", err)
	}
	msg2, err := resp.Message2()
	if err != nil {
		return nil, nil, fmt.Errorf("control: message2: %w", err)
	}
	if err := writeRaw(conn, msg2); err != nil {
		return nil, nil, fmt.Errorf("control: write message2: %w", err)
	}
	msg3, err := readRaw(br)
	if err != nil {
		return nil, nil, fmt.Errorf("control: read message3: %w", err)
	}
	sess, err := resp.ReadMessage3(msg3)
	if err != nil {
		return nil, nil, fmt.Errorf("control: message3: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return sess.PeerStatic(), &Conn{nc: conn, br: br, sess: sess}, nil
}

// WriteMsg encrypts and writes one control message. The whole operation runs
// under a single lock: encryption mutates the Noise cipher state (the AEAD
// nonce counter), so two concurrent writers MUST NOT encrypt concurrently or
// the same key+nonce would be used twice. The lock also stops broadcasters
// from interleaving the 4-byte length header with its ciphertext.
func (c *Conn) WriteMsg(plaintext []byte) error {
	c.wm.Lock()
	defer c.wm.Unlock()
	ct, err := c.sess.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("control: encrypt: %w", err)
	}
	msg := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(msg[:4], uint32(len(ct)))
	copy(msg[4:], ct)
	_ = c.nc.SetWriteDeadline(time.Now().Add(writeDeadline))
	_, err = c.nc.Write(msg)
	return err
}

// ReadMsg reads, authenticates and decrypts one control message.
func (c *Conn) ReadMsg() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxMsgLen {
		return nil, errors.New("control: invalid message length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return nil, err
	}
	return c.sess.Decrypt(buf)
}

// Conn returns the underlying network connection, so callers can re-arm
// read deadlines between messages without a separate accessor.
func (c *Conn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.nc
}

// Close closes the underlying socket.
func (c *Conn) Close() error {
	if c == nil || c.nc == nil {
		return nil
	}
	return c.nc.Close()
}

func writeRaw(w io.Writer, b []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readRaw(r *bufio.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
