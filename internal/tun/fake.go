package tun

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

// BufferDevice is an in-memory Device used by tests: packets written to it go
// into a queue that Read consumes, so a producer and consumer goroutine can be
// wired without any OS privileges.
type BufferDevice struct {
	name string
	mtu  int

	mu     sync.Mutex
	cond   *sync.Cond
	buf    [][]byte
	closed bool
}

// NewBufferDevice returns an in-memory Device.
func NewBufferDevice(name string, mtu int) *BufferDevice {
	d := &BufferDevice{name: name, mtu: mtu}
	if d.mtu <= 0 {
		d.mtu = defaultMTU
	}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func (d *BufferDevice) Name() string { return d.name }
func (d *BufferDevice) MTU() int     { return d.mtu }

func (d *BufferDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.cond.Broadcast()
	return nil
}

func (d *BufferDevice) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.buf) == 0 {
		if d.closed {
			return 0, io.EOF
		}
		d.cond.Wait()
	}
	n := copy(p, d.buf[0])
	d.buf = d.buf[1:]
	return n, nil
}

func (d *BufferDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, errors.New("tun: device closed")
	}
	cp := bytes.Clone(p)
	d.buf = append(d.buf, cp)
	d.cond.Signal()
	return len(p), nil
}
