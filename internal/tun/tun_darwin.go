//go:build darwin

package tun

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// utunHeaderLen is the [family u16][interface index u16] prefix macOS utun
// prepends to every packet read from the device and expects on every packet
// written to it in the default (non-packet) mode.
const utunHeaderLen = 4

// openDevice opens /dev/utunN. A requested "utun3" or "/dev/utun3" name maps
// to /dev/utun3; an empty name probes the kernel for the first free one.
func openDevice(name string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	var candidates []string
	switch {
	case name == "":
		for i := 0; i < 16; i++ {
			candidates = append(candidates, fmt.Sprintf("/dev/utun%d", i))
		}
	case strings.HasPrefix(name, "/dev/"):
		candidates = []string{name}
	default:
		candidates = []string{"/dev/" + name}
	}
	var lastErr error
	for _, path := range candidates {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			lastErr = err
			continue
		}
		ifname := strings.TrimPrefix(path, "/dev/")
		return &utunDevice{f: f, name: ifname, mtu: mtu}, nil
	}
	if lastErr == nil {
		lastErr = io.EOF
	}
	return nil, fmt.Errorf("tun: open utun: %w", lastErr)
}

type utunDevice struct {
	f    *os.File
	name string
	mtu  int
}

func (d *utunDevice) Name() string { return d.name }
func (d *utunDevice) MTU() int     { return d.mtu }
func (d *utunDevice) Close() error { return d.f.Close() }

// Read strips the 4-byte utun header before handing back the IP packet.
func (d *utunDevice) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+utunHeaderLen)
	n, err := d.f.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < utunHeaderLen {
		return 0, io.ErrUnexpectedEOF
	}
	return copy(p, buf[utunHeaderLen:n]), nil
}

// Write prepends the utun header with family 0, letting the kernel infer the
// protocol family from the IP header.
func (d *utunDevice) Write(p []byte) (int, error) {
	buf := make([]byte, utunHeaderLen+len(p))
	copy(buf[utunHeaderLen:], p)
	return d.f.Write(buf)
}
