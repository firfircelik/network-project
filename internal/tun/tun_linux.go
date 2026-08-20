//go:build linux

package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunPath   = "/dev/net/tun"
	tunSetIFF = 0x400454ca // TUNSETIFF
	iffTun    = 0x0001
	iffNoPI   = 0x1000
)

// openDevice creates a persistent L3 tun interface via /dev/net/tun. The name
// may contain a "%d" that the kernel fills in with a free index.
func openDevice(name string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	if name == "" {
		name = "meshlink%d"
	}
	f, err := os.OpenFile(tunPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open %s: %w", tunPath, err)
	}
	ifr, err := ifreqTun(name)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("tun: TUNSETIFF %s: %v", name, errno)
	}
	return &linuxDevice{f: f, name: ifrName(ifr), mtu: mtu}, nil
}

type linuxDevice struct {
	f    *os.File
	name string
	mtu  int
}

func (d *linuxDevice) Name() string { return d.name }
func (d *linuxDevice) MTU() int     { return d.mtu }
func (d *linuxDevice) Close() error { return d.f.Close() }
func (d *linuxDevice) Read(p []byte) (int, error) {
	return d.f.Read(p)
}
func (d *linuxDevice) Write(p []byte) (int, error) {
	return d.f.Write(p)
}

// ifreqTun builds the TUNSETIFF request (ifr_name + flags).
func ifreqTun(name string) ([40]byte, error) {
	var ifr [40]byte
	if len(name) >= unix.IFNAMSIZ {
		return ifr, fmt.Errorf("tun: interface name too long: %q", name)
	}
	copy(ifr[:unix.IFNAMSIZ-1], name)
	flags := (*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
	*flags = iffTun | iffNoPI
	return ifr, nil
}

func ifrName(ifr [40]byte) string {
	buf := ifr[:unix.IFNAMSIZ-1]
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
