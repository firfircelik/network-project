// Package tun provides raw L3 tunnel device access for meshlink. It opens a
// TUN interface (macOS utun, Linux /dev/net/tun) delivering and accepting
// plain IPv4 packets, plus an in-memory fake for tests and an IP routing
// layer separate from the OS device.
//
// Opening a real TUN interface requires root; the agent therefore treats the
// device as optional (see docs/TUN.md for the OS configuration steps).
package tun

// defaultMTU is used when a device is opened without an explicit MTU.
const defaultMTU = 1500

// Device is a raw L3 tunnel endpoint. Read returns one plain IP packet at a
// time (truncated to the buffer), Write transmits one. Behavior after Close
// is unspecified.
type Device interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	// Name reports the OS interface name (e.g. "utun9").
	Name() string
	MTU() int
}

// Open opens the named TUN device. An empty name asks the platform for a free
// interface. Opening requires root.
func Open(name string, mtu int) (Device, error) {
	return openDevice(name, mtu)
}
