//go:build !darwin && !linux

package tun

import "errors"

// openDevice reports that the platform has no supported TUN backend yet.
func openDevice(name string, mtu int) (Device, error) {
	return nil, errors.New("tun: unsupported platform")
}
