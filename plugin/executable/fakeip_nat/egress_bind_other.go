//go:build !linux && !darwin

package fakeipnat

// Binding a socket to one interface is not implemented on this platform, so
// the outlet keeps the host routing decision.

import "net"

const sourceBindingSupported = false

func bindToDevice(d *net.Dialer, dev string) {}
