//go:build !linux && !darwin

package egress

// Binding a socket to one interface is not implemented on this platform, so
// the outlet keeps the host routing decision.

import "net"

const sourceBindingSupported = false

// SourceBindingSupported reports whether the kernel accepts a source address
// owned by another interface.
const SourceBindingSupported = sourceBindingSupported

func bindToDevice(d *net.Dialer, dev string) {}
