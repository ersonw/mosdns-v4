//go:build darwin

package egress

// This file binds an egress socket to one interface. Darwin has no
// SO_BINDTODEVICE; IP_BOUND_IF (25) takes an interface index instead.

import (
	"net"
	"syscall"
)

const ipBoundIf = 25

const sourceBindingSupported = false

// SourceBindingSupported reports whether the kernel accepts a source address
// owned by another interface.
const SourceBindingSupported = sourceBindingSupported

// IPBoundIf is the IP_BOUND_IF sockopt number, exposed for the socket layer
// that lives in the plugin.
const IPBoundIf = ipBoundIf

func bindToDevice(d *net.Dialer, dev string) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return
	}
	idx := ifi.Index
	d.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, idx)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
