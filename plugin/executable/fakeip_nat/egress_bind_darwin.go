//go:build darwin

package fakeipnat

// This file binds an egress socket to one interface. Darwin has no
// SO_BINDTODEVICE; IP_BOUND_IF (25) takes an interface index instead.

import (
	"net"
	"syscall"
)

const ipBoundIf = 25

const sourceBindingSupported = false

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
