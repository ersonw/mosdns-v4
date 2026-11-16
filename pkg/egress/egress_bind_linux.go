//go:build linux

package egress

// This file binds an egress socket to one interface. Linux exposes
// SO_BINDTODEVICE (25) for this; the constant is not exported by the syscall
// package, so it is spelled out here with its documented value.

import (
	"net"
	"syscall"
)

const soBindToDevice = 25

const sourceBindingSupported = true

// SourceBindingSupported reports whether the kernel accepts a source address
// owned by another interface. Exporting it keeps callers from re-deciding.
const SourceBindingSupported = sourceBindingSupported

func bindToDevice(d *net.Dialer, dev string) {
	d.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, soBindToDevice, dev)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
