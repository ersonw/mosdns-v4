//go:build linux

package alias

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToDevice forces every socket of this dialer out of one interface, so the
// outlet follows the configured dev even when the host routing table would
// choose another path.
func bindToDevice(d *net.Dialer, dev string) {
	d.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
