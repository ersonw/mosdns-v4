//go:build linux

package asn_tun

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func applySocketOptions(c syscall.RawConn, mark uint32, dev string) error {
	var first error
	err := c.Control(func(fd uintptr) {
		if mark != 0 {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
				first = fmt.Errorf("set SO_MARK: %w", err)
				return
			}
		}
		if dev != "" {
			if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); err != nil {
				first = fmt.Errorf("bind to %s: %w", dev, err)
			}
		}
	})
	if err != nil {
		return err
	}
	return first
}
