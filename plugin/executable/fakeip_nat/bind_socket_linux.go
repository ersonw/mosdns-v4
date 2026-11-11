//go:build linux

package fakeipnat

import "syscall"

// bindSocketToDevice pins an already opened socket to one interface
// (SO_BINDTODEVICE). The egress dialer is bound the same way, see
// egress_bind_linux.go; this variant works on the raw ICMP socket and on the
// per-probe UDP sockets, so ICMP leaves through the configured interface
// instead of the system default route. An empty name leaves it unbound.
func bindSocketToDevice(fd uintptr, dev string) error {
	if dev == "" {
		return nil
	}
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, soBindToDevice, dev)
}
