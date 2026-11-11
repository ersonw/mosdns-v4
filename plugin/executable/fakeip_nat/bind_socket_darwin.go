//go:build darwin

package fakeipnat

import (
	"net"
	"syscall"
)

// bindSocketToDevice pins an already opened socket to one interface
// (IP_BOUND_IF). The egress dialer is bound the same way, see
// egress_bind_darwin.go; this variant works on the raw ICMP socket and on the
// per-probe UDP sockets. An empty name leaves it unbound.
func bindSocketToDevice(fd uintptr, dev string) error {
	if dev == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifi.Index)
}
