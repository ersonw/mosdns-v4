//go:build !linux && !darwin && !freebsd

package fakeipnat

import (
	"errors"
	"net"
)

func listenRawICMP() (*net.IPConn, error) {
	return nil, errors.New("raw icmp socket is not implemented on this platform")
}
