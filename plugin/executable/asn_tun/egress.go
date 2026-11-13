package asn_tun

import (
	"context"
	"net"
	"syscall"
)

type egressDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type directEgress struct {
	mark uint32
	dev  string
}

func (e *directEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{}
	if e.mark != 0 || e.dev != "" {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			return applySocketOptions(c, e.mark, e.dev)
		}
	}
	return d.DialContext(ctx, network, addr)
}
