package fakeipnat

import (
	"context"
	"errors"
	"net"
	"strings"
)

// Egress is the outbound half shared with other TUN based plugins. The
// implementation stays private; callers only need the dial contract.
type Egress interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewProxyEgress builds the proxy outlet described by a proxy URL. It rejects
// an empty URL so a caller cannot accidentally get a direct outlet from this
// entry point.
func NewProxyEgress(raw string, insecure bool) (Egress, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty proxy url")
	}
	return newEgress(raw, insecure)
}

// ProbeEgress verifies a proxy before it is used for real traffic.
func ProbeEgress(ctx context.Context, e Egress) error {
	return probeEgress(ctx, e)
}
