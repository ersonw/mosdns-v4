//go:build linux

package fakeipnat

import (
	"net"
)

// listenRawICMP needs CAP_NET_RAW (root). It receives every ICMP packet of the
// host, so the caller filters for destination-unreachable / time-exceeded.
func listenRawICMP() (*net.IPConn, error) {
	return net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
}
