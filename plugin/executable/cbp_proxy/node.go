package cbp_proxy

import (
	"net"
	"net/url"
	"strings"

	"github.com/ersonw/mosdns-v4/pkg/cbpcoord"
)

// nodeControlAddresses derives the CBP node's TCP control endpoints. These
// are node endpoints from NODE_LIST, not main-server candidates.
//
// Order: public TCP endpoint, public address plus the TCP port, direct TCP
// endpoint, LAN TCP endpoint.
func nodeControlAddresses(node cbpcoord.Node) []string {
	var raw []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			raw = append(raw, value)
		}
	}
	add(node.PublicTCPEndpoint)
	if node.PublicAddr != "" {
		if port := endpointPort(node.TCPEndpoint); port != "" {
			add(net.JoinHostPort(strings.Trim(node.PublicAddr, "[]"), port))
		}
	}
	add(node.TCPEndpoint)
	add(node.LANTCPEndpoint)
	return normalizeNodeAddresses(raw)
}

func endpointPort(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return ""
		}
		return u.Port()
	}
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	return port
}

func normalizeNodeAddresses(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "://") {
			u, err := url.Parse(value)
			if err != nil {
				continue
			}
			value = u.Host
		}
		host, port, err := net.SplitHostPort(value)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			continue
		}
		host = strings.Trim(host, "[]")
		if host == "0.0.0.0" || host == "::" {
			continue
		}
		normalized := net.JoinHostPort(host, port)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func nodeServerName(node cbpcoord.Node, address string) string {
	if strings.TrimSpace(node.PublicAddr) != "" {
		return strings.Trim(strings.TrimSpace(node.PublicAddr), "[]")
	}
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return ""
}
