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
// The server's control_addresses list is authoritative: it already carries
// every NIC/public control endpoint and is validated as IP:port. Only nodes
// from an older coordinator fall back to public_tcp_endpoint, tcp_endpoint,
// lan_tcp_endpoint and finally public_addr. public_addr is display metadata
// derived from an observed NAT address, so it must never be preferred over
// the published control endpoints. Order is only a stable tie-break; the
// dial path probes all entries and selects by latency.
func nodeControlAddresses(node cbpcoord.Node) []string {
	port := endpointPort(node.PublicTCPEndpoint)
	if port == "" {
		port = endpointPort(node.TCPEndpoint)
	}
	addAll := func(values ...string) []string {
		raw := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				raw = append(raw, value)
			}
		}
		return raw
	}

	if len(node.ControlAddresses) > 0 {
		raw := make([]string, 0, len(node.ControlAddresses))
		for _, value := range node.ControlAddresses {
			raw = append(raw, withNodePort(value, port))
		}
		if got := normalizeNodeAddresses(raw); len(got) > 0 {
			return got
		}
	}

	raw := addAll(node.PublicTCPEndpoint, node.TCPEndpoint, node.LANTCPEndpoint)
	if got := normalizeNodeAddresses(raw); len(got) > 0 {
		return got
	}
	if node.PublicAddr != "" {
		return normalizeNodeAddresses([]string{withNodePort(node.PublicAddr, port)})
	}
	return nil
}

// withNodePort turns a bare IP/host from the main-server address list into a
// host:port endpoint. Values that already carry a port or a URL scheme are
// passed through so normalizeNodeAddresses can parse them uniformly.
func withNodePort(value, port string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	if port == "" {
		return value
	}
	host := strings.Trim(value, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return ""
	}
	return net.JoinHostPort(host, port)
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
