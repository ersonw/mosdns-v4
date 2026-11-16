package alias

// egress.go decides the outlet. Only the data path calls it, so the domain is
// known here: a proxy gets "domain:port" and resolves nothing locally, a direct
// outlet resolves the name at this moment and dials the address from the
// configured interface and next hop.
//
// The outlets themselves live in pkg/egress and are shared with fakeip_nat and
// asn_tun. What stays plugin local is the one decision that is actually about
// this plugin: the socket that reaches the proxy is opened by the direct outlet,
// so it leaves through next_hop_dev like the rest of this plugin's traffic
// instead of the host's default route.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	outlet "github.com/ersonw/mosdns-v4/pkg/egress"
	"go.uber.org/zap"
)

const (
	dialTimeout       = 10 * time.Second
	proxyProbeTimeout = 5 * time.Second
)

// newProxyEgress builds the outlet described by a proxy link. base is the pinned
// direct outlet: every proxy connection is opened through it, so a proxy that is
// only reachable over next_hop_dev keeps working.
func newProxyEgress(raw string, insecure bool, base *outlet.Direct) (outlet.Dialer, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch scheme {
	case "socks5", "socks5h":
		if port == "" {
			port = "1080"
		}
		// remoteDNS: the proxy resolves the name, which is the point of this
		// data path - a local answer would be one of the plugin's own virtual
		// addresses.
		out := outlet.NewSocks5(net.JoinHostPort(host, port), user, pass, true)
		out.SetBase(base)
		return out, nil
	case "http", "https":
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "8080"
			}
		}
		var cfg *tls.Config
		if scheme == "https" {
			cfg = &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: insecure,
				MinVersion:         tls.VersionTLS12,
			}
		}
		out := outlet.NewHTTP(net.JoinHostPort(host, port), user, pass, cfg)
		out.SetBase(base)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", scheme)
	}
}

// probeProxy verifies the outlet before it carries traffic. The protocol check
// lives in pkg/egress, so a socks5 port that only completes a handshake and an
// HTTP proxy on the same port are told apart the same way everywhere.
func probeProxy(ctx context.Context, d outlet.Dialer) error {
	probeCtx, cancel := context.WithTimeout(ctx, proxyProbeTimeout)
	defer cancel()
	return outlet.Probe(probeCtx, d)
}

// redactURL drops the credentials before a link reaches a log.
func redactURL(raw string) string {
	return outlet.Redact(raw)
}

// dialTCP is the outlet decision of the TCP path.
func (p *plugin) dialTCP(ctx context.Context, name string, port uint16) (net.Conn, error) {
	target := dialHostPort(name, port)
	if p.proxy != nil {
		p.log().Debug("fakeip_alias: dial via proxy", zap.String("target", target))
		return p.proxy.DialContext(ctx, "tcp", target)
	}
	addr, err := p.resolveForDial(ctx, name)
	if err != nil {
		return nil, err
	}
	if addr.Is6() {
		// The device address is IPv4, so an IPv6 dial keeps the host source.
		d := net.Dialer{Timeout: dialTimeout}
		if dev := p.direct.Dev(); dev != "" {
			bindToDevice(&d, dev)
		}
		return d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
	}
	p.log().Debug("fakeip_alias: dial direct",
		zap.String("domain", name), zap.String("real_ip", addr.String()), zap.Uint16("port", port))
	return p.direct.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
}
