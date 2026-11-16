// Package egress owns the outbound half of the TUN data paths: the dialer
// abstraction, the direct outlet (optionally bound to a device and a source
// address) and the proxy outlets (socks5, socks5h, gost, http, https, trojan),
// plus the startup probe that refuses an unusable proxy.
//
// The implementation used to live inside plugin/executable/fakeip_nat, which
// made that plugin double as a library: asn_tun imported it just to dial a
// proxy, and alias carried a second copy of the same three outlets. Moving it
// here keeps one implementation and lets every plugin depend on a package that
// depends on nothing of its own.
package egress

import (
	"context"
	"crypto/tls"
	"net/netip"
)

// Dialer is the outbound contract every outlet satisfies.
type Dialer = egressDialer

// Prober is implemented by outlets that can be verified before first use.
type Prober = egressProber

// Direct sends connections through the host network. The zero value is a
// plain direct outlet; NewDirect pins it to a device and a source address.
type Direct = directEgress

// Socks5 is the SOCKS5 outlet.
type Socks5 = socks5Egress

// HTTP is the HTTP CONNECT outlet (plain or TLS).
type HTTP = httpEgress

// Trojan is the trojan outlet.
type Trojan = trojanEgress

// Gost is the gost link outlet that probes several protocols per host.
type Gost = gostEgress

// CBP is the CBP/1 outlet. It is not a stream relay: it owns a tunnel session
// and a userspace IP stack, so TCP, UDP and ICMP all leave through one outlet.
type CBP = cbpEgress

// egressCloser is implemented by outlets that hold long-lived resources.
type egressCloser interface {
	Close() error
}

// Close releases whatever an outlet holds. A stream outlet holds nothing
// between dials, so it has no Close; an outlet that owns a tunnel gets torn
// down here when the plugin that built it is replaced or stopped.
func Close(d Dialer) error {
	if closer, ok := d.(egressCloser); ok {
		return closer.Close()
	}
	return nil
}

// New builds the outlet described by a proxy link. An empty link means direct
// egress, which is what a plugin without a proxy must use.
func New(raw string, insecure bool) (Dialer, error) {
	return newEgress(raw, insecure)
}

// NewDirect pins the direct outlet to a device and a source address. Both may
// be empty, which leaves the socket on the host's default route.
func NewDirect(dev string, local netip.Addr) *Direct {
	return &directEgress{dev: dev, local: local}
}

// NewSocks5 builds a SOCKS5 outlet that forwards the target to server.
func NewSocks5(server, user, pass string, remoteDNS bool) *Socks5 {
	return &socks5Egress{server: server, user: user, pass: pass, remoteDNS: remoteDNS}
}

// NewHTTP builds an HTTP CONNECT outlet. A nil tlsCfg means the proxy is
// reached in plain text; a non-nil one means HTTPS to the proxy.
func NewHTTP(server, user, pass string, tlsCfg *tls.Config) *HTTP {
	return &httpEgress{server: server, user: user, pass: pass, tlsCfg: tlsCfg}
}

// NewTrojan builds a trojan outlet.
func NewTrojan(server, password, sni string, insecure bool) *Trojan {
	return &trojanEgress{server: server, password: password, sni: sni, insecure: insecure}
}

// Probe verifies an outlet before it carries real traffic.
func Probe(ctx context.Context, d Dialer) error {
	return probeEgress(ctx, d)
}

// SetFakeRange teaches a SOCKS5 outlet the range this plugin hands out itself,
// so a fake answer is not dialed as if it were a real address.
func SetFakeRange(d Dialer, prefix netip.Prefix) bool {
	return setFakeRange(d, prefix)
}

// SetNoDirectFallback turns off the host-network fallback of a multi-protocol
// outlet: once every proxy flavour failed, the dial reports the error instead
// of leaving from this box's own address.
//
// It reports whether the outlet has such a fallback to disable. A link made of
// a single protocol never falls back, so a false result is not a failure.
func SetNoDirectFallback(d Dialer) bool {
	g, ok := d.(*gostEgress)
	if !ok {
		return false
	}
	g.noFallback = true
	return true
}

// Redact removes credentials from a proxy link before it reaches a log.
func Redact(raw string) string {
	return redactProxy(raw)
}

// ChooseProxyTarget decides what a SOCKS5 outlet is told to reach: the resolved
// address normally, but the original name when that address sits inside the
// range this plugin hands out itself, because only the far side can resolve it.
func ChooseProxyTarget(addr, resolved string, fake netip.Prefix) string {
	return chooseProxyTarget(addr, resolved, fake)
}

// FakeAddressInRange reports whether target is a literal ip inside fake.
func FakeAddressInRange(target string, fake netip.Prefix) bool {
	return fakeAddressInRange(target, fake)
}

// IPv6Target reports whether addr is an IPv6 host:port. A source address bound
// to the v4 range cannot be used against such a target.
func IPv6Target(addr string) bool { return isIPv6Target(addr) }
