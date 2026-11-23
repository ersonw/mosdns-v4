package egress

import (
	"net/netip"
	"time"
)

// Small read-only accessors for the fields a caller outside this package
// legitimately needs: the gost outlet reports which flavour answered so the
// startup log can name it. Everything else stays private, because an outlet is
// only supposed to be used through Dialer.

// Server reports the proxy address an outlet talks to.
func (e *gostEgress) Server() string { return e.server }

// TCPProtocols lists the gost flavours whose handshake succeeded.
func (e *gostEgress) TCPProtocols() []string { return e.tcpProtocols() }

// UDPProtocols lists the gost flavours whose UDP association was granted.
func (e *gostEgress) UDPProtocols() []string { return e.udpProtocols() }

// Server reports the SOCKS5 server address.
func (e *socks5Egress) Server() string { return e.server }

// RemoteDNS reports whether the SOCKS5 outlet resolves the name on the far
// side instead of locally.
func (e *socks5Egress) RemoteDNS() bool { return e.remoteDNS }

// Server reports the HTTP proxy address.
func (e *httpEgress) Server() string { return e.server }

// Server reports the trojan server address.
func (e *trojanEgress) Server() string { return e.server }

// Dev reports the device the direct outlet is bound to, if any.
func (e *directEgress) Dev() string { return e.dev }

// SetDev pins the direct outlet to a device.
func (e *directEgress) SetDev(dev string) { e.dev = dev }

// SetLocal pins the direct outlet's source address.
func (e *directEgress) SetLocal(addr netip.Addr) { e.local = addr }

// SetTimeout bounds a dial attempt. A caller that already sets a context
// deadline does not need it, but an outlet reused as another outlet's base
// dialer often dials under the parent request's context alone.
func (e *directEgress) SetTimeout(d time.Duration) { e.dialer.Timeout = d }

// Describe is the log form of an outlet: protocol and server, never the
// credentials.
func Describe(d Dialer) string { return describeEgress(unwrapDialer(d)) }

// FakeRange reports the range this outlet refuses to dial, because the plugin
// itself answered that address and the name must survive instead.
func (e *socks5Egress) FakeRange() netip.Prefix { return e.fakeRange }

// SetBase pins the socket that reaches the proxy to an injected path, e.g. a
// direct outlet bound to a device. Nil restores the host's own routing.
func (e *socks5Egress) SetBase(d Dialer) { e.base = d }

// SetBase pins the proxy connection of the HTTP outlet.
func (e *httpEgress) SetBase(d Dialer) { e.base = d }

// SetBase pins the proxy connection of the trojan outlet.
func (e *trojanEgress) SetBase(d Dialer) { e.base = d }
