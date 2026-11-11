package fakeipnat

// This file is the egress half of the tun data path. Every TCP connection the
// userspace side accepts is dialed through an egressDialer, so a proxy link
// (socks5 / http / trojan) can replace the local network as the outlet.
//
// A proxy only makes sense with `use_tun: true`: the NAT data path is kernel
// DNAT and never sees the packets.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// egressDialer is the outbound side of the tun data path.
type egressDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// egressProber is implemented by outlets that can be verified before use.
type egressProber interface {
	Probe(ctx context.Context) error
}

// directEgress sends the connection through the host network, i.e. no proxy.
// When the tun outlet is pinned to a gateway/interface, local makes every
// socket leave from the range address (the one the tun device owns, already
// rewritten by the data path) and dev binds it to the configured interface.
type directEgress struct {
	dialer net.Dialer
	local  netip.Addr
	dev    string
}

func (e *directEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := e.dialer
	if e.local.IsValid() {
		ip := net.IP(e.local.AsSlice())
		if strings.HasPrefix(network, "udp") {
			d.LocalAddr = &net.UDPAddr{IP: ip}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	if e.dev != "" {
		bindToDevice(&d, e.dev)
	}
	return d.DialContext(ctx, network, addr)
}

// newEgress builds the outlet described by a proxy link. An empty link means
// direct egress.
func newEgress(raw string, insecure bool) (egressDialer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return &directEgress{}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy %q: %w", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid proxy %q: missing host", raw)
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
		return &socks5Egress{
			server:    net.JoinHostPort(host, port),
			user:      user,
			pass:      pass,
			remoteDNS: scheme == "socks5h",
		}, nil

	case "http", "https":
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "8080"
			}
		}
		e := &httpEgress{server: net.JoinHostPort(host, port), user: user, pass: pass}
		if scheme == "https" {
			e.tlsCfg = &tls.Config{ServerName: host, InsecureSkipVerify: insecure}
		}
		return e, nil

	case "trojan":
		if port == "" {
			port = "443"
		}
		if user == "" {
			return nil, fmt.Errorf("invalid trojan proxy %q: missing password", raw)
		}
		sni := u.Query().Get("sni")
		if sni == "" {
			sni = host
		}
		return &trojanEgress{
			server:   net.JoinHostPort(host, port),
			password: user,
			sni:      sni,
			insecure: insecure,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (supported: socks5, socks5h, http, https, trojan)", u.Scheme)
	}
}

// probeEgress verifies the outlet at startup so a broken link is reported
// immediately instead of on the first connection.
func probeEgress(ctx context.Context, d egressDialer) error {
	if p, ok := d.(egressProber); ok {
		return p.Probe(ctx)
	}
	return nil
}

// describeEgress is the log form of an outlet: protocol and server, never the
// credentials.
func describeEgress(d egressDialer) string {
	switch e := d.(type) {
	case *directEgress:
		return "direct"
	case *socks5Egress:
		if e.remoteDNS {
			return "socks5h://" + e.server
		}
		return "socks5://" + e.server
	case *httpEgress:
		if e.tlsCfg != nil {
			return "https://" + e.server
		}
		return "http://" + e.server
	case *trojanEgress:
		return "trojan://" + e.server
	default:
		return "unknown"
	}
}

// redactProxy keeps the credentials out of the logs.
func redactProxy(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host
}

// socks5Egress speaks RFC 1928 / RFC 1929.
type socks5Egress struct {
	server    string
	user      string
	pass      string
	remoteDNS bool
}

func (e *socks5Egress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5 egress supports tcp only, got %q", network)
	}

	// socks5 resolves the target locally, socks5h lets the server resolve it.
	if !e.remoteDNS {
		addr = resolveLocally(ctx, addr)
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 server %s: %w", e.server, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := e.negotiate(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := e.connect(c, addr); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func (e *socks5Egress) Probe(ctx context.Context) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return fmt.Errorf("dial socks5 server %s: %w", e.server, err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	// Only the method negotiation and the auth exchange are checked; a CONNECT
	// would depend on an arbitrary target being reachable through the proxy.
	return e.negotiate(c)
}

func (e *socks5Egress) negotiate(c net.Conn) error {
	methods := []byte{0x00}
	if e.user != "" || e.pass != "" {
		methods = append(methods, 0x02)
	}
	req := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}

	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return fmt.Errorf("socks5 method reply: %w", err)
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected reply version %#x", sel[0])
	}
	switch sel[1] {
	case 0x00:
		return nil
	case 0x02:
		if e.user == "" && e.pass == "" {
			return errors.New("socks5: server requires username/password, none configured")
		}
		return e.auth(c)
	case 0xFF:
		return errors.New("socks5: server rejected all offered auth methods")
	default:
		return fmt.Errorf("socks5: unsupported auth method %#x", sel[1])
	}
}

func (e *socks5Egress) auth(c net.Conn) error {
	req := []byte{0x01, byte(len(e.user))}
	req = append(req, e.user...)
	req = append(req, byte(len(e.pass)))
	req = append(req, e.pass...)
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("socks5 auth: %w", err)
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fmt.Errorf("socks5 auth reply: %w", err)
	}
	if rep[1] != 0x00 {
		return fmt.Errorf("socks5: authentication rejected (status %#x)", rep[1])
	}
	return nil
}

func (e *socks5Egress) connect(c net.Conn, addr string) error {
	req, err := socks5ConnectRequest(addr)
	if err != nil {
		return err
	}
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}

	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected connect reply version %#x", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect %s failed: %s", addr, socks5ReplyText(head[1]))
	}

	// The bound address in the reply is irrelevant, only its length matters.
	var n int
	switch head[3] {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fmt.Errorf("socks5 connect reply: %w", err)
		}
		n = int(l[0])
	default:
		return fmt.Errorf("socks5: unsupported bind address type %#x", head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, n+2)); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	return nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "ttl expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error %#x", code)
	}
}

// socks5ConnectRequest encodes a CONNECT for an ipv4, ipv6 or domain target.
func socks5ConnectRequest(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	buf := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01, ip4[0], ip4[1], ip4[2], ip4[3])
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("target host %q is too long for socks5", host)
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	return append(buf, byte(port>>8), byte(port&0xFF)), nil
}

// resolveLocally rewrites the host of addr to a literal ip; on failure the
// original addr is kept and the server does the resolving.
func resolveLocally(ctx context.Context, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return addr
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return addr
	}
	return net.JoinHostPort(ips[0].IP.String(), port)
}

// httpEgress dials through an HTTP CONNECT proxy.
type httpEgress struct {
	server string
	user   string
	pass   string
	tlsCfg *tls.Config // nil for plain http
}

func (e *httpEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("http egress supports tcp only, got %q", network)
	}
	c, err := e.dialProxy(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if e.user != "" || e.pass != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(e.user + ":" + e.pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy CONNECT write: %w", err)
	}

	br := bufio.NewReader(c)
	resp, err := br.ReadString('\n')
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy CONNECT read: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(resp))
	if len(fields) < 2 || fields[1] != "200" {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy CONNECT %s failed: %s", addr, strings.TrimSpace(resp))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("http proxy CONNECT headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func (e *httpEgress) Probe(ctx context.Context) error {
	c, err := e.dialProxy(ctx)
	if err != nil {
		return err
	}
	return c.Close()
}

func (e *httpEgress) dialProxy(ctx context.Context) (net.Conn, error) {
	if e.tlsCfg == nil {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", e.server)
		if err != nil {
			return nil, fmt.Errorf("dial http proxy %s: %w", e.server, err)
		}
		return c, nil
	}
	td := &tls.Dialer{Config: e.tlsCfg}
	c, err := td.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return nil, fmt.Errorf("dial https proxy %s: %w", e.server, err)
	}
	return c, nil
}

// trojanEgress speaks the trojan protocol over TLS (CONNECT only).
type trojanEgress struct {
	server   string
	password string
	sni      string
	insecure bool
}

func (e *trojanEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("trojan egress supports tcp only, got %q", network)
	}
	c, err := e.dial(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(trojanConnectRequest(e.password, addr)); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("trojan request: %w", err)
	}
	return c, nil
}

func (e *trojanEgress) Probe(ctx context.Context) error {
	c, err := e.dial(ctx)
	if err != nil {
		return err
	}
	// A completed TLS handshake already proves the endpoint and the certificate
	// are usable; trojan has no plaintext handshake to verify.
	return c.Close()
}

func (e *trojanEgress) dial(ctx context.Context) (net.Conn, error) {
	td := &tls.Dialer{Config: &tls.Config{ServerName: e.sni, InsecureSkipVerify: e.insecure}}
	c, err := td.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return nil, fmt.Errorf("dial trojan server %s: %w", e.server, err)
	}
	return c, nil
}

// trojanConnectRequest builds the v1 header: the first 56 hex chars of
// sha256(password), CRLF, command 1 (CONNECT), CRLF, target, CRLF.
func trojanConnectRequest(password, addr string) []byte {
	sum := sha256.Sum256([]byte(password))
	hash := hex.EncodeToString(sum[:])[:56]
	return []byte(hash + "\r\n1\r\n" + addr + "\r\n")
}
