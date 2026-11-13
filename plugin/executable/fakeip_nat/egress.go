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
	"sort"
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

	case "gost":
		// gost can listen without naming a protocol and detect it from the
		// first bytes. Every flavour this plugin implements is built here and
		// probed at startup; the ones that answer are kept, the rest dropped.
		if port == "" {
			port = "1080"
		}
		return newGostEgress(net.JoinHostPort(host, port), host, user, pass, insecure), nil

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
	case *gostEgress:
		return "gost://" + e.server
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
	// fakeRange is the address range this plugin hands out itself. A local
	// lookup that lands inside it was answered by the plugin's own DNS, so
	// connecting to that address is pointless: the name is kept and the proxy
	// resolves it on the far side.
	fakeRange netip.Prefix
}

func (e *socks5Egress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(network, "udp") {
		return e.dialUDP(ctx, addr)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5 egress does not carry %q", network)
	}

	// socks5 resolves the target locally, socks5h lets the server resolve it.
	// The local answer is dropped when it names one of this plugin's own fake
	// addresses: the proxy would only try to reach a host that does not exist.
	if !e.remoteDNS {
		addr = e.targetAddr(ctx, addr)
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

	if _, err := readSocks5BindAddr(c); err != nil {
		return fmt.Errorf("socks5 connect %s: %w", addr, err)
	}
	return nil
}

// dialUDP opens a socks5 UDP association: the TCP connection stays open as the
// association, datagrams travel over a second socket to the relay the server
// returned.
func (e *socks5Egress) dialUDP(ctx context.Context, addr string) (net.Conn, error) {
	if _, err := appendProxyAddr(nil, addr); err != nil {
		return nil, err
	}
	var d net.Dialer
	ctrl, err := d.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 server %s: %w", e.server, err)
	}
	cleanup := func(err error) (net.Conn, error) {
		_ = ctrl.Close()
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(dl)
	}
	if err := e.negotiate(ctrl); err != nil {
		return cleanup(err)
	}
	if _, err := ctrl.Write(socks5UDPAssociateRequest()); err != nil {
		return cleanup(fmt.Errorf("socks5 udp associate: %w", err))
	}
	bnd, err := readSocks5BindAddr(ctrl)
	if err != nil {
		return cleanup(fmt.Errorf("socks5 udp associate: %w", err))
	}
	// A wildcard bind means "the address you reached me on".
	if host, port, herr := net.SplitHostPort(bnd); herr == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			proxyHost, _, _ := net.SplitHostPort(e.server)
			bnd = net.JoinHostPort(proxyHost, port)
		}
	}
	udp, err := d.DialContext(ctx, "udp", bnd)
	if err != nil {
		return cleanup(fmt.Errorf("socks5 udp relay %s: %w", bnd, err))
	}
	_ = ctrl.SetDeadline(time.Time{})
	return &socks5UDPConn{ctrl: ctrl, udp: udp, addr: addr}, nil
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
	return appendProxyAddr([]byte{0x05, 0x01, 0x00}, addr)
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

// targetAddr is the address a socks5 CONNECT carries. Local resolution is only
// trusted when it names something reachable outside this plugin; in fake-ip
// mode the host resolver is the plugin itself, so a lookup hands back one of
// its own fake addresses and the domain has to be left for the proxy to
// resolve.
func (e *socks5Egress) targetAddr(ctx context.Context, addr string) string {
	return chooseProxyTarget(addr, resolveLocally(ctx, addr), e.fakeRange)
}

// chooseProxyTarget prefers the locally resolved address unless it names one of
// the plugin's own fake addresses, in which case the original name is kept so
// the proxy resolves it on the far side.
func chooseProxyTarget(addr, resolved string, fake netip.Prefix) string {
	if fakeAddressInRange(resolved, fake) {
		return addr
	}
	return resolved
}

// fakeAddressInRange reports whether target is a literal ip inside the plugin's
// own range. A name that does not parse as an ip never counts.
func fakeAddressInRange(target string, fake netip.Prefix) bool {
	if !fake.IsValid() {
		return false
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return false
	}
	return fake.Contains(addr)
}

// setFakeRange teaches the socks5 outlets which addresses they must never dial.
// Only socks5 resolves locally, so the other outlets report false and keep
// sending the domain unchanged. A gost outlet forwards the call to the socks5
// flavours it keeps.
func setFakeRange(d egressDialer, prefix netip.Prefix) bool {
	switch e := d.(type) {
	case *socks5Egress:
		e.fakeRange = prefix
		return true
	case *gostEgress:
		applied := false
		for _, c := range e.all {
			if setFakeRange(c, prefix) {
				applied = true
			}
		}
		return applied
	}
	return false
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

// Probe proves the listener speaks HTTP: the CONNECT request must be answered
// with a status line. A bare TCP connect cannot tell an HTTP proxy from a socks5
// one listening on the same port, which is exactly the case a gost listener
// creates.
func (e *httpEgress) Probe(ctx context.Context) error {
	c, err := e.dialProxy(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
	if e.user != "" || e.pass != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(e.user + ":" + e.pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return fmt.Errorf("http proxy probe write: %w", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return fmt.Errorf("http proxy probe read: %w", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.") {
		return fmt.Errorf("http proxy probe: not an http answer (%q)", strings.TrimSpace(line))
	}
	return nil
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
	if strings.HasPrefix(network, "udp") {
		return e.dialUDP(ctx, addr)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("trojan egress does not carry %q", network)
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

// dialUDP opens the TLS stream and switches it into UDP mode; every datagram
// after the header is a frame (see egress_trojan_udp.go).
func (e *trojanEgress) dialUDP(ctx context.Context, addr string) (net.Conn, error) {
	if _, err := encodeTrojanUDPFrame(addr, nil); err != nil {
		return nil, err
	}
	c, err := e.dial(ctx)
	if err != nil {
		return nil, err
	}
	hdr, err := trojanUDPHeader(e.password)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if _, err := c.Write(hdr); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("trojan udp associate: %w", err)
	}
	return &trojanUDPConn{conn: c, addr: addr}, nil
}

func (e *trojanEgress) Probe(ctx context.Context) error {
	c, err := e.dial(ctx)
	if err != nil {
		return err
	}
	// A completed TLS handshake already proves the endpoint and the certificate
	// are usable; trojan has no plaintext handshake to verify.
	//
	// Closing without a header is deliberate: the server logs one "failed to
	// read hash | EOF" and pushes the connection to its TLS fallback for every
	// startup. That pair of lines is expected noise, not a broken outlet.
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

// gostCandidateProbe bounds one protocol probe of a gost listener. The listener
// answers on the first bytes, so a flavour that is not spoken there either
// closes the connection or stays silent; both are detected within this window.
const gostCandidateProbe = 1500 * time.Millisecond

// gostCandidate is one protocol of a gost listener together with the time its
// handshake took. The latency is what makes "use the fastest protocol for TCP"
// a measurement instead of a guess.
type gostCandidate struct {
	dialer  egressDialer
	latency time.Duration
}

// gostEgress speaks to a gost listener that was started without naming a
// protocol ("-L=user:pass@:1080"): gost detects the protocol from the first
// bytes, so the same address may answer socks5, http or trojan.
//
// Every flavour this plugin implements is built at startup and probed once,
// then kept in two ordered lists:
//
//   - tcp: every flavour that answered, fastest first, used for TCP flows;
//   - udp: only the flavours whose UDP association was granted, fastest first.
//
// A UDP flow therefore never even tries an http outlet, and a TCP flow goes
// straight to the protocol with the shortest handshake. When the chosen list is
// empty, or every entry fails while connecting, the flow leaves through the
// host network just like a run without a proxy link.
type gostEgress struct {
	server string
	all    []egressDialer
	tcp    []gostCandidate
	udp    []gostCandidate
}

// newGostEgress builds the candidate list. socks5h comes first because it keeps
// the domain on the proxy side, which is the only safe choice when this plugin
// is the client's resolver.
func newGostEgress(server, host, user, pass string, insecure bool) *gostEgress {
	return &gostEgress{
		server: server,
		all: []egressDialer{
			&socks5Egress{server: server, user: user, pass: pass, remoteDNS: true},
			&socks5Egress{server: server, user: user, pass: pass},
			&trojanEgress{server: server, password: gostPassword(user, pass), sni: host, insecure: insecure},
			&httpEgress{server: server, user: user, pass: pass, tlsCfg: &tls.Config{ServerName: host, InsecureSkipVerify: insecure}},
			&httpEgress{server: server, user: user, pass: pass},
		},
	}
}

// gostPassword picks the credential a trojan handshake uses. The link form is
// user:pass, so the password half wins; a link with only a user keeps that
// value.
func gostPassword(user, pass string) string {
	if pass != "" {
		return pass
	}
	return user
}

// udpDialer is implemented by the outlets that can carry a datagram: socks5
// through RFC 1928 UDP ASSOCIATE, trojan through its udp-associate stream.
type udpDialer interface {
	dialUDP(ctx context.Context, addr string) (net.Conn, error)
}

// Probe keeps only the flavours the listener actually answered, times each
// handshake, and records which of them accepted a UDP association. It returns
// an error when no flavour answers at all, which makes the caller keep the
// direct outlet.
func (e *gostEgress) Probe(ctx context.Context) error {
	tcp := make([]gostCandidate, 0, len(e.all))
	udp := make([]gostCandidate, 0, len(e.all))
	dropped := make([]string, 0, len(e.all))
	for _, c := range e.all {
		prober, ok := c.(egressProber)
		if !ok {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, gostCandidateProbe)
		start := time.Now()
		err := prober.Probe(probeCtx)
		latency := time.Since(start)
		cancel()
		if err != nil {
			dropped = append(dropped, describeEgress(c))
			continue
		}
		tcp = append(tcp, gostCandidate{dialer: c, latency: latency})

		// Only a flavour whose association is granted may carry UDP. The
		// request is opened and closed without sending a datagram.
		if _, ok := c.(udpDialer); ok {
			udpCtx, udpCancel := context.WithTimeout(ctx, gostCandidateProbe)
			conn, udpErr := c.(udpDialer).dialUDP(udpCtx, "127.0.0.1:9")
			udpCancel()
			if udpErr != nil {
				dropped = append(dropped, describeEgress(c)+" (udp)")
				continue
			}
			_ = conn.Close()
			udp = append(udp, gostCandidate{dialer: c, latency: latency})
		}
	}
	if len(tcp) == 0 {
		return fmt.Errorf("gost listener %s answered no supported protocol (tried %s)",
			e.server, strings.Join(dropped, ", "))
	}
	sortCandidates(tcp)
	sortCandidates(udp)
	e.tcp, e.udp = tcp, udp
	return nil
}

// sortCandidates orders a list fastest-first. The sort is stable, so two
// protocols with the same handshake time keep their configured preference
// (socks5h before socks5, which matters in a fake-ip deployment).
func sortCandidates(list []gostCandidate) {
	sort.SliceStable(list, func(i, j int) bool { return list[i].latency < list[j].latency })
}

// DialContext picks the list that matches the flow: UDP only ever uses a
// protocol whose association was granted; TCP uses the fastest protocol for
// HTTP/HTTPS ports and prefers socks5 for every other port, so an SSH flow
// never lands on gost's HTTP listener just because its handshake was quicker.
// A flavour that fails while connecting falls through to the next, and when the
// list is exhausted the connection leaves without the proxy.
func (e *gostEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	list := e.tcp
	if strings.HasPrefix(network, "udp") {
		list = e.udp
	} else {
		list = e.tcpFor(addr)
	}

	var lastErr error
	for _, c := range list {
		conn, err := c.dialer.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	var direct directEgress
	conn, err := direct.DialContext(ctx, network, addr)
	if err != nil {
		if lastErr != nil {
			return nil, fmt.Errorf("gost candidates failed (%v) and direct dial failed: %w", lastErr, err)
		}
		return nil, err
	}
	return conn, nil
}

// tcpFor keeps the measured fastest-first order for HTTP/HTTPS ports. For all
// other ports it puts the socks5 flavours first and preserves their relative
// order, then appends the remaining protocols in their original order. If no
// socks5 flavour survived the probe, the original list is used unchanged.
func (e *gostEgress) tcpFor(addr string) []gostCandidate {
	if isHTTPPort(addr) {
		return e.tcp
	}
	socks := make([]gostCandidate, 0, len(e.tcp))
	other := make([]gostCandidate, 0, len(e.tcp))
	for _, c := range e.tcp {
		if _, ok := c.dialer.(*socks5Egress); ok {
			socks = append(socks, c)
			continue
		}
		other = append(other, c)
	}
	if len(socks) == 0 {
		return e.tcp
	}
	return append(socks, other...)
}

// isHTTPPort reports whether addr targets the conventional HTTP or HTTPS
// port. The port is compared as text because net.SplitHostPort already
// normalizes an IPv6 bracket form and a missing port has no HTTP meaning.
func isHTTPPort(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return port == "80" || port == "443"
}

// tcpProtocols reports the TCP order kept for this outlet, for the startup log.
func (e *gostEgress) tcpProtocols() []string {
	return describeCandidates(e.tcp)
}

// udpProtocols reports the UDP order kept for this outlet.
func (e *gostEgress) udpProtocols() []string {
	return describeCandidates(e.udp)
}

func describeCandidates(list []gostCandidate) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, fmt.Sprintf("%s (%s)", describeEgress(c.dialer), c.latency.Round(time.Microsecond)))
	}
	return out
}
