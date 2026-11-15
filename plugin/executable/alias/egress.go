package alias

// egress.go decides the outlet. Only the data path calls it, so the domain is
// known here: a proxy gets "domain:port" and resolves nothing locally, a direct
// outlet resolves the name at this moment and dials the address from the
// configured interface and next hop.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	dialTimeout       = 10 * time.Second
	resolveTimeout    = 5 * time.Second
	resolvedTTL       = 5 * time.Minute
	socks5Timeout     = 30 * time.Second
	proxyProbeTarget  = "example.com:80"
	proxyProbeTimeout = 5 * time.Second
)

type egress interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// directEgress dials through the host network. When the outlet is pinned, the
// socket is bound to the configured device and sourced from the device address,
// so it leaves through next_hop_dev and the ip rule installed at startup sends
// it into the dedicated routing table.
type directEgress struct {
	dev   string
	local netip.Addr
}

func (e *directEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	if e.local.IsValid() && !isIPv6Target(addr) {
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

func isIPv6Target(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	parsed, err := netip.ParseAddr(host)
	return err == nil && parsed.Is6()
}

// socks5Egress talks SOCKS5 and always forwards the domain name: the proxy
// resolves it, so the outlet needs no local resolution at all.
type socks5Egress struct {
	server string
	user   string
	pass   string
	dialer egress
}

func (e *socks5Egress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("socks5 outlet carries tcp only")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("socks5 target port %q is invalid", portStr)
	}

	conn, err := e.dialer.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s: %w", e.server, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(socks5Timeout))
	}

	methods := []byte{0x00}
	if e.user != "" {
		methods = []byte{0x00, 0x02}
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if reply[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 server answered version %d", reply[0])
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if e.user == "" {
			_ = conn.Close()
			return nil, fmt.Errorf("socks5 server requires authentication")
		}
		if err := e.authenticate(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case 0xff:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 server rejected every method")
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 server chose unsupported method %d", reply[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03}
	req = append(req, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect reply: %w", err)
	}
	if head[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: reply code %d", head[1])
	}
	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect reply has unknown address type %d", head[3])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (e *socks5Egress) authenticate(conn net.Conn) error {
	req := []byte{0x01, byte(len(e.user))}
	req = append(req, e.user...)
	req = append(req, byte(len(e.pass)))
	req = append(req, e.pass...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 auth write: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 auth reply: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 authentication rejected")
	}
	return nil
}

// httpEgress uses HTTP CONNECT, which every http proxy understands.
type httpEgress struct {
	server string
	auth   string
	dialer egress
}

func (e *httpEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("http outlet carries tcp only")
	}
	conn, err := e.dialer.DialContext(ctx, "tcp", e.server)
	if err != nil {
		return nil, fmt.Errorf("http proxy dial %s: %w", e.server, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(socks5Timeout))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if e.auth != "" {
		fmt.Fprintf(&sb, "Proxy-Authorization: Basic %s\r\n", e.auth)
	}
	sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http connect write: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http connect reply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy refused: %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// tlsEgress upgrades the connection to the proxy itself, which is what an
// "https://" proxy URL asks for: the CONNECT exchange then runs inside TLS.
type tlsEgress struct {
	inner egress
	cfg   *tls.Config
}

func (e *tlsEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := e.inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, e.cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls to proxy: %w", err)
	}
	return tlsConn, nil
}

func newProxyEgress(raw string, insecure bool, dialer *directEgress) (egress, error) {
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
		return &socks5Egress{server: net.JoinHostPort(host, port), user: user, pass: pass, dialer: dialer}, nil
	case "http", "https":
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "8080"
			}
		}
		auth := ""
		if user != "" {
			auth = base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		}
		var proxyDialer egress = dialer
		if scheme == "https" {
			proxyDialer = &tlsEgress{inner: dialer, cfg: &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: insecure,
				MinVersion:         tls.VersionTLS12,
			}}
		}
		return &httpEgress{server: net.JoinHostPort(host, port), auth: auth, dialer: proxyDialer}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", scheme)
	}
}

func probeProxy(ctx context.Context, e egress) error {
	probeCtx, cancel := context.WithTimeout(ctx, proxyProbeTimeout)
	defer cancel()
	conn, err := e.DialContext(probeCtx, "tcp", proxyProbeTarget)
	if err != nil {
		return err
	}
	return conn.Close()
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// resolver resolves a name at connection time through another plugin (a forward
// or a sequence). It must not lead back into this plugin, otherwise the answer
// would be one of its own virtual addresses.
type resolver struct {
	tag    string
	parent *coremain.BP

	mu    sync.Mutex
	cache map[string]resolvedEntry
}

type resolvedEntry struct {
	addr netip.Addr
	at   time.Time
}

var errNoResolvedAddress = errors.New("no address resolved")

func (r *resolver) lookup(ctx context.Context, name string) (netip.Addr, error) {
	if r == nil {
		return netip.Addr{}, errNoResolvedAddress
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]resolvedEntry, 64)
	}
	if e, ok := r.cache[name]; ok && time.Since(e.at) < resolvedTTL {
		r.mu.Unlock()
		return e.addr, nil
	}
	r.mu.Unlock()

	addr, err := r.query(ctx, name, dns.TypeA)
	if err != nil {
		addr, err = r.query(ctx, name, dns.TypeAAAA)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	r.mu.Lock()
	r.cache[name] = resolvedEntry{addr: addr, at: time.Now()}
	r.mu.Unlock()
	return addr, nil
}

// PurgeDomain drops cached addresses of domain and its subdomains, so a name
// that was just removed or re-added is resolved again on the next connection.
func (r *resolver) PurgeDomain(domainName string) {
	if r == nil {
		return
	}
	domainName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainName)), ".")
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.cache {
		if name == domainName || strings.HasSuffix(name, "."+domainName) {
			delete(r.cache, name)
		}
	}
}

// Clear drops every cached address.
func (r *resolver) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cache = make(map[string]resolvedEntry, 64)
	r.mu.Unlock()
}

func (r *resolver) query(ctx context.Context, name string, qtype uint16) (netip.Addr, error) {
	m := r.parent.M()
	if m == nil {
		return netip.Addr{}, fmt.Errorf("resolver %q: no mosdns instance", r.tag)
	}
	exec := m.GetExecutables()[r.tag]
	if exec == nil {
		return netip.Addr{}, fmt.Errorf("resolver plugin %q not found", r.tag)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	qCtx := query_context.NewContext(q, nil)
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	if err := executable_seq.ExecChainNode(ctx, qCtx, executable_seq.WrapExecutable(exec)); err != nil {
		return netip.Addr{}, fmt.Errorf("resolver %q: %w", r.tag, err)
	}
	resp := qCtx.R()
	if resp == nil {
		return netip.Addr{}, fmt.Errorf("resolver %q returned no answer", r.tag)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return netip.Addr{}, fmt.Errorf("resolver %q: rcode %s", r.tag, dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if addr, err := netip.ParseAddr(v.A.String()); err == nil {
				return addr, nil
			}
		case *dns.AAAA:
			if addr, err := netip.ParseAddr(v.AAAA.String()); err == nil {
				return addr, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %s", errNoResolvedAddress, name)
}

// resolveForDial turns a served name into a dialable address on the direct
// outlet.
func (p *plugin) resolveForDial(ctx context.Context, name string) (netip.Addr, error) {
	if p.resolve == nil {
		return netip.Addr{}, fmt.Errorf("resolver is not configured, cannot resolve %s for the direct outlet", name)
	}
	return p.resolve.lookup(ctx, name)
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
		if p.direct.dev != "" {
			bindToDevice(&d, p.direct.dev)
		}
		return d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
	}
	p.log().Debug("fakeip_alias: dial direct",
		zap.String("domain", name), zap.String("real_ip", addr.String()), zap.Uint16("port", port))
	return p.direct.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
}
