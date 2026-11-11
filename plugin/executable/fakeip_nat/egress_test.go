package fakeipnat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/utils"
	"go.uber.org/zap"
)

// fakeSocks5 is a minimal RFC 1928 server: it negotiates auth, answers one
// CONNECT and reports the target it was asked to reach.
type fakeSocks5 struct {
	ln      net.Listener
	user    string
	pass    string
	targets chan string
}

func newFakeSocks5(t *testing.T, user, pass string) (*fakeSocks5, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSocks5{ln: ln, user: user, pass: pass, targets: make(chan string, 1)}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s, ln.Addr().String()
}

func (s *fakeSocks5) serve() {
	c, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()

	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(greet[1]))); err != nil {
		return
	}

	if s.user != "" {
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		var ver [1]byte
		if _, err := io.ReadFull(c, ver[:]); err != nil {
			return
		}
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		u := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		pw := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, pw); err != nil {
			return
		}
		if string(u) != s.user || string(pw) != s.pass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = c.Write([]byte{0x01, 0x00})
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	var hdr [3]byte // ver, cmd, rsv
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	var atyp [1]byte
	if _, err := io.ReadFull(c, atyp[:]); err != nil {
		return
	}
	var host string
	switch atyp[0] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	select {
	case s.targets <- net.JoinHostPort(host, strconv.Itoa(port)):
	default:
	}

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, c)
}

func TestNewEgressParsesProxies(t *testing.T) {
	if d, err := newEgress("", false); err != nil {
		t.Fatalf("empty proxy should mean direct: %v", err)
	} else if _, ok := d.(*directEgress); !ok {
		t.Fatalf("empty proxy = %T, want *directEgress", d)
	}

	s5, err := newEgress("socks5://127.0.0.1:1080", false)
	if err != nil {
		t.Fatalf("socks5 parse failed: %v", err)
	}
	got := s5.(*socks5Egress)
	if got.server != "127.0.0.1:1080" || got.remoteDNS {
		t.Fatalf("socks5 = %+v, want local dns on 127.0.0.1:1080", got)
	}

	s5h, err := newEgress("socks5h://user:secret@proxy.example", false)
	if err != nil {
		t.Fatalf("socks5h parse failed: %v", err)
	}
	gotH := s5h.(*socks5Egress)
	if !gotH.remoteDNS || gotH.user != "user" || gotH.pass != "secret" || gotH.server != "proxy.example:1080" {
		t.Fatalf("socks5h = %+v, want remote dns + creds + default port", gotH)
	}

	tr, err := newEgress("trojan://secret@example.com:4443?sni=sni.example", false)
	if err != nil {
		t.Fatalf("trojan parse failed: %v", err)
	}
	gotT := tr.(*trojanEgress)
	if gotT.server != "example.com:4443" || gotT.password != "secret" || gotT.sni != "sni.example" {
		t.Fatalf("trojan = %+v, want example.com:4443 + sni override", gotT)
	}

	if _, err := newEgress("http://127.0.0.1:3128", false); err != nil {
		t.Fatalf("http parse failed: %v", err)
	}
	if _, err := newEgress("https://proxy.example", false); err != nil {
		t.Fatalf("https parse failed: %v", err)
	}

	for _, raw := range []string{
		"ss://YWVzOnB3@host:8388",  // unsupported scheme
		"trojan://example.com:443", // no password
		"vmess://payload",          // unsupported scheme
		"socks5://",                // no host
		"http://:8080",             // no host
	} {
		if _, err := newEgress(raw, false); err == nil {
			t.Fatalf("newEgress(%q) should fail", raw)
		}
	}
}

func TestSocks5EgressDialsThroughServer(t *testing.T) {
	srv, addr := newFakeSocks5(t, "u", "p")
	d, err := newEgress("socks5h://u:p@"+addr, false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial through socks5 failed: %v", err)
	}
	defer c.Close()

	select {
	case target := <-srv.targets:
		if target != "example.com:443" {
			t.Fatalf("proxy was asked for %q, want example.com:443", target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never received the connect request")
	}
}

func TestSocks5ProbeValidatesAuth(t *testing.T) {
	_, addr := newFakeSocks5(t, "u", "p")
	d, err := newEgress("socks5h://u:p@"+addr, false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeEgress(ctx, d); err != nil {
		t.Fatalf("probe failed against a working proxy: %v", err)
	}
}

func TestSocks5ProbeFailsWhenServerIsDown(t *testing.T) {
	d, err := newEgress("socks5://127.0.0.1:1", false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeEgress(ctx, d); err == nil {
		t.Fatal("probe against a closed port should fail")
	}
}

func TestHTTPEgressRejectsUDP(t *testing.T) {
	// http/https only carry CONNECT; udp falls back to a direct socket.
	d, _ := newEgress("http://127.0.0.1:8080", false)
	if _, err := d.DialContext(context.Background(), "udp", "1.2.3.4:53"); err == nil {
		t.Fatal("http egress should reject udp")
	}
}

func TestSocks5ConnectRequestEncoding(t *testing.T) {
	req, err := socks5ConnectRequest("1.2.3.4:443")
	if err != nil {
		t.Fatalf("ipv4 target failed: %v", err)
	}
	want := []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB}
	if string(req) != string(want) {
		t.Fatalf("ipv4 request = %v, want %v", req, want)
	}

	req, err = socks5ConnectRequest("example.com:80")
	if err != nil {
		t.Fatalf("domain target failed: %v", err)
	}
	if req[3] != 0x03 || req[4] != byte(len("example.com")) || !strings.Contains(string(req), "example.com") {
		t.Fatalf("domain request = %v", req)
	}

	if _, err := socks5ConnectRequest("example.com"); err == nil {
		t.Fatal("target without port should fail")
	}
	if _, err := socks5ConnectRequest("example.com:99999"); err == nil {
		t.Fatal("out of range port should fail")
	}
}

func TestTrojanConnectRequest(t *testing.T) {
	req := trojanConnectRequest("secret", "example.com:443")
	sum := sha256.Sum256([]byte("secret"))
	hash := hex.EncodeToString(sum[:])[:56]

	if !strings.HasPrefix(string(req), hash+"\r\n1\r\n") {
		t.Fatalf("trojan header = %q, want hash + command 1", req)
	}
	if !strings.HasSuffix(string(req), "example.com:443\r\n") {
		t.Fatalf("trojan request = %q, want the target at the end", req)
	}
}

func TestArgsDecodeProxy(t *testing.T) {
	var args Args
	if err := utils.WeakDecode(map[string]interface{}{
		"tun_dev":        "tun9",
		"proxy":          "socks5://user:pass@127.0.0.1:1080",
		"proxy_insecure": true,
	}, &args); err != nil {
		t.Fatalf("decode args failed: %v", err)
	}
	if args.TunDev != "tun9" || args.Proxy != "socks5://user:pass@127.0.0.1:1080" || !args.ProxyInsecure {
		t.Fatalf("unexpected decode result: %+v", args)
	}
}

func TestInitRejectsUnsupportedProxyScheme(t *testing.T) {
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	_, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		Proxy:       "ss://YWVzOnB3@host:8388",
	})
	if err == nil {
		t.Fatal("an unsupported proxy scheme should fail startup")
	}
}

func TestInitWithoutTunKeepsDirectEgress(t *testing.T) {
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	plugin, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		Proxy:       "socks5://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	fp := plugin.(*FakeIPNatPlugin)
	t.Cleanup(func() { _ = fp.Close() })

	// use_tun is false, so the proxy must not be dialed at startup.
	if _, ok := fp.egress.(*directEgress); !ok {
		t.Fatalf("egress = %T, want *directEgress while use_tun is false", fp.egress)
	}
}

// A socks5 link resolves the target with the host resolver. When that answer is
// one of the plugin's own fake addresses, the domain must survive: the proxy
// would otherwise be told to connect to a host that does not exist, which is
// exactly the "dial tcp 198.18.x.x: i/o timeout" seen on the far side.
func TestChooseProxyTargetKeepsDomainForFakeAnswer(t *testing.T) {
	fake := netip.MustParsePrefix("198.18.0.0/15")
	cases := []struct {
		addr     string
		resolved string
		want     string
	}{
		// The host resolver is this plugin: the answer is a fake ip, so the
		// name has to reach the proxy unchanged.
		{"www.google.com:443", "198.18.0.27:443", "www.google.com:443"},
		{"www.google.com:443", "198.19.11.31:443", "www.google.com:443"},
		// A public answer keeps the old behaviour.
		{"www.google.com:443", "142.250.0.1:443", "142.250.0.1:443"},
		// A failed lookup already keeps the name; it must stay untouched.
		{"unknown.invalid:443", "unknown.invalid:443", "unknown.invalid:443"},
	}
	for _, c := range cases {
		if got := chooseProxyTarget(c.addr, c.resolved, fake); got != c.want {
			t.Errorf("chooseProxyTarget(%q, %q) = %q, want %q", c.addr, c.resolved, got, c.want)
		}
	}
	if got := chooseProxyTarget("www.google.com:443", "198.18.0.27:443", netip.Prefix{}); got != "198.18.0.27:443" {
		t.Error("an invalid range must not rewrite the target")
	}
}

func TestFakeAddressInRange(t *testing.T) {
	fake := netip.MustParsePrefix("198.18.0.0/15")
	cases := []struct {
		target string
		want   bool
	}{
		{"198.18.0.27:443", true},
		{"198.19.191.130:443", true},
		{"8.8.8.8:53", false},
		{"www.google.com:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := fakeAddressInRange(c.target, fake); got != c.want {
			t.Errorf("fakeAddressInRange(%q) = %v, want %v", c.target, got, c.want)
		}
	}
	if fakeAddressInRange("198.18.0.27:443", netip.Prefix{}) {
		t.Error("an invalid range must never claim an address")
	}
}

func TestSetFakeRangeOnlyAppliesToSocks5(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/15")
	socks, err := newEgress("socks5://127.0.0.1:1080", false)
	if err != nil {
		t.Fatalf("newEgress failed: %v", err)
	}
	if !setFakeRange(socks, prefix) {
		t.Fatal("socks5 should accept the fake range")
	}
	if !socks.(*socks5Egress).fakeRange.IsValid() {
		t.Fatal("socks5 outlet did not keep the fake range")
	}
	// The other outlets send the domain unchanged, so they must not claim it.
	for _, link := range []string{"http://127.0.0.1:8080", "trojan://pw@127.0.0.1:443", "https://127.0.0.1:443"} {
		e, err := newEgress(link, false)
		if err != nil {
			t.Fatalf("newEgress(%q) failed: %v", link, err)
		}
		if setFakeRange(e, prefix) {
			t.Errorf("%s must not accept the fake range", link)
		}
	}
}

// A target that lands inside the plugin's own range can only come from a broken
// mapping row; dialing it always times out, so it is refused before an outlet
// sees it.
func TestFakeTargetRejectsOwnRange(t *testing.T) {
	p := &FakeIPNatPlugin{prefix: netip.MustParsePrefix("198.18.0.0/15")}
	cases := []struct {
		target string
		want   bool
	}{
		{"198.18.0.27:443", true},
		{"198.19.0.1:80", true},
		{"8.8.8.8:443", false},
		{"www.google.com:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := p.fakeTarget(c.target); got != c.want {
			t.Errorf("fakeTarget(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}
