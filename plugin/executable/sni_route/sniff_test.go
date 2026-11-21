package sni_route

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// captureConn collects what the TLS client writes and fails every read, which
// is enough to capture a real ClientHello without a server.
type captureConn struct{ buf bytes.Buffer }

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *captureConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c := &captureConn{}
	client := tls.Client(c, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	_ = client.Handshake()
	if c.buf.Len() == 0 {
		t.Fatal("no ClientHello captured")
	}
	return c.buf.Bytes()
}

func TestParseClientHelloSNI(t *testing.T) {
	sni, result := parseClientHelloSNI(realClientHello(t, "api16-core.tiktokv.com"))
	if result != helloOK || sni != "api16-core.tiktokv.com" {
		t.Fatalf("sni = %q result = %v", sni, result)
	}
}

func TestParseClientHelloSplitAcrossRecords(t *testing.T) {
	hello := realClientHello(t, "www.tiktok.com")
	if hello[0] != 0x16 {
		t.Fatalf("not a TLS record: %x", hello[0])
	}
	payload := hello[5:]
	split := len(payload) / 2
	if split < 8 || split >= len(payload) {
		t.Fatalf("bad split %d of %d", split, len(payload))
	}
	data := append(tlsRecord(payload[:split]), tlsRecord(payload[split:])...)
	sni, result := parseClientHelloSNI(data)
	if result != helloOK || sni != "www.tiktok.com" {
		t.Fatalf("sni = %q result = %v", sni, result)
	}
}

func TestParseClientHelloWithoutSNI(t *testing.T) {
	_, result := parseClientHelloSNI(realClientHello(t, ""))
	if result != helloInvalid {
		t.Fatalf("result = %v, want helloInvalid", result)
	}
}

func TestParseClientHelloNeedMore(t *testing.T) {
	_, result := parseClientHelloSNI(realClientHello(t, "tiktokv.com")[:8])
	if result != helloNeedMore {
		t.Fatalf("result = %v, want helloNeedMore", result)
	}
}

func TestParseClientHelloNotTLS(t *testing.T) {
	if _, result := parseClientHelloSNI([]byte("GET / HTTP/1.1\r\n")); result != helloInvalid {
		t.Fatalf("result = %v, want helloInvalid", result)
	}
}

func tlsRecord(payload []byte) []byte {
	rec := append([]byte{0x16, 0x03, 0x01, 0x00, 0x00}, payload...)
	rec[3] = byte(len(payload) >> 8)
	rec[4] = byte(len(payload))
	return rec
}

func TestDomainMatcherSuffix(t *testing.T) {
	m, err := newDomainMatcher([]string{"tiktokv.com", "*.tiktokcdn.com", "# comment", "domain:byteoversea.com"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"tiktokv.com":              true,
		"api16-core.tiktokv.com":   true,
		"API16-CORE.TIKTOKV.COM":   true,
		"notiktokv.com":            false,
		"tiktokv.com.evil.example": false,
		"v31-sg.tiktokcdn.com":     true,
		"gecko-sg.byteoversea.com": true,
		"www.tiktok.com":           false,
	}
	for host, want := range cases {
		if got := m.match(host); got != want {
			t.Errorf("match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestNFTRules(t *testing.T) {
	rules := nftRules(nftParams{
		table:   "sni_route",
		mark:    130,
		iface:   "eth1",
		sources: []netip.Prefix{netip.MustParsePrefix("192.168.10.26/32")},
		bypass:  []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15")},
		ports:   []int{443},
	})
	for _, want := range []string{
		"add table inet sni_route",
		`iifname "eth1"`,
		"ip saddr @src4",
		"ip daddr != @bypass4",
		"tcp dport 443",
		"meta mark set 130",
	} {
		if !bytes.Contains([]byte(rules), []byte(want)) {
			t.Errorf("rules missing %q:\n%s", want, rules)
		}
	}
}

func TestNFTRulesQUICDrop(t *testing.T) {
	rules := nftRules(nftParams{
		table:     "sni_route",
		mark:      130,
		iface:     "eth1",
		bypass:    []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")},
		ports:     []int{443},
		blockQUIC: true,
	})
	if !bytes.Contains([]byte(rules), []byte("udp dport 443 counter drop")) {
		t.Errorf("QUIC drop rule missing:\n%s", rules)
	}
}
