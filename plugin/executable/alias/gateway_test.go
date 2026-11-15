package alias

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAliasNameBothForms(t *testing.T) {
	p := &plugin{suffix: ".local"}
	if got := p.aliasName("ip138.com"); got != "ip138.com.local" {
		t.Fatalf("append form = %q", got)
	}
	p.replace = true
	if got := p.aliasName("ip138.com"); got != "ip138.local" {
		t.Fatalf("replace form = %q", got)
	}
	if got := p.aliasName("www.ip138.com"); got != "www.ip138.local" {
		t.Fatalf("replace subdomain form = %q", got)
	}
}

func TestRewriteLocation(t *testing.T) {
	p := &plugin{suffix: ".local"}
	cases := []struct{ in, want string }{
		{"http://ip138.com/path?q=1", "http://ip138.com.local/path?q=1"},
		{"https://www.ip138.com:8443/x", "https://www.ip138.com.local:8443/x"},
		{"http://example.org/x", "http://example.org/x"},
		{"/relative", "/relative"},
		{"http://ip138.com.local/x", "http://ip138.com.local/x"},
	}
	for _, c := range cases {
		if got := p.rewriteLocation(c.in, "ip138.com", "ip138.com.local"); got != c.want {
			t.Fatalf("rewriteLocation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteCookie(t *testing.T) {
	p := &plugin{suffix: ".local"}
	cases := []struct{ in, want string }{
		{"sid=1; Domain=ip138.com; Path=/", "sid=1; Domain=ip138.com.local; Path=/"},
		{"sid=1; Domain=.ip138.com; Path=/; Secure", "sid=1; Domain=.ip138.com.local; Path=/; Secure"},
		{"sid=1; Domain=www.ip138.com; Path=/", "sid=1; Domain=www.ip138.com.local; Path=/"},
		{"__Host-sid=1; Domain=.ip138.com; Path=/; Secure", "__Host-sid=1; Path=/; Secure"},
		{"sid=1; Domain=other.org; Path=/", "sid=1; Domain=other.org; Path=/"},
		{"sid=1; Path=/", "sid=1; Path=/"},
	}
	for _, c := range cases {
		if got := p.rewriteCookie(c.in, "ip138.com", "ip138.com.local"); got != c.want {
			t.Fatalf("rewriteCookie(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteCookieAcrossConfiguredDomains(t *testing.T) {
	s := newTestStore(t)
	for _, name := range []string{"ipinfo.io", "ip138.com"} {
		if _, _, err := s.add(name); err != nil {
			t.Fatal(err)
		}
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		store:   s,
		alloc:   a,
		prefix:  prefix,
		suffix:  ".aa2.dev",
		replace: true,
		dotRepl: "-",
	}
	got := p.rewriteCookie("sid=1; Domain=.ip138.com; Path=/; Secure",
		"ipinfo.io", "ipinfo.aa2.dev")
	if want := "sid=1; Domain=.ip138.aa2.dev; Path=/; Secure"; got != want {
		t.Fatalf("cookie = %q, want %q", got, want)
	}
}

func TestRewriteRequestRestoresAliasNames(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ipinfo.io"); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		store:   s,
		alloc:   a,
		prefix:  prefix,
		suffix:  ".aa2.dev",
		replace: true,
		dotRepl: "-",
	}
	p.aliasName("ipinfo.io")
	p.aliasName("website-cdn.assets.ipinfo.io")

	body := `{"u":"https:\/\/website-cdn-assets-ipinfo.aa2.dev\/x","v":"ipinfo.aa2.dev"}`
	req := &http.Request{
		Method:        http.MethodPost,
		Header:        http.Header{"Content-Type": []string{"application/json"}, "Origin": []string{"https://ipinfo.aa2.dev"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if err := p.rewriteRequest(req); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`https:\/\/website-cdn.assets.ipinfo.io\/x`,
		"ipinfo.io",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("request body missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "aa2.dev") {
		t.Fatalf("request body still contains alias: %s", got)
	}
	if got := req.Header.Get("Origin"); got != "https://ipinfo.io" {
		t.Fatalf("Origin = %q", got)
	}
	if req.ContentLength != int64(len(got)) || req.Header.Get("Content-Length") != fmt.Sprintf("%d", len(got)) {
		t.Fatalf("content length = %d header=%q", req.ContentLength, req.Header.Get("Content-Length"))
	}
}

func TestStripHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom, keep-alive")
	h.Set("X-Custom", "1")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Upgrade", "websocket")
	h.Set("Host", "ip138.com")
	stripHopByHop(h)
	for _, name := range []string{"Connection", "X-Custom", "Keep-Alive", "Upgrade"} {
		if got := h.Get(name); got != "" {
			t.Fatalf("%s still present: %q", name, got)
		}
	}
	if got := h.Get("Host"); got != "ip138.com" {
		t.Fatalf("Host was removed: %q", got)
	}
}

func TestForwardRequestRewritesHostAndPath(t *testing.T) {
	raw := "GET /82.41.237.60.gif?x=1 HTTP/1.1\r\nHost: 6.ipchaxun.net.local\r\nUser-Agent: t\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = "6.ipchaxun.net"
	req.Host = "6.ipchaxun.net"
	if req.URL.Path != "/82.41.237.60.gif" || req.URL.RawQuery != "x=1" {
		t.Fatalf("path/query = %q %q", req.URL.Path, req.URL.RawQuery)
	}
	if _, err := url.ParseRequestURI(req.URL.RequestURI()); err != nil {
		t.Fatalf("request uri: %v", err)
	}
	if !strings.HasPrefix(req.URL.String(), "http://6.ipchaxun.net") {
		t.Fatalf("url = %q", req.URL.String())
	}
}

func TestGatewayRedirectTarget(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	a, err := newAllocator(netip.MustParsePrefix("198.18.4.0/23"))
	if err != nil {
		t.Fatal(err)
	}
	on := &plugin{suffix: ".local", redirect: true, store: s, alloc: a}
	req := &http.Request{Host: "ip138.com", URL: &url.URL{Path: "/a/b", RawQuery: "x=1"}}
	if got := on.gatewayRedirectTarget(req, "ip138.com.local"); got != "ip138.com.local" {
		t.Fatalf("real host target = %q", got)
	}
	if got := on.gatewayRedirectLocation("ip138.com.local", req); got != "http://ip138.com.local/a/b?x=1" {
		t.Fatalf("redirect location = %q", got)
	}

	aliasReq := &http.Request{Host: "ip138.com.local:8080", URL: &url.URL{Path: "/"}}
	if got := on.gatewayRedirectTarget(aliasReq, "ip138.com.local"); got != "" {
		t.Fatalf("alias host must not redirect, got %q", got)
	}

	upper := &http.Request{Host: "IP138.COM.LOCAL", URL: &url.URL{Path: "/"}}
	if got := on.gatewayRedirectTarget(upper, "ip138.com.local"); got != "" {
		t.Fatalf("case-insensitive alias host must not redirect, got %q", got)
	}

	unknown := &http.Request{Host: "other.example", URL: &url.URL{Path: "/"}}
	if got := on.gatewayRedirectTarget(unknown, "ip138.com.local"); got != "" {
		t.Fatalf("unlisted host must not redirect, got %q", got)
	}

	off := &plugin{suffix: ".local", redirect: false}
	if got := off.gatewayRedirectTarget(req, "ip138.com.local"); got != "" {
		t.Fatalf("redirect disabled, got %q", got)
	}

	root := &http.Request{URL: &url.URL{Path: ""}}
	if got := on.gatewayRedirectLocation("ip138.com.local", root); got != "http://ip138.com.local/" {
		t.Fatalf("root redirect = %q", got)
	}
}

func TestServeGatewayRedirectsRealHost(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, suffix: ".local", redirect: true, defScheme: schemeHTTP}
	peer, gw := tcpPair(t)
	done := make(chan struct{})
	go func() {
		p.serveGateway(gw, "ip138.com")
		close(done)
	}()

	if _, err := fmt.Fprintf(peer, "GET /a/b?x=1 HTTP/1.1\r\nHost: ip138.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("read redirect: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://ip138.com.local/a/b?x=1" {
		t.Fatalf("location = %q", got)
	}
	_, _ = io.ReadAll(resp.Body)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not finish after redirect")
	}
}
