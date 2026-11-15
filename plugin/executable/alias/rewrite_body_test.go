package alias

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestRewriteResponseKeepsSameSiteURLsOnAlias(t *testing.T) {
	body := `<link href="//cache.ip138.com/x.css"><a href="https://www.ip138.com/a">` +
		`<img src="https://example.org/x.png"><a href="https://ip138-com.local/">alias</a>`
	p := &plugin{suffix: ".local", dotRepl: "-"}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}, "Content-Location": []string{"http://ip138.com/index.htm"}, "ETag": []string{"W/\"x\""}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if err := p.rewriteResponse(resp, "ip138.com", "ip138-com.local"); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := `<link href="http://cache-ip138-com.local/x.css"><a href="http://www-ip138-com.local/a">` +
		`<img src="https://example.org/x.png"><a href="https://ip138-com.local/">alias</a>`
	if string(got) != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if resp.ContentLength != int64(len(want)) || resp.Header.Get("Content-Length") == "" {
		t.Fatalf("content length = %d header=%q", resp.ContentLength, resp.Header.Get("Content-Length"))
	}
	if resp.Header.Get("Content-Location") != "http://ip138-com.local/index.htm" {
		t.Fatalf("content-location = %q", resp.Header.Get("Content-Location"))
	}
	if resp.Header.Get("ETag") != "" {
		t.Fatalf("etag must be dropped, got %q", resp.Header.Get("ETag"))
	}
}

func TestRewriteBodyExtractsBareWildcardHosts(t *testing.T) {
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

	body := `<link rel="preload" href="https://website-cdn-assets.ipinfo.io/x.css">` +
		`<script type="application/json">{"a":"https:\/\/assets.ipinfo.io\/x","b":"website-cdn-assets.ipinfo.io"}</script>` +
		`<a href="https://example.org/x">`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if err := p.rewriteResponse(resp, "ipinfo.io", "ipinfo.aa2.dev"); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"website-cdn-assets-ipinfo.aa2.dev/x.css",
		`https:\/\/assets-ipinfo.aa2.dev\/x`,
		`"website-cdn-assets-ipinfo.aa2.dev"`,
		"https://example.org/x",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("body missing %q:\n%s", want, got)
		}
	}
	for _, old := range []string{"website-cdn-assets.ipinfo.io", "assets.ipinfo.io"} {
		if strings.Contains(string(got), old) {
			t.Fatalf("body still contains real host %q:\n%s", old, got)
		}
	}

	for _, real := range []string{"website-cdn-assets.ipinfo.io", "assets.ipinfo.io"} {
		if _, ok := a.Lookup(real); !ok {
			t.Fatalf("body rewrite did not preallocate %q", real)
		}
	}
	ip1, _ := a.Lookup("website-cdn-assets.ipinfo.io")
	ip2, _ := a.Lookup("assets.ipinfo.io")
	if ip1 == ip2 {
		t.Fatalf("two extracted subdomains share a virtual IP: %v", ip1)
	}
}

func TestRewriteBodyAcrossConfiguredDomains(t *testing.T) {
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

	body := `<a href="https://www.ip138.com/a">` +
		`<img src="https://cdn.ipinfo.io/x.png">` +
		`<script>{"u":"https:\/\/api.ip138.com\/v1"}</script>`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if err := p.rewriteResponse(resp, "ipinfo.io", "ipinfo.aa2.dev"); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"www-ip138.aa2.dev/a",
		"cdn-ipinfo.aa2.dev/x.png",
		`https:\/\/api-ip138.aa2.dev\/v1`,
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("body missing %q:\n%s", want, got)
		}
	}
	for _, old := range []string{"www.ip138.com", "cdn.ipinfo.io", "api.ip138.com"} {
		if strings.Contains(string(got), old) {
			t.Fatalf("body still contains unconfigured host %q:\n%s", old, got)
		}
	}
	for _, real := range []string{"www.ip138.com", "cdn.ipinfo.io", "api.ip138.com"} {
		if _, ok := a.Lookup(real); !ok {
			t.Fatalf("body rewrite did not preallocate %q", real)
		}
	}
}

func TestRewriteChunkedHTMLBody(t *testing.T) {
	body := `<a href="https://www.ip138.com/x">`
	p := &plugin{suffix: ".local", dotRepl: "-"}
	resp := &http.Response{
		StatusCode:       http.StatusOK,
		Header:           http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:             io.NopCloser(strings.NewReader(body)),
		ContentLength:    -1,
		TransferEncoding: []string{"chunked"},
	}
	if err := p.rewriteResponse(resp, "ip138.com", "ip138-com.local"); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `<a href="http://www-ip138-com.local/x">` {
		t.Fatalf("body = %q", got)
	}
	if resp.TransferEncoding != nil || resp.ContentLength != int64(len(got)) {
		t.Fatalf("framing = transfer=%v length=%d", resp.TransferEncoding, resp.ContentLength)
	}
}

func TestRewriteJavaScriptSubdomains(t *testing.T) {
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

	body := `const cdn="https:\/\/website-cdn.assets.ipinfo.io\/chunk.js";` +
		`fetch("https://ipinfo.io/lookup-data")`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/javascript; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if err := p.rewriteResponse(resp, "ipinfo.io", "ipinfo.aa2.dev"); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`https:\/\/website-cdn-assets-ipinfo.aa2.dev\/chunk.js`,
		`ipinfo.aa2.dev/lookup-data`,
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("JS missing %q:\n%s", want, got)
		}
	}
	for _, old := range []string{"website-cdn.assets.ipinfo.io", "ipinfo.io/lookup-data"} {
		if strings.Contains(string(got), old) {
			t.Fatalf("JS still contains %q:\n%s", old, got)
		}
	}
	if _, ok := a.Lookup("website-cdn.assets.ipinfo.io"); !ok {
		t.Fatal("JS rewrite did not preallocate the real subdomain")
	}
}

func TestGatewayAcceptEncoding(t *testing.T) {
	cases := []struct{ in, want string }{
		{"gzip, deflate, br, zstd", "gzip, deflate"},
		{"gzip;q=1.0, deflate;q=0.5", "gzip, deflate"},
		{"gzip;q=0, deflate", "deflate"},
		{"br", ""},
	}
	for _, c := range cases {
		if got := gatewayAcceptEncoding(c.in); got != c.want {
			t.Fatalf("gatewayAcceptEncoding(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
