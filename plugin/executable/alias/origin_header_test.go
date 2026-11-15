package alias

import (
	"net/http"
	"testing"
)

func TestRewriteOriginHeaders(t *testing.T) {
	h := http.Header{
		"Referer": []string{"https://ip138-com.aa2.dev/a?x=1"},
		"Origin":  []string{"https://ip138-com.aa2.dev:443"},
		"Accept":  []string{"text/html"},
	}
	rewriteOriginHeaders(h, "ip138.com", "ip138-com.aa2.dev", true)
	if got := h.Get("Referer"); got != "https://ip138.com/a?x=1" {
		t.Fatalf("referer = %q", got)
	}
	if got := h.Get("Origin"); got != "https://ip138.com:443" {
		t.Fatalf("origin = %q", got)
	}
	if got := h.Get("Accept"); got != "text/html" {
		t.Fatalf("accept changed to %q", got)
	}

	h.Set("Referer", "https://ip138.com/a")
	rewriteOriginHeaders(h, "ip138.com", "ip138-com.aa2.dev", false)
	if got := h.Get("Referer"); got != "https://ip138.com/a" {
		t.Fatalf("real referer must stay, got %q", got)
	}

	h.Set("Origin", "null")
	rewriteOriginHeaders(h, "ip138.com", "ip138-com.aa2.dev", false)
	if got := h.Get("Origin"); got != "null" {
		t.Fatalf("null origin must stay, got %q", got)
	}
}
