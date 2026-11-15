package alias

import (
	"net/http"
	"testing"
)

func TestFollowableUpstreamRedirect(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://ip138.com/a?x=1", nil)
	req.URL.Scheme = "http"
	resp := &http.Response{StatusCode: http.StatusMovedPermanently, Header: http.Header{"Location": []string{"https://ip138.com/a?x=1"}}}
	if loc, ok := followableUpstreamRedirect(req, resp, "ip138.com", false); !ok || loc != "https://ip138.com/a?x=1" {
		t.Fatalf("same-host https redirect: loc=%q ok=%v", loc, ok)
	}

	resp.Header.Set("Location", "https://www.ip138.com/a?x=1")
	if _, ok := followableUpstreamRedirect(req, resp, "ip138.com", false); ok {
		t.Fatal("cross-host redirect must not be followed")
	}

	resp.Header.Set("Location", "https://ip138.com/a?x=1")
	post, _ := http.NewRequest(http.MethodPost, "http://ip138.com/a?x=1", nil)
	post.URL.Scheme = "http"
	if _, ok := followableUpstreamRedirect(post, resp, "ip138.com", false); ok {
		t.Fatal("POST redirect must not be followed")
	}

	same, _ := http.NewRequest(http.MethodGet, "https://ip138.com/a?x=1", nil)
	same.URL.Scheme = "https"
	if _, ok := followableUpstreamRedirect(same, resp, "ip138.com", true); ok {
		t.Fatal("self redirect must not be followed")
	}

	resp.Header.Set("Location", "/b?x=2")
	if loc, ok := followableUpstreamRedirect(req, resp, "ip138.com", false); !ok || loc != "/b?x=2" {
		t.Fatalf("relative redirect: loc=%q ok=%v", loc, ok)
	}
}
