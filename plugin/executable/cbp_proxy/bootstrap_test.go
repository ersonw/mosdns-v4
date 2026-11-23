package cbp_proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
)

func TestFetchMainCandidatesUsesHTTPSAndAPIKey(t *testing.T) {
	var gotAuth, gotAPIKey string
	var sawAuth bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, sawAuth = r.Header["Authorization"]
		gotAPIKey = r.Header.Get("X-API-Key")
		if r.URL.Path != "/v1/edge/bootstrap" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("X-CustomBrowser-Client-ID") != "" || r.Header.Get("X-CustomBrowser-Signature") != "" {
			t.Error("desktop client signature headers must not be sent")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server": map[string]any{
				"public_ip": "203.0.113.10",
				"candidates": []map[string]any{
					{
						"id":        "main",
						"role":      "main",
						"addresses": []string{"203.0.113.10:9443", "10.0.0.10:9443"},
					},
				},
			},
			// A node directory here is ignored on purpose.
			"edge": map[string]any{"payload": "not-a-node-list"},
		})
	}))
	defer srv.Close()

	cfg := coremain.ProxyProvideConfig{
		Tag:    "cbp_sg",
		Domain: srv.URL,
		Token:  "cbak_non_desktop_test_key",
	}
	got, err := FetchMainCandidates(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if sawAuth || gotAuth != "" {
		t.Fatalf("Authorization must not be sent, got %q", gotAuth)
	}
	if gotAPIKey != "cbak_non_desktop_test_key" {
		t.Fatalf("X-API-Key = %q", gotAPIKey)
	}
	if len(got) != 1 || got[0].ID != "main" {
		t.Fatalf("candidates = %+v", got)
	}
	if len(got[0].Addresses) != 2 || got[0].Addresses[0] != "203.0.113.10:9443" {
		t.Fatalf("addresses = %+v", got[0].Addresses)
	}
}

func TestFetchMainCandidatesOmitsAPIKeyWhenTokenIsEmpty(t *testing.T) {
	var gotAuth, gotAPIKey string
	var sawAuth, sawAPIKey bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, sawAuth = r.Header["Authorization"]
		gotAPIKey = r.Header.Get("X-API-Key")
		_, sawAPIKey = r.Header["X-API-Key"]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server": map[string]any{
				"coordinator_addresses": []string{"198.51.100.20:9443"},
			},
		})
	}))
	defer srv.Close()

	cfg := coremain.ProxyProvideConfig{Tag: "cbp_sg", Domain: srv.URL}
	got, err := FetchMainCandidates(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if sawAuth || gotAuth != "" || sawAPIKey || gotAPIKey != "" {
		t.Fatalf("auth headers should be absent, got Authorization=%q X-API-Key=%q", gotAuth, gotAPIKey)
	}
	if len(got) != 1 || got[0].Role != "main" || got[0].Addresses[0] != "198.51.100.20:9443" {
		t.Fatalf("candidates = %+v", got)
	}
}

func TestNormalizeCandidateAddressesRejectsSomethingWithoutPort(t *testing.T) {
	got := normalizeCandidateAddresses([]string{
		"tls://203.0.113.10:9443",
		"203.0.113.10:9443",
		"203.0.113.10",
		"",
	})
	if len(got) != 1 || strings.Contains(got[0], "tls://") {
		t.Fatalf("addresses = %+v", got)
	}
}
