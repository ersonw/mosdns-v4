package cbp_proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/miekg/dns"
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

func TestBootstrapDialContextResolvesThroughIndependentDNS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA && strings.EqualFold(q.Name, "bootstrap.test.") {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("127.0.0.1"),
				})
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	defer func() { _ = dnsSrv.Shutdown() }()

	oldServers := bootstrapDNSServers
	bootstrapDNSServers = []string{pc.LocalAddr().String()}
	defer func() { bootstrapDNSServers = oldServers }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bootstrapDialContext(ctx, "tcp", "bootstrap.test:"+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
