package alias

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fixedEgress struct {
	addr string
}

func (e fixedEgress) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, e.addr)
}

func TestInsecureUpstreamTLSIsExplicitOnly(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	p := &plugin{proxy: fixedEgress{addr: server.Listener.Addr().String()}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secure, err := p.dialUpstreamOne(ctx, "obzr.online", 443, true, false)
	if err == nil {
		_ = secure.Close()
		t.Fatal("default TLS unexpectedly accepted an untrusted certificate")
	}

	insecure, err := p.dialUpstreamOne(ctx, "obzr.online", 443, true, true)
	if err != nil {
		t.Fatalf("explicit insecure TLS failed: %v", err)
	}
	_ = insecure.Close()
}
