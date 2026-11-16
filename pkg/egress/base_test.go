package egress

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// recordingBase stands in for a pinned direct outlet: it dials for real but
// records the address, so a test can prove the proxy connection went through it
// instead of the host's own routing.
type recordingBase struct {
	mu    sync.Mutex
	addrs []string
}

func (b *recordingBase) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	b.mu.Lock()
	b.addrs = append(b.addrs, addr)
	b.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (b *recordingBase) seen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.addrs...)
}

func TestBaseDialerCarriesTheProxyConnection(t *testing.T) {
	server, addr := newFakeSocks5(t, "", "")
	defer server.ln.Close()
	go server.serve()

	base := &recordingBase{}
	out := NewSocks5(addr, "", "", true)
	out.SetBase(base)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dial through the outlet failed: %v", err)
	}
	defer conn.Close()

	seen := base.seen()
	if len(seen) != 1 {
		t.Fatalf("base dialer was used %d times, want 1: %v", len(seen), seen)
	}
	if seen[0] != addr {
		t.Fatalf("base dialer reached %q, want the proxy %q: the proxy connection must not use the host route", seen[0], addr)
	}
}

func TestBaseDialerIsOptional(t *testing.T) {
	server, addr := newFakeSocks5(t, "", "")
	defer server.ln.Close()
	go server.serve()

	out := NewSocks5(addr, "", "", true)
	if out.base != nil {
		t.Fatal("a freshly built outlet must not carry a base dialer")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dial without a base failed: %v", err)
	}
	_ = conn.Close()
}
