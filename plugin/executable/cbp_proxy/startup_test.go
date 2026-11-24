package cbp_proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/egress"
	"go.uber.org/zap"
)

type startupFakeDialer struct {
	err error
}

func (f *startupFakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if f.err != nil {
		return nil, f.err
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (f *startupFakeDialer) Probe(context.Context) error { return f.err }

func (f *startupFakeDialer) OpenRawIP(context.Context) (egress.RawIPConn, error) {
	return nil, errors.New("fake raw unsupported")
}

func (f *startupFakeDialer) Close() error { return nil }

func newTestStartupDialer(started <-chan struct{}, dial func(context.Context) (egress.Dialer, string, error)) *startupDialer {
	d := &startupDialer{
		params:   "cbp_sg:edge-sg-1",
		insecure: true,
		started:  started,
		log:      zap.NewNop(),
		closeCh:  make(chan struct{}),
		ready:    make(chan struct{}),
		dial:     dial,
	}
	go d.waitForServers()
	return d
}

func TestStartupDialerDefersLoginUntilServersStarted(t *testing.T) {
	oldSettle := startupSettleDelay
	startupSettleDelay = 0
	defer func() { startupSettleDelay = oldSettle }()

	started := make(chan struct{})
	var calls atomic.Int32
	d := newTestStartupDialer(started, func(context.Context) (egress.Dialer, string, error) {
		calls.Add(1)
		return &startupFakeDialer{}, "203.0.113.9", nil
	})
	defer d.Close()

	if err := d.Probe(context.Background()); !errors.Is(err, egress.ErrDeferred) {
		t.Fatalf("Probe before servers started = %v, want ErrDeferred", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("login ran before servers-started signal: %d", got)
	}

	close(started)
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("login calls after signal = %d, want 1", got)
	}
	select {
	case <-d.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("startup dialer did not become ready")
	}
	if err := d.Probe(context.Background()); err != nil {
		t.Fatalf("Probe after login = %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestStartupDialerRetriesFailedAsyncLoginOnDial(t *testing.T) {
	oldSettle := startupSettleDelay
	startupSettleDelay = 0
	defer func() { startupSettleDelay = oldSettle }()

	started := make(chan struct{})
	var calls atomic.Int32
	d := newTestStartupDialer(started, func(context.Context) (egress.Dialer, string, error) {
		if calls.Add(1) == 1 {
			return nil, "", errors.New("bootstrap temporarily failed")
		}
		return &startupFakeDialer{}, "203.0.113.9", nil
	})
	defer d.Close()
	close(started)

	select {
	case <-d.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("first async login did not finish")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("first login calls = %d, want 1", got)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext after failed async login = %v", err)
	}
	_ = conn.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("login calls after retry = %d, want 2", got)
	}
}

func TestStartupDialerWaitStartedHonorsContext(t *testing.T) {
	d := newTestStartupDialer(make(chan struct{}), func(context.Context) (egress.Dialer, string, error) {
		return &startupFakeDialer{}, "203.0.113.9", nil
	})
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.DialContext(ctx, "tcp", "example.com:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext before signal = %v, want context deadline", err)
	}
}

func TestStartupDialerConcurrentDialsShareOneLogin(t *testing.T) {
	oldSettle := startupSettleDelay
	startupSettleDelay = 0
	defer func() { startupSettleDelay = oldSettle }()

	started := make(chan struct{})
	var calls atomic.Int32
	d := newTestStartupDialer(started, func(context.Context) (egress.Dialer, string, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return &startupFakeDialer{}, "203.0.113.9", nil
	})
	defer d.Close()
	close(started)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
			if err != nil {
				t.Errorf("concurrent DialContext: %v", err)
				return
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("login calls = %d, want 1 (async login plus concurrent dials must share it)", got)
	}
}
