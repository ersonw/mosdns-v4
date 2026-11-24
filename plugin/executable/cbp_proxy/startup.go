package cbp_proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/egress"
	"go.uber.org/zap"
)

const startupLoginTimeout = 45 * time.Second

// startupSettleDelay gives the rest of the start pass a moment to settle
// before the first bootstrap request. Tests shorten it.
var startupSettleDelay = 200 * time.Millisecond

// startupDialer registers an egress outlet during plugin initialization but
// does not touch the network until mosdns has opened its DNS listeners. CBP's
// bootstrap and AUTH both need a resolver; at plugin init the system resolver
// may point at mosdns' own not-yet-listening 127.0.0.1:53. Waiting for the
// servers-started signal removes that circular dependency without giving the
// bootstrap its own private DNS resolver.
type startupDialer struct {
	manager  *Manager
	params   string
	insecure bool
	started  <-chan struct{}
	log      *zap.Logger
	dial     func(context.Context) (egress.Dialer, string, error)

	closeCh   chan struct{}
	closeOnce sync.Once

	loginMu   sync.Mutex
	ready     chan struct{}
	readyOnce sync.Once

	mu      sync.Mutex
	inner   egress.Dialer
	host    string
	lastErr error
	closed  bool
}

func newStartupDialer(manager *Manager, params string, insecure bool, started <-chan struct{}, log *zap.Logger) *startupDialer {
	d := &startupDialer{
		manager:  manager,
		params:   params,
		insecure: insecure,
		started:  started,
		log:      log,
		closeCh:  make(chan struct{}),
		ready:    make(chan struct{}),
	}
	d.dial = func(ctx context.Context) (egress.Dialer, string, error) {
		return manager.NewProxyDialer(params, insecure)
	}
	go d.waitForServers()
	return d
}

func (d *startupDialer) waitForServers() {
	select {
	case <-d.started:
	case <-d.closeCh:
		return
	}
	// Give the rest of the start pass a moment to settle (the fakeip TUN route
	// is installed by plugin init, but it is cheap to avoid racing the first
	// bootstrap request).
	select {
	case <-time.After(startupSettleDelay):
	case <-d.closeCh:
		return
	}
	d.log.Info("cbp_proxy: servers started, logging in CBP node")
	ctx, cancel := context.WithTimeout(context.Background(), startupLoginTimeout)
	defer cancel()
	if _, err := d.login(ctx); err != nil {
		d.log.Warn("cbp_proxy: deferred CBP login failed, first data dial will retry", zap.Error(err))
	}
}

func (d *startupDialer) login(ctx context.Context) (egress.Dialer, error) {
	d.loginMu.Lock()
	defer d.loginMu.Unlock()

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("cbp_proxy: startup dialer is closed")
	}
	if d.inner != nil {
		inner := d.inner
		d.mu.Unlock()
		d.signalReady()
		return inner, nil
	}
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, startupLoginTimeout)
	defer cancel()
	inner, host, err := d.dial(ctx)

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		if inner != nil {
			_ = egress.Close(inner)
		}
		return nil, errors.New("cbp_proxy: startup dialer is closed")
	}
	if err == nil && inner != nil {
		d.inner = inner
		d.host = host
		d.lastErr = nil
	} else {
		d.lastErr = err
	}
	d.mu.Unlock()
	d.signalReady()
	if err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, errors.New("cbp_proxy: startup dialer returned no dialer")
	}
	d.log.Info("cbp_proxy: deferred CBP login ready", zap.String("proxy_host", host))
	return inner, nil
}

func (d *startupDialer) signalReady() {
	d.readyOnce.Do(func() { close(d.ready) })
}

func (d *startupDialer) waitStarted(ctx context.Context) error {
	select {
	case <-d.started:
		return nil
	case <-d.closeCh:
		return errors.New("cbp_proxy: startup dialer is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *startupDialer) ensure(ctx context.Context) (egress.Dialer, error) {
	if err := d.waitStarted(ctx); err != nil {
		return nil, err
	}
	d.mu.Lock()
	inner := d.inner
	d.mu.Unlock()
	if inner != nil {
		return inner, nil
	}

	// The asynchronous login after the servers-started signal may still be in
	// progress. Wait for its first result, then either use it or retry under
	// loginMu (a failed bootstrap must not make the outlet permanently dead).
	select {
	case <-d.ready:
	case <-d.closeCh:
		return nil, errors.New("cbp_proxy: startup dialer is closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	d.mu.Lock()
	inner = d.inner
	d.mu.Unlock()
	if inner != nil {
		return inner, nil
	}
	return d.login(ctx)
}

func (d *startupDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	inner, err := d.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return inner.DialContext(ctx, network, addr)
}

func (d *startupDialer) OpenRawIP(ctx context.Context) (egress.RawIPConn, error) {
	inner, err := d.ensure(ctx)
	if err != nil {
		return nil, err
	}
	raw, ok := inner.(egress.RawIPDialer)
	if !ok {
		return nil, errors.New("cbp_proxy: startup dialer does not expose raw IP")
	}
	return raw.OpenRawIP(ctx)
}

func (d *startupDialer) Probe(ctx context.Context) error {
	select {
	case <-d.started:
	default:
		return fmt.Errorf("cbp_proxy: waiting for DNS servers: %w", egress.ErrDeferred)
	}
	d.mu.Lock()
	inner := d.inner
	lastErr := d.lastErr
	d.mu.Unlock()
	if inner == nil {
		if lastErr != nil {
			return fmt.Errorf("cbp_proxy: startup login failed: %w: %v", egress.ErrDeferred, lastErr)
		}
		return fmt.Errorf("cbp_proxy: startup login pending: %w", egress.ErrDeferred)
	}
	if p, ok := inner.(egress.Prober); ok {
		return p.Probe(ctx)
	}
	return nil
}

// ProxyHost reports the real far endpoint once the deferred login has resolved
// it. Before that it returns an empty string, which lets egress_route keep its
// registration placeholder instead of treating the node label as a resolvable
// proxy address.
func (d *startupDialer) ProxyHost() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.host
}

func (d *startupDialer) Close() error {
	d.closeOnce.Do(func() {
		close(d.closeCh)
		d.signalReady()
	})
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	inner := d.inner
	d.inner = nil
	d.mu.Unlock()
	if inner == nil {
		return nil
	}
	return egress.Close(inner)
}

var _ egress.Dialer = (*startupDialer)(nil)
var _ egress.RawIPDialer = (*startupDialer)(nil)
