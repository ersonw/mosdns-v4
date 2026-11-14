package fakeipnat

// This file answers one question the DNS half cannot answer on its own: can
// this host reach an IPv6 destination right now?
//
// A direct outlet has to dial the real address, so a fake IPv4 for an
// IPv6-only name is only useful when the host owns a working IPv6 path. The
// plugin therefore probes the host's egress instead of the query: the result
// is kept for a short while and shared by every name. When the probe fails the
// plugin keeps the old behaviour, an empty A response, which is exactly what a
// host without IPv6 has always produced.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	// defaultIPv6Probe is a public TCP endpoint. Any reachable address works;
	// this one is anycast, answers on 443, and needs no DNS lookup, so the
	// probe itself cannot be the thing that breaks when this plugin is also the
	// host's resolver.
	defaultIPv6Probe = "[2606:4700:4700::1111]:443"
	// ipv6ProbeTimeout bounds one dial: a black-holed IPv6 path times out
	// instead of hanging the checker.
	ipv6ProbeTimeout = 4 * time.Second
	// defaultIPv6ProbeInterval re-checks often enough that a NAT66/NPTv6 link
	// that comes up later is picked up without a restart.
	defaultIPv6ProbeInterval = 5 * time.Minute
)

// v6EgressProbe reports whether a direct outlet may dial IPv6.
type v6EgressProbe struct {
	enabled bool
	target  string
	every   time.Duration
	// probe is the dial itself; tests replace it instead of opening sockets.
	probe func(ctx context.Context, target string) error
	ready atomic.Bool

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// newIPv6EgressProbe builds the checker described by the configuration. It
// returns nil when the mode is off, so the answer path costs one nil check.
// every is the resolved re-check interval; 0 means "probe once at startup".
func newIPv6EgressProbe(cfg *Args, every time.Duration, log *zap.Logger) *v6EgressProbe {
	mode := strings.ToLower(strings.TrimSpace(cfg.IPv6Egress))
	if mode == "off" || mode == "disable" || mode == "disabled" {
		return nil
	}
	target := strings.TrimSpace(cfg.IPv6Probe)
	if target == "" {
		target = defaultIPv6Probe
	}
	v := &v6EgressProbe{
		enabled: true,
		target:  target,
		every:   every,
		probe:   dialIPv6Probe,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if log != nil {
		log.Debug("fakeip nat: ipv6 egress probe armed",
			zap.String("target", target), zap.Duration("interval", every))
	}
	return v
}

// parseIPv6ProbeInterval resolves ipv6_probe_interval: empty means the
// default, "0" means probe once at startup, anything else is a Go duration.
func parseIPv6ProbeInterval(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultIPv6ProbeInterval, nil
	}
	if raw == "0" {
		return 0, nil
	}
	every, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid ipv6_probe_interval %q: %w", raw, err)
	}
	if every < 0 {
		return 0, fmt.Errorf("invalid ipv6_probe_interval %q: must not be negative", raw)
	}
	return every, nil
}

// dialIPv6Probe is the production probe: a plain TCP connect on the host
// network. A completed handshake proves route, source address and NAT all
// work for IPv6.
func dialIPv6Probe(ctx context.Context, target string) error {
	d := net.Dialer{Timeout: ipv6ProbeTimeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Ready reports the last probe result. A nil checker (mode off) is never ready.
func (v *v6EgressProbe) Ready() bool {
	return v != nil && v.ready.Load()
}

// Start runs one probe synchronously so the first answer after a restart sees
// the real state, then keeps re-checking in the background.
func (v *v6EgressProbe) Start(ctx context.Context, log *zap.Logger) {
	if v == nil {
		return
	}
	v.check(ctx, log)
	if v.every <= 0 {
		close(v.done)
		return
	}
	go func() {
		defer close(v.done)
		ticker := time.NewTicker(v.every)
		defer ticker.Stop()
		for {
			select {
			case <-v.stop:
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(context.Background(), ipv6ProbeTimeout+time.Second)
				v.check(checkCtx, log)
				cancel()
			}
		}
	}()
}

func (v *v6EgressProbe) check(ctx context.Context, log *zap.Logger) {
	was := v.ready.Load()
	probeCtx, cancel := context.WithTimeout(ctx, ipv6ProbeTimeout)
	var err error
	if v.probe == nil {
		err = fmt.Errorf("no probe configured")
	} else {
		err = v.probe(probeCtx, v.target)
	}
	cancel()
	v.ready.Store(err == nil)
	if log == nil {
		return
	}
	// Only transitions are logged: this runs on a timer, and a permanently
	// black-holed IPv6 path would otherwise fill the log.
	switch {
	case err == nil && !was:
		log.Info("fakeip nat: ipv6 direct egress usable, ipv6-only names get a fake ipv4",
			zap.String("target", v.target))
	case err != nil && was:
		log.Warn("fakeip nat: ipv6 direct egress lost, ipv6-only names fall back to an empty answer",
			zap.String("target", v.target), zap.Error(err))
	case err != nil:
		log.Debug("fakeip nat: ipv6 direct egress unavailable",
			zap.String("target", v.target), zap.Error(err))
	}
}

// Stop ends the background re-check. A checker that never started (probing off,
// or a struct built without Start, as tests do) has no channels to close.
func (v *v6EgressProbe) Stop() {
	if v == nil || v.stop == nil {
		return
	}
	v.stopOnce.Do(func() { close(v.stop) })
	select {
	case <-v.done:
	case <-time.After(2 * time.Second):
	}
}
