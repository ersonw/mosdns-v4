package fakeipnat

// The outbound half of the TUN data path lives in pkg/egress now: asn_tun used
// to import this plugin only to dial a proxy, and alias carried a second copy
// of the same outlets. These aliases keep the call sites in this package, and
// the tests that inspect an outlet's concrete type, working unchanged.

import (
	"context"
	"net/netip"

	"github.com/ersonw/mosdns-v4/pkg/egress"
)

type egressDialer = egress.Dialer
type egressProber = egress.Prober

func newEgress(raw string, insecure bool) (egress.Dialer, error) {
	return egress.New(raw, insecure)
}

func probeEgress(ctx context.Context, d egress.Dialer) error {
	return egress.Probe(ctx, d)
}

func setFakeRange(d egress.Dialer, prefix netip.Prefix) bool {
	return egress.SetFakeRange(d, prefix)
}

func redactProxy(raw string) string {
	return egress.Redact(raw)
}
