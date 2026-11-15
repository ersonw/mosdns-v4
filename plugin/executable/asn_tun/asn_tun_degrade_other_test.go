//go:build !linux

package asn_tun

import (
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

// A host that cannot provide the data plane (macOS has no TUN/nft here) must
// still start the DNS service: the plugin is disabled, not fatal.
func TestInitDegradesWhenDataPlaneSetupFails(t *testing.T) {
	bp := coremain.NewBP("asn_degrade_test", PluginType, zap.NewNop(), nil)
	p, err := Init(bp, &Args{
		ASN:     []uint32{112},
		Source:  "bgpq3",
		Refresh: "0",
		Proxy:   "ftp://127.0.0.1:1", // unsupported scheme: setupEgress fails early
	})
	if err != nil {
		t.Fatalf("Init must not fail the whole process: %v", err)
	}
	if p == nil {
		t.Fatal("Init returned a nil plugin")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close after degraded start: %v", err)
	}
}
