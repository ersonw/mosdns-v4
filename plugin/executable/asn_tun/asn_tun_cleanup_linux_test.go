//go:build linux

package asn_tun

import (
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func TestCloseRemovesTunCreatedByPlugin(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	runner := new(recordingRunner)
	p := &ASNTunPlugin{
		BP:         bp,
		runner:     runner,
		args:       Args{NftTable: "asn_tun"},
		tunDev:     "asn0",
		tunCreated: true,
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(runner.calls, "\n")
	if !strings.Contains(got, "ip link del dev asn0") {
		t.Fatalf("plugin-owned tun was not removed: %v", runner.calls)
	}
}

func TestCloseKeepsPreExistingTun(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	runner := new(recordingRunner)
	p := &ASNTunPlugin{
		BP:     bp,
		runner: runner,
		args:   Args{NftTable: "asn_tun"},
		tunDev: "asn0",
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("pre-existing tun must not be removed: %v", runner.calls)
	}
}
