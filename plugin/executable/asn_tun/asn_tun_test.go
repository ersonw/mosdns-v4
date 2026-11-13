package asn_tun

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func TestParsePrefixLinesSkipsCommentsAndTinyBlocks(t *testing.T) {
	body := `
# AS4134
1.2.3.0/24
1.2.3.0/24
5.6.0.0/16 # inline comment
10.0.0.0/7
2001:db8::/32
bad-line
`
	got, err := parsePrefixLines(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("prefixes = %v, want two IPv4 prefixes", got)
	}
	if got[0].String() != "1.2.3.0/24" || got[1].String() != "5.6.0.0/16" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestNftFileContainsIntervalSetAndBypass(t *testing.T) {
	text := nftFile("asn_tun", 291, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("5.6.0.0/16"),
	}, []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
	})
	for _, want := range []string{
		"add table inet asn_tun",
		"type ipv4_addr; flags interval",
		"add rule inet asn_tun mark_pre meta mark 0 ip daddr != @bypass4 ip daddr @asn4 meta mark set 291",
		"add rule inet asn_tun mark_out meta mark 0 ip daddr != @bypass4 ip daddr @asn4 meta mark set 291",
		"add element inet asn_tun asn4 { 1.2.3.0/24, 5.6.0.0/16 }",
		"add element inet asn_tun bypass4 { 8.8.8.8 }",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("nft file missing %q:\n%s", want, text)
		}
	}
}

func TestNewPluginDefaults(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	p, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		NextHop:    "10.0.0.1",
		NextHopDev: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.args.NftTable != "asn_tun" || p.routeTable != "123" {
		t.Fatalf("defaults: nft=%q route=%q", p.args.NftTable, p.routeTable)
	}
	if p.mark != 123 || p.egressMark != 124 {
		t.Fatalf("marks: %d/%d", p.mark, p.egressMark)
	}
	if p.tunAddr.String() != "192.0.2.1" {
		t.Fatalf("tun addr = %s", p.tunAddr)
	}
}

func TestNewPluginRejectsMainRouteTable(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	_, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		NextHop:    "10.0.0.1",
		RouteTable: "main",
	})
	if err == nil {
		t.Fatal("main route table should be rejected")
	}
}

func TestPolicyRuleUsesDistinctMarks(t *testing.T) {
	p := &ASNTunPlugin{mark: 123, routeTable: "123", egressMark: 124, egressTable: "124", rulePrio: 1000}
	if got := strings.Join(p.ingressRuleArgs("add"), " "); got != "rule add fwmark 123 lookup 123 prio 1000" {
		t.Fatalf("ingress rule = %q", got)
	}
	if got := strings.Join(p.egressRuleArgs("add"), " "); got != "rule add fwmark 124 lookup 124 prio 1001" {
		t.Fatalf("egress rule = %q", got)
	}
}
