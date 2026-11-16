package egress_route_test

import (
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/plugin/executable/asn_tun"
	"github.com/ersonw/mosdns-v4/plugin/executable/egress_route"
	"github.com/ersonw/mosdns-v4/plugin/executable/fakeip_nat"
	"gopkg.in/yaml.v3"
)

// The config an operator writes has to decode without a single unknown key:
// mosdns reports "parameter does not exist" at load time, which would only be
// discovered after the service is already stopped.
const splitConfig = `
egress: &egress_asn
  mark: 126
  nft_table: asn_tun
  route_table: "126"
  rule_priority: 1001
  next_hop: 11.10.12.1
  next_hop_dev: wg0
  proxy: "gost://admin:admin@11.10.10.13:1080"
  proxy_insecure: true

asn_tun: &asn
  asn: [62041, 13335]
  source: bgpq3
  refresh: "0"
  cache: /etc/mosdns/asn_tun_prefixes.json
  fetch_script: scripts/bgpq3_fetch_asn.py
  merge_script: scripts/cidr_merge.py
  python: python3
  tun_dev: asn0
  mirror_dev: eth1
  tun_addr: 192.0.2.1/32
  tun_mtu: 1400
  nft_table: asn_tun
  mark: 125
  route_table: "125"
  route_rule_priority: 1000
  egress: egress_asn
`

func TestSplitConfigDecodesStrictly(t *testing.T) {
	var doc struct {
		Egress *egress_route.Args `yaml:"egress"`
		ASN    *asn_tun.Args      `yaml:"asn_tun"`
	}
	dec := yaml.NewDecoder(strings.NewReader(splitConfig))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the split config does not decode strictly: %v", err)
	}
	if doc.Egress == nil || doc.ASN == nil {
		t.Fatal("both blocks must decode")
	}
	if doc.Egress.Mark != 126 || doc.Egress.RouteTable != "126" || doc.Egress.RulePriority != 1001 {
		t.Fatalf("egress block decoded as %+v", *doc.Egress)
	}
	if doc.ASN.Egress != "egress_asn" {
		t.Fatalf("asn block lost its egress reference: %+v", *doc.ASN)
	}
}

// The data-plane plugins borrow the exit by tag now, so their own config must
// accept the new key and keep rejecting anything unknown.
const borrowedConfig = `
egress_tiktok:
  proxy: "gost://admin:admin@11.10.10.31:1080"
  proxy_insecure: true

fakeip:
  ipv4_range: 198.17.0.0/16
  use_tun: true
  egress: egress_tiktok
`

func TestBorrowedEgressDecodesStrictly(t *testing.T) {
	var doc struct {
		FakeIP *fakeipnat.Args    `yaml:"fakeip"`
		Exit   *egress_route.Args `yaml:"egress_tiktok"`
	}
	dec := yaml.NewDecoder(strings.NewReader(borrowedConfig))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the borrowed config does not decode strictly: %v", err)
	}
	if doc.FakeIP == nil || doc.Exit == nil {
		t.Fatal("both blocks must decode")
	}
	if doc.FakeIP.Egress != "egress_tiktok" {
		t.Fatalf("fakeip lost its egress reference: %+v", *doc.FakeIP)
	}
}

func TestEgressBlockRejectsUnknownKeys(t *testing.T) {
	var args egress_route.Args
	dec := yaml.NewDecoder(strings.NewReader("mark: 126\nroute_table: \"126\"\nnext_hop_dev: wg0\nroute_mark: 999\n"))
	dec.KnownFields(true)
	err := dec.Decode(&args)
	if err == nil {
		t.Fatal("an unknown key must be reported, otherwise the old names silently linger")
	}
}
