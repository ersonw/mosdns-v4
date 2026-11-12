package telegram_bot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
)

// stubPlane answers like a tun plane with one mark rule and one recorded object.
type stubPlane struct {
	plane    fakeipadmin.Plane
	diag     fakeipadmin.Diagnosis
	removed  []string
	sweepOK  bool
	diagArgs []string
}

func (s *stubPlane) AdminPlane(context.Context) (fakeipadmin.Plane, error) {
	return s.plane, nil
}

func (s *stubPlane) AdminDiagnose(_ context.Context, domain string) (fakeipadmin.Diagnosis, error) {
	s.diagArgs = append(s.diagArgs, domain)
	d := s.diag
	if d.Domain == "" {
		d.Domain = domain
	}
	return d, nil
}

func (s *stubPlane) AdminSweep(context.Context) ([]string, error) {
	return s.removed, nil
}

func newPlaneBot(t *testing.T) (*telegramBot, *stubPlane) {
	t.Helper()
	p := newStubPlugin()
	plane := &stubPlane{
		plane: fakeipadmin.Plane{
			DataPlane:   "tun",
			Device:      "mth0",
			Range:       "198.18.0.0/15",
			ProxyActive: false,
			MarkEnabled: true,
			RouteMark:   123,
			RouteTable:  "123",
			OutletTable: "101",
			RealIPs:     4,
			Rules: []string{
				"5:\tfrom all to 198.18.0.0/15 lookup main",
				"1000:\tfrom all fwmark 0x7b lookup 123",
			},
			Routes:   []string{"table 101: default via 11.10.12.1 dev wg0"},
			Recorded: map[string]string{"fake_range_rule": "5|198.18.0.0/15", "tun_egress": "101|198.18.0.0/15"},
		},
		diag: fakeipadmin.Diagnosis{
			FakeIP:      "198.18.0.36",
			CreatedAt:   1700000000,
			RealIPs:     []string{"142.250.4.35"},
			RealIPKnown: true,
			Outlet:      "tun via 11.10.12.1 dev wg0 (table 101)",
			Marked:      true,
		},
		removed: []string{"outlet 100|198.18.0.0/15"},
	}
	p.plane = plane
	return p, plane
}

func TestNetShowsTheDataPlane(t *testing.T) {
	p, _ := newPlaneBot(t)
	reply, err := p.handleText(context.Background(), 123, "/net")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	for _, want := range []string{
		"plane: tun (mth0)", "proxy: off", "mark: on (0x7b -> table 123)",
		"outlet table: 101", "mark set: 4", "lookup main",
	} {
		if !strings.Contains(reply, want) {
			t.Fatalf("reply missing %q:\n%s", want, reply)
		}
	}
}

func TestLedgerShowsRecordedObjects(t *testing.T) {
	p, _ := newPlaneBot(t)
	reply, err := p.handleText(context.Background(), 123, "/ledger")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "fake_range_rule = 5|198.18.0.0/15") ||
		!strings.Contains(reply, "tun_egress = 101|198.18.0.0/15") {
		t.Fatalf("reply = %s", reply)
	}
}

func TestSweepNeedsConfirm(t *testing.T) {
	p, plane := newPlaneBot(t)
	reply, _ := p.handleText(context.Background(), 123, "/sweep")
	if !strings.Contains(reply, "/sweep confirm") {
		t.Fatalf("reply = %s, want the confirmation hint", reply)
	}
	reply, err := p.handleText(context.Background(), 123, "/sweep confirm")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, plane.removed[0]) {
		t.Fatalf("reply = %s, want the removed object", reply)
	}
}

func TestDiagAnswersOneDomain(t *testing.T) {
	p, plane := newPlaneBot(t)
	reply, err := p.handleText(context.Background(), 123, "/diag www.google.com")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if len(plane.diagArgs) != 1 || plane.diagArgs[0] != "www.google.com" {
		t.Fatalf("diag args = %v", plane.diagArgs)
	}
	for _, want := range []string{"fake ip: 198.18.0.36", "real ips: 142.250.4.35", "outlet: tun via"} {
		if !strings.Contains(reply, want) {
			t.Fatalf("reply missing %q:\n%s", want, reply)
		}
	}
}

func TestProxyReadsAndWritesTheConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`plugins:
  - tag: fakeip
    type: fakeip_nat
    args:
      proxy: "socks5://user:pass@127.0.0.1:1080"
      ttl: 60
servers: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newStubPlugin()
	p.args.ConfigPath = path

	reply, err := p.handleText(context.Background(), 123, "/proxy")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if strings.Contains(reply, "user:pass") {
		t.Fatalf("reply leaks the credential: %s", reply)
	}
	if !strings.Contains(reply, "socks5://***@127.0.0.1:1080") {
		t.Fatalf("reply = %s", reply)
	}

	if _, err := p.handleText(context.Background(), 123, "/proxy off"); err != nil {
		t.Fatalf("handleText: %v", err)
	}
	doc, err := loadConfigDocument(path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	block := pluginBlock(doc, "fakeip")
	args := mappingGet(block, "args")
	// nodeText renders a scalar through the yaml encoder, so an empty string
	// comes back as the two quote characters.
	if v := mappingGet(args, "proxy"); v == nil || nodeText(v) != `""` {
		t.Fatalf("proxy value = %v, want empty", v)
	}
	if v := mappingGet(args, "ttl"); v == nil || nodeText(v) != "60" {
		t.Fatalf("ttl changed to %v, want 60", nodeText(v))
	}
}

func TestAuditRecordsMutatingCommandsOnly(t *testing.T) {
	dir := t.TempDir()
	p, _ := newPlaneBot(t)
	p.args.AuditLog = filepath.Join(dir, "audit.log")

	if _, err := p.handleText(context.Background(), 123, "/net"); err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if _, err := p.handleText(context.Background(), 123, "/sweep confirm"); err != nil {
		t.Fatalf("handleText: %v", err)
	}

	entries, err := p.readAudit(10)
	if err != nil {
		t.Fatalf("readAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want one (/sweep only)", entries)
	}
	if entries[0].Action != "/sweep" || entries[0].ChatID != 123 {
		t.Fatalf("entry = %+v", entries[0])
	}

	reply, err := p.handleText(context.Background(), 123, "/audit")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "/sweep confirm") {
		t.Fatalf("reply = %s", reply)
	}
}

// A config write must keep the key path but never the value: the value is how a
// token or a password reaches the log.
func TestAuditDetailDropsValuesAndURLs(t *testing.T) {
	if got := auditDetail("/config", []string{"set", "plugins[1].args.proxy", "socks5://u:p@h:1"}); got != "set plugins[1].args.proxy" {
		t.Fatalf("config detail = %q", got)
	}
	if got := auditDetail("/proxy", []string{"on", "socks5://u:p@h:1"}); got != "on" {
		t.Fatalf("proxy detail = %q", got)
	}
}
