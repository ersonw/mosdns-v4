package fakeipnat

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
)

func TestTrafficWatchMergesFlowsAndKeepsNewest(t *testing.T) {
	w := newTrafficWatch()
	if !w.add("192.0.2.10") {
		t.Fatal("first add should start capture")
	}
	base := int64(1_700_000_000)
	for i := 0; i < 25; i++ {
		w.record(fakeipadmin.TrafficEvent{
			Time:            base + int64(i),
			ClientIP:        "192.0.2.10",
			ClientPort:      uint16(40000 + i),
			DestinationIP:   "203.0.113.9",
			DestinationPort: 443,
			Protocol:        "tcp",
			Packets:         1,
		})
	}
	// Same five-tuple as the first of the 25 flows: it must merge and move to
	// the head instead of creating a 26th line.
	w.record(fakeipadmin.TrafficEvent{
		Time:            base + 100,
		ClientIP:        "192.0.2.10",
		ClientPort:      40000,
		DestinationIP:   "203.0.113.9",
		DestinationPort: 443,
		Protocol:        "tcp",
		Packets:         2,
	})
	events, version, ok := w.snapshot("192.0.2.10", 20)
	if !ok || version == 0 {
		t.Fatalf("snapshot ok=%v version=%d", ok, version)
	}
	if len(events) != 20 {
		t.Fatalf("snapshot len = %d, want 20", len(events))
	}
	if events[0].ClientPort != 40000 || events[0].Packets != 3 {
		t.Fatalf("head = %+v, want merged port 40000 with 3 packets", events[0])
	}
	if events[0].Time != base+100 {
		t.Fatalf("head time = %d, want %d", events[0].Time, base+100)
	}
}

func TestTrafficWatchReferenceCount(t *testing.T) {
	w := newTrafficWatch()
	if !w.add("192.0.2.10") {
		t.Fatal("first add should start capture")
	}
	if w.add("192.0.2.10") {
		t.Fatal("second add must share the capture")
	}
	if w.remove("192.0.2.10") {
		t.Fatal("one reference left, capture must stay")
	}
	if _, _, ok := w.snapshot("192.0.2.10", 20); !ok {
		t.Fatal("source disappeared too early")
	}
	if !w.remove("192.0.2.10") {
		t.Fatal("last reference must stop capture")
	}
	if _, _, ok := w.snapshot("192.0.2.10", 20); ok {
		t.Fatal("source still exists after last remove")
	}
}

func TestParseWatchPacket(t *testing.T) {
	pkt := buildTCPPacket(t, "192.0.2.10", "198.18.0.5", 50000, 443)
	flow, ok := parseWatchPacket(pkt)
	if !ok {
		t.Fatal("tcp packet was not parsed")
	}
	if flow.src.String() != "192.0.2.10" || flow.dst.String() != "198.18.0.5" ||
		flow.proto != "tcp" || flow.srcPort != 50000 || flow.dstPort != 443 {
		t.Fatalf("flow = %+v", flow)
	}
}

func TestParseConntrackLine(t *testing.T) {
	proto, tuples, ok := parseConntrackLine(
		"tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.18.0.5 sport=50000 dport=443 " +
			"src=203.0.113.9 dst=192.0.2.10 sport=443 dport=50000 [ASSURED] mark=0 use=1")
	if !ok || proto != "tcp" || len(tuples) != 2 {
		t.Fatalf("proto=%q tuples=%+v ok=%v", proto, tuples, ok)
	}
	if tuples[0].src != "192.0.2.10" || tuples[0].dst != "198.18.0.5" ||
		tuples[0].sport != 50000 || tuples[0].dport != 443 {
		t.Fatalf("client tuple = %+v", tuples[0])
	}
	if tuples[1].src != "203.0.113.9" || tuples[1].dst != "192.0.2.10" {
		t.Fatalf("reply tuple = %+v", tuples[1])
	}
}

func newWatchTestPlugin() *FakeIPNatPlugin {
	p := &FakeIPNatPlugin{
		BP:      coremain.NewBP("watch-test", "fakeip_nat", nil, nil),
		prefix:  netip.MustParsePrefix("198.18.0.0/16"),
		runtime: newRuntimeMap(),
		watch:   newTrafficWatch(),
	}
	p.runtime.put("example.com", "198.18.0.5")
	p.runtime.putReal("example.com", []string{"203.0.113.9"})
	return p
}

func TestObserveTunPacketRecordsWatchedSource(t *testing.T) {
	p := newWatchTestPlugin()
	p.watch.add("192.0.2.10")
	p.observeTunPacket(buildTCPPacket(t, "192.0.2.10", "198.18.0.5", 50000, 443))

	events, _, ok := p.watch.snapshot("192.0.2.10", 20)
	if !ok || len(events) != 1 {
		t.Fatalf("events=%+v ok=%v", events, ok)
	}
	e := events[0]
	if e.Domain != "example.com" || e.FakeIP != "198.18.0.5" ||
		e.DestinationIP != "203.0.113.9" || e.Protocol != "tcp" ||
		e.ClientPort != 50000 || e.DestinationPort != 443 || e.Packets != 1 {
		t.Fatalf("event = %+v", e)
	}
}

type watchRunner struct {
	out string
	err error
}

func (r watchRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if r.err != nil {
		return r.out, r.err
	}
	return r.out, nil
}

func TestAdminWatchNonTunUsesConntrack(t *testing.T) {
	p := newWatchTestPlugin()
	p.runner = watchRunner{out: "tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.18.0.5 " +
		"sport=50000 dport=443 src=203.0.113.9 dst=192.0.2.10 sport=443 dport=50000 [ASSURED]\n"}
	ctx := context.Background()
	if err := p.AdminWatchStart(ctx, "192.0.2.10"); err != nil {
		t.Fatalf("AdminWatchStart: %v", err)
	}
	events, _, err := p.AdminWatchSnapshot(ctx, "192.0.2.10", 20)
	if err != nil {
		t.Fatalf("AdminWatchSnapshot: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	e := events[0]
	if e.Domain != "example.com" || e.DestinationIP != "203.0.113.9" ||
		e.FakeIP != "198.18.0.5" || e.Protocol != "tcp" {
		t.Fatalf("event = %+v", e)
	}
	if err := p.AdminWatchStop(ctx, "192.0.2.10"); err != nil {
		t.Fatalf("AdminWatchStop: %v", err)
	}
	p.stopTrafficWatch()
}

func TestAdminWatchStartErrorIsReported(t *testing.T) {
	p := newWatchTestPlugin()
	p.runner = watchRunner{out: "conntrack: command not found", err: fmt.Errorf("exit status 1")}
	if err := p.AdminWatchStart(context.Background(), "192.0.2.10"); err == nil {
		t.Fatal("missing conntrack should fail the start")
	}
	// The failed start must not leave a watched source behind.
	if _, _, ok := p.watch.snapshot("192.0.2.10", 20); ok {
		t.Fatal("failed start left a watched source")
	}
}

func TestAdminWatchTunRequiresRunningDataPath(t *testing.T) {
	p := newWatchTestPlugin()
	p.useTun = true
	if err := p.AdminWatchStart(context.Background(), "192.0.2.10"); err == nil {
		t.Fatal("tun watch must refuse to start while the data path is down")
	}
	p.tunStarted = true
	if err := p.AdminWatchStart(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("tun watch start: %v", err)
	}
	if err := p.AdminWatchStop(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("tun watch stop: %v", err)
	}
}

func TestAdminWatchTunAlsoUsesConntrackFallback(t *testing.T) {
	p := newWatchTestPlugin()
	p.useTun = true
	p.tunStarted = true
	p.runner = watchRunner{out: "tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.18.0.5 " +
		"sport=50000 dport=443 src=203.0.113.9 dst=192.0.2.10 sport=443 dport=50000 [ASSURED]\n"}
	if err := p.AdminWatchStart(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("AdminWatchStart: %v", err)
	}
	defer func() {
		_ = p.AdminWatchStop(context.Background(), "192.0.2.10")
		p.stopTrafficWatch()
	}()
	events, _, err := p.AdminWatchSnapshot(context.Background(), "192.0.2.10", 20)
	if err != nil {
		t.Fatalf("AdminWatchSnapshot: %v", err)
	}
	if len(events) != 1 || events[0].Domain != "example.com" {
		t.Fatalf("events = %+v", events)
	}
}

func TestAdminWatchRejectsIPv6Source(t *testing.T) {
	p := newWatchTestPlugin()
	if err := p.AdminWatchStart(context.Background(), "2001:db8::1"); err == nil {
		t.Fatal("ipv6 source must be rejected")
	}
}

type fallbackRunner struct {
	calls []string
}

func (r *fallbackRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	r.calls = append(r.calls, name)
	if len(r.calls) == 1 {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	return "tcp 6 1 ESTABLISHED src=192.0.2.10 dst=198.18.0.5 sport=50000 dport=443 " +
		"src=203.0.113.9 dst=192.0.2.10 sport=443 dport=50000\n", nil
}

func TestAdminWatchFallsBackToAbsoluteConntrackPath(t *testing.T) {
	p := newWatchTestPlugin()
	r := &fallbackRunner{}
	p.runner = r
	if err := p.AdminWatchStart(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("AdminWatchStart: %v", err)
	}
	if len(r.calls) != 2 || r.calls[0] != "conntrack" || r.calls[1] != "/usr/sbin/conntrack" {
		t.Fatalf("calls = %v", r.calls)
	}
	_ = p.AdminWatchStop(context.Background(), "192.0.2.10")
	p.stopTrafficWatch()
}
