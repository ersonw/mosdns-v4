package cbp_proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSelectNodeAddressesRequiresTCPAndSkipsClosedPorts(t *testing.T) {
	openA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer openA.Close()
	openB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer openB.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := selectNodeAddresses(ctx, []string{openA.Addr().String(), closedAddr, openB.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("reachable = %+v, want 2", got)
	}
	for _, candidate := range got {
		if candidate.Address == closedAddr {
			t.Fatalf("closed TCP port was selected: %+v", got)
		}
	}
}

func TestRelayChoicesPrefersMainAfterNodeRelay(t *testing.T) {
	primary := SelectedMain{ID: "edge-sg", Role: "relay", Address: "43.128.119.39:8443", RTT: 3 * time.Millisecond}
	fallbacks := []SelectedMain{
		{ID: "edge-ph", Role: "relay", Address: "82.41.237.60:8443", RTT: 30 * time.Millisecond},
		{ID: "main", Role: "main", Address: "103.49.60.205:9443", RTT: 40 * time.Millisecond},
	}
	got := relayChoices(primary, fallbacks)
	if len(got) != 3 {
		t.Fatalf("choices = %+v", got)
	}
	if got[0].Address != primary.Address || got[1].Address != "103.49.60.205:9443" || got[2].Address != "82.41.237.60:8443" {
		t.Fatalf("choices = %+v", got)
	}
}
