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
