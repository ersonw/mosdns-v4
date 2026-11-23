package egress_route

import (
	"context"
	"errors"
	"net"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type loggingTestDialer struct {
	err error
}

func (d loggingTestDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func TestLoggingDialerRecordsSuccessAtDebug(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	d := &loggingDialer{
		dialer: loggingTestDialer{},
		log:    zap.New(core),
		exit:   "proxy",
		proxy:  "127.0.0.1:1080",
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("got %d log entries, want 2: %#v", len(entries), entries)
	}
	if entries[0].Message != "egress_route: dialing" || entries[0].Level != zap.DebugLevel {
		t.Fatalf("first entry = %#v", entries[0])
	}
	if entries[0].ContextMap()["mode"] != "proxy" || entries[0].ContextMap()["target"] != "example.com:443" {
		t.Fatalf("first entry context = %#v", entries[0].ContextMap())
	}
	if entries[1].Message != "egress_route: dial ready" || entries[1].Level != zap.DebugLevel {
		t.Fatalf("second entry = %#v", entries[1])
	}
}

func TestLoggingDialerRecordsFailureAtWarn(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	d := &loggingDialer{
		dialer: loggingTestDialer{err: errors.New("proxy refused")},
		log:    zap.New(core),
		exit:   "proxy",
		proxy:  "127.0.0.1:1080",
	}
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("dial succeeded, want error")
	}

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("got %d log entries, want 2", len(entries))
	}
	if entries[1].Message != "egress_route: dial failed" || entries[1].Level != zap.WarnLevel {
		t.Fatalf("failure entry = %#v", entries[1])
	}
	if entries[1].ContextMap()["target"] != "example.com:443" {
		t.Fatalf("failure context = %#v", entries[1].ContextMap())
	}
}

func TestLoggingDialerUnwrapsForTypeSpecificOptions(t *testing.T) {
	core, _ := observer.New(zap.DebugLevel)
	d := &loggingDialer{
		dialer: loggingTestDialer{},
		log:    zap.New(core),
		exit:   "proxy",
		proxy:  "127.0.0.1:1080",
	}
	if got := d.UnwrapDialer(); got != d.dialer {
		t.Fatalf("UnwrapDialer = %T, want the wrapped dialer", got)
	}
}
