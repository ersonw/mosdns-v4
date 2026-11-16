package egress

// The URL form is what users actually write in config.yaml, so this test goes
// through newEgress instead of calling cbp.Dial directly. It needs the
// development edge: set CBP_SMOKE_ADDR to run it.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/egress/cbp"
)

func TestNewEgressCBPURL(t *testing.T) {
	addr := os.Getenv("CBP_SMOKE_ADDR")
	if addr == "" {
		t.Skip("CBP_SMOKE_ADDR not set")
	}

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := cbp.ClientIdentity{
		ClientID:   "mosdns-url-test",
		PublicKey:  base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)),
		PrivateKey: base64.RawURLEncoding.EncodeToString(private.Seed()),
	}
	body, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(identityPath, body, 0600); err != nil {
		t.Fatal(err)
	}

	raw := fmt.Sprintf("cbp://dev-token-change-me@%s?identity_file=%s&insecure=true&client_id=mosdns-url-test",
		addr, url.QueryEscape(identityPath))
	d, err := newEgress(raw, false)
	if err != nil {
		t.Fatalf("newEgress: %v", err)
	}
	outlet, ok := d.(*cbpEgress)
	if !ok {
		t.Fatalf("cbp scheme produced %T", d)
	}
	defer outlet.Close()

	if got := describeEgress(d); got != "cbp://"+addr {
		t.Fatalf("describe = %q", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeEgress(ctx, d); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if outlet.mtu != 1280 {
		t.Fatalf("mtu = %d, want the tunnel mtu", outlet.mtu)
	}
	if !outlet.v4.Is4() {
		t.Fatalf("tunnel ipv4 = %v", outlet.v4)
	}
}

func TestNewEgressCBPRequiresIdentityFile(t *testing.T) {
	if _, err := newEgress("cbp://token@127.0.0.1:9443", false); err == nil {
		t.Fatal("missing identity_file accepted")
	}
}

// A standalone edge's keygen bundle is the whole credential: it carries the
// client key, node token, CA path and endpoint. The URL below deliberately has
// no token, so a successful TCP exchange proves the bundle supplied it.
func TestCBPStandaloneBundleSmoke(t *testing.T) {
	bundlePath := os.Getenv("CBP_STANDALONE_BUNDLE")
	if bundlePath == "" {
		t.Skip("CBP_STANDALONE_BUNDLE not set")
	}
	_, meta, found, err := cbp.LoadClientIdentity(bundlePath)
	if err != nil || !found {
		t.Fatalf("load standalone bundle: found=%v err=%v", found, err)
	}
	addr := os.Getenv("CBP_STANDALONE_ADDR")
	if addr == "" {
		addr = strings.TrimPrefix(meta.ControlEndpoint, "tls://")
		addr = strings.TrimPrefix(addr, "quic://")
	}
	if addr == "" {
		t.Fatal("bundle has no control endpoint; set CBP_STANDALONE_ADDR")
	}

	raw := fmt.Sprintf("cbp://%s?identity_file=%s", addr, url.QueryEscape(bundlePath))
	d, err := newEgress(raw, false)
	if err != nil {
		t.Fatalf("newEgress without URL token: %v", err)
	}
	defer Close(d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeEgress(ctx, d); err != nil {
		t.Fatalf("probe: %v", err)
	}

	target := os.Getenv("CBP_STANDALONE_TARGET")
	if target == "" {
		target = "1.1.1.1:80"
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dcancel()
	conn, err := d.DialContext(dctx, "tcp", target)
	if err != nil {
		t.Fatalf("dial %s through standalone edge: %v", target, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "HTTP/") {
		t.Fatalf("unexpected response %q", buf[:n])
	}
	_ = conn.Close()

	// CBP carries raw IPv4/IPv6, so UDP must work through the same session.
	// A DNS query is the smallest observable server response.
	udpTarget := os.Getenv("CBP_STANDALONE_UDP_TARGET")
	if udpTarget == "" {
		udpTarget = "1.1.1.1:53"
	}
	uconn, err := d.DialContext(dctx, "udp", udpTarget)
	if err != nil {
		t.Fatalf("dial udp %s through standalone edge: %v", udpTarget, err)
	}
	defer uconn.Close()
	_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := uconn.Write(query); err != nil {
		t.Fatalf("write udp: %v", err)
	}
	if n, err := uconn.Read(buf); err != nil || n < 12 {
		t.Fatalf("read udp response = %d bytes, err %v", n, err)
	}
}
