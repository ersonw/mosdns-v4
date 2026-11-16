package cbp

// Smoke test against a real edge: it only runs when CBP_SMOKE_ADDR is set, so
// the normal unit test run stays offline. It exercises the whole path a plugin
// cares about - identity signature, control handshake, QUIC bind, fragmented
// send, reassembly and the ACK/repair loop.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionSmoke(t *testing.T) {
	addr := os.Getenv("CBP_SMOKE_ADDR")
	if addr == "" {
		t.Skip("CBP_SMOKE_ADDR not set")
	}
	token := os.Getenv("CBP_SMOKE_TOKEN")
	if token == "" {
		t.Log("CBP_SMOKE_TOKEN not set, using the development token")
		token = "dev-token-change-me"
	}

	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.json")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := ClientIdentity{
		ClientID:   "mosdns-smoke",
		PublicKey:  base64.RawURLEncoding.EncodeToString(public),
		PrivateKey: base64.RawURLEncoding.EncodeToString(private.Seed()),
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := Dial(ctx, Config{
		ControlAddr:        addr,
		Token:              token,
		IdentityFile:       identityPath,
		InsecureSkipVerify: true,
		DialTimeout:        10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()

	ready := sess.Ready()
	if ready.SessionID == 0 {
		t.Fatal("session id is zero")
	}
	t.Logf("session=%d mtu=%d v4=%s gateway=%s data=%s", ready.SessionID, ready.MTU, ready.TunnelIPv4, ready.GatewayIPv4, ready.DataAddr)

	// A raw IPv4 packet with an ICMP echo body: the development edge runs the
	// memory tunnel, which echoes whatever it receives.
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	// The edge routes a tunnel packet by its destination lease, so the echo
	// only comes back when the packet is addressed to this session's own
	// tunnel address.
	own, err := netip.ParseAddr(ready.TunnelIPv4)
	if err != nil {
		t.Fatalf("parse tunnel address %q: %v", ready.TunnelIPv4, err)
	}
	// The edge rejects a packet whose source is not this session's own lease,
	// and routes the echo back by destination lease, so both ends are ours.
	copy(packet[12:16], own.AsSlice())
	copy(packet[16:20], own.AsSlice())
	packet[20] = 8
	packet[21] = 0
	binary.BigEndian.PutUint16(packet[24:26], 0x1234)
	binary.BigEndian.PutUint16(packet[26:28], 1)
	// Header checksum.
	var sum uint32
	for i := 0; i < 20; i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))

	if err := sess.SendPacket(packet); err != nil {
		t.Fatalf("send: %v", err)
	}

	received, err := sess.ReceivePacket(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(received, packet) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(received), len(packet))
	}
	t.Log("raw ip echo verified through cbp data plane")
}
