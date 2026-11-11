package fakeipnat

// Echo requests have two outlets: a proxy cannot carry ICMP at all, so the
// device answers on behalf of the destination; a direct outlet sends the echo
// through the configured interface.

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// captureDevice records what the plugin writes to the tun device.
type captureDevice struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *captureDevice) Read([]byte) (int, error)        { return 0, io.EOF }
func (c *captureDevice) SetReadDeadline(time.Time) error { return nil }
func (c *captureDevice) Close() error                    { return nil }

func (c *captureDevice) Write(pkt []byte) (int, error) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), pkt...))
	c.mu.Unlock()
	return len(pkt), nil
}

func (c *captureDevice) last() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pkts) == 0 {
		return nil
	}
	return c.pkts[len(c.pkts)-1]
}

func seedMapping(t *testing.T, p *FakeIPNatPlugin, domain, fakeIP, realIP string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().Unix()
	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.mapTable+" (domain, fake_ip, created_at, last_seen) VALUES (?,?,?,?)",
		domain, fakeIP, now, now); err != nil {
		t.Fatalf("seed mapping failed: %v", err)
	}
	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?,?,?)",
		domain, realIP, now); err != nil {
		t.Fatalf("seed real ip failed: %v", err)
	}
}

func TestProxyAnswersEchoLocally(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	seedMapping(t, p, "example.com", "198.18.0.8", "93.184.216.34")
	p.proxyActive = true

	// A stand-in conn only satisfies the "relay is active" check: both the raw
	// socket write and the device write are asserted separately.
	p.icmpMu.Lock()
	p.icmp = newICMPRelay(func([]byte) error {
		t.Fatal("the local answer goes through the device, not the raw socket")
		return nil
	})
	p.icmp.conn = &net.IPConn{}
	p.icmpMu.Unlock()
	p.icmp.sendHook = func([]byte, netip.Addr) error {
		t.Fatal("a proxy cannot carry icmp, the real path must not be used")
		return nil
	}

	dev := &captureDevice{}
	st := &tunStack{dev: dev}
	client := netip.MustParseAddr("192.168.10.20")
	fakeIP := netip.MustParseAddr("198.18.0.8")
	payload := []byte("0123456789abcdef")
	const clientID, seq = uint16(0x4242), uint16(7)

	p.forwardICMPEcho(st, client, fakeIP, clientID, seq, payload)

	reply := dev.last()
	if reply == nil {
		t.Fatal("no echo reply was written to the device")
	}
	if reply[9] != protoICMP {
		t.Fatalf("protocol = %d, want icmp", reply[9])
	}
	icmp := reply[ipv4HeaderMinLen:]
	if icmp[0] != icmpEchoReply || icmp[1] != 0 {
		t.Fatalf("icmp type/code = %d/%d, want 0/0", icmp[0], icmp[1])
	}
	if got := binary.BigEndian.Uint16(icmp[4:6]); got != clientID {
		t.Fatalf("echo id = %d, want the client's %d", got, clientID)
	}
	if got := binary.BigEndian.Uint16(icmp[6:8]); got != seq {
		t.Fatalf("echo seq = %d, want %d", got, seq)
	}
	if string(icmp[icmpHeaderLen:]) != string(payload) {
		t.Fatalf("payload = %q, want %q", icmp[icmpHeaderLen:], payload)
	}
	from := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]})
	to := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]})
	if from != fakeIP || to != client {
		t.Fatalf("reply %s -> %s, want %s -> %s", from, to, fakeIP, client)
	}
	if !checkIPv4Checksum(reply) || fold16(sumBytes(reply[ipv4HeaderMinLen:], 0)) != 0xffff {
		t.Fatal("reply checksums are wrong")
	}
	p.icmp.mu.Lock()
	pending := len(p.icmp.echoes)
	p.icmp.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d echo requests left pending after a local answer", pending)
	}
}

func TestDirectOutletForwardsEchoToTheRealPath(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	seedMapping(t, p, "example.com", "198.18.0.8", "93.184.216.34")
	p.proxyActive = false

	var sent []byte
	var sentTo netip.Addr
	p.icmpMu.Lock()
	p.icmp = newICMPRelay(func([]byte) error { t.Fatal("no reply should reach the client yet"); return nil })
	p.icmp.conn = &net.IPConn{}
	p.icmpMu.Unlock()
	p.icmp.sendHook = func(pkt []byte, dst netip.Addr) error {
		sent = append([]byte(nil), pkt...)
		sentTo = dst
		return nil
	}

	dev := &captureDevice{}
	st := &tunStack{dev: dev}
	client := netip.MustParseAddr("192.168.10.20")
	fakeIP := netip.MustParseAddr("198.18.0.8")
	payload := []byte("0123456789abcdef")
	const clientID, seq = uint16(0x4242), uint16(7)

	p.forwardICMPEcho(st, client, fakeIP, clientID, seq, payload)

	if sent == nil {
		t.Fatal("nothing was sent to the real path")
	}
	if sent[0] != icmpEchoRequest {
		t.Fatalf("icmp type = %d, want an echo request", sent[0])
	}
	if sentTo != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("echo sent to %s, want the real ip", sentTo)
	}
	// The wire identifier belongs to the relay, the client's id is restored on
	// the reply, so the two must differ here.
	if id := binary.BigEndian.Uint16(sent[4:6]); id == clientID {
		t.Fatalf("wire id = %d, must not collide with the client's id", id)
	}
	if dev.last() != nil {
		t.Fatal("a forwarded echo must not answer the client yet")
	}

	p.icmp.mu.Lock()
	defer p.icmp.mu.Unlock()
	if len(p.icmp.echoes) != 1 {
		t.Fatalf("%d pending echo requests, want 1", len(p.icmp.echoes))
	}
	for _, pending := range p.icmp.echoes {
		if pending.clientID != clientID || pending.seq != seq {
			t.Fatalf("pending entry keeps id %d seq %d, want %d/%d", pending.clientID, pending.seq, clientID, seq)
		}
		if pending.fakeIP != fakeIP || pending.client != client {
			t.Fatalf("pending entry points at %s/%s, want %s/%s", pending.fakeIP, pending.client, fakeIP, client)
		}
	}
}

// An unmapped fake ip has no destination to speak for, so nothing is answered
// even on a proxied outlet.
func TestProxyDoesNotAnswerUnmappedEcho(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	p.proxyActive = true

	dev := &captureDevice{}
	st := &tunStack{dev: dev}
	p.forwardICMPEcho(st, netip.MustParseAddr("192.168.10.20"), netip.MustParseAddr("198.18.0.99"), 1, 1, []byte("x"))

	if dev.last() != nil {
		t.Fatal("an unmapped fake ip must stay silent")
	}
}
