package fakeipnat

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

type fakeRawIPConn struct {
	tunnel netip.Addr
	mu     sync.Mutex
	writes [][]byte
}

func (c *fakeRawIPConn) TunnelIPv4() netip.Addr { return c.tunnel }
func (c *fakeRawIPConn) WritePacket(pkt []byte) error {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), pkt...))
	c.mu.Unlock()
	return nil
}
func (c *fakeRawIPConn) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *fakeRawIPConn) Close() error { return nil }
func (c *fakeRawIPConn) lastWrite(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		t.Fatal("no packet written")
	}
	return c.writes[len(c.writes)-1]
}

func TestCBPICMPRelayForwardsEchoAndRewritesReply(t *testing.T) {
	tunnel := netip.MustParseAddr("10.66.0.2")
	realIP := netip.MustParseAddr("93.184.216.34")
	client := netip.MustParseAddr("192.168.1.10")
	fakeIP := netip.MustParseAddr("198.18.0.7")
	conn := &fakeRawIPConn{tunnel: tunnel}
	out := &fakeRawIPConn{tunnel: netip.MustParseAddr("192.168.1.1")}
	r := newCBPICMPRelay(conn, out.WritePacket, zap.NewNop())

	payload := []byte{1, 2, 3, 4}
	if err := r.forwardEcho(client, fakeIP, realIP, 0x1234, 7, payload); err != nil {
		t.Fatalf("forwardEcho: %v", err)
	}
	req := conn.lastWrite(t)
	if len(req) != ipv4HeaderMinLen+icmpHeaderLen+len(payload) {
		t.Fatalf("request length = %d", len(req))
	}
	if got := netip.AddrFrom4([4]byte{req[12], req[13], req[14], req[15]}); got != tunnel {
		t.Fatalf("request src = %s, want %s", got, tunnel)
	}
	if got := netip.AddrFrom4([4]byte{req[16], req[17], req[18], req[19]}); got != realIP {
		t.Fatalf("request dst = %s, want %s", got, realIP)
	}
	if req[9] != protoICMP || req[ipv4HeaderMinLen] != icmpEchoRequest {
		t.Fatalf("not an icmp echo request: proto=%d type=%d", req[9], req[ipv4HeaderMinLen])
	}
	tunnelID := binary.BigEndian.Uint16(req[ipv4HeaderMinLen+4 : ipv4HeaderMinLen+6])

	reply := buildICMPEchoIPv4(icmpEchoReply, realIP, tunnel, tunnelID, 7, payload)
	if reply == nil {
		t.Fatal("reply packet not built")
	}
	p := &FakeIPNatPlugin{BP: coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)}
	p.handleCBPEchoReply(r, realIP, reply[ipv4HeaderMinLen:])

	got := out.lastWrite(t)
	if len(got) < ipv4HeaderMinLen+icmpHeaderLen {
		t.Fatalf("relayed packet too short: %d", len(got))
	}
	if src := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]}); src != fakeIP {
		t.Fatalf("relayed src = %s, want %s", src, fakeIP)
	}
	if dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]}); dst != client {
		t.Fatalf("relayed dst = %s, want %s", dst, client)
	}
	if got[ipv4HeaderMinLen] != icmpEchoReply {
		t.Fatalf("relayed type = %d", got[ipv4HeaderMinLen])
	}
	if id := binary.BigEndian.Uint16(got[ipv4HeaderMinLen+4 : ipv4HeaderMinLen+6]); id != 0x1234 {
		t.Fatalf("relayed id = %#x, want client id", id)
	}
}

func TestBuildUDPProbeIPv4(t *testing.T) {
	src := netip.MustParseAddr("10.66.0.2")
	dst := netip.MustParseAddr("93.184.216.34")
	pkt := buildUDPProbeIPv4(src, dst, 31000, 33434, 5, make([]byte, probePayloadSz))
	if pkt == nil {
		t.Fatal("probe packet not built")
	}
	if pkt[8] != 5 || pkt[9] != protoUDP {
		t.Fatalf("ttl/proto = %d/%d", pkt[8], pkt[9])
	}
	if sum := sumBytes(pkt[:ipv4HeaderMinLen], 0); fold16(sum) != 0xffff {
		t.Fatalf("ipv4 checksum does not fold to 0xffff: %#x", fold16(sum))
	}
	udp := pkt[ipv4HeaderMinLen:]
	if got := binary.BigEndian.Uint16(udp[0:2]); got != 31000 {
		t.Fatalf("sport = %d", got)
	}
	if got := binary.BigEndian.Uint16(udp[2:4]); got != 33434 {
		t.Fatalf("dport = %d", got)
	}
	if got := binary.BigEndian.Uint16(udp[4:6]); got != uint16(udpHeaderLen+probePayloadSz) {
		t.Fatalf("udp length = %d", got)
	}
}

func TestCBPOutletProbesTracerouteWithoutLocalICMP(t *testing.T) {
	p := &FakeIPNatPlugin{BP: coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil), cbpOutlet: true}
	if !p.shouldProbe(5) {
		t.Fatal("cbp outlet must probe traceroute hops")
	}
	p.cbpOutlet = false
	if p.shouldProbe(5) {
		t.Fatal("direct outlet without a raw relay must not probe")
	}
}

func TestCBPICMPErrorRelaysHopToOneClient(t *testing.T) {
	tunnel := netip.MustParseAddr("10.66.0.2")
	realIP := netip.MustParseAddr("93.184.216.34")
	client := netip.MustParseAddr("192.168.1.10")
	fakeIP := netip.MustParseAddr("198.18.0.7")
	conn := &fakeRawIPConn{tunnel: tunnel}
	out := &fakeRawIPConn{tunnel: netip.MustParseAddr("192.168.1.1")}
	p := &FakeIPNatPlugin{
		BP:       coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil),
		prefix:   netip.MustParsePrefix("198.18.0.0/15"),
		maxHosts: 512,
		runtime:  newRuntimeMap(),
	}
	r := newCBPICMPRelay(conn, out.WritePacket, p.L())

	flow := icmpFlow{client: client, fakeIP: fakeIP, fakePort: 33434, clientPort: 44000}
	if _, err := r.forwardProbe(flow, realIP, 5); err != nil {
		t.Fatalf("forwardProbe: %v", err)
	}
	probe := conn.lastWrite(t)

	msg := make([]byte, icmpHeaderLen+len(probe))
	msg[0] = icmpTimeExceeded
	copy(msg[icmpHeaderLen:], probe)
	p.handleCBPICMPError(r, netip.MustParseAddr("203.0.113.9"), msg)

	got := out.lastWrite(t)
	if len(got) < ipv4HeaderMinLen+icmpHeaderLen {
		t.Fatalf("relayed packet too short: %d", len(got))
	}
	if typ := got[ipv4HeaderMinLen]; typ != icmpTimeExceeded {
		t.Fatalf("relayed type = %d, want time exceeded", typ)
	}
	if dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]}); dst != client {
		t.Fatalf("relayed dst = %s, want client", dst)
	}
	quoted := got[ipv4HeaderMinLen+icmpHeaderLen:]
	if len(quoted) < ipv4HeaderMinLen+udpHeaderLen {
		t.Fatalf("relayed quote too short: %d", len(quoted))
	}
	if sport := binary.BigEndian.Uint16(quoted[ipv4HeaderMinLen : ipv4HeaderMinLen+2]); sport != flow.clientPort {
		t.Fatalf("quoted sport = %d, want %d", sport, flow.clientPort)
	}
	if dport := binary.BigEndian.Uint16(quoted[ipv4HeaderMinLen+2 : ipv4HeaderMinLen+4]); dport != flow.fakePort {
		t.Fatalf("quoted dport = %d, want %d", dport, flow.fakePort)
	}
}

type fakeTunDevice struct {
	mu     sync.Mutex
	writes [][]byte
}

func (d *fakeTunDevice) Read(buf []byte) (int, error)      { return 0, context.Canceled }
func (d *fakeTunDevice) SetReadDeadline(t time.Time) error { return nil }
func (d *fakeTunDevice) Close() error                      { return nil }
func (d *fakeTunDevice) Write(pkt []byte) (int, error) {
	d.mu.Lock()
	d.writes = append(d.writes, append([]byte(nil), pkt...))
	d.mu.Unlock()
	return len(pkt), nil
}
func (d *fakeTunDevice) lastWrite(t *testing.T) []byte {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.writes) == 0 {
		t.Fatal("tun device got no packet")
	}
	return d.writes[len(d.writes)-1]
}

func TestCBPForwardEchoWritesReplyToTun(t *testing.T) {
	tunnel := netip.MustParseAddr("10.66.0.2")
	realIP := netip.MustParseAddr("1.1.1.1")
	client := netip.MustParseAddr("192.168.1.10")
	fakeIP := netip.MustParseAddr("198.18.0.9")
	tunDev := &fakeTunDevice{}
	st := &tunStack{dev: tunDev}
	conn := &fakeRawIPConn{tunnel: tunnel}
	p := &FakeIPNatPlugin{BP: coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil), cbpOutlet: true}
	r := newCBPICMPRelay(conn, st.writeOut, p.L())
	p.cbpICMP = r

	payload := []byte{8, 8, 8, 8}
	p.cbpForwardEcho(st, client, fakeIP, realIP, 0x4321, 9, payload)
	req := conn.lastWrite(t)
	if req[ipv4HeaderMinLen] != icmpEchoRequest {
		t.Fatalf("request type = %d", req[ipv4HeaderMinLen])
	}
	reply := buildICMPEchoIPv4(icmpEchoReply, realIP, tunnel,
		binary.BigEndian.Uint16(req[ipv4HeaderMinLen+4:ipv4HeaderMinLen+6]), 9, payload)
	p.handleCBPEchoReply(r, realIP, reply[ipv4HeaderMinLen:])

	got := tunDev.lastWrite(t)
	if dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]}); dst != client {
		t.Fatalf("tun reply dst = %s, want %s", dst, client)
	}
	if src := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]}); src != fakeIP {
		t.Fatalf("tun reply src = %s, want %s", src, fakeIP)
	}
	if id := binary.BigEndian.Uint16(got[ipv4HeaderMinLen+4 : ipv4HeaderMinLen+6]); id != 0x4321 {
		t.Fatalf("tun reply id = %#x", id)
	}
}
