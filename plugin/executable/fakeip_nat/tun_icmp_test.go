package fakeipnat

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func syscallECONNREFUSED() error { return syscall.ECONNREFUSED }
func syscallEHOSTUNREACH() error { return syscall.EHOSTUNREACH }
func syscallENETUNREACH() error  { return syscall.ENETUNREACH }

type errString string

func (e errString) Error() string { return string(e) }

func TestBuildClientUDPQuote(t *testing.T) {
	flow := icmpFlow{
		client:     netip.MustParseAddr("198.18.0.1"),
		clientPort: 53898,
		fakeIP:     netip.MustParseAddr("198.18.0.8"),
		fakePort:   33440,
	}
	pkt := buildClientUDPQuote(flow)
	if len(pkt) != ipv4HeaderMinLen+udpHeaderLen {
		t.Fatalf("len = %d, want %d", len(pkt), ipv4HeaderMinLen+udpHeaderLen)
	}
	if pkt[9] != protoUDP {
		t.Fatalf("protocol = %d, want udp", pkt[9])
	}
	if got := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}); got != flow.client {
		t.Fatalf("src = %s, want %s", got, flow.client)
	}
	if got := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}); got != flow.fakeIP {
		t.Fatalf("dst = %s, want %s", got, flow.fakeIP)
	}
	if sum := sumBytes(pkt[:ipv4HeaderMinLen], 0); fold16(sum) != 0xffff {
		t.Fatalf("ipv4 header checksum invalid")
	}
	udp := pkt[ipv4HeaderMinLen:]
	if binary.BigEndian.Uint16(udp[0:2]) != flow.clientPort || binary.BigEndian.Uint16(udp[2:4]) != flow.fakePort {
		t.Fatalf("udp ports = %d/%d", binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]))
	}
}

func TestBuildICMPEchoIPv4(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.8")
	dst := netip.MustParseAddr("198.18.0.1")
	pkt := buildICMPEchoIPv4(icmpEchoReply, src, dst, 0x1234, 7, []byte("payload"))
	if pkt[9] != protoICMP {
		t.Fatalf("protocol = %d, want icmp", pkt[9])
	}
	if got := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}); got != src {
		t.Fatalf("src = %s, want %s", got, src)
	}
	if got := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}); got != dst {
		t.Fatalf("dst = %s, want %s", got, dst)
	}
	if sum := sumBytes(pkt[:ipv4HeaderMinLen], 0); fold16(sum) != 0xffff {
		t.Fatalf("ipv4 header checksum invalid")
	}
	icmp := pkt[ipv4HeaderMinLen:]
	if icmp[0] != icmpEchoReply {
		t.Fatalf("icmp type = %d, want %d", icmp[0], icmpEchoReply)
	}
	if binary.BigEndian.Uint16(icmp[4:6]) != 0x1234 || binary.BigEndian.Uint16(icmp[6:8]) != 7 {
		t.Fatalf("id/seq = %d/%d", binary.BigEndian.Uint16(icmp[4:6]), binary.BigEndian.Uint16(icmp[6:8]))
	}
	if sum := sumBytes(icmp, 0); fold16(sum) != 0xffff {
		t.Fatalf("icmp checksum invalid")
	}
}

func TestICMPErrorFromSocketError(t *testing.T) {
	cases := []struct {
		err  error
		typ  uint8
		code uint8
		ok   bool
	}{
		{syscallECONNREFUSED(), icmpDstUnreachable, icmpPortUnreachable, true},
		{syscallEHOSTUNREACH(), icmpDstUnreachable, icmpHostUnreachable, true},
		{syscallENETUNREACH(), icmpDstUnreachable, icmpNetUnreachable, true},
		{errString("other"), 0, 0, false},
	}
	for _, c := range cases {
		typ, code, ok := icmpErrorFromSocketError(c.err)
		if ok != c.ok || (ok && (typ != c.typ || code != c.code)) {
			t.Fatalf("%v: got %d/%d/%v, want %d/%d/%v", c.err, typ, code, ok, c.typ, c.code, c.ok)
		}
	}
}

func TestICMPRelayTables(t *testing.T) {
	r := newICMPRelay(nil)
	r.add(5000, icmpFlow{clientPort: 1})
	if _, ok := r.lookup(5000); !ok {
		t.Fatalf("flow 5000 missing")
	}
	r.remove(5000)
	if _, ok := r.lookup(5000); ok {
		t.Fatalf("flow 5000 not removed")
	}

	id1 := r.newEchoID()
	r.addEcho(id1, &echoPending{seq: 1, deadline: time.Now().Add(time.Second)})
	id2 := r.newEchoID()
	if id2 == id1 {
		t.Fatalf("echo id %d reused while pending", id1)
	}
	if _, ok := r.takeEcho(id2); ok {
		t.Fatalf("echo id %d should not be pending", id2)
	}
	if _, ok := r.takeEcho(id1); !ok {
		t.Fatalf("echo id %d missing", id1)
	}

	r.addEcho(9, &echoPending{deadline: time.Now().Add(-time.Second)})
	if n := r.sweepEcho(time.Now()); n != 1 {
		t.Fatalf("swept %d entries, want 1", n)
	}
}

func TestHandleICMPEchoAcceptsFakeIPOnly(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	st, err := newTunStack(1500, netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()

	build := func(dst netip.Addr, typ uint8) []byte {
		pkt := make([]byte, ipv4HeaderMinLen+icmpHeaderLen+8)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		pkt[8] = 64
		pkt[9] = protoICMP
		s4 := netip.MustParseAddr("198.18.0.1").As4()
		d4 := dst.As4()
		copy(pkt[12:16], s4[:])
		copy(pkt[16:20], d4[:])
		pkt[ipv4HeaderMinLen] = typ
		binary.BigEndian.PutUint16(pkt[ipv4HeaderMinLen+4:], 0x55)
		binary.BigEndian.PutUint16(pkt[ipv4HeaderMinLen+6:], 1)
		return pkt
	}

	if !p.handleICMPEcho(st, build(netip.MustParseAddr("198.18.0.8"), icmpEchoRequest)) {
		t.Fatalf("echo request to a fake ip must be consumed")
	}
	if p.handleICMPEcho(st, build(netip.MustParseAddr("198.18.0.1"), icmpEchoRequest)) {
		t.Fatalf("echo request to the device address must go to the stack")
	}
	if p.handleICMPEcho(st, build(netip.MustParseAddr("198.18.0.8"), icmpEchoReply)) {
		t.Fatalf("an echo reply must not be forwarded")
	}
}

func TestBuildICMPErrorQuotesTransportHeader(t *testing.T) {
	flow := icmpFlow{
		client:     netip.MustParseAddr("198.18.0.1"),
		clientPort: 52319,
		fakeIP:     netip.MustParseAddr("198.18.0.8"),
		fakePort:   33470,
	}
	quote := buildClientUDPQuote(flow)
	reply := buildICMPError(flow.fakeIP, flow.client, quote, icmpDstUnreachable, icmpPortUnreachable)
	if reply == nil {
		t.Fatalf("buildICMPError returned nil")
	}
	// 20 byte IP header + 8 byte ICMP header + 20 byte quoted IP header +
	// 8 byte quoted UDP header. Anything shorter is rejected as bad length.
	if len(reply) != ipv4HeaderMinLen+icmpHeaderLen+ipv4HeaderMinLen+udpHeaderLen {
		t.Fatalf("len = %d, want %d", len(reply), ipv4HeaderMinLen+icmpHeaderLen+ipv4HeaderMinLen+udpHeaderLen)
	}
	quoted := reply[ipv4HeaderMinLen+icmpHeaderLen:]
	if first := quoted[0]; first != 0x45 {
		t.Fatalf("quoted vhl = %#x, want 0x45", first)
	}
	if sport := binary.BigEndian.Uint16(quoted[ipv4HeaderMinLen : ipv4HeaderMinLen+2]); sport != flow.clientPort {
		t.Fatalf("quoted sport = %d, want %d", sport, flow.clientPort)
	}
	if dport := binary.BigEndian.Uint16(quoted[ipv4HeaderMinLen+2 : ipv4HeaderMinLen+4]); dport != flow.fakePort {
		t.Fatalf("quoted dport = %d, want %d", dport, flow.fakePort)
	}

	// A header without the transport header must not be quoted at all.
	if pkt := buildICMPError(flow.fakeIP, flow.client, quote[:ipv4HeaderMinLen], icmpDstUnreachable, icmpPortUnreachable); pkt != nil {
		t.Fatalf("buildICMPError accepted a quote without the transport header")
	}
}

func TestShouldProbeBounds(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	for _, ttl := range []uint8{1, 31, 64, 128, 255} {
		if p.shouldProbe(ttl) {
			t.Fatalf("ttl %d must not start a probe", ttl)
		}
	}
	// Without the raw socket there is no way to see the answer.
	if p.shouldProbe(8) {
		t.Fatalf("probe must stay off while the relay is disabled")
	}
}

func TestProbeTableIsOneShot(t *testing.T) {
	r := newICMPRelay(nil)
	e := &probeEntry{ttl: 3, deadline: time.Now().Add(time.Second)}
	r.addProbe(7000, e)
	if _, ok := r.takeProbe(7000); !ok {
		t.Fatalf("probe 7000 missing")
	}
	if _, ok := r.takeProbe(7000); ok {
		t.Fatalf("probe entry survived its answer")
	}
	r.addProbe(7001, &probeEntry{deadline: time.Now().Add(-time.Second)})
	if n := r.sweepProbe(time.Now()); n != 1 {
		t.Fatalf("swept %d probes, want 1", n)
	}
}

func TestProbeReplyRewritesHopAddress(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	var written []byte
	p.icmpMu.Lock()
	p.icmp = newICMPRelay(func(b []byte) error { written = b; return nil })
	p.icmpMu.Unlock()

	client := netip.MustParseAddr("198.18.0.1")
	fakeIP := netip.MustParseAddr("198.18.0.8")
	hop := netip.MustParseAddr("192.168.88.1")
	quote := buildClientUDPQuote(icmpFlow{client: client, clientPort: 41000, fakeIP: fakeIP, fakePort: 33440})

	const probePort = 52000
	p.icmp.addProbe(probePort, &probeEntry{
		client: client, fakeIP: fakeIP, realIP: fakeIP, ttl: 2,
		quote: quote, deadline: time.Now().Add(hopProbeTimeout),
	})

	msg := make([]byte, icmpHeaderLen+len(quote))
	msg[0] = icmpTimeExceeded
	msg[1] = 0
	copy(msg[icmpHeaderLen:], quote)
	// The probe socket source port lives in the quoted UDP header.
	binary.BigEndian.PutUint16(msg[icmpHeaderLen+ipv4HeaderMinLen:], probePort)

	if !p.probeReply(&net.IPAddr{IP: net.IP(hop.AsSlice())}, msg) {
		t.Fatalf("probe answer was not matched")
	}
	if written == nil {
		t.Fatalf("nothing was written to the client")
	}
	if got := netip.AddrFrom4([4]byte{written[12], written[13], written[14], written[15]}); got != hop {
		t.Fatalf("source = %s, want the hop %s", got, hop)
	}
	if got := netip.AddrFrom4([4]byte{written[16], written[17], written[18], written[19]}); got != client {
		t.Fatalf("destination = %s, want the client %s", got, client)
	}
	if written[ipv4HeaderMinLen] != icmpTimeExceeded {
		t.Fatalf("icmp type = %d, want time exceeded", written[ipv4HeaderMinLen])
	}
	if _, ok := p.icmp.takeProbe(probePort); ok {
		t.Fatalf("probe entry must be gone after the answer")
	}
}
