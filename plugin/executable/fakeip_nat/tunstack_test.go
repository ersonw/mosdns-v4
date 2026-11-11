package fakeipnat

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// buildUDPPacket builds a minimal IPv4 + UDP datagram for injecting into the
// stack. Checksums are left at zero: the stack validates lazily and IPv4 allows
// an unused UDP checksum.
func buildUDPPacket(t *testing.T, src, dst string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, ipv4HeaderMinLen+udpHeaderLen+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = protoUDP
	copy(buf[12:16], net.ParseIP(src).To4())
	copy(buf[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(len(buf)-ipv4HeaderMinLen))
	copy(buf[ipv4HeaderMinLen+udpHeaderLen:], payload)
	// Fill in both checksums: the stack may drop datagrams with a zero header
	// checksum, and a real client never sends one.
	v, err := parseIPv4Packet(buf)
	if err != nil {
		t.Fatalf("parse built udp packet: %v", err)
	}
	v.recomputeChecksums()
	return buf
}

func readStackPacket(t *testing.T, st *tunStack) *packetView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw := st.nextPacket(ctx)
	if raw == nil {
		t.Fatal("the stack emitted no packet")
	}
	v, err := parseIPv4Packet(raw)
	if err != nil {
		t.Fatalf("parse emitted packet: %v", err)
	}
	return v
}

func TestDialTargetUsesDomainWhenProxied(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()
	fakeIP, err := p.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}
	p.proxyActive = true

	target, err := p.dialTarget(fakeIP, 443)
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	// The proxy resolves the name itself, so the domain is handed over verbatim.
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
}

func TestDialTargetUsesRealIPWhenDirect(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()
	fakeIP, err := p.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	target, err := p.dialTarget(fakeIP, 443)
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	if target != "1.2.3.4:443" {
		t.Fatalf("target = %q, want the most recent real ip", target)
	}
}

func TestDialTargetRejectsUnknownFakeIP(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	if _, err := p.dialTarget("198.18.99.99", 443); err == nil {
		t.Fatal("an unmapped fake ip should not be dialled")
	}
}

// The UDP path is the one that can be exercised end to end off Linux: the
// datagram is injected into the stack, relayed to a local socket, and the reply
// comes back out of the stack addressed to the client.
func TestStackRelaysUDPDatagram(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()
	fakeIP, err := p.recordAndAllocate(ctx, "example.com", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer server.Close()
	serverPort := uint16(server.LocalAddr().(*net.UDPAddr).Port)

	st, err := newTunStack(defaultTunMTU, netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()
	p.startStack(st)

	const clientIP = "192.168.1.10"
	st.inject(buildUDPPacket(t, clientIP, fakeIP, 5353, serverPort, []byte("ping")))

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, clientAddr, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the relayed datagram did not arrive: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("payload = %q, want ping", buf[:n])
	}

	if _, err := server.WriteTo([]byte("pong"), clientAddr); err != nil {
		t.Fatalf("reply: %v", err)
	}
	v := readStackPacket(t, st)
	if v.proto != protoUDP {
		t.Fatalf("reply protocol = %d, want udp", v.proto)
	}
	if v.src.String() != fakeIP || v.dst.String() != clientIP {
		t.Fatalf("reply %s -> %s, want %s -> %s", v.src, v.dst, fakeIP, clientIP)
	}
	if v.srcPort != serverPort || v.dstPort != 5353 {
		t.Fatalf("reply ports %d -> %d, want %d -> 5353", v.srcPort, v.dstPort, serverPort)
	}
	if payload := v.buf[v.ihl+udpHeaderLen:]; string(payload) != "pong" {
		t.Fatalf("reply payload = %q, want pong", payload)
	}
}

// A TCP SYN must be answered by the stack itself, which is what proves the
// client talks to a terminated connection rather than to the real server.
func TestStackAnswersSYNFromFakeIP(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()
	fakeIP, err := p.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	st, err := newTunStack(defaultTunMTU, netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()
	p.startStack(st)

	const clientIP = "192.168.1.10"
	const clientPort = 40000
	st.inject(buildTCPPacket(t, clientIP, fakeIP, clientPort, 443))

	v := readStackPacket(t, st)
	if v.src.String() != fakeIP || v.dst.String() != clientIP {
		t.Fatalf("reply %s -> %s, want %s -> %s", v.src, v.dst, fakeIP, clientIP)
	}
	if v.srcPort != 443 || v.dstPort != clientPort {
		t.Fatalf("reply ports %d -> %d, want 443 -> %d", v.srcPort, v.dstPort, clientPort)
	}
	flags := v.buf[v.ihl+13]
	const synAck = 0x12
	if flags&synAck != synAck {
		t.Fatalf("tcp flags = %#x, want SYN|ACK", flags)
	}
}
