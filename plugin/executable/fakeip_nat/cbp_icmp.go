package fakeipnat

// cbp_icmp.go lets a CBP outlet carry raw ICMP and traceroute packets. CBP is
// the one proxy protocol here that exposes a packet tunnel: the node accepts
// complete IP packets whose source is the session's tunnel address and mirrors
// the return packets back over the same authenticated control stream.
//
// Without this path every proxy outlet answered echo requests locally, because
// socks5/http/trojan carry no ICMP. That answer was a stand-in, not the real
// host. For CBP the request is forwarded into the tunnel instead, and the
// reply is rewritten from tunnelIPv4 to the fake ip the client pinged.

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/egress"
	"go.uber.org/zap"
)

// cbpEchoPending remembers one echo request sent into the CBP tunnel.
type cbpEchoPending struct {
	client   netip.Addr
	fakeIP   netip.Addr
	realIP   netip.Addr
	clientID uint16
	seq      uint16
	payload  []byte
	deadline time.Time
}

// cbpHopProbe remembers one UDP traceroute probe sent into the tunnel. The
// quoted source port in the returned ICMP error is its lookup key.
type cbpHopProbe struct {
	flow     icmpFlow
	deadline time.Time
}

type cbpICMPRelay struct {
	conn   egress.RawIPConn
	tunnel netip.Addr
	write  func([]byte) error
	log    *zap.Logger

	mu       sync.Mutex
	echoes   map[uint16]*cbpEchoPending
	probes   map[uint16]*cbpHopProbe
	nextEcho uint16
	nextPort uint16
}

func newCBPICMPRelay(conn egress.RawIPConn, write func([]byte) error, log *zap.Logger) *cbpICMPRelay {
	return &cbpICMPRelay{
		conn:     conn,
		tunnel:   conn.TunnelIPv4(),
		write:    write,
		log:      log,
		echoes:   make(map[uint16]*cbpEchoPending),
		probes:   make(map[uint16]*cbpHopProbe),
		nextPort: 20000,
	}
}

func (r *cbpICMPRelay) addEcho(id uint16, p *cbpEchoPending) {
	r.mu.Lock()
	r.echoes[id] = p
	r.mu.Unlock()
}

func (r *cbpICMPRelay) takeEcho(id uint16) (*cbpEchoPending, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.echoes[id]
	if !ok {
		return nil, false
	}
	delete(r.echoes, id)
	if time.Now().After(p.deadline) {
		return nil, false
	}
	return p, true
}

func (r *cbpICMPRelay) dropEcho(id uint16) {
	r.mu.Lock()
	delete(r.echoes, id)
	r.mu.Unlock()
}

func (r *cbpICMPRelay) nextEchoID() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < 65535; i++ {
		r.nextEcho++
		if r.nextEcho == 0 {
			r.nextEcho = 1
		}
		if _, used := r.echoes[r.nextEcho]; !used {
			return r.nextEcho
		}
	}
	return 0
}

func (r *cbpICMPRelay) addProbe(port uint16, p *cbpHopProbe) {
	r.mu.Lock()
	r.probes[port] = p
	r.mu.Unlock()
}

func (r *cbpICMPRelay) takeProbe(port uint16) (*cbpHopProbe, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.probes[port]
	if !ok {
		return nil, false
	}
	delete(r.probes, port)
	if time.Now().After(p.deadline) {
		return nil, false
	}
	return p, true
}

func (r *cbpICMPRelay) dropProbe(port uint16) {
	r.mu.Lock()
	delete(r.probes, port)
	r.mu.Unlock()
}

func (r *cbpICMPRelay) nextProbePort() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < 65535; i++ {
		r.nextPort++
		if r.nextPort < 20000 {
			r.nextPort = 20000
		}
		if _, used := r.probes[r.nextPort]; !used {
			return r.nextPort
		}
	}
	return 0
}

func (r *cbpICMPRelay) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, p := range r.echoes {
		if now.After(p.deadline) {
			delete(r.echoes, id)
		}
	}
	for port, p := range r.probes {
		if now.After(p.deadline) {
			delete(r.probes, port)
		}
	}
}

func (r *cbpICMPRelay) forwardEcho(client, fakeIP, realIP netip.Addr, clientID, seq uint16, payload []byte) error {
	id := r.nextEchoID()
	if id == 0 {
		return errors.New("tun icmp: no free cbp echo id")
	}
	pkt := buildICMPEchoIPv4(icmpEchoRequest, r.tunnel, realIP, id, seq, payload)
	if pkt == nil {
		return errors.New("tun icmp: cannot build cbp echo packet")
	}
	r.addEcho(id, &cbpEchoPending{
		client: client, fakeIP: fakeIP, realIP: realIP,
		clientID: clientID, seq: seq, payload: payload,
		deadline: time.Now().Add(echoPendingTTL),
	})
	if err := r.conn.WritePacket(pkt); err != nil {
		r.dropEcho(id)
		return err
	}
	r.log.Debug("tun icmp: cbp echo forwarded",
		zap.String("fake_ip", fakeIP.String()), zap.String("real_ip", realIP.String()),
		zap.Uint16("seq", seq), zap.String("tunnel_ipv4", r.tunnel.String()))
	return nil
}

func (r *cbpICMPRelay) forwardProbe(flow icmpFlow, realIP netip.Addr, ttl int) (uint16, error) {
	port := r.nextProbePort()
	if port == 0 {
		return 0, errors.New("tun icmp: no free cbp probe port")
	}
	pkt := buildUDPProbeIPv4(r.tunnel, realIP, port, flow.fakePort, uint8(ttl), make([]byte, probePayloadSz))
	if pkt == nil {
		return 0, errors.New("tun icmp: cannot build cbp udp probe")
	}
	r.addProbe(port, &cbpHopProbe{
		flow:     flow,
		deadline: time.Now().Add(hopProbeTimeout),
	})
	if err := r.conn.WritePacket(pkt); err != nil {
		r.dropProbe(port)
		return 0, err
	}
	r.log.Debug("tun icmp: cbp hop probe sent",
		zap.String("fake_ip", flow.fakeIP.String()), zap.String("real_ip", realIP.String()),
		zap.Int("ttl", ttl), zap.Uint16("port", port), zap.String("tunnel_ipv4", r.tunnel.String()))
	return port, nil
}

func (p *FakeIPNatPlugin) startCBPICMP(ctx context.Context, st *tunStack) {
	if !p.cbpOutlet || p.cbpRaw == nil {
		return
	}
	openCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := p.cbpRaw.OpenRawIP(openCtx)
	if err != nil {
		p.L().Warn("tun icmp: cbp raw tunnel unavailable, ping and traceroute stay unanswered",
			zap.Error(err))
		return
	}
	r := newCBPICMPRelay(conn, st.writeOut, p.L())
	p.cbpMu.Lock()
	p.cbpICMP = r
	p.cbpMu.Unlock()
	p.L().Info("tun icmp: cbp raw tunnel ready",
		zap.String("tunnel_ipv4", r.tunnel.String()))
	go p.cbpICMPLoop(ctx, r)
}

func (p *FakeIPNatPlugin) stopCBPICMP() {
	p.cbpMu.Lock()
	r := p.cbpICMP
	p.cbpICMP = nil
	p.cbpMu.Unlock()
	if r != nil {
		_ = r.conn.Close()
	}
}

func (p *FakeIPNatPlugin) currentCBPICMP() *cbpICMPRelay {
	p.cbpMu.Lock()
	defer p.cbpMu.Unlock()
	return p.cbpICMP
}

func (p *FakeIPNatPlugin) cbpICMPLoop(ctx context.Context, r *cbpICMPRelay) {
	// Pending echoes and probes are swept on their own timer: the read loop
	// blocks on the tunnel and would never see an idle ticker.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				r.sweep(now)
			}
		}
	}()
	for {
		pkt, err := r.conn.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() == nil {
				p.L().Debug("tun icmp: cbp raw read stopped", zap.Error(err))
			}
			return
		}
		p.handleCBPPacket(r, pkt)
	}
}

func (p *FakeIPNatPlugin) handleCBPPacket(r *cbpICMPRelay, pkt []byte) {
	if len(pkt) < ipv4HeaderMinLen || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < ipv4HeaderMinLen || total > len(pkt) || total < ihl+icmpHeaderLen || pkt[9] != protoICMP {
		return
	}
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	msg := pkt[ihl:total]
	switch msg[0] {
	case icmpEchoReply:
		p.handleCBPEchoReply(r, src, msg)
	case icmpDstUnreachable, icmpTimeExceeded:
		p.handleCBPICMPError(r, src, msg)
	}
}

func (p *FakeIPNatPlugin) handleCBPEchoReply(r *cbpICMPRelay, src netip.Addr, msg []byte) {
	if len(msg) < icmpHeaderLen {
		return
	}
	id := binary.BigEndian.Uint16(msg[4:6])
	pending, ok := r.takeEcho(id)
	if !ok {
		return
	}
	if pending.realIP.IsValid() && src != pending.realIP {
		p.L().Debug("tun icmp: cbp echo reply from an unexpected address",
			zap.String("from", src.String()), zap.String("want", pending.realIP.String()))
		return
	}
	reply := buildICMPEchoIPv4(icmpEchoReply, pending.fakeIP, pending.client,
		pending.clientID, pending.seq, pending.payload)
	if reply == nil {
		return
	}
	if err := r.write(reply); err != nil {
		p.L().Warn("tun icmp: write cbp echo reply failed", zap.Error(err))
		return
	}
	p.L().Debug("tun icmp: cbp echo reply relayed",
		zap.String("fake_ip", pending.fakeIP.String()), zap.String("real_ip", pending.realIP.String()),
		zap.String("client", pending.client.String()), zap.Uint16("seq", pending.seq))
}

func (p *FakeIPNatPlugin) handleCBPICMPError(r *cbpICMPRelay, src netip.Addr, msg []byte) {
	if len(msg) < icmpHeaderLen+ipv4HeaderMinLen {
		return
	}
	typ, code := msg[0], msg[1]
	quoted := msg[icmpHeaderLen:]
	ihl := int(quoted[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(quoted) < ihl+8 || quoted[9] != protoUDP {
		return
	}
	port := binary.BigEndian.Uint16(quoted[ihl : ihl+2])
	probe, ok := r.takeProbe(port)
	if !ok {
		return
	}
	from := p.hopSource(src, typ)
	reply := buildICMPError(from, probe.flow.client, buildClientUDPQuote(probe.flow), typ, code)
	if reply == nil {
		return
	}
	if err := r.write(reply); err != nil {
		p.L().Warn("tun icmp: write cbp icmp error failed", zap.Error(err))
		return
	}
	p.L().Debug("tun icmp: cbp error relayed",
		zap.String("from", src.String()), zap.String("shown_as", from.String()),
		zap.Uint8("type", typ), zap.Uint8("code", code),
		zap.String("client", probe.flow.client.String()), zap.String("fake_ip", probe.flow.fakeIP.String()))
}

func (p *FakeIPNatPlugin) cbpForwardEcho(st *tunStack, client, fakeIP, realIP netip.Addr, clientID, seq uint16, payload []byte) {
	r := p.currentCBPICMP()
	if r == nil {
		p.L().Warn("tun icmp: cbp raw tunnel is not ready, dropping echo",
			zap.String("fake_ip", fakeIP.String()), zap.String("client", client.String()))
		return
	}
	if err := r.forwardEcho(client, fakeIP, realIP, clientID, seq, payload); err != nil {
		p.L().Warn("tun icmp: cbp echo forward failed",
			zap.String("fake_ip", fakeIP.String()), zap.String("real_ip", realIP.String()), zap.Error(err))
	}
}

func (p *FakeIPNatPlugin) cbpProbeHop(flow icmpFlow, realIP netip.Addr, ttl int) {
	r := p.currentCBPICMP()
	if r == nil {
		p.L().Warn("tun icmp: cbp raw tunnel is not ready, dropping traceroute probe",
			zap.String("fake_ip", flow.fakeIP.String()), zap.Int("ttl", ttl))
		return
	}
	p.beginProbeRound(ttl)
	port, err := r.forwardProbe(flow, realIP, ttl)
	if err != nil {
		p.L().Warn("tun icmp: cbp hop probe failed",
			zap.String("real_ip", realIP.String()), zap.Int("ttl", ttl), zap.Error(err))
		return
	}
	time.Sleep(hopProbeTimeout)
	r.dropProbe(port)
}

func buildUDPProbeIPv4(src, dst netip.Addr, sport, dport uint16, ttl uint8, payload []byte) []byte {
	if !src.Is4() || !dst.Is4() {
		return nil
	}
	udpLen := udpHeaderLen + len(payload)
	pkt := make([]byte, ipv4HeaderMinLen+udpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttl
	pkt[9] = protoUDP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^fold16(sumBytes(pkt[:ipv4HeaderMinLen], 0)))

	udp := pkt[ipv4HeaderMinLen:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[udpHeaderLen:], payload)
	// UDP checksum zero is valid for IPv4 and lets the tunnel carry a probe
	// without a pseudo-header calculation.
	return pkt
}
