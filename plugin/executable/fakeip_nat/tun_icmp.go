package fakeipnat

// This file gives the tun data path the ICMP behaviour of a real host:
//
//   - echo requests addressed to a fake ip are forwarded to the real ip the
//     fake ip is mapped to, and the reply is rewritten back to the fake ip;
//   - ICMP errors produced by the outlet (port unreachable from the far end,
//     time exceeded from a router on the way) are relayed to the client with
//     the address they actually came from, never with the fake ip;
//   - a traceroute probe is answered by probing the real path itself, and the
//     hop is shown as a virtual address of this range whose PTR record names
//     the real hop.
//
// Both need a raw ICMP socket: the upstream UDP socket only reports an error
// as a failed read and carries no address, and the userspace stack never
// emits echo requests itself.

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	icmpEchoRequest = 8
	icmpEchoReply   = 0
	// echoPendingTTL bounds how long a forwarded echo request is remembered.
	echoPendingTTL = 10 * time.Second
)

// icmpFlow is the client side of one UDP flow, kept so an ICMP error quoting
// the upstream packet can be rewritten as a reply to the client.
type icmpFlow struct {
	client     netip.Addr
	clientPort uint16
	fakeIP     netip.Addr
	fakePort   uint16
	// quote is the header of the packet the client actually sent. A host
	// quotes the packet it received byte for byte, and the client kernel
	// matches its socket on those bytes, so a rebuilt header is not accepted.
	quote []byte
}

// quoteKey identifies the packet a client sent, so the relay can quote it.
type quoteKey struct {
	src, dst     netip.Addr
	sport, dport uint16
}

type clientQuote struct {
	pkt []byte
	ttl uint8
	at  time.Time
}

const (
	maxClientQuotes = 4096
	clientQuoteTTL  = 5 * time.Second
)

// echoPending remembers one forwarded echo request: the client that sent it,
// the fake ip it targeted, and the payload to echo back.
type echoPending struct {
	client   netip.Addr
	fakeIP   netip.Addr
	realIP   netip.Addr
	clientID uint16
	seq      uint16
	payload  []byte
	deadline time.Time
}

// probeEntry is one hop probe sent to the real ip on behalf of a traceroute
// probe. The key is the local port of the probe socket: the ICMP error quotes
// it, which is how the answer is matched back. It lives only until the answer
// arrives or the deadline passes.
type probeEntry struct {
	client   netip.Addr
	fakeIP   netip.Addr
	realIP   netip.Addr
	ttl      int
	quote    []byte
	deadline time.Time
}

const (
	hopProbeTimeout = 1200 * time.Millisecond
	probeMinTTL     = 2
	probeMaxTTL     = 30
	probePayloadSz  = 32
)

// icmpRelay owns the raw socket and the tables (UDP flows for error relay,
// forwarded echo requests, hop probes).
type icmpRelay struct {
	mu     sync.Mutex
	conn   *net.IPConn
	flows  map[uint16]icmpFlow
	echoes map[uint16]*echoPending
	probes map[uint16]*probeEntry
	nextID uint16
	write  func([]byte) error
}

func newICMPRelay(write func([]byte) error) *icmpRelay {
	return &icmpRelay{
		flows:  make(map[uint16]icmpFlow),
		echoes: make(map[uint16]*echoPending),
		probes: make(map[uint16]*probeEntry),
		write:  write,
	}
}

func (r *icmpRelay) add(port uint16, f icmpFlow) {
	r.mu.Lock()
	r.flows[port] = f
	r.mu.Unlock()
}

func (r *icmpRelay) remove(port uint16) {
	r.mu.Lock()
	delete(r.flows, port)
	r.mu.Unlock()
}

func (r *icmpRelay) lookup(port uint16) (icmpFlow, bool) {
	r.mu.Lock()
	f, ok := r.flows[port]
	r.mu.Unlock()
	return f, ok
}

// newEchoID allocates the identifier used on the wire. The client keeps its
// own identifier, which is restored on the reply.
func (r *icmpRelay) newEchoID() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < 65536; i++ {
		r.nextID++
		if r.nextID == 0 {
			r.nextID = 1
		}
		if _, busy := r.echoes[r.nextID]; !busy {
			return r.nextID
		}
	}
	return r.nextID
}

func (r *icmpRelay) addEcho(id uint16, p *echoPending) {
	r.mu.Lock()
	r.echoes[id] = p
	r.mu.Unlock()
}

func (r *icmpRelay) takeEcho(id uint16) (*echoPending, bool) {
	r.mu.Lock()
	p, ok := r.echoes[id]
	delete(r.echoes, id)
	r.mu.Unlock()
	return p, ok
}

func (r *icmpRelay) dropEcho(id uint16) {
	r.mu.Lock()
	delete(r.echoes, id)
	r.mu.Unlock()
}

// sweepEcho drops requests that will never be answered.
func (r *icmpRelay) sweepEcho(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, p := range r.echoes {
		if now.After(p.deadline) {
			delete(r.echoes, id)
			n++
		}
	}
	return n
}

func (r *icmpRelay) addProbe(port uint16, e *probeEntry) {
	r.mu.Lock()
	r.probes[port] = e
	r.mu.Unlock()
}

// takeProbe removes and returns the pending probe for that port: the entry is
// gone as soon as its answer arrives, so the table never outlives a probe.
func (r *icmpRelay) takeProbe(port uint16) (*probeEntry, bool) {
	r.mu.Lock()
	e, ok := r.probes[port]
	if ok {
		delete(r.probes, port)
	}
	r.mu.Unlock()
	return e, ok
}

func (r *icmpRelay) dropProbe(port uint16) {
	r.mu.Lock()
	delete(r.probes, port)
	r.mu.Unlock()
}

func (r *icmpRelay) sweepProbe(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for port, e := range r.probes {
		if now.After(e.deadline) {
			delete(r.probes, port)
			n++
		}
	}
	return n
}

func (r *icmpRelay) send(pkt []byte, dst netip.Addr) error {
	if r.conn == nil {
		return syscall.ENOTCONN
	}
	_, err := r.conn.WriteToIP(pkt, &net.IPAddr{IP: net.IP(dst.AsSlice())})
	return err
}

// startICMPRelay opens the raw socket and starts the reader. A failure (no
// privilege, unsupported platform) only disables ICMP relay; TCP and UDP keep
// working.
func (p *FakeIPNatPlugin) startICMPRelay(ctx context.Context, st *tunStack) {
	r := newICMPRelay(st.writeOut)
	conn, err := listenRawICMP()
	if err != nil {
		// Warn, not Debug: without this socket ping and traceroute silently
		// stop working while TCP/UDP keep flowing, and at info level the only
		// hint would be missing.
		p.L().Warn("tun icmp: raw icmp socket unavailable, ping and traceroute are disabled",
			zap.Error(err), zap.String("hint", "needs root or CAP_NET_RAW"))
		return
	}
	r.conn = conn
	p.icmpMu.Lock()
	p.icmp = r
	p.icmpMu.Unlock()
	p.L().Debug("tun icmp: relay started")

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go p.icmpRelayLoop(ctx, r)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if n := r.sweepEcho(now); n > 0 {
					p.L().Debug("tun icmp: expired echo requests dropped", zap.Int("count", n))
				}
				if n := r.sweepProbe(now); n > 0 {
					p.L().Debug("tun icmp: expired hop probes dropped", zap.Int("count", n))
				}
				if n := p.sweepHops(now); n > 0 {
					p.L().Debug("tun icmp: expired hop views dropped", zap.Int("count", n))
				}
			}
		}
	}()
}

func (p *FakeIPNatPlugin) icmpRelayLoop(ctx context.Context, r *icmpRelay) {
	buf := make([]byte, 1024)
	for {
		n, src, err := r.conn.ReadFromIP(buf)
		if err != nil {
			p.L().Debug("tun icmp: raw socket read stopped", zap.Error(err))
			return
		}
		if n < icmpHeaderLen {
			continue
		}
		switch buf[0] {
		case icmpEchoReply:
			p.relayEchoReply(src, buf[:n])
		case icmpDstUnreachable, icmpTimeExceeded:
			if p.probeReply(src, buf[:n]) {
				continue
			}
			p.relayICMPError(src, buf[:n])
		}
	}
}

// relayEchoReply rewrites the answer of the real host into an answer from the
// fake ip, so the client sees the address it pinged.
func (p *FakeIPNatPlugin) relayEchoReply(src *net.IPAddr, msg []byte) {
	if len(msg) < icmpHeaderLen {
		return
	}
	id := binary.BigEndian.Uint16(msg[4:6])
	pending, ok := p.icmp.takeEcho(id)
	if !ok {
		return
	}
	if want := addrOf(src); want.IsValid() && pending.realIP.IsValid() && want != pending.realIP {
		p.L().Debug("tun icmp: echo reply from an unexpected address",
			zap.String("from", want.String()), zap.String("want", pending.realIP.String()))
		return
	}
	reply := buildICMPEchoIPv4(icmpEchoReply, pending.fakeIP, pending.client,
		pending.clientID, pending.seq, pending.payload)
	if reply == nil {
		return
	}
	if err := p.icmp.write(reply); err != nil {
		p.L().Warn("tun icmp: write echo reply to client failed", zap.Error(err))
		return
	}
	p.L().Debug("tun icmp: echo reply relayed",
		zap.String("fake_ip", pending.fakeIP.String()), zap.String("real_ip", pending.realIP.String()),
		zap.String("client", pending.client.String()), zap.Uint16("seq", pending.seq))
}

// relayICMPError forwards an ICMP error to the client that owns the quoted
// UDP packet, keeping the address the error came from as the reply source.
func (p *FakeIPNatPlugin) relayICMPError(src *net.IPAddr, msg []byte) {
	if len(msg) < icmpHeaderLen+ipv4HeaderMinLen {
		return
	}
	typ, code := msg[0], msg[1]
	quoted := msg[icmpHeaderLen:]
	ihl := int(quoted[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(quoted) < ihl+8 || quoted[9] != protoUDP {
		return
	}
	// The quoted source port is the local port of the upstream socket.
	localPort := binary.BigEndian.Uint16(quoted[ihl : ihl+2])
	flow, ok := p.icmp.lookup(localPort)
	if !ok {
		return
	}
	reply := buildICMPError(addrOf(src), flow.client, buildClientUDPQuote(flow), typ, code)
	if reply == nil {
		return
	}
	if err := p.icmp.write(reply); err != nil {
		p.L().Warn("tun icmp: write icmp error to client failed", zap.Error(err))
		return
	}
	p.L().Debug("tun icmp: error relayed to client",
		zap.String("from", src.String()), zap.Uint8("type", typ), zap.Uint8("code", code),
		zap.String("client", flow.client.String()), zap.String("fake_ip", flow.fakeIP.String()))
}

// rememberClientQuote keeps the header of a UDP packet the client just sent.
// Only the IPv4 header and the UDP header are kept: that is exactly what an
// ICMP error quotes.
func (p *FakeIPNatPlugin) rememberClientQuote(pkt []byte) {
	if len(pkt) < ipv4HeaderMinLen+udpHeaderLen || pkt[9] != protoUDP || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(pkt) < ihl+udpHeaderLen {
		return
	}
	key := quoteKey{
		src:   netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}),
		dst:   netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}),
		sport: binary.BigEndian.Uint16(pkt[ihl : ihl+2]),
		dport: binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]),
	}
	quoteLen := ihl + udpHeaderLen
	quote := append([]byte(nil), pkt[:quoteLen]...)
	// The quote is cut after the transport header, so its length field has to
	// describe the quoted bytes; a field announcing a longer original packet
	// makes the client kernel reject the ICMP message as bad length.
	binary.BigEndian.PutUint16(quote[2:4], uint16(quoteLen))

	now := time.Now()
	p.quoteMu.Lock()
	if p.quotes == nil {
		p.quotes = make(map[quoteKey]clientQuote, 64)
	}
	if len(p.quotes) >= maxClientQuotes {
		for k, q := range p.quotes {
			if now.Sub(q.at) > clientQuoteTTL {
				delete(p.quotes, k)
			}
		}
	}
	p.quotes[key] = clientQuote{pkt: quote, ttl: pkt[8], at: now}
	p.quoteMu.Unlock()
}

// takeClientQuote returns the packet the client sent for this flow and the TTL
// it was sent with.
func (p *FakeIPNatPlugin) takeClientQuote(key quoteKey) ([]byte, uint8) {
	p.quoteMu.Lock()
	defer p.quoteMu.Unlock()
	q, ok := p.quotes[key]
	if !ok {
		return nil, 0
	}
	delete(p.quotes, key)
	if time.Since(q.at) > clientQuoteTTL {
		return nil, 0
	}
	return q.pkt, q.ttl
}

// hopView is one traceroute hop handed to the client: the virtual address it
// was shown as, the real address behind it, and when it was last used.
type hopView struct {
	real netip.Addr
	at   time.Time
}

const (
	// hopViewTTL is only a backstop: a finished round is dropped as soon as the
	// next one starts, and this only catches a traceroute that stops without
	// another following. Long enough that a reply to the client's reverse
	// lookup, which can lag the probe, still finds the view.
	hopViewTTL = 30 * time.Second
	hopViewMax = 256
	// probeRoundGap separates two rounds that walk back to a shorter TTL: a
	// round climbs from probeMinTTL to probeMaxTTL, so a shorter TTL after a
	// pause means traceroute started again.
	probeRoundGap = 2 * time.Second
)

// beginProbeRound tracks the trace in flight and drops every hop view of the
// previous round as soon as a new one starts. The client never announces the
// end of a traceroute, but its probe TTL does: it climbs inside one round and
// falls back to a shorter value when the next round begins.
func (p *FakeIPNatPlugin) beginProbeRound(ttl int) {
	p.beginProbeRoundAt(ttl, time.Now())
}

func (p *FakeIPNatPlugin) beginProbeRoundAt(ttl int, now time.Time) {
	p.hopMu.Lock()
	defer p.hopMu.Unlock()
	if p.probeTTL > 0 && ttl < p.probeTTL && now.Sub(p.probeAt) > probeRoundGap {
		// A new round: nothing of the previous one is worth keeping.
		p.hops = make(map[netip.Addr]hopView)
		p.hopByReal = make(map[netip.Addr]netip.Addr)
		p.probeTTL = 0
	}
	if ttl > p.probeTTL || now.Sub(p.probeAt) > probeRoundGap {
		p.probeTTL = ttl
	}
	p.probeAt = now
}

// hopFakeFor returns the virtual address that stands for this real hop. The
// offset comes from a hash of the real address, so repeated traceroutes show
// the same virtual hop for the same real hop and a cached PTR answer keeps
// matching. A collision (an address owned by a domain, or one another live hop
// already holds) walks the scan towards lower addresses instead.
func (p *FakeIPNatPlugin) hopFakeFor(real netip.Addr) (netip.Addr, bool) {
	if !real.Is4() {
		return netip.Addr{}, false
	}
	p.hopMu.Lock()
	defer p.hopMu.Unlock()
	if p.hops == nil {
		p.hops = make(map[netip.Addr]hopView)
		p.hopByReal = make(map[netip.Addr]netip.Addr)
	}
	if f, ok := p.hopByReal[real]; ok {
		if v, live := p.hops[f]; live && time.Since(v.at) <= hopViewTTL {
			p.hops[f] = hopView{real: real, at: time.Now()}
			return f, true
		}
		delete(p.hopByReal, real)
	}
	base := p.prefix.Addr().As4()
	baseUint := uint64(binary.BigEndian.Uint32(base[:]))
	// Offsets 0..maxHosts-2 cover base+maxHosts down to base+2, i.e. every
	// usable host except the range head that the tun device owns.
	span := p.maxHosts - 1
	start := hopOffsetFor(real, span)
	for i := uint64(0); i < span; i++ {
		off := (start + i) % span
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], uint32(baseUint+p.maxHosts-off))
		cand := netip.AddrFrom4(a)
		if p.runtime.taken(cand.String()) {
			continue
		}
		if v, ok := p.hops[cand]; ok && time.Since(v.at) <= hopViewTTL {
			continue
		}
		p.hops[cand] = hopView{real: real, at: time.Now()}
		p.hopByReal[real] = cand
		p.trimHops()
		return cand, true
	}
	return netip.Addr{}, false
}

// hopOffsetFor maps a real hop address to a stable offset inside the pool.
func hopOffsetFor(real netip.Addr, span uint64) uint64 {
	if span == 0 {
		return 0
	}
	h := fnv.New32a()
	b := real.As4()
	_, _ = h.Write(b[:])
	return uint64(h.Sum32()) % span
}

// trimHops bounds the table: the oldest entries go first.
func (p *FakeIPNatPlugin) trimHops() {
	if len(p.hops) <= hopViewMax {
		return
	}
	var oldestAddr netip.Addr
	var oldest time.Time
	for addr, v := range p.hops {
		if oldest.IsZero() || v.at.Before(oldest) {
			oldestAddr, oldest = addr, v.at
		}
	}
	delete(p.hops, oldestAddr)
	for real, addr := range p.hopByReal {
		if addr == oldestAddr {
			delete(p.hopByReal, real)
			break
		}
	}
}

// hopOf resolves a virtual hop address back to the real one. The view stays
// booked until hopViewTTL expires: traceroute sends several probes per hop and
// the reverse lookup may arrive after them, so dropping the entry on the first
// lookup would hand the next probe a different address and leave the client
// with a bare address and no name for that hop.
func (p *FakeIPNatPlugin) hopOf(addr netip.Addr) (netip.Addr, bool) {
	p.hopMu.Lock()
	defer p.hopMu.Unlock()
	v, ok := p.hops[addr]
	if !ok {
		return netip.Addr{}, false
	}
	if time.Since(v.at) > hopViewTTL {
		return netip.Addr{}, false
	}
	// Keep the view alive while the client still asks about it.
	p.hops[addr] = hopView{real: v.real, at: time.Now()}
	return v.real, true
}

// sweepHops drops views the client is done with.
func (p *FakeIPNatPlugin) sweepHops(now time.Time) int {
	p.hopMu.Lock()
	defer p.hopMu.Unlock()
	n := 0
	for addr, v := range p.hops {
		if now.Sub(v.at) > hopViewTTL {
			delete(p.hops, addr)
			n++
		}
	}
	for real, addr := range p.hopByReal {
		if _, ok := p.hops[addr]; !ok {
			delete(p.hopByReal, real)
		}
	}
	return n
}

// ptrAddr parses a reverse lookup name (a.b.c.d.in-addr.arpa) into an address.
func ptrAddr(name string) (netip.Addr, bool) {
	s := strings.ToLower(strings.TrimSuffix(name, "."))
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(s, suffix) {
		return netip.Addr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(s, suffix), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var a [4]byte
	for i, part := range parts {
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 255 {
			return netip.Addr{}, false
		}
		a[3-i] = byte(v)
	}
	return netip.AddrFrom4(a), true
}

// shouldProbe reports whether the client TTL marks a traceroute probe. A host
// answers a probe with the hop at that distance; here the tunnel terminates the
// flow, so the answer has to be fetched from the real path.
func (p *FakeIPNatPlugin) shouldProbe(ttl uint8) bool {
	if ttl < probeMinTTL || ttl > probeMaxTTL {
		return false
	}
	return p.icmpRelayActive()
}

// probeHop sends one UDP probe with the client TTL to the real ip and waits for
// the ICMP error that names the hop. The entry is removed when the answer
// arrives (probeReply) or when the probe times out.
func (p *FakeIPNatPlugin) probeHop(flow icmpFlow, realIP netip.Addr, ttl int) {
	p.beginProbeRound(ttl)
	r := p.currentICMP()
	if r == nil {
		return
	}
	conn, err := listenProbeSocket(ttl)
	if err != nil {
		p.L().Debug("tun icmp: open hop probe socket failed", zap.Int("ttl", ttl), zap.Error(err))
		return
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.IP(realIP.AsSlice()), Port: int(flow.fakePort)}
	if _, err := conn.WriteToUDP(make([]byte, probePayloadSz), dst); err != nil {
		p.L().Debug("tun icmp: send hop probe failed",
			zap.String("real_ip", realIP.String()), zap.Int("ttl", ttl), zap.Error(err))
		return
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port == 0 {
		return
	}
	port := uint16(local.Port)
	r.addProbe(port, &probeEntry{
		client: flow.client, fakeIP: flow.fakeIP, realIP: realIP, ttl: ttl,
		quote: flow.quote, deadline: time.Now().Add(hopProbeTimeout),
	})
	p.L().Debug("tun icmp: hop probe sent",
		zap.String("fake_ip", flow.fakeIP.String()), zap.String("real_ip", realIP.String()),
		zap.Int("ttl", ttl), zap.Uint16("port", port))

	time.Sleep(hopProbeTimeout)
	r.dropProbe(port)
}

// probeReply matches an ICMP error to a pending hop probe and rewrites it for
// the client, with the address of the hop as the source.
func (p *FakeIPNatPlugin) probeReply(src *net.IPAddr, msg []byte) bool {
	if len(msg) < icmpHeaderLen+ipv4HeaderMinLen {
		return false
	}
	quoted := msg[icmpHeaderLen:]
	ihl := int(quoted[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(quoted) < ihl+udpHeaderLen || quoted[9] != protoUDP {
		return false
	}
	r := p.currentICMP()
	if r == nil {
		return false
	}
	entry, ok := r.takeProbe(binary.BigEndian.Uint16(quoted[ihl : ihl+2]))
	if !ok {
		return false
	}
	// The hop is shown to the client as a virtual address of this range: that
	// is the only range the client always routes here. Its PTR record names
	// the real hop, so traceroute prints both.
	hop, hopOK := netip.AddrFromSlice(src.IP)
	virtual, ok := netip.Addr{}, false
	if hopOK {
		virtual, ok = p.hopFakeFor(hop)
	}
	if !ok {
		reply := buildICMPError(addrOf(src), entry.client, entry.quote, msg[0], msg[1])
		if reply != nil {
			_ = r.write(reply)
		}
		return true
	}
	reply := buildICMPError(virtual, entry.client, entry.quote, msg[0], msg[1])
	if reply != nil {
		if err := r.write(reply); err != nil {
			p.L().Warn("tun icmp: write hop answer to client failed", zap.Error(err))
		} else {
			p.L().Debug("tun icmp: hop probe answered",
				zap.String("from", src.String()), zap.String("virtual_ip", virtual.String()),
				zap.Int("ttl", entry.ttl),
				zap.String("client", entry.client.String()), zap.String("fake_ip", entry.fakeIP.String()))
		}
	}
	return true
}

// listenProbeSocket opens an unconnected UDP socket whose IPv4 TTL is fixed,
// so the probe expires exactly at the requested hop.
func listenProbeSocket(ttl int) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); cerr != nil {
		_ = conn.Close()
		return nil, cerr
	}
	if serr != nil {
		_ = conn.Close()
		return nil, serr
	}
	return conn, nil
}

func (p *FakeIPNatPlugin) stopICMPRelay() {
	p.icmpMu.Lock()
	r := p.icmp
	p.icmp = nil
	p.icmpMu.Unlock()
	if r != nil && r.conn != nil {
		_ = r.conn.Close()
	}
}

func (p *FakeIPNatPlugin) currentICMP() *icmpRelay {
	p.icmpMu.Lock()
	defer p.icmpMu.Unlock()
	return p.icmp
}

// sendICMPErrorFromTarget answers the client without the raw socket: the
// source address is the destination the outlet tried to reach.
func (p *FakeIPNatPlugin) sendICMPErrorFromTarget(st *tunStack, flow icmpFlow, target string, typ, code uint8) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	src, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	pkt := buildICMPError(src, flow.client, buildClientUDPQuote(flow), typ, code)
	if pkt == nil {
		return
	}
	if err := st.writeOut(pkt); err != nil {
		p.L().Warn("tun icmp: write unreachable to client failed", zap.Error(err))
		return
	}
	p.L().Debug("tun icmp: error answered from the target",
		zap.String("from", src.String()), zap.Uint8("type", typ), zap.Uint8("code", code),
		zap.String("client", flow.client.String()))
}

func (p *FakeIPNatPlugin) icmpRelayActive() bool {
	p.icmpMu.Lock()
	defer p.icmpMu.Unlock()
	return p.icmp != nil && p.icmp.conn != nil
}

// handleICMPEcho forwards an echo request addressed to a fake ip. It returns
// true when the packet was consumed, so the stack never sees it (the stack
// would drop it: the destination is not a local address).
func (p *FakeIPNatPlugin) handleICMPEcho(st *tunStack, pkt []byte) bool {
	if len(pkt) < ipv4HeaderMinLen+icmpHeaderLen || pkt[9] != protoICMP {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(pkt) < ihl+icmpHeaderLen {
		return false
	}
	icmp := pkt[ihl:]
	if icmp[0] != icmpEchoRequest || icmp[1] != 0 {
		return false
	}
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	if dst == st.local {
		// The device's own address is answered by the ipv4 protocol.
		return false
	}
	payload := append([]byte(nil), icmp[icmpHeaderLen:]...)
	clientID := binary.BigEndian.Uint16(icmp[4:6])
	seq := binary.BigEndian.Uint16(icmp[6:8])
	p.L().Debug("tun icmp: echo request for fake ip",
		zap.String("fake_ip", dst.String()), zap.String("client", src.String()), zap.Uint16("seq", seq))
	// Resolution touches sqlite, so it must not block the read loop.
	go p.forwardICMPEcho(st, src, dst, clientID, seq, payload)
	return true
}

func (p *FakeIPNatPlugin) forwardICMPEcho(st *tunStack, client, fakeIP netip.Addr, clientID, seq uint16, payload []byte) {
	if !p.icmpRelayActive() {
		p.L().Debug("tun icmp: echo request dropped, icmp relay is disabled",
			zap.String("fake_ip", fakeIP.String()))
		return
	}
	target, err := p.realTarget(fakeIP.String(), 0)
	if err != nil {
		p.L().Debug("tun icmp: no route for fake ip",
			zap.String("fake_ip", fakeIP.String()), zap.Error(err))
		return
	}
	realIP, err := netip.ParseAddr(target[:len(target)-2]) // strip ":0"
	if err != nil {
		// Fall back to the host part when the port is not the last element.
		host, _, _ := net.SplitHostPort(target)
		realIP, err = netip.ParseAddr(host)
		if err != nil {
			p.L().Warn("tun icmp: invalid real ip", zap.String("target", target), zap.Error(err))
			return
		}
	}
	r := p.icmp
	id := r.newEchoID()
	r.addEcho(id, &echoPending{
		client: client, fakeIP: fakeIP, realIP: realIP,
		clientID: clientID, seq: seq, payload: payload,
		deadline: time.Now().Add(echoPendingTTL),
	})
	req := buildICMPEchoPacket(icmpEchoRequest, id, seq, payload)
	if err := r.send(req, realIP); err != nil {
		r.dropEcho(id)
		p.L().Warn("tun icmp: forward echo request failed",
			zap.String("real_ip", realIP.String()), zap.Error(err))
		return
	}
	p.L().Debug("tun icmp: echo forwarded",
		zap.String("fake_ip", fakeIP.String()), zap.String("real_ip", realIP.String()), zap.Uint16("seq", seq))
}

// buildICMPEchoPacket builds a bare ICMP echo message (the raw socket adds the
// IPv4 header).
func buildICMPEchoPacket(typ uint8, id, seq uint16, payload []byte) []byte {
	msg := make([]byte, icmpHeaderLen+len(payload))
	msg[0] = typ
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[icmpHeaderLen:], payload)
	binary.BigEndian.PutUint16(msg[2:4], ^fold16(sumBytes(msg, 0)))
	return msg
}

// buildICMPEchoIPv4 wraps an echo message in an IPv4 header addressed to the
// client, with the fake ip as source.
func buildICMPEchoIPv4(typ uint8, src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	msg := buildICMPEchoPacket(typ, id, seq, payload)
	pkt := make([]byte, ipv4HeaderMinLen+len(msg))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttlReplyTTL
	pkt[9] = protoICMP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^fold16(sumBytes(pkt[:ipv4HeaderMinLen], 0)))
	copy(pkt[ipv4HeaderMinLen:], msg)
	return pkt
}

// buildClientUDPQuote returns the packet the client sent. An ICMP error quotes
// the original header, so the client kernel can match it to its socket; the
// rebuilt form is only a fallback for a flow whose packet was not captured.
func buildClientUDPQuote(f icmpFlow) []byte {
	if len(f.quote) >= ipv4HeaderMinLen+udpHeaderLen {
		return append([]byte(nil), f.quote...)
	}
	pkt := make([]byte, ipv4HeaderMinLen+udpHeaderLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttlReplyTTL
	pkt[9] = protoUDP
	s4 := f.client.As4()
	d4 := f.fakeIP.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^fold16(sumBytes(pkt[:ipv4HeaderMinLen], 0)))

	udp := pkt[ipv4HeaderMinLen:]
	binary.BigEndian.PutUint16(udp[0:2], f.clientPort)
	binary.BigEndian.PutUint16(udp[2:4], f.fakePort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen))
	return pkt
}

func addrOf(a *net.IPAddr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	addr, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// icmpErrorFromSocketError maps the error a UDP socket reports for an ICMP
// reply back to the ICMP type/code a host would send to its client.
func icmpErrorFromSocketError(err error) (typ, code uint8, ok bool) {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return icmpDstUnreachable, icmpPortUnreachable, true
	case errors.Is(err, syscall.EHOSTUNREACH):
		return icmpDstUnreachable, icmpHostUnreachable, true
	case errors.Is(err, syscall.ENETUNREACH):
		return icmpDstUnreachable, icmpNetUnreachable, true
	}
	return 0, 0, false
}
