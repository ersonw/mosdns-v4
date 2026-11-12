package fakeipnat

// This file is the userspace half of the tun data path. Instead of rewriting
// packets and pushing them back into the kernel, the traffic that arrives on the
// tun device is terminated by an in-process TCP/IP stack (gVisor netstack) and
// dialled out through egress. Terminating the connection is what makes the proxy
// case work at all: only then does the plugin know the domain name, and only
// then can it send `CONNECT domain:port` to the proxy instead of a bare IP.
//
// Two outlet modes share this stack:
//   - proxy configured and reachable: dial `domain:port`, the proxy resolves it;
//   - otherwise: look the fake IP up in the mapping table, take the most recent
//     real IP of that domain and dial `realIP:port`.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"go.uber.org/zap"
)

const (
	// defaultTunMTU matches the MTU setupTun puts on the device.
	defaultTunMTU = 1500
	// proxyTunMTU leaves room for the tunnel a proxied outlet runs through. A
	// wireguard hop is commonly 1420, and trojan adds a TLS record on top, so
	// 1500-byte segments are lost on that path while handshakes still succeed:
	// the page loads its first exchange and then hangs. 1400 keeps a safe
	// headroom and an explicit tun_mtu overrides it.
	proxyTunMTU = 1400
	// minTunMTU is the smallest IPv4 reassembly size a host must accept.
	minTunMTU = 576
	// maxTunMTU is the Ethernet MTU; a fake range never needs more.
	maxTunMTU = 1500
	// tunLinkQueue is how many outbound packets may wait to be written back to
	// the device before the stack starts dropping.
	tunLinkQueue = 256
	// tunTCPMaxInFlight bounds simultaneously terminated TCP connections.
	tunTCPMaxInFlight = 1024
	// tunTargetTimeout bounds the "fake IP -> domain -> real IP" database work.
	tunTargetTimeout = 5 * time.Second
	// tunDialTimeout bounds the egress handshake (proxy CONNECT included).
	tunDialTimeout = 10 * time.Second
	// tunRelayBuffer is the copy buffer per direction.
	tunRelayBuffer = 32 << 10
	// tunUDPMaxDatagram is large enough for any IPv4 UDP payload.
	tunUDPMaxDatagram = 65535
)

// tunStack is the in-process stack attached to the tun device: packets read from
// the device are injected here, packets the stack emits are written back.
type tunStack struct {
	link  *channel.Endpoint
	stk   *stack.Stack
	nicID tcpip.NICID
	mtu   uint32
	// local is the device's own address (the first host of ipv4_range). It is
	// registered on the NIC so packets sent to it are delivered locally instead
	// of being treated as traffic for a fake IP.
	local netip.Addr
	// virtualSrc maps an address to the virtual one it is shown as. It is used
	// when this device answers as a hop: a reply whose source is the device's
	// own address is dropped by the receiving kernel as a martian source, so the
	// device answers as a stand-in address of the range, whose PTR record names
	// the device (see hopFakeFor). A nil hook answers with the bare address.
	virtualSrc func(netip.Addr) (netip.Addr, bool)
	// dev is the device the write loop writes to. ICMP replies built outside
	// the stack (echo relay, error relay) use writeOut, so both writers share
	// one mutex.
	dev     tunDevice
	writeMu sync.Mutex
}

// answerSource picks the address a reply built by this device is sent from.
func (t *tunStack) answerSource(addr netip.Addr) netip.Addr {
	if t.virtualSrc == nil || !addr.IsValid() {
		return addr
	}
	if v, ok := t.virtualSrc(addr); ok {
		return v
	}
	return addr
}

// resolveTunMTU picks the MTU of the tun device: an explicit tun_mtu wins,
// otherwise a direct outlet keeps the Ethernet size and a proxied outlet drops
// to proxyTunMTU, because a proxy path carries another tunnel underneath.
func resolveTunMTU(explicit int, proxyActive bool) (uint32, error) {
	mtu := uint32(explicit)
	if mtu == 0 {
		mtu = defaultTunMTU
		if proxyActive {
			mtu = proxyTunMTU
		}
	}
	if mtu < minTunMTU || mtu > maxTunMTU {
		return 0, fmt.Errorf("tun_mtu %d is outside %d..%d", explicit, minTunMTU, maxTunMTU)
	}
	return mtu, nil
}

func newTunStack(mtu uint32, local netip.Addr) (*tunStack, error) {
	if mtu == 0 {
		mtu = defaultTunMTU
	}
	if !local.Is4() {
		return nil, fmt.Errorf("tun address %q is not ipv4", local)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(tunLinkQueue, mtu, "")
	nicID := s.NextNICID()
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("create tun nic: %v", err)
	}
	// Owning the first host address is what makes the device answer like a
	// host: the ipv4 protocol replies to echo requests delivered locally.
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(local.As4()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add tun address %s: %v", local, err)
	}
	// The device only owns the first host of ipv4_range, so every other address
	// in the range is foreign to it: promiscuous mode accepts them all and
	// spoofing lets the stack speak as those addresses when it replies.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("enable promiscuous mode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("enable spoofing: %v", err)
	}
	// Replies go back out the same device whatever the client address is.
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})
	return &tunStack{link: linkEP, stk: s, nicID: nicID, mtu: mtu, local: local}, nil
}

// precheck inspects one packet read from the device before it reaches the
// stack. A packet addressed to the device's own address is delivered locally
// (the ipv4 protocol answers echo requests itself). Everything else is traffic
// for a fake IP, which a real host would forward, so a TTL of 1 has to be
// answered with ICMP Time Exceeded - that is what lets traceroute show this
// device as the first hop. The returned reply must be written back to the
// device and the original packet dropped.
func (t *tunStack) precheck(pkt []byte) (reply []byte, drop bool) {
	// Parsed by hand rather than with parseIPv4Packet: that helper only accepts
	// TCP and UDP, while ICMP needs the same TTL treatment.
	if len(pkt) < ipv4HeaderMinLen || pkt[0]>>4 != 4 {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ipv4HeaderMinLen || total > len(pkt) {
		return nil, false
	}
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	if dst == t.local {
		// The device runs no UDP services, so a probe to it has to be refused
		// like a host without a listener would; otherwise traceroute's UDP
		// probes reach the fake-ip allocator and log "not allocated". This
		// answer names the device itself as the destination, so it keeps the
		// device address: the client is probing this address.
		if pkt[9] == protoUDP {
			// DNS on the device address is answered by the relay in relayUDP,
			// so it must reach the stack instead of being refused here.
			if !dnsPacket(pkt[:total]) {
				return buildICMPPortUnreachable(t.local, src, pkt[:total]), true
			}
		}
		return nil, false
	}
	if pkt[8] <= 1 {
		// Answered as a hop, so the source has to be a stand-in address: the
		// receiving host drops an ICMP error whose source is one of its own
		// addresses (martian source), which is why the bare device address
		// never shows up as the first hop.
		return buildICMPTimeExceeded(t.answerSource(t.local), src, pkt[:total]), true
	}
	return nil, false
}

// inject hands one packet read from the device to the stack. Ownership of the
// packet buffer moves to the stack, so it must not be released here.
func (t *tunStack) inject(pkt []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	t.link.InjectInbound(header.IPv4ProtocolNumber, pb)
}

// nextPacket blocks until the stack emits a packet and returns it as a
// contiguous slice (a tun device write must carry exactly one IP packet).
func (t *tunStack) nextPacket(ctx context.Context) []byte {
	pb := t.link.ReadContext(ctx)
	if pb == nil {
		return nil
	}
	defer pb.DecRef()
	return append([]byte(nil), pb.ToView().AsSlice()...)
}

// close stops the link endpoint, which unblocks nextPacket.
func (t *tunStack) close() {
	t.link.Close()
}

// startStack installs the TCP and UDP forwarders: connection attempts to any
// address of ipv4_range land in handlers that dial the real destination.
func (p *FakeIPNatPlugin) startStack(t *tunStack) {
	tcpFwd := tcp.NewForwarder(t.stk, 0, tunTCPMaxInFlight, func(r *tcp.ForwarderRequest) {
		go p.relayTCP(r)
	})
	t.stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(t.stk, func(r *udp.ForwarderRequest) bool {
		go p.relayUDP(r, t)
		return true // the forwarder owns the request once handled
	})
	t.stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	p.L().Info("fakeip nat: transport forwarders installed",
		zap.Uint32("mtu", t.mtu),
		zap.Int("nic_id", int(t.nicID)),
		zap.Uint32("tcp_max_in_flight", tunTCPMaxInFlight))
}

// relayTCP terminates one TCP connection and relays it to the outlet.
func (p *FakeIPNatPlugin) relayTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

	if dnsFlow(id.LocalPort) {
		p.relayTunDNSTCP(r)
		return
	}

	// Resolve the target before touching the endpoint: a fake ip that is not in
	// the mapping table has no route, and that branch must not leave the client
	// waiting on a connection that was already accepted.
	target, err := p.dialTarget(id.LocalAddress.String(), id.LocalPort)
	if err != nil {
		// The device's own address is a real host address with nothing
		// listening on it, so it is refused like one (RST). Any other fake ip
		// without a mapping gets no answer at all: the client times out.
		if addr, parseErr := netip.ParseAddr(id.LocalAddress.String()); parseErr == nil && addr == p.reservedAddr() {
			r.Complete(true)
			p.L().Debug("tun tcp: connection to the device address refused",
				zap.String("addr", id.LocalAddress.String()), zap.Uint16("port", id.LocalPort))
			return
		}
		p.L().Debug("tun tcp: no route for fake ip",
			zap.String("fake_ip", id.LocalAddress.String()),
			zap.Uint16("port", id.LocalPort), zap.Error(err))
		// Deliberately left unanswered, per the "unknown fake ip times out"
		// rule; the forwarder drops the request when the client gives up.
		return
	}

	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		r.Complete(true) // reset the client instead of leaving it hanging
		p.L().Warn("tun tcp: create endpoint failed, client reset", zap.Error(tunError(epErr)))
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	remote, dialErr := p.egress.DialContext(ctx, "tcp", target)
	if dialErr != nil {
		p.L().Warn("tun tcp: dial failed",
			zap.String("fake_ip", id.LocalAddress.String()), zap.String("target", target), zap.Error(dialErr))
		return
	}
	defer remote.Close()

	outlet := "real_ip"
	if p.proxyActive {
		outlet = "domain_via_proxy"
	}
	start := time.Now()
	p.L().Debug("fakeip nat: tcp flow opened",
		zap.String("fake_ip", id.LocalAddress.String()), zap.Uint16("fake_port", id.LocalPort),
		zap.String("client", id.RemoteAddress.String()), zap.Uint16("client_port", id.RemotePort),
		zap.String("target", target), zap.String("outlet", outlet))
	bytesUp, bytesDown := pipeConns(local, remote)
	p.L().Debug("fakeip nat: tcp flow closed",
		zap.String("target", target),
		zap.Int64("bytes_up", bytesUp), zap.Int64("bytes_down", bytesDown),
		zap.Duration("duration", time.Since(start)))
}

// relayUDP terminates one UDP flow and relays datagrams to the outlet. Probes
// of a client traceroute are handed to the hop prober instead.
func (p *FakeIPNatPlugin) relayUDP(r *udp.ForwarderRequest, t *tunStack) {
	id := r.ID()

	if dnsFlow(id.LocalPort) {
		p.relayTunDNSUDP(r)
		return
	}

	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		p.L().Debug("tun udp: create endpoint failed", zap.Error(tunError(epErr)))
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()

	target, err := p.realTarget(id.LocalAddress.String(), id.LocalPort)
	if err != nil {
		p.L().Debug("tun udp: no route for fake ip",
			zap.String("fake_ip", id.LocalAddress.String()),
			zap.Uint16("port", id.LocalPort), zap.Error(err))
		return
	}
	// The outlet decides: direct egress binds the range address, a proxy that
	// cannot carry UDP falls back to a direct socket inside dialUDP.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	remote, dialErr := p.dialUDP(dialCtx, target)
	if dialErr != nil {
		p.L().Warn("tun udp: dial failed",
			zap.String("fake_ip", id.LocalAddress.String()), zap.String("target", target), zap.Error(dialErr))
		return
	}
	defer remote.Close()

	// Register the flow so an ICMP error quoting the upstream socket can be
	// routed back to the client. The key is the upstream local port, which is
	// what the quoted UDP header carries.
	clientAddr, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	fakeAddr, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	flow := icmpFlow{
		client: clientAddr, clientPort: id.RemotePort,
		fakeIP: fakeAddr, fakePort: id.LocalPort,
	}
	var clientTTL uint8
	flow.quote, clientTTL = p.takeClientQuote(quoteKey{
		src: clientAddr, dst: fakeAddr,
		sport: id.RemotePort, dport: id.LocalPort,
	})

	// A traceroute probe carries a small TTL: it must be answered by the real
	// path, not by this device. Probe the real ip with the same TTL and relay
	// whichever hop answers; the table entry lives only until the answer.
	if p.shouldProbe(clientTTL) {
		if host, _, herr := net.SplitHostPort(target); herr == nil {
			if realIP, perr := netip.ParseAddr(host); perr == nil {
				go p.probeHop(flow, realIP, int(clientTTL))
				return
			}
		}
	}
	var relay *icmpRelay
	if la, ok := remote.LocalAddr().(*net.UDPAddr); ok {
		if relay = p.currentICMP(); relay != nil {
			upstreamPort := uint16(la.Port)
			relay.add(upstreamPort, flow)
			defer relay.remove(upstreamPort)
		}
	}

	p.L().Debug("fakeip nat: udp flow opened",
		zap.String("fake_ip", id.LocalAddress.String()), zap.Uint16("fake_port", id.LocalPort),
		zap.String("client", id.RemoteAddress.String()), zap.Uint16("client_port", id.RemotePort),
		zap.String("target", target), zap.String("outlet", "direct"))

	var downDatagrams, downBytes, upDatagrams, upBytes int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, tunUDPMaxDatagram)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				p.L().Debug("fakeip nat: udp upstream read stopped", zap.String("target", target), zap.Error(err))
				// Answer immediately: the raw relay may see the same error a
				// moment later, but the client kernel matches the socket by
				// the address the ICMP came from, so the reply is built here
				// from the fake ip either way.
				if typ, code, ok := icmpErrorFromSocketError(err); ok {
					p.sendICMPErrorFromTarget(t, flow, target, typ, code)
				}
				return
			}
			if _, err := local.Write(buf[:n]); err != nil {
				p.L().Debug("fakeip nat: udp write to client stopped", zap.Error(err))
				return
			}
			downDatagrams++
			downBytes += int64(n)
		}
	}()

	buf := make([]byte, tunUDPMaxDatagram)
	for {
		n, err := local.Read(buf)
		if err != nil {
			p.L().Debug("fakeip nat: udp client read stopped", zap.Error(err))
			break
		}
		if _, err := remote.Write(buf[:n]); err != nil {
			p.L().Debug("fakeip nat: udp dial write stopped", zap.String("target", target), zap.Error(err))
			break
		}
		upDatagrams++
		upBytes += int64(n)
	}
	_ = remote.Close()
	<-done
	p.L().Debug("fakeip nat: udp flow closed",
		zap.String("target", target),
		zap.Int64("datagrams_up", upDatagrams), zap.Int64("bytes_up", upBytes),
		zap.Int64("datagrams_down", downDatagrams), zap.Int64("bytes_down", downBytes))
}

// dialTarget turns the destination of an intercepted connection into an address
// the egress can dial. With a working proxy the domain goes straight to the
// proxy, otherwise the fake IP is resolved back to the most recent real IP.
func (p *FakeIPNatPlugin) dialTarget(localAddr string, port uint16) (string, error) {
	addr, err := netip.ParseAddr(localAddr)
	if err != nil {
		return "", fmt.Errorf("unexpected destination %q: %w", localAddr, err)
	}
	// A real destination reaches the device when the mark path routed it here.
	// There is no fake ip to resolve, so the address itself is the target, and
	// the proxy or the pinned outlet carries it like any other flow.
	if !p.isFakeAddr(addr) {
		target := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
		p.L().Debug("fakeip nat: real destination enters the device",
			zap.String("destination", addr.String()), zap.String("target", target))
		return target, nil
	}
	fake := addr
	ctx, cancel := context.WithTimeout(context.Background(), tunTargetTimeout)
	defer cancel()

	domain, err := p.domainForFakeIP(ctx, fake.String())
	if err != nil {
		return "", err
	}
	if p.proxyActive {
		target := net.JoinHostPort(domain, strconv.Itoa(int(port)))
		if p.fakeTarget(target) {
			return "", fmt.Errorf("outlet target %s is inside the fake range", target)
		}
		p.L().Debug("fakeip nat: target resolved via proxy",
			zap.String("fake_ip", fake.String()), zap.String("domain", domain), zap.String("target", target))
		return target, nil
	}
	real, err := p.primaryRealIP(ctx, domain)
	if err != nil {
		return "", err
	}
	target := net.JoinHostPort(real.String(), strconv.Itoa(int(port)))
	if p.fakeTarget(target) {
		return "", fmt.Errorf("outlet target %s is inside the fake range", target)
	}
	p.L().Debug("fakeip nat: target resolved to real ip",
		zap.String("fake_ip", fake.String()), zap.String("domain", domain), zap.String("target", target))
	return target, nil
}

// realDestKeep bounds the set of real destinations the device may accept. A
// destination is only useful while a client still holds the answer it came
// from, so the set stays small; the oldest entries are dropped first.
const realDestKeep = 4096

// rememberRealDst records a real destination this plugin routed into the
// device. Only these addresses are accepted by the device read loop.
func (p *FakeIPNatPlugin) rememberRealDst(addr netip.Addr) {
	if !addr.IsValid() || !addr.Is4() {
		return
	}
	key := addr.String()
	now := time.Now().Unix()
	p.realDestMu.Lock()
	if p.realDest == nil {
		p.realDest = make(map[string]int64, 8)
	}
	p.realDest[key] = now
	if len(p.realDest) > realDestKeep {
		oldestKey, oldest := "", now
		for k, at := range p.realDest {
			if at < oldest || oldestKey == "" {
				oldestKey, oldest = k, at
			}
		}
		delete(p.realDest, oldestKey)
	}
	p.realDestMu.Unlock()
}

// ownsRealDst reports whether a real destination was recorded by this run.
// Realip without marks writes host routes instead, and those packets reach the
// device too, so the routing table entry is accepted as ownership.
func (p *FakeIPNatPlugin) ownsRealDst(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	p.realDestMu.Lock()
	if p.realDest != nil {
		if _, ok := p.realDest[addr.String()]; ok {
			p.realDestMu.Unlock()
			return true
		}
	}
	p.realDestMu.Unlock()
	if p.markRoutingEnabled() {
		// Mark routing is the only way in for a real destination then: an
		// unrecorded address was never marked, so it is not ours.
		return false
	}
	// Route split: the ledger names the addresses this plugin wrote a route
	// for, and the route is what brought the packet into the device.
	return p.routeCoversAddr(addr)
}

// routeCoversAddr reports whether a managed route covers addr. It is used only
// for the route-split data path, where the routing table entry is what brought
// the packet into the device.
func (p *FakeIPNatPlugin) routeCoversAddr(addr netip.Addr) bool {
	p.ledgerMu.Lock()
	ledger := p.ledger
	p.ledgerMu.Unlock()
	if ledger == nil {
		return false
	}
	for _, row := range ledger.snapshot() {
		prefix, err := netip.ParsePrefix(row.prefix)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// tunDNSResolver is where DNS addressed to the device's own address is relayed.
// On a box that runs this plugin the host resolver is mosdns itself, which is
// why the answer the client receives is the fake ip it needs.
const tunDNSResolver = "127.0.0.1:53"

// dnsPacket reports whether the packet is a DNS request: UDP or TCP to port 53.
// A tun data path that cannot carry DNS leaves every client that resolves
// through the device without an answer, so this is the one destination class
// the device accepts even though it belongs to somebody else's socket.
func dnsPacket(pkt []byte) bool {
	if len(pkt) < ipv4HeaderMinLen || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	if proto != protoUDP && proto != protoTCP {
		return false
	}
	if ihl < ipv4HeaderMinLen || len(pkt) < ihl+udpHeaderLen {
		return false
	}
	return binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) == 53
}

// dnsFlow reports whether an intercepted flow is DNS. Every DNS flow is relayed
// to the host resolver whichever address the client aimed at: a fake-ip gateway
// only works when the resolver that hands out the fake addresses is the one that
// answers, and a direct socket avoids binding the range address for a flow that
// must reach the host anyway.
func dnsFlow(port uint16) bool {
	return port == 53
}

// ownsTunDestination reports whether a packet read from the device belongs to
// this plugin. Anything else was routed into the device by somebody else's
// rule and has to be dropped rather than relayed to the outlet.
func (p *FakeIPNatPlugin) ownsTunDestination(pkt []byte) bool {
	if len(pkt) < ipv4HeaderMinLen || pkt[0]>>4 != 4 {
		return false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ipv4HeaderMinLen || total > len(pkt) {
		return false
	}
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	if dst == p.reservedAddr() {
		return true
	}
	if p.isFakeAddr(dst) {
		return true
	}
	if dnsPacket(pkt) {
		return true
	}
	return p.ownsRealDst(dst)
}

// isFakeAddr reports whether addr is one of the addresses this plugin itself
// hands out. Anything stored or resolved that lands inside this range is
// unusable as a destination: it only exists inside this plugin's own table.
func (p *FakeIPNatPlugin) isFakeAddr(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	return p.prefix.IsValid() && p.prefix.Contains(addr)
}

// isFakeAddrString is isFakeAddr for a textual address. A name never counts,
// even one that cannot be resolved.
func (p *FakeIPNatPlugin) isFakeAddrString(raw string) bool {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	return p.isFakeAddr(addr)
}

// fakeTarget reports whether an outlet target ("host:port") points inside the
// fake range. Such a target can only come from a broken or stale mapping row,
// and every outlet fails on it, so it is refused with a reason instead of being
// dialed.
func (p *FakeIPNatPlugin) fakeTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return p.isFakeAddr(addr)
}

// realTarget resolves the fake IP to the most recent real IP. UDP uses it even
// when a proxy is configured: the supported proxies only carry TCP, so a UDP
// flow must leave direct and must never be handed a domain.
func (p *FakeIPNatPlugin) realTarget(localAddr string, port uint16) (string, error) {
	addr, err := netip.ParseAddr(localAddr)
	if err != nil {
		return "", fmt.Errorf("unexpected destination %q: %w", localAddr, err)
	}
	// UDP of a real destination: the address is already the target, and UDP
	// always leaves direct because the supported proxies carry TCP only.
	if !p.isFakeAddr(addr) {
		target := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
		p.L().Debug("fakeip nat: real udp destination enters the device",
			zap.String("destination", addr.String()), zap.String("target", target))
		return target, nil
	}
	fake := addr
	ctx, cancel := context.WithTimeout(context.Background(), tunTargetTimeout)
	defer cancel()

	domain, err := p.domainForFakeIP(ctx, fake.String())
	if err != nil {
		return "", err
	}
	real, err := p.primaryRealIP(ctx, domain)
	if err != nil {
		return "", err
	}
	target := net.JoinHostPort(real.String(), strconv.Itoa(int(port)))
	if p.fakeTarget(target) {
		return "", fmt.Errorf("udp target %s is inside the fake range", target)
	}
	p.L().Debug("fakeip nat: udp target resolved to real ip",
		zap.String("fake_ip", fake.String()), zap.String("domain", domain), zap.String("target", target))
	return target, nil
}

// tunError adapts the stack's error type to the standard error interface so it
// can be logged with zap.
func tunError(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v", err)
}

// pipeConns copies both directions until each side is done, propagating
// half-close where the transport supports it.
func pipeConns(a, b net.Conn) (fromA, fromB int64) {
	var wg sync.WaitGroup
	copySide := func(dst, src net.Conn, counter *int64) {
		defer wg.Done()
		buf := make([]byte, tunRelayBuffer)
		n, _ := io.CopyBuffer(dst, src, buf)
		*counter = n
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		_ = dst.Close()
	}
	wg.Add(2)
	go copySide(a, b, &fromB)
	go copySide(b, a, &fromA)
	wg.Wait()
	return fromA, fromB
}

// writeOut writes one packet to the device. The stack write loop and the ICMP
// relay both use it, so a device is never written concurrently.
func (t *tunStack) writeOut(pkt []byte) error {
	if t.dev == nil {
		return errors.New("tun device is not attached")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.dev.Write(pkt)
	return err
}

// relayTunDNSUDP answers one DNS request addressed to the device itself by
// forwarding the datagram to the host resolver. The client keeps using the
// device address, so nothing but this relay has to know where DNS really runs.
func (p *FakeIPNatPlugin) relayTunDNSUDP(r *udp.ForwarderRequest) {
	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		p.L().Debug("tun dns: create endpoint failed", zap.Error(tunError(epErr)))
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	var d net.Dialer
	remote, dialErr := d.DialContext(ctx, "udp", tunDNSResolver)
	if dialErr != nil {
		p.L().Warn("tun dns: dial the host resolver failed", zap.String("resolver", tunDNSResolver), zap.Error(dialErr))
		return
	}
	defer remote.Close()
	p.L().Debug("tun dns: query relayed to the host resolver", zap.String("resolver", tunDNSResolver))

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, tunUDPMaxDatagram)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			if _, err := local.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, tunUDPMaxDatagram)
	for {
		n, err := local.Read(buf)
		if err != nil {
			break
		}
		if _, err := remote.Write(buf[:n]); err != nil {
			break
		}
	}
	_ = remote.Close()
	<-done
}

// relayTunDNSTCP is the stream version: a resolver that truncates over UDP is
// retried over TCP, and that connection is aimed at the device address too.
func (p *FakeIPNatPlugin) relayTunDNSTCP(r *tcp.ForwarderRequest) {
	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		r.Complete(true)
		p.L().Debug("tun dns: create endpoint failed", zap.Error(tunError(epErr)))
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	var d net.Dialer
	remote, dialErr := d.DialContext(ctx, "tcp", tunDNSResolver)
	if dialErr != nil {
		p.L().Warn("tun dns: dial the host resolver failed", zap.String("resolver", tunDNSResolver), zap.Error(dialErr))
		return
	}
	defer remote.Close()
	p.L().Debug("tun dns: tcp query relayed to the host resolver", zap.String("resolver", tunDNSResolver))
	pipeConns(local, remote)
}
