package egress

// CBP outlet. The CBP/1 protocol carries raw IPv4/IPv6 packets over a QUIC
// DATAGRAM plane, so this outlet cannot be a stream dialer like socks5 or
// trojan: it runs a small userspace IP stack (gvisor netstack) and dials the
// target through it. That is what lets one protocol serve TCP, UDP and ICMP
// without a per-protocol proxy command.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/ersonw/mosdns-v4/pkg/egress/cbp"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const (
	// cbpQueueLen bounds packets waiting between the stack and the session.
	cbpQueueLen = 1024
	// cbpDefaultMTU matches the protocol default when the server omits it.
	cbpDefaultMTU = 1280
	// cbpMinMTU keeps the stack above the smallest workable inner MTU.
	cbpMinMTU = 576
	// cbpMaxMTU is the IPv4 limit; the protocol never carries more.
	cbpMaxMTU = 1500
)

// cbpEgress is the CBP outlet: one session, one userspace stack.
type cbpEgress struct {
	cfg cbp.Config

	mu     sync.RWMutex
	sess   *cbp.Session
	stk    *stack.Stack
	link   *channel.Endpoint
	mtu    uint32
	v4     netip.Addr
	v6     netip.Addr
	connMu sync.Mutex

	closed chan struct{}
	once   sync.Once
}

// NewCBP dials one CBP session and returns an outlet that dials through it.
func NewCBP(cfg cbp.Config) (*cbpEgress, error) {
	e := &cbpEgress{cfg: cfg, closed: make(chan struct{})}
	if err := e.connect(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

// connect opens a session and builds the stack that dials through it. It takes
// the write lock only to publish the new session, so a reconnect from ensure()
// never re-enters the lock.
func (e *cbpEgress) connect(ctx context.Context) error {
	sess, stk, linkEP, mtu, v4, v6, err := e.open(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	oldSess, oldLink := e.sess, e.link
	e.sess, e.stk, e.link, e.mtu, e.v4, e.v6 = sess, stk, linkEP, mtu, v4, v6
	e.mu.Unlock()
	if oldLink != nil {
		oldLink.Close()
	}
	if oldSess != nil {
		_ = oldSess.Close()
	}
	go e.pumpInbound(sess, linkEP)
	go e.pumpOutbound(sess, linkEP)
	return nil
}

// open builds a session and its stack without touching e's published fields.
func (e *cbpEgress) open(ctx context.Context) (*cbp.Session, *stack.Stack, *channel.Endpoint, uint32, netip.Addr, netip.Addr, error) {
	sess, err := cbp.Dial(ctx, e.cfg)
	if err != nil {
		return nil, nil, nil, 0, netip.Addr{}, netip.Addr{}, err
	}
	ready := sess.Ready()

	mtu := uint32(ready.MTU)
	if mtu == 0 {
		mtu = cbpDefaultMTU
	}
	if mtu < cbpMinMTU || mtu > cbpMaxMTU {
		_ = sess.Close()
		return nil, nil, nil, 0, netip.Addr{}, netip.Addr{}, fmt.Errorf("egress: cbp session advertised mtu %d, outside %d..%d", ready.MTU, cbpMinMTU, cbpMaxMTU)
	}

	v4, err := parseTunnelAddr(ready.TunnelIPv4CIDR, ready.TunnelIPv4)
	if err != nil {
		_ = sess.Close()
		return nil, nil, nil, 0, netip.Addr{}, netip.Addr{}, err
	}
	// IPv6 is optional: the edge only returns it when it owns a v6 pool.
	v6, v6Err := parseTunnelAddr(ready.TunnelIPv6, ready.TunnelIPv6)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(cbpQueueLen, mtu, "")
	nicID := s.NextNICID()
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		_ = sess.Close()
		return nil, nil, nil, 0, netip.Addr{}, netip.Addr{}, fmt.Errorf("egress: create cbp nic: %v", err)
	}
	// The address is published as a host address: the client owns one address
	// of the tunnel prefix, not the prefix itself, so no neighbouring tunnel
	// address is ever treated as local.
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(v4.As4()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		_ = sess.Close()
		return nil, nil, nil, 0, netip.Addr{}, netip.Addr{}, fmt.Errorf("egress: add cbp address %s: %v", v4, err)
	}
	if v6Err == nil && v6.Is6() {
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(v6.AsSlice()),
				PrefixLen: 128,
			},
		}, stack.AddressProperties{}); err != nil {
			_ = sess.Close()
			return nil, nil, nil, 0, netip.Addr{}, netip.Addr{}, fmt.Errorf("egress: add cbp address %s: %v", v6, err)
		}
	}
	// The tunnel is point-to-point: every destination leaves the same NIC.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	return sess, s, linkEP, mtu, v4, v6, nil
}

// pumpInbound feeds packets received from the edge into the stack.
func (e *cbpEgress) pumpInbound(sess *cbp.Session, linkEP *channel.Endpoint) {
	for {
		pkt, err := sess.ReceivePacket(context.Background())
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		proto := header.IPv4ProtocolNumber
		switch pkt[0] >> 4 {
		case 4:
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		linkEP.InjectInbound(proto, pb)
	}
}

// pumpOutbound sends packets the stack produces to the edge.
func (e *cbpEgress) pumpOutbound(sess *cbp.Session, linkEP *channel.Endpoint) {
	for {
		pb := linkEP.ReadContext(context.Background())
		if pb == nil {
			return
		}
		pkt := append([]byte(nil), pb.ToView().AsSlice()...)
		pb.DecRef()
		if err := sess.SendPacket(pkt); err != nil {
			return
		}
	}
}

// ensure returns a live stack, reconnecting once if the session died.
func (e *cbpEgress) ensure(ctx context.Context) (*stack.Stack, netip.Addr, error) {
	select {
	case <-e.closed:
		return nil, netip.Addr{}, net.ErrClosed
	default:
	}
	e.mu.RLock()
	sess, stk, v4 := e.sess, e.stk, e.v4
	e.mu.RUnlock()
	if sess != nil && sess.Healthy() && stk != nil {
		return stk, v4, nil
	}

	// One reconnect at a time: a burst of failed dials must not build two
	// stacks and leak the loser.
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.mu.RLock()
	sess, stk, v4 = e.sess, e.stk, e.v4
	e.mu.RUnlock()
	if sess != nil && sess.Healthy() && stk != nil {
		return stk, v4, nil
	}
	if err := e.connect(ctx); err != nil {
		return nil, netip.Addr{}, err
	}
	e.mu.RLock()
	stk, v4 = e.stk, e.v4
	e.mu.RUnlock()
	return stk, v4, nil
}

// DialContext dials the target through the tunnel. TCP becomes a netstack TCP
// connection, UDP a netstack UDP connection; a host name is resolved on the
// host first because the tunnel carries IP packets, not names.
func (e *cbpEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, port, err := e.resolveTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	stk, v4, err := e.ensure(ctx)
	if err != nil {
		return nil, fmt.Errorf("egress: cbp session unavailable: %w", err)
	}
	if ip.Is4() && !v4.IsValid() {
		return nil, fmt.Errorf("egress: cbp session has no ipv4 address")
	}

	full := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: port,
	}
	protoNum := ipv4.ProtocolNumber
	if ip.Is6() {
		protoNum = ipv6.ProtocolNumber
	}
	if strings.HasPrefix(network, "udp") {
		return gonet.DialUDP(stk, nil, &full, protoNum)
	}
	return gonet.DialContextTCP(ctx, stk, full, protoNum)
}

// resolveTarget turns host:port into an address the stack can dial.
func (e *cbpEgress) resolveTarget(ctx context.Context, addr string) (netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("egress: cbp target %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("egress: cbp target port %q: %w", portStr, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), uint16(port), nil
	}
	// A name has to become an address here: the edge only sees IP packets.
	ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
	if lookupErr != nil || len(ips) == 0 {
		return netip.Addr{}, 0, fmt.Errorf("egress: resolve %s for cbp: %w", host, lookupErr)
	}
	for _, candidate := range ips {
		if parsed, ok := netip.AddrFromSlice(candidate.IP); ok {
			return parsed.Unmap(), uint16(port), nil
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("egress: resolve %s for cbp: no usable address", host)
}

// Probe reports whether the session can currently be used.
func (e *cbpEgress) Probe(ctx context.Context) error {
	e.mu.RLock()
	sess := e.sess
	e.mu.RUnlock()
	if sess == nil || !sess.Healthy() {
		return fmt.Errorf("egress: cbp session is not healthy")
	}
	return nil
}

// Close tears down the session and the stack.
func (e *cbpEgress) Close() error {
	e.once.Do(func() {
		close(e.closed)
		e.mu.Lock()
		sess, linkEP := e.sess, e.link
		e.sess, e.stk, e.link = nil, nil, nil
		e.mu.Unlock()
		if linkEP != nil {
			linkEP.Close()
		}
		if sess != nil {
			_ = sess.Close()
		}
	})
	return nil
}

// parseTunnelAddr reads the tunnel address from its CIDR form first and falls
// back to a bare address. An empty value means the tunnel has no address of
// that family.
func parseTunnelAddr(cidr, bare string) (netip.Addr, error) {
	if strings.TrimSpace(cidr) != "" {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("egress: cbp tunnel prefix %q: %w", cidr, err)
		}
		return prefix.Addr(), nil
	}
	if strings.TrimSpace(bare) != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(bare))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("egress: cbp tunnel address %q: %w", bare, err)
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("egress: cbp session returned no tunnel address")
}
