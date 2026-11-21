package sni_route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/tunrelay"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"go.uber.org/zap"
)

const (
	tunLinkQueue      = 256
	tunTCPMaxInFlight = 1024
	tunRelayBuffer    = 32 << 10
	tunDialTimeout    = 10 * time.Second
	helloReadTimeout  = 1500 * time.Millisecond
)

type tunStack struct {
	link  *channel.Endpoint
	stk   *stack.Stack
	nicID tcpip.NICID
	mtu   uint32
	dev   osFile
	mu    sync.Mutex
}

type osFile interface {
	Write([]byte) (int, error)
}

func newTunStack(mtu uint32, local netip.Addr) (*tunStack, error) {
	if !local.Is4() {
		return nil, fmt.Errorf("tun address %q is not IPv4", local)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	linkEP := channel.New(tunLinkQueue, mtu, "")
	nicID := s.NextNICID()
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("create tun nic: %v", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(local.As4()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add tun address %s: %v", local, err)
	}
	// Every real destination is foreign to the local address. Promiscuous mode
	// accepts them; spoofing lets the stack answer with the real destination as
	// the source instead of the device's own address.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("enable promiscuous mode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("enable spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})
	return &tunStack{link: linkEP, stk: s, nicID: nicID, mtu: mtu}, nil
}

func (p *Plugin) startStack() error {
	st, err := newTunStack(uint32(p.args.TunMTU), p.tunAddr)
	if err != nil {
		return err
	}
	st.dev = p.tunFile
	tcpFwd := tcp.NewForwarder(st.stk, 0, tunTCPMaxInFlight, func(r *tcp.ForwarderRequest) {
		go p.safeGo("tcp-relay", func() { p.relayTCP(r) })
	})
	st.stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	p.stack = st
	p.L().Info("sni_route: userspace TCP stack started",
		zap.Int("nic_id", int(st.nicID)), zap.Uint32("mtu", st.mtu))
	return nil
}

func (p *Plugin) safeGo(worker string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			p.L().Error("sni_route: worker panic, continuing",
				zap.String("worker", worker), zap.Any("panic", r))
		}
	}()
	fn()
}

func (p *Plugin) safeInject(pkt []byte) {
	defer func() {
		if r := recover(); r != nil {
			p.L().Error("sni_route: packet injection panic, dropping packet", zap.Any("panic", r))
		}
	}()
	if p.stack != nil {
		p.stack.inject(pkt)
	}
}

func (t *tunStack) inject(pkt []byte) {
	data := append([]byte(nil), pkt...)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	t.link.InjectInbound(header.IPv4ProtocolNumber, pb)
}

func (t *tunStack) nextPacket(ctx context.Context) []byte {
	pb := t.link.ReadContext(ctx)
	if pb == nil {
		return nil
	}
	defer pb.DecRef()
	return append([]byte(nil), pb.ToView().AsSlice()...)
}

func (t *tunStack) writeOut(pkt []byte) error {
	if t.dev == nil {
		return errors.New("tun device is not attached")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.dev.Write(pkt)
	return err
}

func tcpipAddr(a tcpip.Address) netip.Addr {
	if a.Len() == 4 {
		return netip.AddrFrom4(a.As4())
	}
	return netip.Addr{}
}

func (t *tunStack) close() { t.link.Close() }

// relayTCP terminates one intercepted connection, reads just enough of the
// ClientHello to learn the server name, then dials the exit that name selects.
// The bytes that were read are written to the remote before the relay starts,
// so the handshake is never replayed or regenerated.
func (p *Plugin) relayTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	targetIP := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		p.L().Warn("sni_route: create TCP endpoint failed", zap.Error(tunErr(err)))
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	head, sni := readClientHello(local, helloReadTimeout)

	dialer := p.direct
	target := targetIP
	clientAddr := tcpipAddr(id.RemoteAddress)
	matched := p.matchSNI(context.Background(), sni, clientAddr)
	if matched {
		dialer = p.matched
		// Only a proxy can resolve a name without asking this box's resolver,
		// which would answer with a fake IP. A direct or CBP exit gets the real
		// destination address instead.
		if p.proxyActive && sni != "" {
			target = net.JoinHostPort(sni, fmt.Sprint(id.LocalPort))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	remote, dialErr := dialer.DialContext(ctx, "tcp", target)
	if dialErr != nil {
		p.L().Warn("sni_route: TCP dial failed",
			zap.String("target", target), zap.String("sni", sni),
			zap.Bool("matched", matched), zap.Error(dialErr))
		return
	}
	defer remote.Close()

	if len(head) > 0 {
		if _, err := remote.Write(head); err != nil {
			p.L().Debug("sni_route: writing ClientHello to remote failed", zap.Error(err))
			return
		}
	}

	start := time.Now()
	p.L().Debug("sni_route: TCP flow opened",
		zap.String("sni", sni),
		zap.Bool("matched", matched),
		zap.String("target", target),
		zap.String("client", id.RemoteAddress.String()),
		zap.Uint16("client_port", id.RemotePort),
		zap.Bool("proxy", p.proxyActive))
	up, down := pipeConns(local, remote)
	p.L().Debug("sni_route: TCP flow closed",
		zap.String("sni", sni),
		zap.Bool("matched", matched),
		zap.Int64("bytes_up", up), zap.Int64("bytes_down", down),
		zap.Duration("duration", time.Since(start)))
}

// readClientHello reads only as long as it takes to parse a ClientHello. A
// non-TLS connection, a timeout, or a handshake without SNI returns whatever
// was read and an empty name, and the caller relays it byte for byte.
func readClientHello(conn net.Conn, timeout time.Duration) ([]byte, string) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	var buf []byte
	tmp := make([]byte, 2048)
	for len(buf) < maxHelloBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			sni, result := parseClientHelloSNI(buf)
			switch result {
			case helloOK:
				return buf, sni
			case helloInvalid:
				return buf, ""
			}
		}
		if err != nil {
			return buf, ""
		}
	}
	return buf, ""
}

const flowIdle = 10 * time.Minute

func pipeConns(a, b net.Conn) (fromA, fromB int64) {
	return tunrelay.Pipe(a, b, flowIdle)
}

func tunErr(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v", err)
}
