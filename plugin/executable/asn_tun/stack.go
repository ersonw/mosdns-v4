package asn_tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	tunLinkQueue      = 256
	tunTCPMaxInFlight = 1024
	tunRelayBuffer    = 32 << 10
	tunDialTimeout    = 10 * time.Second
)

type tunStack struct {
	link  *channel.Endpoint
	stk   *stack.Stack
	nicID tcpip.NICID
	mtu   uint32
	dev   osFile
	mu    sync.Mutex
}

// osFile is the small part of *os.File the stack needs. Tests can replace it.
type osFile interface {
	Write([]byte) (int, error)
}

func newTunStack(mtu uint32, local netip.Addr) (*tunStack, error) {
	if !local.Is4() {
		return nil, fmt.Errorf("tun address %q is not IPv4", local)
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

func (p *ASNTunPlugin) startStack() error {
	st, err := newTunStack(uint32(p.args.TunMTU), p.tunAddr)
	if err != nil {
		return err
	}
	st.dev = p.tunFile
	tcpFwd := tcp.NewForwarder(st.stk, 0, tunTCPMaxInFlight, func(r *tcp.ForwarderRequest) {
		go p.relayTCP(r)
	})
	st.stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(st.stk, func(r *udp.ForwarderRequest) bool {
		go p.relayUDP(r)
		return true
	})
	st.stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	p.stack = st
	p.L().Info("asn_tun: userspace TCP/IP stack started",
		zap.Int("nic_id", int(st.nicID)), zap.Uint32("mtu", st.mtu))
	return nil
}

func (t *tunStack) inject(pkt []byte) {
	// The read buffer is reused by runTunDevice, while the stack may keep the
	// payload beyond this call boundary.
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

func (t *tunStack) close() {
	t.link.Close()
}

func (p *ASNTunPlugin) relayTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	target := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		p.L().Warn("asn_tun: create TCP endpoint failed", zap.Error(tunErr(err)))
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	remote, dialErr := p.egress.DialContext(ctx, "tcp", target)
	if dialErr != nil {
		p.L().Warn("asn_tun: TCP dial failed", zap.String("target", target), zap.Error(dialErr))
		return
	}
	defer remote.Close()
	start := time.Now()
	p.L().Debug("asn_tun: TCP flow opened",
		zap.String("target", target),
		zap.String("client", id.RemoteAddress.String()),
		zap.Uint16("client_port", id.RemotePort),
		zap.Bool("proxy", p.proxyActive))
	up, down := pipeConns(local, remote)
	p.L().Debug("asn_tun: TCP flow closed",
		zap.String("target", target),
		zap.Int64("bytes_up", up), zap.Int64("bytes_down", down),
		zap.Duration("duration", time.Since(start)))
}

func (p *ASNTunPlugin) relayUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	target := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		p.L().Debug("asn_tun: create UDP endpoint failed", zap.Error(tunErr(err)))
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	remote, dialErr := p.egress.DialContext(ctx, "udp", target)
	if dialErr != nil {
		p.L().Warn("asn_tun: UDP dial failed", zap.String("target", target), zap.Error(dialErr))
		return
	}
	defer remote.Close()
	p.L().Debug("asn_tun: UDP flow opened",
		zap.String("target", target),
		zap.String("client", id.RemoteAddress.String()),
		zap.Uint16("client_port", id.RemotePort),
		zap.Bool("proxy", p.proxyActive))

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, readErr := remote.Read(buf)
			if readErr != nil {
				return
			}
			if _, writeErr := local.Write(buf[:n]); writeErr != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, readErr := local.Read(buf)
		if readErr != nil {
			break
		}
		if _, writeErr := remote.Write(buf[:n]); writeErr != nil {
			break
		}
	}
	_ = remote.Close()
	<-done
}

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

func tunErr(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v", err)
}
