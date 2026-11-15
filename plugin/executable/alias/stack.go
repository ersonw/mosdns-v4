package alias

// stack.go is the userspace half of the tun data path. Traffic arriving on the
// device is terminated by an in-process TCP/IP stack (gVisor netstack) and
// dialled out through the outlet. Terminating the connection is what makes the
// proxy case work at all: only here is the domain name known, and only here can
// the plugin send "domain:port" to the proxy instead of a bare address.

import (
	"context"
	"crypto/tls"
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
	tunLinkQueue                = 256
	tunTCPMaxInFlight           = 1024
	tunDialTimeout              = 30 * time.Second
	udpFlowTimeout              = 60 * time.Second
	httpPort                    = 80
	gatewayMaxInternalRedirects = 3
	httpsPort                   = 443
	tlsHandshakeTimeout         = 10 * time.Second
)

type tunStack struct {
	link  *channel.Endpoint
	stk   *stack.Stack
	nicID tcpip.NICID
	mtu   uint32
	local netip.Addr
}

func newTunStack(mtu uint32, local netip.Addr) (*tunStack, error) {
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
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(local.As4()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add tun address %s: %v", local, err)
	}
	// Only the first host of the range belongs to the device. Every other
	// address is foreign to it, so promiscuous mode accepts them and spoofing
	// lets the stack answer as those addresses.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("enable promiscuous mode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("enable spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return &tunStack{link: linkEP, stk: s, nicID: nicID, mtu: mtu, local: local}, nil
}

func (t *tunStack) inject(pkt []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
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

func (t *tunStack) close() { t.link.Close() }

func (p *plugin) startStack(t *tunStack) {
	tcpFwd := tcp.NewForwarder(t.stk, 0, tunTCPMaxInFlight, func(r *tcp.ForwarderRequest) {
		go p.relayTCP(r)
	})
	t.stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(t.stk, func(r *udp.ForwarderRequest) bool {
		go p.relayUDP(r)
		return true
	})
	t.stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	p.log().Info("alias: transport forwarders installed",
		zap.Uint32("mtu", t.mtu), zap.Int("nic_id", int(t.nicID)))
}

// relayTCP terminates one TCP connection and hands it to the outlet. Port 80
// goes through the HTTP gateway, which rewrites Host and re-originates; every
// other port is a byte-transparent relay.
func (p *plugin) relayTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	fakeAddr, parseErr := netip.ParseAddr(id.LocalAddress.String())
	if parseErr != nil {
		r.Complete(true)
		return
	}
	domainName, ok := p.alloc.DomainOf(fakeAddr)
	if !ok {
		// The device address itself has nothing listening, so it is refused.
		r.Complete(true)
		p.log().Debug("alias: tcp to unmapped address refused",
			zap.String("addr", id.LocalAddress.String()), zap.Uint16("port", id.LocalPort))
		return
	}

	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		r.Complete(true)
		p.log().Warn("alias: create endpoint failed", zap.Stringer("error", epErr))
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	if id.LocalPort == httpPort {
		p.serveGateway(local, domainName)
		return
	}
	if id.LocalPort == httpsPort && p.tlsConfig != nil {
		p.serveTLSGateway(local, domainName)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	remote, dialErr := p.dialTCP(ctx, domainName, uint16(id.LocalPort))
	if dialErr != nil {
		p.log().Warn("alias: dial failed",
			zap.String("domain", domainName), zap.Uint16("port", id.LocalPort), zap.Error(dialErr))
		return
	}
	defer remote.Close()

	p.log().Debug("alias: tcp flow opened",
		zap.String("virtual_ip", fakeAddr.String()), zap.String("domain", domainName),
		zap.Uint16("port", id.LocalPort), zap.String("client", id.RemoteAddress.String()))
	pipeConns(local, remote)
}

// serveTLSGateway terminates TLS with the configured certificate and runs the
// same HTTP gateway over it. Redirects therefore work for HTTPS too, and an
// alias host is served over TLS. Without a certificate, 443 never reaches
// here and stays byte-transparent.
func (p *plugin) serveTLSGateway(client net.Conn, domainName string) {
	tlsConn := tls.Server(client, p.tlsConfig.Clone())
	ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		p.log().Debug("alias: tls handshake failed",
			zap.String("domain", domainName), zap.Error(err))
		return
	}
	defer tlsConn.Close()
	p.serveGateway(tlsConn, domainName)
}

// relayUDP relays datagrams on the direct outlet. With a proxy configured the
// flow is dropped on purpose: a proxy that only carries TCP cannot keep the
// client's address family, and letting QUIC through direct would leak the real
// egress. Dropping makes the client fall back to TCP, which the proxy carries.
func (p *plugin) relayUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	fakeAddr, parseErr := netip.ParseAddr(id.LocalAddress.String())
	if parseErr != nil {
		return
	}
	domainName, ok := p.alloc.DomainOf(fakeAddr)
	if !ok {
		return
	}
	if p.proxy != nil {
		p.log().Debug("alias: udp dropped while the proxy outlet is active",
			zap.String("domain", domainName), zap.Uint16("port", id.LocalPort))
		return
	}

	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		p.log().Debug("alias: udp create endpoint failed", zap.Stringer("error", epErr))
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), tunDialTimeout)
	defer cancel()
	addr, err := p.resolveForDial(ctx, domainName)
	if err != nil {
		p.log().Debug("alias: udp resolve failed", zap.String("domain", domainName), zap.Error(err))
		return
	}
	remote, err := p.direct.DialContext(ctx, "udp", net.JoinHostPort(addr.String(), strconv.Itoa(int(id.LocalPort))))
	if err != nil {
		p.log().Debug("alias: udp dial failed", zap.String("domain", domainName), zap.Error(err))
		return
	}
	defer remote.Close()

	_ = local.SetReadDeadline(time.Now().Add(udpFlowTimeout))
	go func() {
		buf := make([]byte, 1500)
		for {
			n, rerr := remote.Read(buf)
			if rerr != nil {
				_ = local.Close()
				return
			}
			if _, werr := local.Write(buf[:n]); werr != nil {
				return
			}
		}
	}()
	buf := make([]byte, 1500)
	for {
		n, rerr := local.Read(buf)
		if rerr != nil {
			return
		}
		if _, werr := remote.Write(buf[:n]); werr != nil {
			return
		}
	}
}

func pipeConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
