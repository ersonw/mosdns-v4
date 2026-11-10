
package server

import (
	"context"
	"fmt"
	"github.com/liang-hiwin/mosdns-v4/pkg/pool"
	"github.com/liang-hiwin/mosdns-v4/pkg/query_context"
	"net/netip"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"io"
	"net"
)

// cmcUDPConn can read and write cmsg.
type cmcUDPConn interface {
	readFrom(b []byte) (n int, dst net.IP, IfIndex int, src net.Addr, err error)
	writeTo(b []byte, src net.IP, IfIndex int, dst net.Addr) (n int, err error)
}

func (s *Server) ServeUDP(c net.PacketConn) error {
	defer c.Close()

	handler := s.opts.DNSHandler
	if handler == nil {
		return errMissingDNSHandler
	}

	closer := io.Closer(c)
	if ok := s.trackCloser(&closer, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(&closer, false)

	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readBuf := pool.GetBuf(64 * 1024)
	defer readBuf.Release()
	rb := readBuf.Bytes()

	var cmc cmcUDPConn
	var err error
	uc, ok := c.(*net.UDPConn)
	if ok && uc.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		cmc, err = newCmc(uc)
		if err != nil {
			return fmt.Errorf("failed to control socket cmsg, %w", err)
		}
	} else {
		cmc = newDummyCmc(c)
	}

	for {
		n, localAddr, ifIndex, remoteAddr, err := cmc.readFrom(rb)
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			return fmt.Errorf("unexpected read err: %w", err)
		}
		
		// clientAddr := utils.GetAddrFromAddr(remoteAddr)
		//
		clientAddrStr, _, err := net.SplitHostPort(remoteAddr.String())
        if err != nil {
	        s.opts.Logger.Error("failed to parse request remote addr", zap.String("addr", remoteAddr.String()), zap.Error(err)); continue
        }
		//

		q := new(dns.Msg)
		if err := q.Unpack(rb[:n]); err != nil {
			s.opts.Logger.Warn("invalid msg", zap.Error(err), zap.Binary("msg", rb[:n]), zap.Stringer("from", remoteAddr))
			continue
		}

		// handle query
		go func() {
			meta := &query_context.RequestMeta{
				ClientAddr: func() netip.Addr { a, _ := netip.ParseAddr(clientAddrStr); return a }(),
			}

			r, err := handler.ServeDNS(listenerCtx, q, meta)
			if err != nil {
				s.opts.Logger.Warn("handler err", zap.Error(err))
			}
			if r != nil {
				r.Truncate(getUDPSize(q))
				b, buf, err := pool.PackBuffer(r)
				if err != nil {
					s.opts.Logger.Error("failed to unpack handler's response", zap.Error(err), zap.Stringer("msg", r))
				}
				defer buf.Release()
				if _, err := cmc.writeTo(b, localAddr, ifIndex, remoteAddr); err != nil {
					s.opts.Logger.Warn("failed to write response", zap.Stringer("client", remoteAddr), zap.Error(err))
				}
			}
		}()
	}
}

func getUDPSize(m *dns.Msg) int {
	var s uint16
	if opt := m.IsEdns0(); opt != nil {
		s = opt.UDPSize()
	}
	if s < dns.MinMsgSize {
		s = dns.MinMsgSize
	}
	return int(s)
}

// newDummyCmc returns a dummyCmcWrapper.
func newDummyCmc(c net.PacketConn) cmcUDPConn {
	return dummyCmcWrapper{c: c}
}

// dummyCmcWrapper is just a wrapper that implements cmcUDPConn but does not
// write or read any control msg.
type dummyCmcWrapper struct {
	c net.PacketConn
}

func (w dummyCmcWrapper) readFrom(b []byte) (n int, dst net.IP, IfIndex int, src net.Addr, err error) {
	n, src, err = w.c.ReadFrom(b)
	return
}

func (w dummyCmcWrapper) writeTo(b []byte, src net.IP, IfIndex int, dst net.Addr) (n int, err error) {
	return w.c.WriteTo(b, dst)
}
