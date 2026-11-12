package radius

import (
	"net"
	"sync"

	"go.uber.org/zap"
)

// attrClass carries the group name back to ocserv (RFC 2865 §5.25). ocserv
// reads it as the group a user is placed in.
const attrClass = 25

// server owns the two UDP sockets and the request handling.
type server struct {
	secret []byte
	store  *store
	lg     *zap.Logger

	auth *net.UDPConn
	acct *net.UDPConn

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

func newServer(lg *zap.Logger, secret []byte, st *store, authAddr, acctAddr string) (*server, error) {
	s := &server{
		secret: secret,
		store:  st,
		lg:     lg,
		closed: make(chan struct{}),
	}
	if authAddr != "" {
		c, err := listenUDP(authAddr)
		if err != nil {
			return nil, err
		}
		s.auth = c
	}
	if acctAddr != "" {
		c, err := listenUDP(acctAddr)
		if err != nil {
			if s.auth != nil {
				_ = s.auth.Close()
			}
			return nil, err
		}
		s.acct = c
	}
	return s, nil
}

func listenUDP(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", a)
}

func (s *server) start() {
	if s.auth != nil {
		s.wg.Add(1)
		go s.serve(s.auth, s.handleAccess)
		s.lg.Info("radius: authentication listener started", zap.String("addr", s.auth.LocalAddr().String()))
	}
	if s.acct != nil {
		s.wg.Add(1)
		go s.serve(s.acct, s.handleAccounting)
		s.lg.Info("radius: accounting listener started", zap.String("addr", s.acct.LocalAddr().String()))
	}
}

func (s *server) close() {
	s.once.Do(func() {
		close(s.closed)
		if s.auth != nil {
			_ = s.auth.Close()
		}
		if s.acct != nil {
			_ = s.acct.Close()
		}
		s.wg.Wait()
	})
}

func (s *server) serve(conn *net.UDPConn, handler func(*net.UDPAddr, []byte) []byte) {
	defer s.wg.Done()
	buf := make([]byte, radiusMaxPacket)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			s.lg.Warn("radius: read failed", zap.Error(err))
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		if reply := handler(addr, raw); reply != nil {
			if _, err := conn.WriteToUDP(reply, addr); err != nil {
				s.lg.Warn("radius: write failed", zap.String("client", addr.String()), zap.Error(err))
			}
		}
	}
}

// handleAccess authenticates an Access-Request with PAP. Anything else (CHAP,
// EAP) is rejected with a readable reason instead of being silently dropped.
func (s *server) handleAccess(src *net.UDPAddr, raw []byte) []byte {
	p, err := parsePacket(raw)
	if err != nil {
		s.lg.Warn("radius: malformed access request", zap.String("client", src.String()), zap.Error(err))
		return nil
	}
	if p.code != codeAccessRequest {
		s.lg.Debug("radius: unexpected code on the auth port",
			zap.String("client", src.String()), zap.Uint8("code", p.code))
		return nil
	}
	withMA, ok := verifyMessageAuthenticator(raw, s.secret)
	if !ok {
		s.lg.Warn("radius: message-authenticator mismatch, packet dropped", zap.String("client", src.String()))
		return nil
	}

	name := p.getString(attrUserName)
	if name == "" {
		s.lg.Debug("radius: access request without user-name", zap.String("client", src.String()))
		return s.reply(p, withMA, codeAccessReject, "missing user-name", nil)
	}

	enc, hasPAP := p.get(attrUserPassword)
	if !hasPAP {
		if _, hasCHAP := p.get(attrCHAPPassword); hasCHAP {
			s.lg.Warn("radius: chap rejected, only pap is implemented",
				zap.String("user", name), zap.String("client", src.String()))
			return s.reply(p, withMA, codeAccessReject, "CHAP/MSCHAPv2 is not supported, use PAP", nil)
		}
		return s.reply(p, withMA, codeAccessReject, "missing user-password", nil)
	}

	plain, err := decodeUserPassword(enc, s.secret, p.authenticator[:])
	if err != nil {
		s.lg.Warn("radius: undecodable user-password", zap.String("user", name), zap.Error(err))
		return s.reply(p, withMA, codeAccessReject, "malformed user-password", nil)
	}

	u, found, err := s.store.getUser(name)
	if err != nil {
		s.lg.Error("radius: user lookup failed", zap.String("user", name), zap.Error(err))
		return s.reply(p, withMA, codeAccessReject, "internal error", nil)
	}
	if !found || !u.Enabled || !verifyPassword(u.Password, plain) {
		s.lg.Debug("radius: authentication rejected",
			zap.String("user", name), zap.String("client", src.String()),
			zap.Bool("known", found))
		return s.reply(p, withMA, codeAccessReject, "invalid credentials", nil)
	}

	var extra []attribute
	if u.Group != "" {
		extra = append(extra, attribute{typ: attrClass, value: []byte(u.Group)})
	}
	if u.IP != "" {
		// Framed-IP-Address is a 4-byte IPv4 value. SetIP only stores a
		// canonical address, but re-check here so a hand-edited SQLite row
		// cannot make the encoder write a malformed attribute.
		if ip := net.ParseIP(u.IP).To4(); ip != nil {
			extra = append(extra, attribute{typ: attrFramedIPAddress, value: ip})
		} else {
			s.lg.Warn("radius: stored fixed ip is not ipv4, ignored",
				zap.String("user", name), zap.String("ip", u.IP))
		}
	}
	s.lg.Debug("radius: authentication accepted",
		zap.String("user", name), zap.String("client", src.String()),
		zap.String("group", u.Group), zap.String("ip", u.IP))
	return s.reply(p, withMA, codeAccessAccept, "", extra)
}

// handleAccounting validates the request authenticator and folds the record into
// the session table. ocserv expects an Accounting-Response or it retries.
func (s *server) handleAccounting(src *net.UDPAddr, raw []byte) []byte {
	p, err := parsePacket(raw)
	if err != nil {
		s.lg.Warn("radius: malformed accounting request", zap.String("client", src.String()), zap.Error(err))
		return nil
	}
	if p.code != codeAccountingRequest {
		return nil
	}
	if !verifyRequestAuthenticator(p, raw, s.secret) {
		s.lg.Warn("radius: accounting authenticator mismatch, packet dropped", zap.String("client", src.String()))
		return nil
	}

	status, _ := p.getUint32(attrAcctStatusType)
	name := p.getString(attrUserName)
	session := p.getString(attrAcctSessionID)
	in, _ := p.getUint32(attrAcctInputOctets)
	out, _ := p.getUint32(attrAcctOutputOctets)

	if err := s.store.applyAccounting(session, name, src.String(), status, int64(in), int64(out)); err != nil {
		s.lg.Error("radius: accounting update failed", zap.String("user", name), zap.Error(err))
	}
	s.lg.Debug("radius: accounting recorded",
		zap.String("user", name), zap.String("session", session),
		zap.Uint32("status", status), zap.Uint32("in", in), zap.Uint32("out", out))
	return buildAccountingResponse(p, s.secret)
}

// reply builds the response and mirrors the Message-Authenticator only when the
// request carried one, which is what radcli expects.
func (s *server) reply(req *packet, withMA bool, code byte, reason string, extra []attribute) []byte {
	var attrs []attribute
	if reason != "" {
		attrs = append(attrs, attribute{typ: attrReplyMessage, value: []byte(reason)})
	}
	attrs = append(attrs, extra...)
	resp := &packet{code: code, id: req.id, attrs: attrs}
	if withMA {
		resp.attrs = append(resp.attrs, attribute{typ: attrMessageAuthenticator, value: make([]byte, 16)})
	}
	raw := resp.encode(s.secret, req.authenticator[:])
	if withMA {
		// RFC 3579: the response authenticator goes in first, then the HMAC is
		// computed over the finished packet with this attribute zeroed.
		setMessageAuthenticator(raw, s.secret)
	}
	return raw
}
