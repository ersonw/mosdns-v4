package fakeipnat

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 UDP ASSOCIATE (RFC 1928 section 7): the client keeps one TCP
// connection open as the association, and sends datagrams to the relay
// endpoint the server reports. Each datagram is wrapped as
//
//	RSV(2)=0 | FRAG(1)=0 | ATYP+ADDR+PORT | PAYLOAD
//
// Fragmentation is not implemented; a datagram with FRAG != 0 is dropped.
const socks5CmdUDPAssociate = 0x03

// socks5UDPAssociateRequest asks the server to allocate a relay endpoint. The
// client does not know which local address it will send from yet, so the
// address field is a zero IPv4 address.
func socks5UDPAssociateRequest() []byte {
	return []byte{0x05, socks5CmdUDPAssociate, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

// readSocks5BindAddr parses a reply's bound address and returns it as
// "host:port"; the same shape is used by the CONNECT reply and the UDP
// ASSOCIATE reply.
func readSocks5BindAddr(c net.Conn) (string, error) {
	// VER, REP, RSV; the address type that follows is read by readProxyAddr.
	var head [3]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", fmt.Errorf("socks5 reply: %w", err)
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("socks5: unexpected reply version %#x", head[0])
	}
	if head[1] != 0x00 {
		return "", fmt.Errorf("socks5: request failed: %s", socks5ReplyText(head[1]))
	}
	addr, err := readProxyAddr(c)
	if err != nil {
		return "", fmt.Errorf("socks5 reply: %w", err)
	}
	return addr, nil
}

// socks5UDPConn is a net.Conn that carries datagrams through a socks5 UDP
// association: ctrl is the TCP control connection that keeps the association
// alive, udp is the socket talking to the relay.
type socks5UDPConn struct {
	ctrl   net.Conn
	udp    net.Conn
	addr   string
	writeM sync.Mutex
	buf    []byte
}

func (c *socks5UDPConn) Read(p []byte) (int, error) {
	if c.buf == nil {
		c.buf = make([]byte, 65535+256)
	}
	n, err := c.udp.Read(c.buf)
	if err != nil {
		return 0, err
	}
	pkt := c.buf[:n]
	if len(pkt) < 3 {
		return 0, fmt.Errorf("socks5 udp: short datagram (%d bytes)", len(pkt))
	}
	if pkt[2] != 0x00 {
		return 0, fmt.Errorf("socks5 udp: fragmented datagrams are not supported (frag %#x)", pkt[2])
	}
	// Skip RSV(2) + FRAG(1), then the source address, what remains is payload.
	r := &byteReader{b: pkt[3:]}
	if _, err := readProxyAddr(r); err != nil {
		return 0, fmt.Errorf("socks5 udp: source address: %w", err)
	}
	return copy(p, r.b), nil
}

func (c *socks5UDPConn) Write(p []byte) (int, error) {
	hdr := []byte{0x00, 0x00, 0x00}
	var err error
	hdr, err = appendProxyAddr(hdr, c.addr)
	if err != nil {
		return 0, err
	}
	pkt := append(hdr, p...)
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if _, err := c.udp.Write(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPConn) Close() error {
	_ = c.ctrl.Close()
	return c.udp.Close()
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr               { return c.udp.RemoteAddr() }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// byteReader lets readProxyAddr work on an already-read datagram without
// allocating a bufio.Reader per packet.
type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
