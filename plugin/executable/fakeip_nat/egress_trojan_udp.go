package fakeipnat

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Trojan carries UDP over the TLS stream it already has for TCP. The request
// line switches the stream into UDP mode (command 3) and, like the TCP request,
// ends with a target address and CRLF:
//
//	hash(56 hex) CRLF 0x03 CRLF ATYP+ADDR+PORT CRLF
//
// After that every datagram is a packet, with no command byte of its own:
//
//	ATYP+ADDR+PORT | LEN(2, big endian) | PAYLOAD
//
// The request address is the placeholder 0.0.0.0:0 used by the ASSOCIATE form,
// and the packets carry the real target. One TLS connection serves one UDP
// flow.
const (
	trojanCmdUDPAssociate = 3
	trojanUDPMaxPayload   = 65535
)

// trojanUDPHeader is the request that switches the stream into UDP mode: the
// first 56 hex chars of sha256(password), CRLF, command 3, CRLF, the associate
// address (always 0.0.0.0:0), CRLF.
func trojanUDPHeader(password string) ([]byte, error) {
	sum := sha256.Sum256([]byte(password))
	hash := hex.EncodeToString(sum[:])[:56]
	buf := []byte(hash + "\r\n3\r\n")
	buf, err := appendProxyAddr(buf, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return append(buf, '\r', '\n'), nil
}

// encodeTrojanUDPFrame wraps one datagram for the trojan stream.
func encodeTrojanUDPFrame(addr string, payload []byte) ([]byte, error) {
	if len(payload) > trojanUDPMaxPayload {
		return nil, fmt.Errorf("trojan udp payload too large: %d", len(payload))
	}
	buf, err := appendProxyAddr(nil, addr)
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(len(payload)>>8), byte(len(payload)))
	return append(buf, payload...), nil
}

// readTrojanUDPFrame reads one frame and returns its source address with the
// payload. It is also what the tests use on the server side.
func readTrojanUDPFrame(r io.Reader) (string, []byte, error) {
	addr, err := readProxyAddr(r)
	if err != nil {
		return "", nil, fmt.Errorf("trojan udp: address: %w", err)
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", nil, err
	}
	return addr, payload, nil
}

// trojanUDPConn is a net.Conn over the trojan DTLS-free framing above: one
// Write is one datagram, one Read returns one datagram.
type trojanUDPConn struct {
	conn   net.Conn
	addr   string
	writeM sync.Mutex
}

func (c *trojanUDPConn) Read(p []byte) (int, error) {
	_, payload, err := readTrojanUDPFrame(c.conn)
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (c *trojanUDPConn) Write(p []byte) (int, error) {
	frame, err := encodeTrojanUDPFrame(c.addr, p)
	if err != nil {
		return 0, err
	}
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if _, err := c.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *trojanUDPConn) Close() error                       { return c.conn.Close() }
func (c *trojanUDPConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *trojanUDPConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *trojanUDPConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *trojanUDPConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *trojanUDPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
