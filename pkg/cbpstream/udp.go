package cbpstream

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
)

// UDPConn is one unconnected UDP association carried over CBP. It implements
// net.PacketConn so a SOCKS5 UDP ASSOCIATE handler can treat a remote node in
// exactly the same way as a local UDP socket.
type UDPConn struct {
	client *Client
	id     uint64

	mu         sync.Mutex
	cond       *sync.Cond
	chunks     []udpChunk
	closed     bool
	remoteDone bool

	readDeadline time.Time
	readTimer    *time.Timer
}

type udpChunk struct {
	addr    *net.UDPAddr
	payload []byte
}

func newUDPConn(client *Client, id uint64) *UDPConn {
	conn := &UDPConn{client: client, id: id}
	conn.cond = sync.NewCond(&conn.mu)
	return conn
}

func (c *UDPConn) deliver(frame []byte, fin bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fin {
		c.remoteDone = true
		c.cond.Broadcast()
		return
	}
	if len(frame) == 0 {
		return
	}
	addr, payload, err := cbp.DecodeUDPFrame(frame)
	if err != nil {
		return
	}
	// Datagrams are independent. Keeping a bounded queue prevents a peer
	// flooding WebRTC candidates from growing memory without bound.
	if len(c.chunks) >= 512 {
		c.chunks = c.chunks[1:]
	}
	c.chunks = append(c.chunks, udpChunk{addr: addr, payload: payload})
	c.cond.Broadcast()
}

func (c *UDPConn) markRemoteClosed() {
	c.mu.Lock()
	c.remoteDone = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.chunks) == 0 && !c.closed && !c.remoteDone {
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	if len(c.chunks) == 0 {
		return 0, nil, io.EOF
	}
	chunk := c.chunks[0]
	c.chunks = c.chunks[1:]
	n := copy(p, chunk.payload)
	return n, chunk.addr, nil
}

func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, err
		}
	}
	frame, err := cbp.EncodeUDPFrame(udpAddr, p)
	if err != nil {
		return 0, err
	}
	if err := c.client.sendStreamData(c.id, frame); err != nil {
		return 0, fmt.Errorf("cbpstream: write UDP: %w", err)
	}
	return len(p), nil
}

func (c *UDPConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	_ = c.client.send("STREAM_CLOSE", closeFrame{StreamID: c.id})
	c.client.removeUDPConn(c.id)
	return nil
}

func (c *UDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.setReadDeadlineLocked(t)
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.setReadDeadlineLocked(t)
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) setReadDeadlineLocked(t time.Time) {
	c.readDeadline = t
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if t.IsZero() {
		c.cond.Broadcast()
		return
	}
	if d := time.Until(t); d > 0 {
		c.readTimer = time.AfterFunc(d, func() {
			c.mu.Lock()
			c.cond.Broadcast()
			c.mu.Unlock()
		})
	} else {
		c.cond.Broadcast()
	}
}

func (c *UDPConn) SetWriteDeadline(time.Time) error { return nil }
