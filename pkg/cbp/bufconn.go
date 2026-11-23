package cbp

import (
	"bufio"
	"net"
	"sync"
)

// BufferedConn coalesces the small writes crypto/tls emits per record into
// larger underlying writes. A 64 KiB stream frame otherwise becomes four 16
// KiB TLS records and four syscalls; buffering turns that into one syscall.
//
// Reads flush first so a pending write can never deadlock a request/response
// TLS handshake or a control-frame exchange.
type BufferedConn struct {
	net.Conn

	mu sync.Mutex
	w  *bufio.Writer
}

func NewBufferedConn(conn net.Conn, size int) *BufferedConn {
	if size <= 0 {
		size = 256 << 10
	}
	return &BufferedConn{
		Conn: conn,
		w:    bufio.NewWriterSize(conn, size),
	}
}

func (c *BufferedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	n, err := c.w.Write(p)
	c.mu.Unlock()
	return n, err
}

func (c *BufferedConn) Flush() error {
	c.mu.Lock()
	err := c.w.Flush()
	c.mu.Unlock()
	return err
}

func (c *BufferedConn) Read(p []byte) (int, error) {
	if err := c.Flush(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
