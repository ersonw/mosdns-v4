//go:build darwin || freebsd

package fakeipnat

// Shared packet device for the BSD derived targets: the interface is a file
// descriptor, readiness is polled so a read deadline still expires, and the
// optional 4 byte address-family header used by utun is stripped on read and
// added on write.

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const afInetHeader = 2 // AF_INET as the utun header value

type fdTunDevice struct {
	fd     int32
	hdrLen int // 4 when the platform prefixes packets with an address family
	name   string

	mu       sync.Mutex
	deadline time.Time

	buf []byte
}

func (d *fdTunDevice) Read(p []byte) (int, error) {
	for {
		d.mu.Lock()
		dl := d.deadline
		d.mu.Unlock()

		timeout := -1
		if !dl.IsZero() {
			remain := time.Until(dl)
			if remain <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timeout = int(remain/time.Millisecond) + 1
		}

		fds := []unix.PollFd{{Fd: d.fd, Events: unix.POLLIN}}
		n, err := unix.Poll(fds, timeout)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		if n == 0 {
			return 0, os.ErrDeadlineExceeded
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) == 0 {
			continue
		}

		need := len(p) + d.hdrLen
		if len(d.buf) < need {
			d.buf = make([]byte, need)
		}
		rn, rerr := unix.Read(int(d.fd), d.buf)
		if rerr != nil {
			if errors.Is(rerr, unix.EINTR) || errors.Is(rerr, unix.EAGAIN) || errors.Is(rerr, unix.EWOULDBLOCK) {
				continue
			}
			return 0, rerr
		}
		if rn < d.hdrLen {
			return 0, nil
		}
		return copy(p, d.buf[d.hdrLen:rn]), nil
	}
}

func (d *fdTunDevice) Write(p []byte) (int, error) {
	if d.hdrLen == 0 {
		return unix.Write(int(d.fd), p)
	}
	buf := make([]byte, d.hdrLen+len(p))
	binary.BigEndian.PutUint32(buf[:d.hdrLen], afInetHeader)
	copy(buf[d.hdrLen:], p)
	if _, err := unix.Write(int(d.fd), buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *fdTunDevice) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadline = t
	d.mu.Unlock()
	return nil
}

func (d *fdTunDevice) Close() error {
	return unix.Close(int(d.fd))
}
