// Package tunrelay holds the connection relaying shared by the data-plane
// plugins: copy both directions, and close the pair when it has gone silent.
//
// The silence timeout is the point of the package. A relay that only exits on
// EOF leaks whenever a peer disappears without one - a VPN client that is
// killed, a QUIC flow the NAT drops, a connection the middle of the path
// quietly abandons. Those cases look exactly like an idle connection, so
// without a timeout every one of them keeps two goroutines and two buffers
// alive for as long as the process runs.
package tunrelay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// IdleWatch records when a flow last carried traffic.
type IdleWatch struct {
	last atomic.Int64
	idle atomic.Int64 // nanoseconds; 0 means "not watched"
}

// NewIdleWatch returns a watch that starts counting from now.
func NewIdleWatch() *IdleWatch {
	w := &IdleWatch{}
	w.last.Store(time.Now().UnixNano())
	return w
}

// Touch marks the flow as active.
func (w *IdleWatch) Touch() { w.last.Store(time.Now().UnixNano()) }

// IdleFor reports how long the flow has been silent.
func (w *IdleWatch) IdleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - w.last.Load())
}

// A flow is watched by one shared sweeper rather than one goroutine per flow.
// A per-flow watchdog doubles the goroutine count of the data plane, and the
// count is exactly what an overloaded router must keep small: one TCP flow was
// two copiers, a relay and a watchdog. One scan over the live flows every
// second costs nothing and keeps the per-flow cost at zero goroutines.
var (
	sweepOnce sync.Once
	sweepMu   sync.Mutex
	swept     = make(map[*IdleWatch]func())
)

func sweepLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sweepMu.Lock()
		for w, closeFn := range swept {
			idle := time.Duration(w.idle.Load())
			if idle <= 0 || w.IdleFor() < idle {
				continue
			}
			delete(swept, w)
			closeFn()
		}
		sweepMu.Unlock()
	}
}

// Start watches the flow and calls closeFn once it has been silent for idle.
// The returned stop function ends the watch and is safe to call more than once.
func (w *IdleWatch) Start(idle time.Duration, closeFn func()) (stop func()) {
	if idle <= 0 {
		return func() {}
	}
	w.idle.Store(int64(idle))
	sweepMu.Lock()
	swept[w] = closeFn
	sweepMu.Unlock()
	sweepOnce.Do(func() { go sweepLoop() })

	var once sync.Once
	return func() {
		once.Do(func() {
			sweepMu.Lock()
			delete(swept, w)
			sweepMu.Unlock()
		})
	}
}

// touchReader refreshes the watch whenever a read returns data.
type touchReader struct {
	net.Conn
	w *IdleWatch
}

func (r *touchReader) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.w.Touch()
	}
	return n, err
}

// Pipe copies both directions until each side is done, propagating half-close
// where the transport supports it. If neither side says anything for idle, both
// connections are closed: an abandoned flow must not outlive its usefulness.
func Pipe(a, b net.Conn, idle time.Duration) (fromA, fromB int64) {
	w := NewIdleWatch()
	stop := w.Start(idle, func() {
		_ = a.Close()
		_ = b.Close()
	})
	defer stop()

	var counters [2]atomic.Int64
	var wg sync.WaitGroup
	copySide := func(dst, src net.Conn, counter *atomic.Int64) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		n, _ := io.CopyBuffer(dst, &touchReader{Conn: src, w: w}, buf)
		counter.Store(n)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		_ = dst.Close()
	}
	wg.Add(2)
	go copySide(b, a, &counters[0]) // a -> b
	go copySide(a, b, &counters[1]) // b -> a
	wg.Wait()
	return counters[0].Load(), counters[1].Load()
}
