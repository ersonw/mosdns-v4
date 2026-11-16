package tunrelay

import (
	"net"
	"testing"
	"time"
)

// A pair whose peer says nothing is what a killed VPN client looks like: no
// FIN, no reset, just silence. It must not keep the relay alive.
func TestPipeClosesASilentPair(t *testing.T) {
	a, b := net.Pipe()
	stopPeer := make(chan struct{})
	go func() {
		<-stopPeer
	}()

	done := make(chan struct{})
	go func() {
		Pipe(a, b, 200*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a silent pair outlived its idle timeout: this is the goroutine leak")
	}
	close(stopPeer)
}

// Traffic keeps a flow open past the timeout, which is what a long download or
// a live keep-alive needs.
func TestPipeKeepsAnActivePairAlive(t *testing.T) {
	clientSide, stackSide := net.Pipe()
	proxySide, remoteSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		Pipe(stackSide, proxySide, 300*time.Millisecond)
		close(done)
	}()

	go func() {
		buf := make([]byte, 64)
		for i := 0; i < 10; i++ {
			if _, err := clientSide.Write([]byte("ping")); err != nil {
				return
			}
			if _, err := remoteSide.Read(buf); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-done:
		t.Fatal("an active flow was closed by the idle watchdog")
	case <-time.After(700 * time.Millisecond):
	}
	clientSide.Close()
	remoteSide.Close()
	<-done
}

func TestPipeCountsBothDirections(t *testing.T) {
	client, stackSide := net.Pipe()
	proxySide, remote := net.Pipe()

	done := make(chan struct{})
	var up, down int64
	go func() {
		down, up = Pipe(stackSide, proxySide, 5*time.Second)
		close(done)
	}()

	go func() {
		if _, err := remote.Write([]byte("hello")); err != nil {
			return
		}
		buf := make([]byte, 16)
		if _, err := remote.Read(buf); err != nil {
			return
		}
	}()

	buf := make([]byte, 16)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	client.Close()
	remote.Close()
	<-done
	if up != 5 {
		t.Fatalf("upstream bytes b->a = %d, want 5", up)
	}
	if down != 0 {
		t.Fatalf("downstream bytes a->b = %d, want 0", down)
	}
}
