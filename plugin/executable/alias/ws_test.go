package alias

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// tcpPair returns a connected pair of real sockets. net.Pipe is fully synchronous
// and would deadlock around the handshake reads and writes.
func tcpPair(t *testing.T) (peer, side net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	side, err = ln.Accept()
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	_ = peer.SetDeadline(deadline)
	_ = side.SetDeadline(deadline)
	t.Cleanup(func() {
		peer.Close()
		side.Close()
	})
	return peer, side
}

func TestIsUpgradeRequest(t *testing.T) {
	raw := []string{
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, Upgrade\r\nUpgrade: h2c\r\n\r\n",
	}
	for _, r := range raw {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(r)))
		if err != nil {
			t.Fatal(err)
		}
		if !isUpgradeRequest(req) {
			t.Fatalf("upgrade not detected in %q", r)
		}
	}

	plain, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if isUpgradeRequest(plain) {
		t.Fatal("plain request detected as upgrade")
	}
	bad, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if isUpgradeRequest(bad) {
		t.Fatal("Upgrade without Connection: upgrade detected")
	}
}

func TestRelayUpgradeTunnel(t *testing.T) {
	clientPeer, clientGW := tcpPair(t)
	upPeer, upGW := tcpPair(t)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /chat?x=1 HTTP/1.1\r\nHost: ws.example.com.local\r\n" +
			"Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	// Mirror forwardUpgrade: origin-form URI and real Host.
	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = "ws.example.com"
	req.Host = "ws.example.com"
	req.Close = false

	p := &plugin{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.relayUpgrade(clientGW, bufio.NewReader(clientGW), upGW, req, "ws.example.com", "ws.example.com.local")
	}()

	upReq, err := http.ReadRequest(bufio.NewReader(upPeer))
	if err != nil {
		t.Fatalf("upstream read request: %v", err)
	}
	if upReq.Host != "ws.example.com" {
		t.Fatalf("upstream host = %q", upReq.Host)
	}
	if upReq.URL.Path != "/chat" || upReq.URL.RawQuery != "x=1" {
		t.Fatalf("upstream uri = %q", upReq.URL.RequestURI())
	}
	if upReq.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("upgrade header lost: %q", upReq.Header.Get("Upgrade"))
	}
	if !strings.Contains(strings.ToLower(upReq.Header.Get("Connection")), "upgrade") {
		t.Fatalf("connection header lost: %q", upReq.Header.Get("Connection"))
	}
	if upReq.Header.Get("Sec-WebSocket-Key") == "" {
		t.Fatal("sec-websocket-key lost")
	}

	if _, err := fmt.Fprintf(upPeer, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	clientReader := bufio.NewReader(clientPeer)
	resp, err := http.ReadResponse(clientReader, nil)
	if err != nil {
		t.Fatalf("client read 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("client upgrade header = %q", resp.Header.Get("Upgrade"))
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "close") {
		t.Fatalf("client connection header = %q", resp.Header.Get("Connection"))
	}

	// Frames travel in both directions after the handshake.
	if _, err := clientPeer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4)
	if _, err := io.ReadFull(bufio.NewReader(upPeer), frame); err != nil {
		t.Fatalf("upstream read frame: %v", err)
	}
	if string(frame) != "ping" {
		t.Fatalf("upstream frame = %q", frame)
	}
	if _, err := upPeer.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(clientReader, frame); err != nil {
		t.Fatalf("client read frame: %v", err)
	}
	if string(frame) != "pong" {
		t.Fatalf("client frame = %q", frame)
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("relay returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish after peers closed")
	}
}

func TestRelayUpgradeRejectedFallsBack(t *testing.T) {
	clientPeer, clientGW := tcpPair(t)
	upPeer, upGW := tcpPair(t)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = "ws.example.com"
	req.Host = "ws.example.com"

	p := &plugin{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.relayUpgrade(clientGW, bufio.NewReader(clientGW), upGW, req, "ws.example.com", "ws.example.com.local")
	}()

	if _, err := http.ReadRequest(bufio.NewReader(upPeer)); err != nil {
		t.Fatalf("upstream read request: %v", err)
	}
	if _, err := io.WriteString(upPeer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientPeer), nil)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "no" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}

	_ = upPeer.Close()
	_ = clientPeer.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("relay returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
}
