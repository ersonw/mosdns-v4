package fakeipnat

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mosdns-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func TestProxyAddrRoundTrip(t *testing.T) {
	cases := []string{"1.2.3.4:443", "example.com:53", "[2001:db8::1]:8080"}
	for _, addr := range cases {
		buf, err := appendProxyAddr(nil, addr)
		if err != nil {
			t.Fatalf("encode %q: %v", addr, err)
		}
		got, err := readProxyAddr(bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("decode %q: %v", addr, err)
		}
		if got != addr {
			t.Fatalf("round trip %q -> %q", addr, got)
		}
	}
	if _, err := appendProxyAddr(nil, "example.com"); err == nil {
		t.Fatal("address without port should fail")
	}
}

func TestTrojanUDPRequestAndPacket(t *testing.T) {
	hdr, err := trojanUDPHeader("secret")
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	sum := sha256.Sum256([]byte("secret"))
	hash := hex.EncodeToString(sum[:])[:56]
	if !strings.HasPrefix(string(hdr), hash+"\r\n3\r\n") {
		t.Fatalf("request line = %q, want hash + command 3", hdr)
	}
	// The associate address is 0.0.0.0:0 and the line ends with CRLF.
	if !strings.HasSuffix(string(hdr), "\x01\x00\x00\x00\x00\x00\x00\r\n") {
		t.Fatalf("request line = %q, want the zero associate address and CRLF", hdr)
	}

	// A packet carries no command byte: the first byte is the address type.
	pkt, err := encodeTrojanUDPFrame("10.0.0.1:53", []byte("hi"))
	if err != nil {
		t.Fatalf("encode packet: %v", err)
	}
	if pkt[0] != 0x01 {
		t.Fatalf("packet starts with %#x, want the address type instead of a command byte", pkt[0])
	}
	addr, payload, err := readTrojanUDPFrame(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if addr != "10.0.0.1:53" || string(payload) != "hi" {
		t.Fatalf("packet = %q %q", addr, payload)
	}
}

func TestTrojanUDPEgressEndToEnd(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testTLSConfig(t))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		if _, err := r.ReadString('\n'); err != nil {
			done <- err
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			done <- err
			return
		}
		if _, err := readProxyAddr(r); err != nil {
			done <- err
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			done <- err
			return
		}
		addr, payload, err := readTrojanUDPFrame(r)
		if err != nil {
			done <- err
			return
		}
		if addr != "10.1.2.3:53" || string(payload) != "ping" {
			done <- io.ErrUnexpectedEOF
			return
		}
		reply, err := encodeTrojanUDPFrame("10.1.2.3:53", []byte("pong"))
		if err != nil {
			done <- err
			return
		}
		_, err = c.Write(reply)
		done <- err
	}()

	e := &trojanEgress{server: ln.Addr().String(), password: "secret", insecure: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := e.DialContext(ctx, "udp", "10.1.2.3:53")
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("reply = %q", buf[:n])
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestSocks5UDPEgressEndToEnd(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp relay: %v", err)
	}
	defer relay.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	// Relay: read a wrapped datagram, bounce the payload back in the same shape.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil || n < 4 {
				return
			}
			r := &byteReader{b: buf[3:n]}
			addr, err := readProxyAddr(r)
			if err != nil {
				return
			}
			out, err := appendProxyAddr([]byte{0, 0, 0}, addr)
			if err != nil {
				return
			}
			out = append(out, bytes.ToUpper(r.b)...)
			_, _ = relay.WriteToUDP(out, from)
		}
	}()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var greeting [3]byte
		if _, err := io.ReadFull(r, greeting[:]); err != nil {
			done <- err
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			done <- err
			return
		}
		var req [10]byte
		if _, err := io.ReadFull(r, req[:]); err != nil {
			done <- err
			return
		}
		if req[0] != 0x05 || req[1] != socks5CmdUDPAssociate {
			done <- io.ErrUnexpectedEOF
			return
		}
		relayAddr := relay.LocalAddr().(*net.UDPAddr)
		rep := []byte{0x05, 0x00, 0x00, 0x01}
		rep = append(rep, relayAddr.IP.To4()...)
		rep = append(rep, byte(relayAddr.Port>>8), byte(relayAddr.Port))
		if _, err := c.Write(rep); err != nil {
			done <- err
			return
		}
		// Keep the control connection open as the association.
		done <- nil
		_ = r
	}()

	e := &socks5Egress{server: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := e.DialContext(ctx, "udp", "1.2.3.4:53")
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "PING" {
		t.Fatalf("reply = %q", buf[:n])
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}
