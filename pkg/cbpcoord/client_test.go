package cbpcoord

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
)

func TestFetchNodesUsesMainServerTCPAndReturnsOnlyNodeList(t *testing.T) {
	cert := testCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type: "HELLO",
			Payload: mustPayload(t, map[string]any{
				"protocol": ALPNCoord,
				"nonce":    "dGVzdC1ub25jZQ",
			}),
		}); err != nil {
			done <- err
			return
		}
		env, err := cbp.ReadControlFrame(conn)
		if err != nil {
			done <- err
			return
		}
		if env.Type != "CLIENT_AUTH" {
			done <- err
			return
		}
		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type:    "CLIENT_READY",
			Payload: mustPayload(t, map[string]any{"client_id": "cbp_sg", "node_count": 1}),
		}); err != nil {
			done <- err
			return
		}
		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type: "NODE_LIST",
			Payload: mustPayload(t, map[string]any{
				"nodes": []map[string]any{
					{
						"id":                 "edge-sg-1",
						"region":             "sg",
						"tcp_endpoint":       "203.0.113.10:8443",
						"public_tcp_endpoint": "203.0.113.10:8443",
					},
				},
			}),
		}); err != nil {
			done <- err
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodes, err := FetchNodes(ctx, Config{
		Address:            ln.Addr().String(),
		InsecureSkipVerify: true,
		ClientID:           "cbp_sg",
		Timeout:            5 * time.Second,
		privateKey:         privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != "edge-sg-1" {
		t.Fatalf("nodes = %+v", nodes)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	default:
	}
}

func mustPayload(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := cbp.MarshalPayload(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cbpcoord-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
