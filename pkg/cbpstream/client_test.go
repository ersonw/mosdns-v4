package cbpstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
)

func TestStreamSessionOpensTCPAndCarriesData(t *testing.T) {
	cert := streamTestCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	serverErr := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type: "HELLO_ACK",
			Payload: mustStreamPayload(t, map[string]any{
				"nonce":         base64.RawURLEncoding.EncodeToString([]byte("stream-test")),
				"version":       1,
				"auth_required": true,
			}),
		}); err != nil {
			serverErr <- err
			return
		}
		env, err := cbp.ReadControlFrame(conn)
		if err != nil || env.Type != "AUTH" {
			serverErr <- err
			return
		}
		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type: "SESSION_READY",
			Payload: mustStreamPayload(t, map[string]any{
				"session_id": 1,
				"data_addr":  "",
				"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			}),
		}); err != nil {
			serverErr <- err
			return
		}

		for {
			env, err := cbp.ReadControlFrame(conn)
			if err != nil {
				serverErr <- err
				return
			}
			switch env.Type {
			case "STREAM_OPEN":
				var open struct {
					StreamID uint64 `json:"stream_id"`
				}
				_ = cbp.UnmarshalPayload(env.Payload, &open)
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type: "STREAM_ACK",
					Payload: mustStreamPayload(t, map[string]any{
						"stream_id":      open.StreamID,
						"ok":             true,
						"receive_window": cbp.DefaultStreamWindow,
					}),
				})
			case "STREAM_DATA":
				var frame struct {
					StreamID uint64 `json:"stream_id"`
					Data     []byte `json:"data"`
				}
				_ = cbp.UnmarshalPayload(env.Payload, &frame)
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type: "STREAM_DATA",
					Payload: mustStreamPayload(t, map[string]any{
						"stream_id": frame.StreamID,
						"data":      append([]byte("reply:"), frame.Data...),
					}),
				})
			case "STREAM_CLOSE":
				return
			}
		}
	}()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Config{
		ControlAddr: ln.Addr().String(),
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
		Token:       "test-token",
		DeviceID:    "test-device",
		PrivateKey:  privateKey,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.OpenStream(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(conn, buf, len("reply:hello"))
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "reply:hello" {
		t.Fatalf("response = %q", buf[:n])
	}
	_ = conn.Close()
}

func mustStreamPayload(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := cbp.MarshalPayload(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func streamTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cbpstream-test"},
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
