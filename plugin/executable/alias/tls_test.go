package alias

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCertificate(t *testing.T) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ip138.com.local"},
		DNSNames:              []string{"ip138.com.local", "*.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPEM, keyPEM
}

func TestLoadGatewayTLS(t *testing.T) {
	_, certPEM, keyPEM := testCertificate(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.cer")
	keyFile := filepath.Join(dir, "domain.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadGatewayTLS(certFile, keyFile)
	if err != nil {
		t.Fatalf("load pair: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if _, err := loadGatewayTLS(certFile, ""); err == nil {
		t.Fatal("half pair accepted")
	}
	if cfg, err := loadGatewayTLS("", ""); err != nil || cfg != nil {
		t.Fatalf("empty pair = %+v, %v", cfg, err)
	}
}

func TestGatewayRedirectLocationHTTPS(t *testing.T) {
	p := &plugin{tlsConfig: &tls.Config{}}
	req, _ := http.NewRequest(http.MethodGet, "http://ip138.com/a/b?x=1", nil)
	if got := p.gatewayRedirectLocation("ip138.com.local", req); got != "https://ip138.com.local/a/b?x=1" {
		t.Fatalf("location = %q", got)
	}
}

func TestServeTLSGatewayRedirect(t *testing.T) {
	cert, _, _ := testCertificate(t)
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		store:     s,
		suffix:    ".local",
		redirect:  true,
		defScheme: schemeHTTP,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		},
	}
	peer, srv := tcpPair(t)
	done := make(chan struct{})
	go func() {
		p.serveTLSGateway(srv, "ip138.com")
		close(done)
	}()

	tc := tls.Client(peer, &tls.Config{InsecureSkipVerify: true, ServerName: "ip138.com.local"})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := fmt.Fprintf(tc, "GET /a/b?x=1 HTTP/1.1\r\nHost: ip138.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read redirect: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://ip138.com.local/a/b?x=1" {
		t.Fatalf("location = %q", got)
	}
	_, _ = io.ReadAll(resp.Body)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tls gateway did not finish after redirect")
	}
}

func TestRedirectSchemeDefault(t *testing.T) {
	p := &plugin{}
	if got := p.redirectScheme(); got != "http" {
		t.Fatalf("scheme = %q", got)
	}
}
