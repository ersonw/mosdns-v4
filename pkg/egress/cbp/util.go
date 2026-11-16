package cbp

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

func stringsTrim(s string) string { return strings.TrimSpace(s) }

func encodeBase64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

func decodeBase64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}

// decodeBindToken turns the SESSION_READY token into the 32-byte bind payload.
func decodeBindToken(token string) ([]byte, error) {
	raw, err := decodeBase64(token)
	if err != nil {
		return nil, fmt.Errorf("cbp: bad data token: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("cbp: data token is empty")
	}
	return raw, nil
}

// endpointAddress strips a tls:// or quic:// scheme and any path, leaving the
// host:port a dialer can use.
func endpointAddress(endpoint string) string {
	s := strings.TrimSpace(endpoint)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// loadCertPool reads a PEM bundle into a root pool.
func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cbp: read CA file %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("cbp: CA file %s contains no usable certificate", path)
	}
	return pool, nil
}
