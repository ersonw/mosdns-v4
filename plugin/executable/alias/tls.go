package alias

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

// loadGatewayTLS loads the certificate pair used to terminate TLS on 443.
// Both paths must be set; an unset pair keeps 443 byte-transparent.
func loadGatewayTLS(certFile, keyFile string) (*tls.Config, error) {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("alias: tls_cert_file and tls_key_file must be set together")
	}
	for _, f := range []string{certFile, keyFile} {
		st, err := os.Stat(f)
		if err != nil {
			return nil, fmt.Errorf("alias: tls file %s: %w", f, err)
		}
		if st.IsDir() {
			return nil, fmt.Errorf("alias: tls file %s is a directory", f)
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("alias: load tls pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("alias: parse tls certificate: %w", err)
	}
	cert.Leaf = leaf
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("alias: tls certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}
