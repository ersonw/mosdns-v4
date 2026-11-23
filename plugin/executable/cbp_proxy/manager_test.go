package cbp_proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/cbp"
	"github.com/ersonw/mosdns-v4/pkg/cbpcoord"
	"github.com/ersonw/mosdns-v4/pkg/cbpstream"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestManagerClosesLoopFromBootstrapToCBPStream(t *testing.T) {
	cert := testCertificate(t, "cbp-test")
	nodeAuth := make(chan string, 1)
	nodeAddr, closeNode, err := startFakeCBPNode(cert, nodeAuth)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNode()
	coordinatorAddr, closeCoordinator, err := startFakeCoordinator(cert, "edge-sg-1", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCoordinator()

	var tokenSeen bool
	identity := newTestIdentity(t, "cbp_sg")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/edge/bootstrap":
			tokenSeen = r.Header.Get("X-API-Key") == "test-token" && r.Header.Get("Authorization") == ""
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server": map[string]any{
					"candidates": []map[string]any{{
						"id":        "main",
						"role":      "main",
						"addresses": []string{coordinatorAddr},
					}},
				},
			})
		case "/v1/identity/client":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id":   identity.clientID,
				"public_key":  identity.publicKey,
				"private_key": identity.privateKey,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := coremain.ProxyProvideConfig{
		Tag:          "cbp_sg",
		Domain:       srv.URL,
		Token:        "test-token",
		NodeToken:    "node-token",
		IdentityFile: filepath.Join(t.TempDir(), "identity.json"),
	}
	m, err := NewManager([]coremain.ProxyProvideConfig{cfg}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	dialer, host, err := m.NewProxyDialer("cbp_sg:"+"edge-sg-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if host == "" || host != "127.0.0.1" {
		t.Fatalf("proxy host = %q, want host only", host)
	}
	if !tokenSeen {
		t.Fatal("bootstrap did not carry X-API-Key without Authorization")
	}
	select {
	case got := <-nodeAuth:
		if got != "node-token" {
			t.Fatalf("node AUTH token = %q, want node_token", got)
		}
	case <-time.After(time.Second):
		t.Fatal("fake node did not receive AUTH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
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
	_ = egressClose(dialer)
}

func TestManagerUsesExistingIdentityClientID(t *testing.T) {
	cert := testCertificate(t, "cbp-test")
	nodeAddr, closeNode, err := startFakeCBPNode(cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNode()
	coordinatorAddr, closeCoordinator, err := startFakeCoordinator(cert, "edge-sg-1", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCoordinator()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edge/bootstrap" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server": map[string]any{
				"candidates": []map[string]any{{
					"id":        "main",
					"role":      "main",
					"addresses": []string{coordinatorAddr},
				}},
			},
		})
	}))
	defer srv.Close()

	identity := newTestIdentity(t, "cbdev-existing")
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	writeTestIdentity(t, identityPath, identity)
	cfg := coremain.ProxyProvideConfig{
		Tag:          "cbp_sg",
		Domain:       srv.URL,
		Token:        "test-token",
		NodeToken:    "node-token",
		IdentityFile: identityPath,
	}
	m, err := NewManager([]coremain.ProxyProvideConfig{cfg}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	dialer, _, err := m.NewProxyDialer("cbp_sg:"+"edge-sg-1", true)
	if err != nil {
		t.Fatal(err)
	}
	_ = egressClose(dialer)
}

func TestNewProxyDialerResolvesNodeLabel(t *testing.T) {
	cert := testCertificate(t, "cbp-test")
	nodeAddr, closeNode, err := startFakeCBPNode(cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNode()
	coordinatorAddr, closeCoordinator, err := startFakeCoordinator(cert, "edge-sg-1", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCoordinator()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edge/bootstrap" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server": map[string]any{
				"candidates": []map[string]any{{
					"id":        "main",
					"role":      "main",
					"addresses": []string{coordinatorAddr},
				}},
			},
		})
	}))
	defer srv.Close()

	identity := newTestIdentity(t, "cbdev-label")
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	writeTestIdentity(t, identityPath, identity)
	cfg := coremain.ProxyProvideConfig{
		Tag:          "cbp_sg",
		Domain:       srv.URL,
		Token:        "test-token",
		NodeToken:    "node-token",
		IdentityFile: identityPath,
	}
	m, err := NewManager([]coremain.ProxyProvideConfig{cfg}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	dialer, host, err := m.NewProxyDialer("cbp_sg:label-edge-sg-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("proxy host = %q, want node address host", host)
	}
	_ = egressClose(dialer)
}

func TestFindNodePrefersIDAndRejectsAmbiguousLabels(t *testing.T) {
	nodes := map[string]cbpcoord.Node{
		"edge-a":          {ID: "edge-a", Label: "alpha"},
		"edge-b":          {ID: "edge-b", Label: "shared"},
		"edge-c":          {ID: "edge-c", Label: "shared"},
		"edge-with-label": {ID: "edge-with-label", Label: "edge-b"},
	}
	node, ok, err := findNode(nodes, "edge-b")
	if err != nil || !ok || node.ID != "edge-b" {
		t.Fatalf("ID must win over another node's label: node=%+v ok=%v err=%v", node, ok, err)
	}
	node, ok, err = findNode(nodes, "alpha")
	if err != nil || !ok || node.ID != "edge-a" {
		t.Fatalf("unique label lookup failed: node=%+v ok=%v err=%v", node, ok, err)
	}
	if _, _, err := findNode(nodes, "shared"); err == nil {
		t.Fatal("duplicate label must be rejected")
	}
	if _, ok, err := findNode(nodes, "missing"); err != nil || ok {
		t.Fatalf("missing label: ok=%v err=%v", ok, err)
	}
}

func writeTestIdentity(t *testing.T, path string, identity testIdentity) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"client_id":   identity.clientID,
		"public_key":  identity.publicKey,
		"private_key": identity.privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

type testIdentity struct {
	clientID   string
	publicKey  string
	privateKey string
}

func newTestIdentity(t *testing.T, clientID string) testIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{
		clientID:   clientID,
		publicKey:  base64.RawURLEncoding.EncodeToString(pub),
		privateKey: base64.RawURLEncoding.EncodeToString(priv.Seed()),
	}
}

func egressClose(d any) error {
	if c, ok := d.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func startFakeCoordinator(cert tls.Certificate, nodeID, nodeAddr string) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type:    "HELLO",
					Payload: mustJSON(map[string]any{"protocol": "cbp-coord/1", "nonce": "dGVzdC1ub25jZQ"}),
				})
				env, err := cbp.ReadControlFrame(conn)
				if err != nil || env.Type != "CLIENT_AUTH" {
					return
				}
				var auth struct {
					ClientID string `json:"client_id"`
				}
				_ = cbp.UnmarshalPayload(env.Payload, &auth)
				clientID := auth.ClientID
				if clientID == "" {
					clientID = "cbp_sg"
				}
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type:    "CLIENT_READY",
					Payload: mustJSON(map[string]any{"client_id": clientID, "node_count": 1}),
				})
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type: "NODE_LIST",
					Payload: mustJSON(map[string]any{
						"nodes": []map[string]any{{
							"id":                  nodeID,
							"label":               "label-" + nodeID,
							"region":              "test",
							"public_addr":         "127.0.0.1",
							"tcp_endpoint":        nodeAddr,
							"public_tcp_endpoint": nodeAddr,
						}},
					}),
				})
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

func startFakeCBPNode(cert tls.Certificate, authTokens chan<- string) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type:    "HELLO_ACK",
					Payload: mustJSON(map[string]any{"nonce": "dGVzdC1ub25jZQ", "version": 1}),
				})
				env, err := cbp.ReadControlFrame(conn)
				if err != nil || env.Type != "AUTH" {
					return
				}
				var auth cbp.AuthRequest
				if err := cbp.UnmarshalPayload(env.Payload, &auth); err != nil {
					return
				}
				if authTokens != nil {
					authTokens <- auth.Token
				}
				_ = cbp.WriteControlFrame(conn, cbp.Envelope{
					Type:    "SESSION_READY",
					Payload: mustJSON(map[string]any{"session_id": 1, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}),
				})
				for {
					env, err := cbp.ReadControlFrame(conn)
					if err != nil {
						return
					}
					switch env.Type {
					case "RAW_OPEN":
						_ = cbp.WriteControlFrame(conn, cbp.Envelope{
							Type:    "RAW_READY",
							Payload: mustJSON(map[string]any{"tunnel_ipv4": "10.66.0.2", "tunnel_ipv6": "fd00::2"}),
						})
					case "RAW_PACKET":
						_ = cbp.WriteControlFrame(conn, cbp.Envelope{Type: "RAW_PACKET", Payload: env.Payload})
					case "STREAM_OPEN":
						var open struct {
							StreamID uint64 `json:"stream_id"`
						}
						_ = cbp.UnmarshalPayload(env.Payload, &open)
						_ = cbp.WriteControlFrame(conn, cbp.Envelope{
							Type:    "STREAM_ACK",
							Payload: mustJSON(map[string]any{"stream_id": open.StreamID, "ok": true, "receive_window": 2 << 20}),
						})
					case "STREAM_DATA":
						var frame struct {
							StreamID uint64 `json:"stream_id"`
							Data     []byte `json:"data"`
						}
						_ = cbp.UnmarshalPayload(env.Payload, &frame)
						_ = cbp.WriteControlFrame(conn, cbp.Envelope{
							Type:    "STREAM_DATA",
							Payload: mustJSON(map[string]any{"stream_id": frame.StreamID, "data": append([]byte("reply:"), frame.Data...)}),
						})
					case "STREAM_CLOSE":
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

func TestCBPProxyDialerOpenRawIP(t *testing.T) {
	cert := testCertificate(t, "cbp-raw-test")
	nodeAddr, stop, err := startFakeCBPNode(cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &cbpDialer{
		cfg: cbpstream.Config{
			ControlAddr: nodeAddr,
			TLSConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			},
			Token:       "test-token",
			DeviceID:    "test-device",
			PrivateKey:  privateKey,
			DialTimeout: 5 * time.Second,
		},
		log:  zap.NewNop(),
		node: "test-node",
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.OpenRawIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.TunnelIPv4(); got.String() != "10.66.0.2" {
		t.Fatalf("tunnel ipv4 = %s", got)
	}
	packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 66, 0, 2, 93, 184, 216, 34}
	if err := conn.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	got, err := conn.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(packet) {
		t.Fatalf("raw packet = %x, want %x", got, packet)
	}
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func testCertificate(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: commonName},
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

func TestWriteManagedDatOnlyRewritesWhenNodeTableChanges(t *testing.T) {
	dir := t.TempDir()
	cfg := coremain.ProxyProvideConfig{
		Tag:          "cbp_managed",
		Domain:       "https://api.aa2.dev",
		Token:        "token",
		NodeToken:    "node-token",
		IdentityFile: filepath.Join(dir, "identity.json"),
		ConfigDat:    filepath.Join(dir, "proxy_provides", "cbp_managed.dat"),
		ManageDat:    true,
		GenerateDat:  true,
	}
	s := &tagState{cfg: cfg, log: zap.NewNop()}
	nodes := []cbpcoord.Node{{ID: "edge-old", Region: "vyos", PublicTCPEndpoint: "1.2.3.4:8443"}}
	if !s.writeGeneratedDat(nodes, false) {
		t.Fatal("initial write failed")
	}
	s.datFingerprint = nodeTableFingerprint(nodes)
	s.cfg.GenerateDat = false
	stamp := time.Unix(1700000000, 0)
	if err := os.Chtimes(cfg.ConfigDat, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	s.writeDatIfChanged(nodes, false)
	info, err := os.Stat(cfg.ConfigDat)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stamp) {
		t.Fatal("unchanged node table rewrote the dat")
	}
	renamed := []cbpcoord.Node{{ID: "edge-renamed", Region: "vyos", PublicTCPEndpoint: "1.2.3.4:8443"}}
	s.writeDatIfChanged(renamed, false)
	info, err = os.Stat(cfg.ConfigDat)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(stamp) {
		t.Fatal("changed node table did not rewrite the dat")
	}
}

func TestManagerLogsLifecycleAndDialAtExpectedLevels(t *testing.T) {
	cert := testCertificate(t, "cbp-test")
	nodeAuth := make(chan string, 1)
	nodeAddr, closeNode, err := startFakeCBPNode(cert, nodeAuth)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNode()
	coordinatorAddr, closeCoordinator, err := startFakeCoordinator(cert, "edge-sg-1", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCoordinator()

	identity := newTestIdentity(t, "cbp_sg")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/edge/bootstrap":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server": map[string]any{
					"candidates": []map[string]any{{
						"id": "main", "role": "main", "addresses": []string{coordinatorAddr},
					}},
				},
			})
		case "/v1/identity/client":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": identity.clientID, "public_key": identity.publicKey, "private_key": identity.privateKey,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := coremain.ProxyProvideConfig{
		Tag:          "cbp_sg",
		Domain:       srv.URL,
		Token:        "test-token",
		NodeToken:    "node-token",
		IdentityFile: filepath.Join(t.TempDir(), "identity.json"),
	}
	core, logs := observer.New(zap.DebugLevel)
	m, err := NewManager([]coremain.ProxyProvideConfig{cfg}, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	dialer, _, err := m.NewProxyDialer("cbp_sg:edge-sg-1", true)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = egressClose(dialer)

	want := map[string]zapcore.Level{
		"cbp_proxy: manager initialized":          zapcore.InfoLevel,
		"cbp_proxy: provider configured":          zapcore.InfoLevel,
		"cbp_proxy: node cache stale":             zapcore.DebugLevel,
		"cbp_proxy: bootstrap candidates fetched": zapcore.DebugLevel,
		"cbp_proxy: main candidates ranked":       zapcore.DebugLevel,
		"cbp_proxy: CBP node list refreshed":      zapcore.InfoLevel,
		"cbp_proxy: trying coordinator relay":     zapcore.DebugLevel,
		"cbp_proxy: starting CBP handshake":       zapcore.DebugLevel,
		"cbp_proxy: CBP stream session ready":     zapcore.InfoLevel,
		"cbp_proxy: CBP dial":                     zapcore.DebugLevel,
		"cbp_proxy: CBP dial ready":               zapcore.DebugLevel,
	}
	seen := map[string]zapcore.Level{}
	for _, entry := range logs.All() {
		seen[entry.Message] = entry.Level
		if strings.Contains(entry.Message, "node-token") || strings.Contains(fmt.Sprint(entry.ContextMap()), "node-token") {
			t.Fatalf("node token leaked into %q: %v", entry.Message, entry.ContextMap())
		}
	}
	for message, level := range want {
		got, ok := seen[message]
		if !ok {
			t.Fatalf("missing log %q, got %v", message, seen)
		}
		if got != level {
			t.Fatalf("log %q level = %v, want %v", message, got, level)
		}
	}
}
