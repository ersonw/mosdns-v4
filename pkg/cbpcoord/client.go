// Package cbpcoord is the smallest client for the main server's TCP
// coordinator. It authenticates with the same Ed25519 identity the node
// control session uses, then reads exactly one NODE_LIST and closes.
//
// HTTPS only lists main-server TCP candidates. This package is the second
// step: the caller has already selected one of those candidates and now asks
// that main server for the current CBP node list.
package cbpcoord

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
	cbpidentity "github.com/ersonw/mosdns-v4/pkg/cbpidentity"
)

const (
	ALPNCoord = "cbp-coord/1"

	typeHello       = "HELLO"
	typeClientAuth  = "CLIENT_AUTH"
	typeClientReady = "CLIENT_READY"
	typeNodeList    = "NODE_LIST"
	typeError       = "ERROR"
)

// Config selects one main-server TCP candidate and the identity used to
// authenticate against it.
type Config struct {
	Address                    string
	ServerName                 string
	InsecureSkipVerify         bool
	ClientID                   string
	IdentityFile               string
	IdentityServerURL          string
	IdentityToken              string
	IdentityInsecureSkipVerify bool
	Regions                    []string
	Timeout                    time.Duration

	privateKey ed25519.PrivateKey
}

// Node is one CBP node as published by NODE_LIST. Its TCP control endpoint is
// the address a CBP stream session dials; it is not a main-server candidate.
type Node struct {
	ID string `json:"id"`
	// Label is the operator-facing display name reported by the node. Node
	// identity and routing still key off ID; Label is only a lookup alias.
	Label             string  `json:"label,omitempty"`
	Region            string  `json:"region"`
	Endpoint          string  `json:"endpoint"`
	PublicAddr        string  `json:"public_addr,omitempty"`
	LANEndpoint       string  `json:"lan_endpoint,omitempty"`
	TCPEndpoint       string  `json:"tcp_endpoint"`
	LANTCPEndpoint    string  `json:"lan_tcp_endpoint,omitempty"`
	PublicEndpoint    string  `json:"public_endpoint,omitempty"`
	PublicTCPEndpoint string  `json:"public_tcp_endpoint,omitempty"`
	PublicKey         string  `json:"public_key"`
	Weight            int     `json:"weight,omitempty"`
	Load              float64 `json:"load,omitempty"`
}

type hello struct {
	Protocol string `json:"protocol"`
	Nonce    string `json:"nonce"`
}

type clientAuth struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type clientReady struct {
	ClientID  string   `json:"client_id"`
	Regions   []string `json:"regions,omitempty"`
	NodeCount int      `json:"node_count"`
}

type nodeList struct {
	Nodes []Node `json:"nodes"`
}

type errorMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// FetchNodes connects to the selected main server, authenticates, reads one
// NODE_LIST and closes. It never returns main-server candidates as nodes.
func FetchNodes(ctx context.Context, cfg Config) ([]Node, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, errors.New("cbpcoord: main-server address is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if err := cfg.loadIdentity(ctx); err != nil {
		return nil, err
	}
	if len(cfg.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("cbpcoord: Ed25519 identity is required")
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{ALPNCoord},
	}
	if tlsCfg.ServerName == "" && !tlsCfg.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(cfg.Address)
		if err == nil {
			tlsCfg.ServerName = strings.Trim(host, "[]")
		}
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("cbpcoord: dial %s: %w", cfg.Address, err)
	}
	defer raw.Close()

	conn := tls.Client(raw, tlsCfg)
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, fmt.Errorf("cbpcoord: TLS handshake: %w", err)
	}
	deadline := time.Now().Add(cfg.Timeout)
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	env, err := cbp.ReadControlFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("cbpcoord: read HELLO: %w", err)
	}
	if env.Type != typeHello {
		return nil, fmt.Errorf("cbpcoord: expected HELLO, got %s", env.Type)
	}
	var helloMsg hello
	if err := cbp.UnmarshalPayload(env.Payload, &helloMsg); err != nil {
		return nil, err
	}
	if helloMsg.Protocol != ALPNCoord {
		return nil, fmt.Errorf("cbpcoord: unexpected protocol %q", helloMsg.Protocol)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(helloMsg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("cbpcoord: bad nonce: %w", err)
	}
	publicKey := cfg.privateKey.Public().(ed25519.PublicKey)
	auth := clientAuth{
		ClientID:  cfg.ClientID,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(cfg.privateKey, nonce)),
	}
	payload, err := cbp.MarshalPayload(auth)
	if err != nil {
		return nil, err
	}
	if err := cbp.WriteControlFrame(conn, cbp.Envelope{Type: typeClientAuth, Payload: payload}); err != nil {
		return nil, fmt.Errorf("cbpcoord: send CLIENT_AUTH: %w", err)
	}

	env, err = cbp.ReadControlFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("cbpcoord: read CLIENT_READY: %w", err)
	}
	if env.Type == typeError {
		var em errorMessage
		_ = cbp.UnmarshalPayload(env.Payload, &em)
		return nil, fmt.Errorf("cbpcoord: auth failed: %s: %s", em.Code, em.Message)
	}
	if env.Type != typeClientReady {
		return nil, fmt.Errorf("cbpcoord: expected CLIENT_READY, got %s", env.Type)
	}
	var ready clientReady
	if err := cbp.UnmarshalPayload(env.Payload, &ready); err != nil {
		return nil, err
	}
	if ready.ClientID != "" && ready.ClientID != cfg.ClientID {
		return nil, fmt.Errorf("cbpcoord: server authenticated client %q, want %q", ready.ClientID, cfg.ClientID)
	}

	env, err = cbp.ReadControlFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("cbpcoord: read NODE_LIST: %w", err)
	}
	if env.Type != typeNodeList {
		if env.Type == typeError {
			var em errorMessage
			_ = cbp.UnmarshalPayload(env.Payload, &em)
			return nil, fmt.Errorf("cbpcoord: node list failed: %s: %s", em.Code, em.Message)
		}
		return nil, fmt.Errorf("cbpcoord: expected NODE_LIST, got %s", env.Type)
	}
	var list nodeList
	if err := cbp.UnmarshalPayload(env.Payload, &list); err != nil {
		return nil, err
	}
	if len(list.Nodes) == 0 {
		return nil, errors.New("cbpcoord: NODE_LIST is empty")
	}
	return list.Nodes, nil
}

// loadIdentity is split out so tests can supply a private key without a file.
func (cfg *Config) loadIdentity(ctx context.Context) error {
	if len(cfg.privateKey) != 0 {
		return nil
	}
	if strings.TrimSpace(cfg.IdentityFile) == "" {
		return errors.New("cbpcoord: identity_file is required")
	}
	identity, err := cbpidentity.LoadOrIssueClient(ctx, cbpidentity.ClientIdentityConfig{
		FilePath:           cfg.IdentityFile,
		ServerURL:          cfg.IdentityServerURL,
		Token:              cfg.IdentityToken,
		ClientID:           cfg.ClientID,
		InsecureSkipVerify: cfg.IdentityInsecureSkipVerify,
		Regions:            cfg.Regions,
	})
	if err != nil {
		return err
	}
	seed, err := base64.RawURLEncoding.DecodeString(identity.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("cbpcoord: invalid private key in identity file")
	}
	cfg.privateKey = ed25519.NewKeyFromSeed(seed)
	if cfg.ClientID == "" {
		cfg.ClientID = identity.ClientID
	}
	return nil
}

// MarshalNodeList is a small helper used by tests and by logging a count
// without exposing node addresses one by one.
func MarshalNodeList(nodes []Node) ([]byte, error) {
	return json.Marshal(struct {
		Nodes []Node `json:"nodes"`
	}{Nodes: nodes})
}
