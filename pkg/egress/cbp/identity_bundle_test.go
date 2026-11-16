package cbp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A standalone node writes a nested bundle. It must load without an identity
// server, and its node fields must fill the session config so the operator does
// not have to repeat the token and CA path in every proxy URL.
func TestStandaloneBundleFillsSessionConfig(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var bundle ClientIdentityBundle
	bundle.Schema = "custombrowser.cbp-client/v1"
	bundle.ClientID = "external-client-1"
	bundle.Client.PrivateKey = base64.RawURLEncoding.EncodeToString(priv.Seed())
	bundle.Client.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
	bundle.Node.ID = "edge-sg-standalone"
	bundle.Node.PublicKey = "node-public-key"
	bundle.Node.ControlEndpoint = "tls://11.10.10.31:8443"
	bundle.Node.DataEndpoint = "quic://11.10.10.31:8443"
	bundle.Node.AuthToken = "standalone-token"
	bundle.Node.TLSCAFile = "/etc/mosdns/cbp-ca.crt"

	path := filepath.Join(t.TempDir(), "client-identity.json")
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	identity, meta, found, err := LoadClientIdentity(path)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	if !found {
		t.Fatal("bundle was reported as missing")
	}
	if identity.ClientID != bundle.ClientID || identity.PublicKey != bundle.Client.PublicKey {
		t.Fatalf("client half mismatch: %+v", identity)
	}
	if meta.AuthToken != bundle.Node.AuthToken || meta.TLSCAFile != bundle.Node.TLSCAFile {
		t.Fatalf("node half mismatch: %+v", meta)
	}

	cfg := Config{IdentityFile: path}
	key, _, err := resolveIdentity(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if got := key.Public().(ed25519.PublicKey); string(got) != string(pub) {
		t.Fatal("resolved key does not match the bundle")
	}
	if cfg.Token != bundle.Node.AuthToken {
		t.Fatalf("token = %q, want the bundle value", cfg.Token)
	}
	if cfg.CACertFile != bundle.Node.TLSCAFile {
		t.Fatalf("CA = %q, want the bundle value", cfg.CACertFile)
	}
	if cfg.ClientID != bundle.ClientID || cfg.DeviceID != bundle.ClientID {
		t.Fatalf("client/device identity = %q/%q, want %q", cfg.ClientID, cfg.DeviceID, bundle.ClientID)
	}
}

// A flat cache file carries no node token. It must still load, and the absence
// of a token must fail at the authentication boundary rather than being
// silently accepted with an empty credential.
func TestFlatIdentityStillNeedsAToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	identity := ClientIdentity{
		ClientID:   "flat-client",
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv.Seed()),
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	if _, _, found, err := LoadClientIdentity(path); err != nil || !found {
		t.Fatalf("flat identity = found %v, err %v", found, err)
	}
	cfg := Config{IdentityFile: path}
	if _, _, err := resolveIdentity(context.Background(), &cfg); err == nil {
		t.Fatal("flat identity without a token was accepted")
	}

	// The central flow supplies the token separately and must keep working.
	cfg.Token = "central-token"
	key, meta, err := resolveIdentity(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("resolve flat identity with token: %v", err)
	}
	if got := key.Public().(ed25519.PublicKey); string(got) != string(pub) {
		t.Fatal("flat identity key mismatch")
	}
	if meta.AuthToken != "" || cfg.DeviceID != identity.ClientID {
		t.Fatalf("flat identity metadata = %+v, device = %q", meta, cfg.DeviceID)
	}
}

// A nested bundle must not silently degrade into a flat identity with empty
// keys, and a missing bundle must still be distinguishable from a malformed
// one so the central issue path only runs when it is safe.
func TestMalformedBundleIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-identity.json")
	if err := os.WriteFile(path, []byte(`{"client":{"public_key":"x"}}`), 0600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if _, _, found, err := LoadClientIdentity(path); err == nil || !found {
		t.Fatalf("malformed bundle = found %v, err %v; want a parse error", found, err)
	}
	if _, _, found, err := LoadClientIdentity(filepath.Join(t.TempDir(), "missing.json")); err != nil || found {
		t.Fatalf("missing file = found %v, err %v; want found=false", found, err)
	}
}
