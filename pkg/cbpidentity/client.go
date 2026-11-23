package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ClientIdentity is a client-side Ed25519 identity issued by the main node.
type ClientIdentity struct {
	ClientID   string   `json:"client_id"`
	PublicKey  string   `json:"public_key"`
	PrivateKey string   `json:"private_key"`
	Regions    []string `json:"regions,omitempty"`
}

// ClientIdentityConfig describes where a client stores its identity and how to
// request one when no local key exists.
type ClientIdentityConfig struct {
	FilePath  string
	ServerURL string
	Token     string
	ClientID  string
	Regions   []string
	HTTP      *http.Client
	Timeout   time.Duration

	// InsecureSkipVerify applies only when HTTP is nil and the client builds
	// its own transport. It exists for a main server with a private CA that
	// the operator explicitly chose to trust at the CBP layer.
	InsecureSkipVerify bool
}

// LoadOrIssueClient loads a persisted client identity from FilePath. It only
// calls POST /v1/identity/client when the file does not exist. A present but
// malformed file returns an error instead of silently requesting a new key.
func LoadOrIssueClient(ctx context.Context, cfg ClientIdentityConfig) (ClientIdentity, error) {
	path := strings.TrimSpace(cfg.FilePath)
	if path == "" {
		return ClientIdentity{}, errors.New("identity: client identity file path is required")
	}
	if data, err := os.ReadFile(path); err == nil {
		var identity ClientIdentity
		if err := json.Unmarshal(data, &identity); err != nil {
			return ClientIdentity{}, fmt.Errorf("identity: parse client identity %s: %w", path, err)
		}
		if err := validateClientIdentity(identity); err != nil {
			return ClientIdentity{}, fmt.Errorf("identity: client identity %s: %w", path, err)
		}
		return identity, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ClientIdentity{}, fmt.Errorf("identity: read client identity %s: %w", path, err)
	}

	reqBody, err := json.Marshal(struct {
		ClientID string   `json:"client_id"`
		Regions  []string `json:"regions,omitempty"`
	}{ClientID: strings.TrimSpace(cfg.ClientID), Regions: cfg.Regions})
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("identity: encode issue request: %w", err)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/") + "/v1/identity/client"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("identity: create issue request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	client := cfg.HTTP
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		if cfg.InsecureSkipVerify {
			client = &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		} else {
			client = &http.Client{Timeout: timeout}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("identity: issue client identity: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("identity: read issue response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ClientIdentity{}, fmt.Errorf("identity: issue client identity: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var identity ClientIdentity
	if err := json.Unmarshal(body, &identity); err != nil {
		return ClientIdentity{}, fmt.Errorf("identity: parse issue response: %w", err)
	}
	if err := validateClientIdentity(identity); err != nil {
		return ClientIdentity{}, fmt.Errorf("identity: server returned invalid client identity: %w", err)
	}
	if err := SaveClientIdentity(path, identity); err != nil {
		return ClientIdentity{}, err
	}
	return identity, nil
}

// SaveClientIdentity atomically writes the identity with 0600 permissions.
func SaveClientIdentity(path string, identity ClientIdentity) error {
	if err := validateClientIdentity(identity); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: encode client identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("identity: create client identity directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return fmt.Errorf("identity: write client identity: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("identity: replace client identity: %w", err)
	}
	return nil
}

func validateClientIdentity(identity ClientIdentity) error {
	if strings.TrimSpace(identity.ClientID) == "" {
		return errors.New("client_id is required")
	}
	public, err := base64.RawURLEncoding.DecodeString(identity.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("invalid public_key")
	}
	seed, err := base64.RawURLEncoding.DecodeString(identity.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("invalid private_key")
	}
	derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !equal(derived, public) {
		return errors.New("public_key and private_key do not match")
	}
	return nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
