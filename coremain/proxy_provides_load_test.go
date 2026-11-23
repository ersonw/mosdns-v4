package coremain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFilePreparesProxyProvides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
proxy_provides:
  - tag: cbp_sg
    domain: api.example.com
    token: ""
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ProxyProvides) != 1 {
		t.Fatalf("entries = %d", len(cfg.ProxyProvides))
	}
	got := cfg.ProxyProvides[0]
	if got.Domain != "https://api.example.com" {
		t.Fatalf("domain = %q", got.Domain)
	}
	want := filepath.Join(dir, "proxy_provides", "cbp_sg.json")
	if got.IdentityFile != want {
		t.Fatalf("identity_file = %q, want %q", got.IdentityFile, want)
	}
}
