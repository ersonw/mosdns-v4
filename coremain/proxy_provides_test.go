package coremain

import (
	"path/filepath"
	"testing"
)

func TestPrepareProxyProvidesDefaultsAndValidation(t *testing.T) {
	cfg := &Config{
		configDir: "/etc/mosdns",
		ProxyProvides: []ProxyProvideConfig{
			{Tag: "cbp_sg", Domain: "api.example.com", Token: "  token  ", NodeToken: "  node-token  "},
		},
	}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Domain != "https://api.example.com" {
		t.Fatalf("domain = %q", got.Domain)
	}
	if got.Token != "token" {
		t.Fatalf("token = %q", got.Token)
	}
	if got.NodeToken != "node-token" {
		t.Fatalf("node_token = %q", got.NodeToken)
	}
	if got.NodeTokenValue() != "node-token" {
		t.Fatalf("node token value = %q", got.NodeTokenValue())
	}
	wantPath := filepath.Join("/etc/mosdns", "proxy_provides", "cbp_sg.json")
	if got.IdentityFile != wantPath {
		t.Fatalf("identity_file = %q, want %q", got.IdentityFile, wantPath)
	}
	if u := ProxyProvideBootstrapURL(got.Domain); u != "https://api.example.com/v1/edge/bootstrap" {
		t.Fatalf("bootstrap URL = %q", u)
	}
}

func TestPrepareProxyProvidesRejectsBadEntries(t *testing.T) {
	cases := []struct {
		name string
		cfg  ProxyProvideConfig
	}{
		{"http", ProxyProvideConfig{Tag: "cbp", Domain: "http://api.example.com"}},
		{"no-host", ProxyProvideConfig{Tag: "cbp", Domain: "https://"}},
		{"colon-tag", ProxyProvideConfig{Tag: "cbp:sg", Domain: "https://api.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{ProxyProvides: []ProxyProvideConfig{tc.cfg}}
			if err := cfg.prepareProxyProvides(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPrepareProxyProvidesRejectsDuplicateTag(t *testing.T) {
	cfg := &Config{ProxyProvides: []ProxyProvideConfig{
		{Tag: "cbp", Domain: "https://a.example.com"},
		{Tag: "cbp", Domain: "https://b.example.com"},
	}}
	if err := cfg.prepareProxyProvides(); err == nil {
		t.Fatal("expected duplicate tag error")
	}
}

func TestProxyProvideBootstrapURLKeepsExistingPath(t *testing.T) {
	got := ProxyProvideBootstrapURL("https://api.example.com/v1/edge/bootstrap")
	if got != "https://api.example.com/v1/edge/bootstrap" {
		t.Fatalf("URL = %q", got)
	}
}

func TestProxyProvideIdentityURLStripsBootstrapPath(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com":                    "https://api.example.com",
		"https://api.example.com/":                   "https://api.example.com",
		"https://api.example.com/v1/edge/bootstrap":  "https://api.example.com",
		"https://api.example.com/v1/edge/bootstrap/": "https://api.example.com",
	}
	for in, want := range cases {
		if got := ProxyProvideIdentityURL(in); got != want {
			t.Fatalf("ProxyProvideIdentityURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNodeTokenFallsBackToToken(t *testing.T) {
	cfg := ProxyProvideConfig{Token: "shared-token"}
	if got := cfg.NodeTokenValue(); got != "shared-token" {
		t.Fatalf("node token value = %q", got)
	}
}

func TestBuiltinProxyProvideAuthApplied(t *testing.T) {
	cfg := &Config{configDir: t.TempDir(), ProxyProvides: []ProxyProvideConfig{
		{Tag: "cbp_sg", Domain: "api.aa2.dev"},
	}}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Token == "" || got.Token != builtinProxyProvideControlToken {
		t.Fatal("built-in control token was not applied")
	}
	if got.NodeToken == "" || got.NodeToken != builtinProxyProvideNodeToken {
		t.Fatal("built-in node token was not applied")
	}
}

func TestBuiltinProxyProvideAuthKeepsExplicitTokens(t *testing.T) {
	cfg := &Config{configDir: t.TempDir(), ProxyProvides: []ProxyProvideConfig{
		{Tag: "cbp_sg", Domain: "https://api.aa2.dev/v1/edge/bootstrap", Token: "custom-control", NodeToken: "custom-node"},
	}}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Token != "custom-control" || got.NodeToken != "custom-node" {
		t.Fatalf("explicit tokens overwritten: %q %q", got.Token, got.NodeToken)
	}
}

func TestUnknownHostKeepsEmptyTokenMeaning(t *testing.T) {
	cfg := &Config{configDir: t.TempDir(), ProxyProvides: []ProxyProvideConfig{
		{Tag: "cbp_sg", Domain: "https://api.example.com"},
	}}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Token != "" || got.NodeToken != "" {
		t.Fatalf("unknown host received built-in token: %q %q", got.Token, got.NodeToken)
	}
}
