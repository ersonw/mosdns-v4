package telegram_bot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aliasadmin "github.com/ersonw/mosdns-v4/pkg/alias_admin"
)

func writeAliasTestConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := filepath.Join(dir, "config.yaml")
	body := `log:
  level: info
plugins:
  - tag: cache
    type: cache
    args:
      size: 1024
  - tag: alias_local
    type: alias
    args:
      domain_file: ` + filepath.Join(dir, "alias.txt") + `
      suffix: local
      ipv4_range: 192.16.0.0/16
`
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPluginIndexByTag(t *testing.T) {
	dir := t.TempDir()
	cfg := writeAliasTestConfig(t, dir)
	doc, err := loadConfigDocument(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if idx := pluginIndexByTag(doc, "alias_local"); idx != 1 {
		t.Fatalf("alias_local index = %d, want 1", idx)
	}
	if idx := pluginIndexByTag(doc, "cache"); idx != 0 {
		t.Fatalf("cache index = %d, want 0", idx)
	}
	if idx := pluginIndexByTag(doc, "missing"); idx != -1 {
		t.Fatalf("missing index = %d, want -1", idx)
	}
}

func TestPersistAliasArgWritesConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := writeAliasTestConfig(t, dir)
	p := newStubPlugin()
	p.args.ConfigPath = cfg

	backup, err := p.persistAliasArg("alias_local", "ipv4_range", "198.19.0.0/16")
	if err != nil {
		t.Fatalf("persist range: %v", err)
	}
	if backup == "" {
		t.Fatal("no backup path returned")
	}
	doc, err := loadConfigDocument(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := nodePath(doc, []string{"plugins[1]", "args", "ipv4_range"})
	if n == nil || n.Value != "198.19.0.0/16" {
		t.Fatalf("ipv4_range node = %#v", n)
	}
	// Re-reading the written file must still parse as the same document.
	if _, err := loadConfigDocument(cfg); err != nil {
		t.Fatalf("written config is unreadable: %v", err)
	}

	if _, err := p.persistAliasArg("missing", "suffix", "loc"); err == nil {
		t.Fatal("persist for an unknown tag was accepted")
	}
}

func TestAliasRuleDomain(t *testing.T) {
	cases := map[string]string{
		"ip138.com":         "ip138.com",
		"https://ip138.com": "ip138.com",
		"HTTPS://IP138.COM": "ip138.com",
		"  http://cip.cc  ": "cip.cc",
		"6.ipchaxun.net":    "6.ipchaxun.net",
	}
	for in, want := range cases {
		if got := aliasRuleDomain(in); got != want {
			t.Fatalf("aliasRuleDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAliasCommandWithoutPlugin(t *testing.T) {
	p := newStubPlugin()
	reply, err := p.handleAlias(context.Background(), 123, nil)
	if err != nil {
		t.Fatalf("handleAlias: %v", err)
	}
	if !strings.Contains(reply, "no alias plugin") && !strings.Contains(reply, "没有加载") {
		t.Fatalf("reply = %q", reply)
	}
}

func TestAliasHostFor(t *testing.T) {
	appendSnap := aliasadmin.Snapshot{Suffix: "local"}
	if got := aliasHostFor(appendSnap, "6.ipchaxun.net"); got != "6.ipchaxun.net.local" {
		t.Fatalf("append host = %q", got)
	}
	replaceSnap := aliasadmin.Snapshot{Suffix: "loc", ReplaceSuffix: true}
	if got := aliasHostFor(replaceSnap, "6.ipchaxun.net"); got != "6.ipchaxun.loc" {
		t.Fatalf("replace host = %q", got)
	}
}

func TestAliasHostForFlatten(t *testing.T) {
	snap := aliasadmin.Snapshot{Suffix: "dyize.com", DotReplacement: "-"}
	if got := aliasHostFor(snap, "ip138.com"); got != "ip138-com.dyize.com" {
		t.Fatalf("flatten host = %q", got)
	}
}
