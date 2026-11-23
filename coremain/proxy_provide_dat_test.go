package coremain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestParseProxyProvideDatCBPFields(t *testing.T) {
	raw := proxyProvideTestDat()
	got, err := parseProxyProvideDat(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.IdentityServerURL != "https://api.example.com" {
		t.Fatalf("identity server = %q", got.IdentityServerURL)
	}
	if got.SecondaryIdentityServerURL != "https://backup.example.com" {
		t.Fatalf("secondary = %q", got.SecondaryIdentityServerURL)
	}
	if got.IdentityToken != "identity-token" || got.Token != "node-token" {
		t.Fatal("tokens were not decoded")
	}
	if got.IdentityFile != "/tmp/identity.json" {
		t.Fatalf("identity file = %q", got.IdentityFile)
	}
	if !got.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify was not decoded")
	}
}

func TestPrepareProxyProvideFromPortableDat(t *testing.T) {
	plain := proxyProvideTestDat()
	sealed, err := proxyProvideTestSeal(plain)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cbp.dat")
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{configDir: dir, ProxyProvides: []ProxyProvideConfig{{
		Tag:       "cbp_sg",
		ConfigDat: path,
	}}}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Domain != "https://api.example.com" {
		t.Fatalf("domain = %q", got.Domain)
	}
	if got.Token != "identity-token" || got.NodeToken != "node-token" {
		t.Fatal("dat tokens were not applied")
	}
	if got.IdentityFile != "/tmp/identity.json" {
		t.Fatalf("identity file = %q", got.IdentityFile)
	}
	if got.Insecure == nil || !*got.Insecure {
		t.Fatal("dat insecure_skip_verify was not applied")
	}
}

func TestPrepareProxyProvideYAMLOverridesDat(t *testing.T) {
	plain := proxyProvideTestDat()
	sealed, err := proxyProvideTestSeal(plain)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cbp.dat")
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{configDir: dir, ProxyProvides: []ProxyProvideConfig{{
		Tag:       "cbp_sg",
		ConfigDat: path,
		Domain:    "https://explicit.example.com",
		Token:     "explicit-control",
	}}}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Domain != "https://explicit.example.com" || got.Token != "explicit-control" {
		t.Fatalf("explicit values not preserved: %q %q", got.Domain, got.Token)
	}
	if got.NodeToken != "node-token" {
		t.Fatalf("node token = %q", got.NodeToken)
	}
}

func TestPrepareProxyProvideFromRuntimeDat(t *testing.T) {
	plain := proxyProvideTestDat()
	master := bytes.Repeat([]byte{7}, 32)
	sealed, err := proxyProvideTestSealMagic(plain, proxyProvideDatRuntime, deriveProxyProvideConfigKey(master))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cbp.dat")
	keyPath := filepath.Join(dir, "db.key")
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.RawStdEncoding.EncodeToString(master)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{configDir: dir, ProxyProvides: []ProxyProvideConfig{{
		Tag:           "cbp_sg",
		ConfigDat:     path,
		ConfigKeyFile: keyPath,
	}}}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.Domain != "https://api.example.com" || got.Token != "identity-token" {
		t.Fatalf("runtime dat values = %q %q", got.Domain, got.Token)
	}
}

func TestPrepareProxyProvideRejectsRuntimeDat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cbp.dat")
	if err := os.WriteFile(path, []byte("CBCFG2not-a-real-dat"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{configDir: dir, ProxyProvides: []ProxyProvideConfig{{
		Tag:       "cbp_sg",
		ConfigDat: path,
	}}}
	err := cfg.prepareProxyProvides()
	if err == nil || !strings.Contains(err.Error(), "CBCFG2") {
		t.Fatalf("err = %v", err)
	}
}

func proxyProvideTestDat() []byte {
	var cbp []byte
	cbp = proxyProvidePBString(cbp, 3, "node-token")
	cbp = proxyProvidePBString(cbp, 4, "/tmp/identity.json")
	cbp = proxyProvidePBString(cbp, 5, "https://api.example.com")
	cbp = proxyProvidePBString(cbp, 6, "identity-token")
	cbp = proxyProvidePBString(cbp, 15, "https://backup.example.com")
	cbp = protowire.AppendTag(cbp, 14, protowire.VarintType)
	cbp = protowire.AppendVarint(cbp, 1)

	var network []byte
	network = protowire.AppendTag(network, 4, protowire.BytesType)
	network = protowire.AppendBytes(network, cbp)

	var config []byte
	config = protowire.AppendTag(config, 6, protowire.BytesType)
	config = protowire.AppendBytes(config, network)

	var doc []byte
	doc = proxyProvidePBString(doc, 1, proxyProvideDatSchema)
	doc = protowire.AppendTag(doc, 2, protowire.BytesType)
	doc = protowire.AppendBytes(doc, config)
	return doc
}

func proxyProvideTestSeal(plain []byte) ([]byte, error) {
	return proxyProvideTestSealMagic(plain, proxyProvideDatPortable, builtinProxyProvideDatKey[:])
}

func proxyProvideTestSealMagic(plain []byte, magic string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := []byte(magic)
	version := "v1"
	if magic == proxyProvideDatRuntime {
		version = "v2"
	}
	aad := append(append([]byte(nil), header...), []byte("custombrowser/config-dat/"+version)...)
	sealed := gcm.Seal(nil, nonce, plain, aad)
	out := append(append([]byte(nil), header...), nonce...)
	return append(out, sealed...), nil
}

func TestPrepareProxyProvideDefaultDatIsGeneratedLater(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		configDir: dir,
		ProxyProvides: []ProxyProvideConfig{
			{Tag: "cbp_default", Domain: "https://api.aa2.dev"},
		},
	}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	want := filepath.Join(dir, "proxy_provides", "cbp_default.dat")
	if got.ConfigDat != want {
		t.Fatalf("config_dat = %q, want %q", got.ConfigDat, want)
	}
	if !got.GenerateDat {
		t.Fatal("GenerateDat = false, want true")
	}
	if !got.ManageDat {
		t.Fatal("ManageDat = false, want true for the default path")
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("generated dat should not exist yet: %v", err)
	}
}

func TestPrepareProxyProvideExplicitMissingDatGenerates(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		configDir: dir,
		ProxyProvides: []ProxyProvideConfig{
			{Tag: "cbp_missing", Domain: "https://api.aa2.dev", ConfigDat: "missing.dat"},
		},
	}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.ConfigDat != filepath.Join(dir, "missing.dat") {
		t.Fatalf("config_dat = %q", got.ConfigDat)
	}
	if !got.GenerateDat {
		t.Fatal("GenerateDat = false, want true")
	}
	if got.ManageDat {
		t.Fatal("ManageDat = true, want false for an explicit dat outside proxy_provides")
	}
}

func TestWriteProxyProvideDatRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy_provides", "cbp_written.dat")
	cfg := ProxyProvideConfig{
		Tag:          "cbp_written",
		Domain:       "https://api.aa2.dev",
		Token:        "identity-token",
		NodeToken:    "node-token",
		IdentityFile: "/tmp/identity.json",
	}
	nodes := []ProxyProvideDatNode{
		{ID: "edge-sg-1", Region: "sg", ControlAddr: "10.0.0.1:8443", PublicHost: "edge.example", PublicAddr: "1.2.3.4:8443", LANAddr: "192.168.1.2:8443"},
	}
	if err := WriteProxyProvideDat(path, cfg, true, nodes); err != nil {
		t.Fatal(err)
	}
	dat, err := loadProxyProvideDat(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if dat.IdentityServerURL != "https://api.aa2.dev" || dat.IdentityToken != "identity-token" || dat.Token != "node-token" || dat.IdentityFile != "/tmp/identity.json" || !dat.InsecureSkipVerify {
		t.Fatalf("round trip mismatch: %+v", dat)
	}
}

func TestGeneratedDefaultDatIsReusedWithoutDomain(t *testing.T) {
	dir := t.TempDir()
	cfg := ProxyProvideConfig{
		Tag:          "cbp_reuse",
		Domain:       "https://api.aa2.dev",
		Token:        "identity-token",
		NodeToken:    "node-token",
		IdentityFile: filepath.Join(dir, "proxy_provides", "cbp_reuse.json"),
	}
	path := filepath.Join(dir, "proxy_provides", "cbp_reuse.dat")
	if err := WriteProxyProvideDat(path, cfg, false, []ProxyProvideDatNode{{ID: "edge-sg-1", ControlAddr: "1.2.3.4:8443"}}); err != nil {
		t.Fatal(err)
	}
	root := &Config{configDir: dir, ProxyProvides: []ProxyProvideConfig{{Tag: "cbp_reuse"}}}
	if err := root.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := root.ProxyProvides[0]
	if got.Domain != "https://api.aa2.dev" || got.Token != "identity-token" || got.NodeToken != "node-token" || got.IdentityFile != cfg.IdentityFile {
		t.Fatalf("reused dat mismatch: %+v", got)
	}
	if got.GenerateDat {
		t.Fatal("GenerateDat = true, want false for existing default dat")
	}
}

func TestPrepareProxyProvideManagedExplicitDat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy_provides", "custom.dat")
	cfg := &Config{
		configDir: dir,
		ProxyProvides: []ProxyProvideConfig{
			{Tag: "cbp_managed", Domain: "https://api.aa2.dev", ConfigDat: path},
		},
	}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if !got.ManageDat || !got.GenerateDat {
		t.Fatalf("ManageDat/GenerateDat = %v/%v, want true/true", got.ManageDat, got.GenerateDat)
	}
}

func TestPrepareProxyProvideExplicitExistingDatIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desktop.dat")
	seed := ProxyProvideConfig{
		Tag:          "cbp_desktop",
		Domain:       "https://api.aa2.dev",
		Token:        "token",
		IdentityFile: filepath.Join(dir, "identity.json"),
	}
	if err := WriteProxyProvideDat(path, seed, false, nil); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		configDir:     dir,
		ProxyProvides: []ProxyProvideConfig{{Tag: "cbp_desktop", ConfigDat: path}},
	}
	if err := cfg.prepareProxyProvides(); err != nil {
		t.Fatal(err)
	}
	got := cfg.ProxyProvides[0]
	if got.ManageDat || got.GenerateDat {
		t.Fatalf("ManageDat/GenerateDat = %v/%v, want false/false", got.ManageDat, got.GenerateDat)
	}
}
