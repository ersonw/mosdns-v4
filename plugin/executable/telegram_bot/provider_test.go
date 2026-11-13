package telegram_bot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/matcher/v2data"
	"google.golang.org/protobuf/proto"
)

func TestProviderOverviewListsConfiguredNodes(t *testing.T) {
	dir := t.TempDir()
	writeProviderTestDat(t, filepath.Join(dir, "geosite.dat"), "cn", "a.example.com")
	writeProviderTestDat(t, filepath.Join(dir, "geoip.dat"), "cn", "")
	if err := os.WriteFile(filepath.Join(dir, "cn.txt"), []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := writeProviderTestConfig(t, dir)

	p := newStubPlugin()
	p.args.ConfigPath = cfg
	reply, err := p.handleText(context.Background(), 123, "/provider")
	if err != nil {
		t.Fatalf("provider overview: %v", err)
	}
	for _, want := range []string{"geosite", "geoip", "cn_domains_text", "/provider geosite add example.com", "/provider cn_domains_text list"} {
		if !strings.Contains(reply, want) {
			t.Errorf("overview lacks %q:\n%s", want, reply)
		}
	}
}

func TestProviderChineseTextAndEnglishCommands(t *testing.T) {
	dir := t.TempDir()
	writeProviderTestDat(t, filepath.Join(dir, "geosite.dat"), "cn", "a.example.com")
	if err := os.WriteFile(filepath.Join(dir, "cn.txt"), []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := writeProviderTestConfig(t, dir)

	p := newStubPlugin()
	p.args.ConfigPath = cfg
	reply, err := p.handleText(context.Background(), 123, "/provider", langZH)
	if err != nil {
		t.Fatalf("provider overview zh: %v", err)
	}
	if !strings.Contains(reply, "域名数据源") || !strings.Contains(reply, "按页列出") {
		t.Errorf("overview should be Chinese:\n%s", reply)
	}
	if !strings.Contains(reply, "/provider cn_domains_text list <page> <page_size>") {
		t.Errorf("command examples must stay English:\n%s", reply)
	}
	if strings.Contains(reply, "增加 <域名>") || strings.Contains(reply, "增加 域名") {
		t.Errorf("command placeholders must stay English:\n%s", reply)
	}

	_, err = p.handleText(context.Background(), 123, "/provider cn_domains_text list 1", langZH)
	if err == nil || !strings.Contains(err.Error(), "页码和分页大小必须同时提供") {
		t.Fatalf("zh page error = %v", err)
	}
}

func TestProviderTextActionsAndPagination(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(file, []byte("b.example.com\na.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := writeProviderTestConfig(t, dir)

	p := newStubPlugin()
	p.args.ConfigPath = cfg
	p.args.DomainManageScript = "/fake/domain_manage.py"
	p.args.Txt2DatScript = "/fake/txt2dat.py"
	p.domainRunner = fakeDomainRunner

	reply, err := p.handleText(context.Background(), 123, "/provider cn_domains_text list 1 2")
	if err != nil || !strings.Contains(reply, "1. a.example.com") || !strings.Contains(reply, "2. b.example.com") {
		t.Fatalf("list = %q err=%v", reply, err)
	}
	if _, err := p.handleText(context.Background(), 123, "/provider cn_domains_text list 1"); err == nil {
		t.Fatal("page without page size must fail")
	}
	if _, err := p.handleText(context.Background(), 123, "/provider geosite list"); err == nil {
		t.Fatal("list on a non-.txt provider must fail")
	}

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text add c.example.com")
	if err != nil || !strings.Contains(reply, "action: add") {
		t.Fatalf("add = %q err=%v", reply, err)
	}
	assertProviderFile(t, file, "a.example.com", "b.example.com", "c.example.com")

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text mod b.example.com d.example.com")
	if err != nil || !strings.Contains(reply, "action: mod") {
		t.Fatalf("mod = %q err=%v", reply, err)
	}
	assertProviderFile(t, file, "a.example.com", "c.example.com", "d.example.com")

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text del a.example.com")
	if err != nil || !strings.Contains(reply, "action: del") {
		t.Fatalf("del = %q err=%v", reply, err)
	}
	assertProviderFile(t, file, "c.example.com", "d.example.com")

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text clear")
	if err != nil || !strings.Contains(reply, "action: clear") {
		t.Fatalf("clear = %q err=%v", reply, err)
	}
	assertProviderFile(t, file)
}

func TestProviderTextTypedRulesAndIP(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(file, []byte("cip.cc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := writeProviderTestConfig(t, dir)

	p := newStubPlugin()
	p.args.ConfigPath = cfg
	p.args.DomainManageScript = "/fake/domain_manage.py"
	p.args.Txt2DatScript = "/fake/txt2dat.py"
	p.domainRunner = fakeDomainRunner

	reply, err := p.handleText(context.Background(), 123, "/provider cn_domains_text add domain:cip.cc")
	if err != nil || (!strings.Contains(reply, "已存在") && !strings.Contains(reply, "already present")) {
		t.Fatalf("typed suffix duplicate = %q err=%v", reply, err)
	}

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text mod cip.cc domain:cip.cc")
	if err != nil || (!strings.Contains(reply, "相同") && !strings.Contains(reply, "identical")) {
		t.Fatalf("typed suffix mod = %q err=%v", reply, err)
	}

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text add domain:new.example.com")
	if err != nil || !strings.Contains(reply, "action: add") {
		t.Fatalf("typed suffix add = %q err=%v", reply, err)
	}
	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text add 10.0.0.0/8")
	if err != nil || !strings.Contains(reply, "action: add") {
		t.Fatalf("IP add = %q err=%v", reply, err)
	}
	assertProviderFile(t, file, "cip.cc", "domain:new.example.com", "10.0.0.0/8")

	reply, err = p.handleText(context.Background(), 123, "/provider cn_domains_text list 1 10")
	if err != nil || !strings.Contains(reply, "domain:new.example.com") || !strings.Contains(reply, "10.0.0.0/8") {
		t.Fatalf("typed list = %q err=%v", reply, err)
	}
}

func TestProviderV2DatTypedRules(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "geosite.dat")
	writeProviderTestDat(t, file, "cn", "a.example.com")
	cfg := writeProviderTestConfig(t, dir)

	p := newStubPlugin()
	p.args.ConfigPath = cfg
	p.args.DomainManageScript = "/fake/domain_manage.py"
	p.args.Txt2DatScript = "/fake/txt2dat.py"
	p.domainRunner = fakeDomainRunner

	for _, rule := range []string{"full:api.example.com", "keyword:tiktok", `regexp:^ads\.example\.com$`} {
		reply, err := p.handleText(context.Background(), 123, "/provider geosite add "+rule)
		if err != nil || !strings.Contains(reply, "action: add") {
			t.Fatalf("v2dat add %s = %q err=%v", rule, reply, err)
		}
	}
	assertProviderDat(t, file, "cn", "a.example.com", "full:api.example.com", "keyword:tiktok", `regexp:^ads\.example\.com$`)
}

func TestReadTextDomainsNormalizesRules(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rules.txt")
	body := "# comment\ndomain:cip.cc\nfull:api.example.com\nkeyword:TikTok\nregexp:^ads\\.example\\.com$\n10.0.0.0/8 # CIDR\nbare.example.com # suffix\n"
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTextDomains(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"domain:cip.cc", "full:api.example.com", "keyword:tiktok", `regexp:^ads\.example\.com$`, "10.0.0.0/8", "bare.example.com"} {
		if _, ok := got[ruleKey(rule)]; !ok {
			t.Fatalf("missing %s in %#v", rule, got)
		}
	}
	if len(got) != 6 {
		t.Fatalf("rules = %#v want 6 entries", got)
	}
}

func TestProviderV2DatAddModDelCategory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "geosite.dat")
	writeProviderTestDat(t, file, "cn", "a.example.com", "b.example.com")
	writeProviderTestDat(t, file, "jp", "keep.example.com")
	cfg := writeProviderTestConfig(t, dir)

	p := newStubPlugin()
	p.args.ConfigPath = cfg
	p.args.DomainManageScript = "/fake/domain_manage.py"
	p.args.Txt2DatScript = "/fake/txt2dat.py"
	p.domainRunner = fakeDomainRunner

	reply, err := p.handleText(context.Background(), 123, "/provider geosite add c.example.com")
	if err != nil || !strings.Contains(reply, "action: add") {
		t.Fatalf("v2dat add = %q err=%v", reply, err)
	}
	assertProviderDat(t, file, "cn", "a.example.com", "b.example.com", "c.example.com")
	assertProviderDat(t, file, "jp", "keep.example.com")

	reply, err = p.handleText(context.Background(), 123, "/provider geosite mod b.example.com d.example.com")
	if err != nil || !strings.Contains(reply, "category: cn") {
		t.Fatalf("v2dat mod = %q err=%v", reply, err)
	}
	assertProviderDat(t, file, "cn", "a.example.com", "c.example.com", "d.example.com")

	reply, err = p.handleText(context.Background(), 123, "/provider geosite del a.example.com")
	if err != nil || !strings.Contains(reply, "action: del") {
		t.Fatalf("v2dat del = %q err=%v", reply, err)
	}
	assertProviderDat(t, file, "cn", "c.example.com", "d.example.com")

	reply, err = p.handleText(context.Background(), 123, "/provider geosite clear")
	if err != nil || !strings.Contains(reply, "action: clear") {
		t.Fatalf("v2dat clear = %q err=%v", reply, err)
	}
	assertProviderDat(t, file, "cn")
	assertProviderDat(t, file, "jp", "keep.example.com")
}

func writeProviderTestConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := filepath.Join(dir, "config.yaml")
	body := `data_providers:
  - tag: geosite
    file: ` + filepath.Join(dir, "geosite.dat") + `
    auto_reload: true
  - tag: geoip
    file: ` + filepath.Join(dir, "geoip.dat") + `
    auto_reload: true
  - tag: cn_domains_text
    file: ` + filepath.Join(dir, "domains.txt") + `
    auto_reload: true
plugins:
  - tag: match
    type: query_matcher
    args:
      domain:
        - "provider:geosite:cn"
        - "provider:cn_domains_text"
      ip:
        - "provider:geoip:cn"
`
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeProviderTestDat(t *testing.T, path string, category string, domains ...string) {
	t.Helper()
	list := new(v2data.GeoSiteList)
	var sites []*v2data.GeoSite
	if b, err := os.ReadFile(path); err == nil {
		if err := proto.Unmarshal(b, list); err != nil {
			t.Fatal(err)
		}
		sites = list.Entry
	}
	site := &v2data.GeoSite{CountryCode: category}
	for _, d := range domains {
		if d == "" {
			continue
		}
		site.Domain = append(site.Domain, &v2data.Domain{Type: v2data.Domain_Domain, Value: d})
	}
	replaced := false
	for i, s := range sites {
		if strings.EqualFold(s.GetCountryCode(), category) {
			sites[i] = site
			replaced = true
			break
		}
	}
	if !replaced {
		sites = append(sites, site)
	}
	list.Entry = sites
	b, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertProviderFile(t *testing.T, path string, want ...string) {
	t.Helper()
	got, err := readTextDomains(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%s domains = %v want %v", path, got, want)
	}
	for _, d := range want {
		if _, ok := got[ruleKey(d)]; !ok {
			t.Fatalf("%s lacks %s: %v", path, d, got)
		}
	}
}

func assertProviderDat(t *testing.T, path, category string, want ...string) {
	t.Helper()
	got, err := readGeoSiteDomains(path, category, langEN)
	if err != nil {
		t.Fatal(err)
	}
	if !domainsEqual(got, want) {
		t.Fatalf("%s/%s = %v want %v", path, category, got, want)
	}
}

// fakeDomainRunner simulates the two script contracts: domain_manage.py edits
// a text file, txt2dat.py replaces one category in the output dat.
func fakeDomainRunner(_ context.Context, script string, args ...string) (string, error) {
	switch script {
	case "/fake/domain_manage.py":
		action := args[0]
		i := 1
		if i < len(args) && args[i] == "-a" {
			i++
		}
		if i+1 >= len(args) {
			return "", nil
		}
		file, domain := args[i], args[i+1]
		set := map[string]bool{}
		if b, err := os.ReadFile(file); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					set[line] = true
				}
			}
		}
		if action == "add" {
			set[domain] = true
		} else if action == "del" {
			delete(set, domain)
		}
		var lines []string
		for d := range set {
			lines = append(lines, d)
		}
		sortStrings(lines)
		if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return "", err
		}
		return "text " + action + " ok", nil
	case "/fake/txt2dat.py":
		if len(args) < 3 {
			return "", nil
		}
		input, output, category := args[0], args[1], args[2]
		b, err := os.ReadFile(input)
		if err != nil {
			return "", err
		}
		list := new(v2data.GeoSiteList)
		if old, err := os.ReadFile(output); err == nil {
			if err := proto.Unmarshal(old, list); err != nil {
				return "", err
			}
		}
		site := &v2data.GeoSite{CountryCode: category}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			key, text, ok := normalizeProviderRule(line)
			if !ok {
				continue
			}
			dtype := v2data.Domain_Domain
			value := text
			switch {
			case strings.HasPrefix(key, "full:"):
				dtype = v2data.Domain_Full
				value = strings.TrimPrefix(text, "full:")
			case strings.HasPrefix(key, "keyword:"):
				dtype = v2data.Domain_Plain
				value = strings.TrimPrefix(text, "keyword:")
			case strings.HasPrefix(key, "regexp:"):
				dtype = v2data.Domain_Regex
				value = strings.TrimPrefix(text, "regexp:")
			case strings.HasPrefix(key, "ip:"):
				continue
			case strings.HasPrefix(key, "domain:"):
				value = strings.TrimPrefix(text, "domain:")
			}
			site.Domain = append(site.Domain, &v2data.Domain{Type: dtype, Value: value})
		}
		replaced := false
		for i, s := range list.Entry {
			if strings.EqualFold(s.GetCountryCode(), category) {
				list.Entry[i] = site
				replaced = true
				break
			}
		}
		if !replaced {
			list.Entry = append(list.Entry, site)
		}
		b, err = proto.Marshal(list)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(output, b, 0o644); err != nil {
			return "", err
		}
		return "dat ok", nil
	}
	return "", nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
