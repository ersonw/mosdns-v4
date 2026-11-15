package alias

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func newTestStore(t *testing.T) *domainStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.txt")
	s, err := loadDomainStore(path, schemeHTTP)
	if err != nil {
		t.Fatalf("load empty store: %v", err)
	}
	return s
}

func TestStoreAddDedupeScheme(t *testing.T) {
	s := newTestStore(t)

	_, added, err := s.add("ip138.com")
	if err != nil || !added {
		t.Fatalf("add plain domain: added=%v err=%v", added, err)
	}
	_, added, err = s.add("ip138.com")
	if err != nil || added {
		t.Fatalf("duplicate must not be added: added=%v err=%v", added, err)
	}
	_, added, err = s.add("https://cip.cc")
	if err != nil || !added {
		t.Fatalf("add https entry: added=%v err=%v", added, err)
	}
	if scheme, ok := s.matchName("cip.cc"); !ok || scheme != schemeHTTPS {
		t.Fatalf("cip.cc scheme = %q ok=%v, want https", scheme, ok)
	}
	if scheme, ok := s.matchName("ip138.com"); !ok || scheme != schemeHTTP {
		t.Fatalf("ip138.com scheme = %q ok=%v, want http default", scheme, ok)
	}

	_, removed, err := s.del("ip138.com")
	if err != nil || !removed {
		t.Fatalf("delete: removed=%v err=%v", removed, err)
	}
	_, removed, err = s.del("ip138.com")
	if err != nil || removed {
		t.Fatalf("delete missing: removed=%v err=%v", removed, err)
	}
}

func TestStoreInsecureHTTPScheme(t *testing.T) {
	s := newTestStore(t)
	if _, added, err := s.add("https+insecure://obzr.online"); err != nil || !added {
		t.Fatalf("add insecure entry: added=%v err=%v", added, err)
	}
	if scheme, ok := s.matchName("obzr.online"); !ok || scheme != schemeHTTPSInsecure {
		t.Fatalf("scheme = %q ok=%v, want %q", scheme, ok, schemeHTTPSInsecure)
	}
	if scheme, ok := s.matchName("b2b.obzr.online"); !ok || scheme != schemeHTTPSInsecure {
		t.Fatalf("subdomain scheme = %q ok=%v, want %q", scheme, ok, schemeHTTPSInsecure)
	}
}

func TestStoreValidation(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []string{
		"", "ip138", "ftp://ip138.com", "domain:ip138.com", "*.ip138.com",
		"10.0.0.1", "ip138.com/x", "ip_138.com", "-ip138.com", "ip138..com",
	} {
		if _, _, err := s.add(bad); err == nil {
			t.Fatalf("add(%q) accepted an invalid entry", bad)
		}
	}
}

func TestStoreMatchesSubdomain(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"ip138.com":       true,
		"www.ip138.com":   true,
		"a.b.ip138.com":   true,
		"notip138.com":    false,
		"ip138.com.local": false,
	} {
		if _, ok := s.matchName(name); ok != want {
			t.Fatalf("matchName(%q) = %v, want %v", name, ok, want)
		}
	}
}

func TestStorePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	s, err := loadDomainStore(path, schemeHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.add("https://ip138.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.add("cip.cc"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("file is empty after add")
	}
	reloaded, err := loadDomainStore(path, schemeHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.count() != 2 {
		t.Fatalf("reloaded count = %d, want 2", reloaded.count())
	}
	if scheme, ok := reloaded.matchName("ip138.com"); !ok || scheme != schemeHTTPS {
		t.Fatalf("reloaded scheme = %q ok=%v", scheme, ok)
	}
}

func TestAllocatorStableAndPurge(t *testing.T) {
	prefix, err := parsePrefixForTest("192.16.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Allocate("ip138.com")
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Allocate("ip138.com")
	if err != nil || again != first {
		t.Fatalf("second allocate = %v err=%v, want %v", again, err, first)
	}
	if first == a.deviceAddr() {
		t.Fatalf("allocated address equals the device address %v", first)
	}
	sub, err := a.Allocate("www.ip138.com")
	if err != nil || sub == first {
		t.Fatalf("subdomain must get its own address: %v err=%v", sub, err)
	}
	removed := a.PurgeDomain("ip138.com")
	if len(removed) != 2 {
		t.Fatalf("purge removed %d names, want 2 (%v)", len(removed), removed)
	}
	if _, ok := a.DomainOf(first); ok {
		t.Fatal("address still mapped after purge")
	}
}

func TestLookupAppendAndReplace(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	p := &plugin{suffix: ".local", replace: false, store: s, defScheme: schemeHTTP}

	if real, _, ok := p.lookup("ip138.com.local"); !ok || real != "ip138.com" {
		t.Fatalf("append lookup = %q ok=%v", real, ok)
	}
	if _, _, ok := p.lookup("www.ip138.com.local"); !ok {
		t.Fatal("append lookup must accept a subdomain")
	}
	if _, _, ok := p.lookup("other.example.local"); ok {
		t.Fatal("append lookup accepted an unlisted name")
	}
	if _, _, ok := p.lookup("ip138.com"); ok {
		t.Fatal("plain name must go through the chain, not this plugin")
	}

	p.replace = true
	if real, _, ok := p.lookup("ip138.local"); !ok || real != "ip138.com" {
		t.Fatalf("replace lookup = %q ok=%v", real, ok)
	}
	if real, _, ok := p.lookup("www.ip138.local"); !ok || real != "www.ip138.com" {
		t.Fatalf("replace subdomain lookup = %q ok=%v", real, ok)
	}
	if _, _, ok := p.lookup("ip138.com.local"); ok {
		t.Fatal("suffix form must not match in replace mode")
	}
}

func parsePrefixForTest(s string) (netip.Prefix, error) {
	return netip.ParsePrefix(s)
}

func TestStoreTolerantFileParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	body := "\ufeff# header\r\n\r\nhttps://ip138.com  # inline note\r\n  cip.cc\r\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := loadDomainStore(path, schemeHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 2 {
		t.Fatalf("count = %d, want 2", s.count())
	}
	if scheme, ok := s.matchName("ip138.com"); !ok || scheme != schemeHTTPS {
		t.Fatalf("ip138.com = %q ok=%v", scheme, ok)
	}
	if scheme, ok := s.matchName("cip.cc"); !ok || scheme != schemeHTTP {
		t.Fatalf("cip.cc = %q ok=%v", scheme, ok)
	}
}

func TestStoreDelAcceptsSchemeForm(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("https://ip138.com"); err != nil {
		t.Fatal(err)
	}
	if _, removed, err := s.del("https://ip138.com"); err != nil || !removed {
		t.Fatalf("delete by scheme form: removed=%v err=%v", removed, err)
	}
}

func TestStoreModAndClear(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.add("cip.cc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.mod("ip138.com", "https://6.ipchaxun.net"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.matchName("ip138.com"); ok {
		t.Fatal("old name still served after mod")
	}
	if scheme, ok := s.matchName("6.ipchaxun.net"); !ok || scheme != schemeHTTPS {
		t.Fatalf("mod target = %q ok=%v", scheme, ok)
	}
	// mod to an existing name would create a duplicate; the store must refuse.
	if _, err := s.mod("6.ipchaxun.net", "cip.cc"); err == nil {
		t.Fatal("mod into an existing name was accepted")
	}
	n, err := s.clear()
	if err != nil || n != 2 {
		t.Fatalf("clear = %d err=%v, want 2", n, err)
	}
}

func TestAllocPrune(t *testing.T) {
	prefix, err := netip.ParsePrefix("192.16.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	keepAddr, err := a.Allocate("keep.com")
	if err != nil {
		t.Fatal(err)
	}
	dropAddr, err := a.Allocate("drop.com")
	if err != nil {
		t.Fatal(err)
	}
	if n := a.Prune(func(name string) bool { return name == "keep.com" }); n != 1 {
		t.Fatalf("prune dropped %d, want 1", n)
	}
	if _, ok := a.DomainOf(dropAddr); ok {
		t.Fatal("dropped name still mapped")
	}
	if name, ok := a.DomainOf(keepAddr); !ok || name != "keep.com" {
		t.Fatalf("kept mapping = %q ok=%v", name, ok)
	}
}

func TestAdminAliasAddRegistersRuntimeAlias(t *testing.T) {
	s := newTestStore(t)
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, alloc: a, prefix: prefix, suffix: ".local", replace: true}
	if added, err := p.AdminAliasAdd(nil, "ipinfo.io"); err != nil || !added {
		t.Fatalf("add: added=%v err=%v", added, err)
	}
	if real, ok := p.lookupAlias("ipinfo.local"); !ok || real != "ipinfo.io" {
		t.Fatalf("alias = %q ok=%v, want ipinfo.io", real, ok)
	}
	if _, ok := a.Lookup("ipinfo.io"); !ok {
		t.Fatal("added domain has no virtual address")
	}
}

func TestAdminAliasSnapshotIncludesAliasAndAddress(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ipinfo.io"); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		BP:      coremain.NewBP("test", PluginType, zap.NewNop(), nil),
		store:   s,
		alloc:   a,
		prefix:  prefix,
		suffix:  ".local",
		replace: true,
	}
	p.rebuildAliasMappings()

	snap, err := p.AdminAliasSnapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) != 1 {
		t.Fatalf("entries = %d", len(snap.Entries))
	}
	e := snap.Entries[0]
	if e.Domain != "ipinfo.io" || e.Alias != "ipinfo.local" {
		t.Fatalf("entry = %+v", e)
	}
	if e.IPv4 == "" {
		t.Fatal("snapshot has no assigned address")
	}
	if addr, ok := a.Lookup("ipinfo.io"); !ok || addr.String() != e.IPv4 {
		t.Fatalf("snapshot address %q does not match allocator %v/%v", e.IPv4, addr, ok)
	}
	if real, ok := p.lookupAlias("ipinfo.local"); !ok || real != "ipinfo.io" {
		t.Fatalf("runtime alias = %q ok=%v", real, ok)
	}
}

func TestAdminAliasDeleteDropsRuntimeAlias(t *testing.T) {
	s := newTestStore(t)
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, alloc: a, prefix: prefix, suffix: ".local", replace: true}
	if _, err := p.AdminAliasAdd(nil, "ipinfo.io"); err != nil {
		t.Fatal(err)
	}
	if removed, err := p.AdminAliasDelete(nil, "ipinfo.io"); err != nil || !removed {
		t.Fatalf("delete: removed=%v err=%v", removed, err)
	}
	if _, ok := p.lookupAlias("ipinfo.local"); ok {
		t.Fatal("runtime alias survived deletion")
	}
	if _, ok := a.Lookup("ipinfo.io"); ok {
		t.Fatal("virtual address survived deletion")
	}
}

func TestAdminAliasReloadDropsRemovedNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("ip138.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := loadDomainStore(path, schemeHTTP)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("192.16.0.0/16")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := a.Allocate("ip138.com")
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, alloc: a, prefix: prefix, suffix: ".local"}
	p.aliasName("ip138.com")
	if err := os.WriteFile(path, []byte("cip.cc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.AdminAliasReload(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.DomainOf(addr); ok {
		t.Fatal("reload kept a mapping for a name that is no longer served")
	}
	if _, ok := p.lookupAlias("ip138.com.local"); ok {
		t.Fatal("reload kept a runtime alias for a removed name")
	}
	if real, ok := p.lookupAlias("cip.cc.local"); !ok || real != "cip.cc" {
		t.Fatalf("reloaded alias = %q ok=%v, want cip.cc", real, ok)
	}
}

func TestAdminAliasSetSuffixRebuildsRuntimeAliases(t *testing.T) {
	s := newTestStore(t)
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, alloc: a, prefix: prefix, suffix: ".local", replace: true}
	if _, err := p.AdminAliasAdd(nil, "ipinfo.io"); err != nil {
		t.Fatal(err)
	}
	if err := p.AdminAliasSetSuffix(nil, "new"); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.lookupAlias("ipinfo.local"); ok {
		t.Fatal("old suffix alias survived suffix change")
	}
	if real, ok := p.lookupAlias("ipinfo.new"); !ok || real != "ipinfo.io" {
		t.Fatalf("new suffix alias = %q ok=%v", real, ok)
	}
}

func TestRedirectToAliasSharesVirtualIP(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, alloc: a, prefix: prefix, suffix: ".local", redirect: true}

	realAlias, _, ok := p.lookup("IP138.COM.local")
	if !ok || realAlias != "ip138.com" {
		t.Fatalf("alias lookup = %q ok=%v", realAlias, ok)
	}
	realPlain, _, ok := p.lookup("ip138.com")
	if !ok || realPlain != "ip138.com" {
		t.Fatalf("real lookup = %q ok=%v", realPlain, ok)
	}
	if realAlias != realPlain {
		t.Fatalf("real names differ: %q vs %q", realAlias, realPlain)
	}

	addr1, err := a.Allocate(realAlias)
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := a.Allocate(realPlain)
	if err != nil {
		t.Fatal(err)
	}
	if addr1 != addr2 {
		t.Fatalf("alias ip %v != real ip %v", addr1, addr2)
	}

	// A listed suffix serves its subdomains too; each keeps its exact real
	// name so it gets a separate virtual address.
	realSubPlain, _, ok := p.lookup("www.ip138.com")
	if !ok || realSubPlain != "www.ip138.com" {
		t.Fatalf("wildcard real subdomain lookup = %q ok=%v", realSubPlain, ok)
	}
	if subAddr, err := a.Ensure(realSubPlain); err != nil {
		t.Fatal(err)
	} else if subAddr == addr1 {
		t.Fatalf("subdomain shares the parent virtual IP: %v", subAddr)
	}
	// The alias form of a subdomain is still served.
	if realSub, _, ok := p.lookup("www.ip138.com.local"); !ok || realSub != "www.ip138.com" {
		t.Fatalf("alias subdomain lookup = %q ok=%v", realSub, ok)
	}

	p.redirect = false
	if _, _, ok := p.lookup("ip138.com"); ok {
		t.Fatal("real name must not match when redirect_to_alias is off")
	}
}

func TestDotToHyphenAliasName(t *testing.T) {
	p := &plugin{suffix: ".local", dotRepl: "-"}
	if got := p.aliasName("ip138.com"); got != "ip138-com.local" {
		t.Fatalf("flatten append = %q", got)
	}
	p.suffix = ".dyize.com"
	if got := p.aliasName("www.ip138.com"); got != "www-ip138-com.dyize.com" {
		t.Fatalf("flatten subdomain = %q", got)
	}
	p.dotRepl = "_"
	if got := p.aliasName("ip138.com"); got != "ip138_com.dyize.com" {
		t.Fatalf("underscore replacement = %q", got)
	}
}

func TestNormalizeDotReplacement(t *testing.T) {
	for _, in := range []string{"", ".", "-", "_"} {
		if _, err := normalizeDotReplacement(in); err != nil {
			t.Fatalf("%q rejected: %v", in, err)
		}
	}
	for _, in := range []string{"..", "a.b", "a b", "a/b"} {
		if _, err := normalizeDotReplacement(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
	if got, _ := normalizeDotReplacement(""); got != "." {
		t.Fatalf("default = %q", got)
	}
}

func TestDotToHyphenLookup(t *testing.T) {
	s := newTestStore(t)
	for _, d := range []string{"ip138.com", "my-site.org"} {
		if _, _, err := s.add(d); err != nil {
			t.Fatal(err)
		}
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, alloc: a, prefix: prefix, suffix: ".local", dotRepl: "-"}

	if real, _, ok := p.lookup("ip138-com.local"); !ok || real != "ip138.com" {
		t.Fatalf("flat exact = %q ok=%v", real, ok)
	}
	if real, _, ok := p.lookup("www-ip138-com.local"); !ok || real != "www.ip138.com" {
		t.Fatalf("flat subdomain = %q ok=%v", real, ok)
	}
	if real, _, ok := p.lookup("my-site-org.local"); !ok || real != "my-site.org" {
		t.Fatalf("flat hyphenated entry = %q ok=%v", real, ok)
	}
	// Subdomain labels containing a hyphen cannot be reversed unambiguously.
	if _, _, ok := p.lookup("a-b-ip138-com.local"); ok {
		t.Fatal("ambiguous flat subdomain was served")
	}
	// The dotted form is not served in flatten mode.
	if _, _, ok := p.lookup("ip138.com.local"); ok {
		t.Fatal("dotted alias served in flatten mode")
	}

	// redirect_to_alias still serves the exact real name.
	p.redirect = true
	real, _, ok := p.lookup("ip138.com")
	if !ok || real != "ip138.com" {
		t.Fatalf("real name in flatten mode = %q ok=%v", real, ok)
	}
	if a1, err := a.Allocate(real); err != nil {
		t.Fatal(err)
	} else if a2, err := a.Allocate("ip138.com"); err != nil || a1 != a2 {
		t.Fatalf("virtual address mismatch: %v %v err=%v", a1, a2, err)
	}
}

func TestWildcardSubdomainAliasLookup(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ipinfo.io"); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		store:   s,
		alloc:   a,
		prefix:  prefix,
		suffix:  ".aa2.dev",
		replace: true,
		dotRepl: "-",
	}

	// A subdomain label may contain hyphens. Its flattened alias is not
	// reversible from the name alone, so aliasName records the exact pair.
	real := "website-cdn-assets.ipinfo.io"
	alias := p.aliasName(real)
	if alias != "website-cdn-assets-ipinfo.aa2.dev" {
		t.Fatalf("aliasName(%q) = %q", real, alias)
	}
	if _, ok := a.Lookup(real); !ok {
		t.Fatalf("rewriting %q did not preallocate a virtual address", real)
	}
	got, _, ok := p.lookup(alias)
	if !ok || got != real {
		t.Fatalf("wildcard alias lookup = %q ok=%v, want %q", got, ok, real)
	}

	parentIP, err := a.Ensure("ipinfo.io")
	if err != nil {
		t.Fatal(err)
	}
	subIP, err := a.Ensure(real)
	if err != nil {
		t.Fatal(err)
	}
	if parentIP == subIP {
		t.Fatalf("parent and wildcard subdomain share a virtual IP: %v", parentIP)
	}
	otherIP, err := a.Ensure("assets.ipinfo.io")
	if err != nil {
		t.Fatal(err)
	}
	if subIP == otherIP {
		t.Fatalf("wildcard subdomains share a virtual IP: %v", subIP)
	}
}

func TestRewriteLinkHeaderPreallocatesWildcardAlias(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ipinfo.io"); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.18.4.0/23")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		store:   s,
		alloc:   a,
		prefix:  prefix,
		suffix:  ".aa2.dev",
		replace: true,
		dotRepl: "-",
	}

	link := `<https://website-cdn-assets.ipinfo.io/_next/static/media/443896d591e4f761-s.p.woff2>; rel=preload; as="font"`
	got := p.rewriteLinkHeader(link, "ipinfo.io")
	if !strings.Contains(got, "website-cdn-assets-ipinfo.aa2.dev/_next/static/media/443896d591e4f761-s.p.woff2") {
		t.Fatalf("Link header was not rewritten: %q", got)
	}

	real := "website-cdn-assets.ipinfo.io"
	if _, ok := a.Lookup(real); !ok {
		t.Fatalf("Link rewrite did not preallocate a virtual address for %q", real)
	}
	if mapped, _, ok := p.lookup("website-cdn-assets-ipinfo.aa2.dev"); !ok || mapped != real {
		t.Fatalf("Link alias lookup = %q ok=%v, want %q", mapped, ok, real)
	}
}

func TestFlattenCollision(t *testing.T) {
	entries := []entry{{Name: "a-b.com", Scheme: schemeHTTP}, {Name: "a.b.com", Scheme: schemeHTTP}}
	if err := checkFlattenCollision(entries, "-", false); err == nil {
		t.Fatal("collision not detected")
	}
	if err := checkFlattenCollision([]entry{{Name: "a-b.com"}}, "-", false); err != nil {
		t.Fatalf("single entry rejected: %v", err)
	}
	if err := checkFlattenCollision([]entry{{Name: "my-site.org"}, {Name: "my.site.org"}}, "-", true); err == nil {
		t.Fatal("replace collision not detected")
	}
	if err := checkFlattenCollision([]entry{{Name: "my-site.org"}}, "-", true); err != nil {
		t.Fatalf("single replace entry rejected: %v", err)
	}
}

func TestReplaceThenFlattenAliasName(t *testing.T) {
	p := &plugin{suffix: ".local", replace: true, dotRepl: "-"}
	cases := map[string]string{
		"ip138.com":     "ip138.local",
		"www.ip138.com": "www-ip138.local",
		"a.b.ip138.com": "a-b-ip138.local",
	}
	for real, want := range cases {
		if got := p.aliasName(real); got != want {
			t.Fatalf("aliasName(%q) = %q, want %q", real, got, want)
		}
	}
}

func TestReplaceThenFlattenLookup(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	p := &plugin{store: s, suffix: ".local", replace: true, dotRepl: "-"}

	if real, _, ok := p.lookup("ip138.local"); !ok || real != "ip138.com" {
		t.Fatalf("replace flat exact = %q ok=%v", real, ok)
	}
	if real, _, ok := p.lookup("www-ip138.local"); !ok || real != "www.ip138.com" {
		t.Fatalf("replace flat subdomain = %q ok=%v", real, ok)
	}
	if _, _, ok := p.lookup("ip138-com.local"); ok {
		t.Fatal("append flat form served in replace mode")
	}
	if _, _, ok := p.lookup("www-ip138-com.local"); ok {
		t.Fatal("append flat subdomain served in replace mode")
	}
}
