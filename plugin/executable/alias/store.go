package alias

// store.go owns the served name table. Unlike a data_provider it is a plain
// file owned by this plugin, so the bot can edit it without touching the rest
// of the configuration, and every edit is followed by a reload of this table.
//
// One line is one entry: "[scheme://]domain". The scheme is optional and
// decides how the gateway reaches the real site; a missing scheme means the
// plugin default, http. Only the domain is validated strictly: an entry that
// is not a legal domain name is rejected before it reaches the file.

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ersonw/mosdns-v4/pkg/matcher/domain"
)

const (
	schemeHTTP          = "http"
	schemeHTTPS         = "https"
	schemeHTTPSInsecure = "https+insecure"
	schemeAuto          = "auto"
)

type entry struct {
	Name   string // normalized domain
	Scheme string // http, https, https+insecure
}

type domainStore struct {
	path    string
	def     string     // default upstream scheme
	fileMu  sync.Mutex // serializes reload and persist
	mu      sync.RWMutex
	byName  map[string]string // domain -> scheme
	tlds    []string          // last labels seen, for replace_suffix
	entries []entry           // insertion order kept for listing
}

func loadDomainStore(path, def string) (*domainStore, error) {
	s := &domainStore{path: path, def: def}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *domainStore) reload() error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			// A missing file is an empty table, not a startup failure: the bot
			// creates it on the first add.
			s.mu.Lock()
			s.byName = map[string]string{}
			s.entries = nil
			s.tlds = nil
			s.mu.Unlock()
			return nil
		}
		return fmt.Errorf("open %s: %w", s.path, err)
	}
	defer f.Close()

	parsed := make([]entry, 0, 1024)
	byName := make(map[string]string, 1024)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if lineNo == 1 {
			raw = strings.TrimPrefix(raw, "\ufeff")
		}
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		if raw == "" {
			continue
		}
		name, scheme, err := parseEntry(raw)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", s.path, lineNo, err)
		}
		if _, dup := byName[name]; dup {
			// A duplicate in the file itself is tolerated (the first wins), but
			// it is not written back by the bot.
			continue
		}
		byName[name] = scheme
		parsed = append(parsed, entry{Name: name, Scheme: scheme})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}

	s.mu.Lock()
	s.byName = byName
	s.entries = parsed
	s.tlds = tldsOf(parsed)
	s.mu.Unlock()
	return nil
}

// parseEntry splits "[scheme://]domain" and validates both halves.
func parseEntry(raw string) (name, scheme string, err error) {
	scheme = ""
	rest := strings.TrimSpace(raw)
	if idx := strings.Index(rest, "://"); idx >= 0 {
		scheme = strings.ToLower(strings.TrimSpace(rest[:idx]))
		rest = strings.TrimSpace(rest[idx+3:])
		switch scheme {
		case schemeHTTP, schemeHTTPS, schemeHTTPSInsecure:
		case schemeAuto:
			scheme = "" // auto is a dial-time decision, not a stored scheme
		default:
			return "", "", fmt.Errorf("unsupported scheme %q", scheme)
		}
	}
	name = domain.NormalizeDomain(rest)
	if err := validateName(name); err != nil {
		return "", "", err
	}
	return name, scheme, nil
}

// validateName accepts a plain, legal domain name only: no wildcard, no
// matcher prefix, no ip address, no path.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("empty domain")
	}
	if len(name) > 253 {
		return fmt.Errorf("%q is longer than 253 characters", name)
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "*") {
		return fmt.Errorf("%q must not start with %q", name, name[:1])
	}
	for _, prefix := range []string{"domain:", "full:", "keyword:", "regexp:", "regex:", "include:", "exclude:", "provider:"} {
		if strings.HasPrefix(name, prefix) {
			return fmt.Errorf("%q is a matcher rule, not a domain", name)
		}
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%q is an ip address, not a domain", ip)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q has no tld", name)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q contains an empty or oversized label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return fmt.Errorf("label %q contains an invalid character %q", label, r)
			}
		}
	}
	return nil
}

func tldsOf(entries []entry) []string {
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if idx := strings.LastIndexByte(e.Name, '.'); idx >= 0 && idx < len(e.Name)-1 {
			seen[e.Name[idx+1:]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// matchName returns the scheme of the longest listed suffix of name. A default
// entry matches subdomains, so "www.ip138.com" is served by "ip138.com".
func (s *domainStore) matchName(name string) (string, bool) {
	name = domain.NormalizeDomain(name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidate := name
	for {
		if scheme, ok := s.byName[candidate]; ok {
			if scheme == "" {
				scheme = s.def
			}
			return scheme, true
		}
		idx := strings.IndexByte(candidate, '.')
		if idx < 0 {
			return "", false
		}
		candidate = candidate[idx+1:]
	}
}

func (s *domainStore) listEntries() []entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]entry, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *domainStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *domainStore) labelSet() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.tlds))
	copy(out, s.tlds)
	return out
}

func (s *domainStore) contains(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scheme, ok := s.byName[name]
	return scheme, ok
}

func (s *domainStore) add(raw string) (entry, bool, error) {
	name, scheme, err := parseEntry(raw)
	if err != nil {
		return entry{}, false, err
	}
	s.mu.Lock()
	if cur, dup := s.byName[name]; dup {
		// A duplicate that carries another scheme updates the entry instead of
		// being silently dropped.
		if cur == scheme {
			s.mu.Unlock()
			return entry{Name: name, Scheme: cur}, false, nil
		}
		s.byName[name] = scheme
		for i := range s.entries {
			if s.entries[i].Name == name {
				s.entries[i].Scheme = scheme
				break
			}
		}
		s.mu.Unlock()
		if err := s.persist(); err != nil {
			return entry{Name: name, Scheme: scheme}, false, err
		}
		return entry{Name: name, Scheme: scheme}, true, nil
	}
	s.byName[name] = scheme
	s.entries = append(s.entries, entry{Name: name, Scheme: scheme})
	s.tlds = tldsOf(s.entries)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return entry{Name: name, Scheme: scheme}, false, err
	}
	return entry{Name: name, Scheme: scheme}, true, nil
}

func (s *domainStore) del(raw string) (string, bool, error) {
	name, _, err := parseEntry(raw)
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	_, ok := s.byName[name]
	if !ok {
		s.mu.Unlock()
		return name, false, nil
	}
	delete(s.byName, name)
	kept := s.entries[:0]
	for _, e := range s.entries {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	s.entries = append([]entry(nil), kept...)
	s.tlds = tldsOf(s.entries)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return name, false, err
	}
	return name, true, nil
}

func (s *domainStore) mod(oldRaw, newRaw string) (entry, error) {
	oldName, _, err := parseEntry(oldRaw)
	if err != nil {
		return entry{}, err
	}
	newName, scheme, err := parseEntry(newRaw)
	if err != nil {
		return entry{}, err
	}
	if oldName == newName {
		return entry{}, fmt.Errorf("old and new domain are identical")
	}
	s.mu.Lock()
	_, ok := s.byName[oldName]
	if !ok {
		s.mu.Unlock()
		return entry{}, fmt.Errorf("%s is not in %s", oldName, s.path)
	}
	if _, exists := s.byName[newName]; exists {
		s.mu.Unlock()
		return entry{}, fmt.Errorf("%s is already served; delete it before renaming to it", newName)
	}
	delete(s.byName, oldName)
	s.byName[newName] = scheme
	replaced := false
	for i := range s.entries {
		if s.entries[i].Name == oldName {
			s.entries[i] = entry{Name: newName, Scheme: scheme}
			replaced = true
			break
		}
	}
	if !replaced {
		s.entries = append(s.entries, entry{Name: newName, Scheme: scheme})
	}
	s.tlds = tldsOf(s.entries)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return entry{}, err
	}
	return entry{Name: newName, Scheme: scheme}, nil
}

func (s *domainStore) clear() (int, error) {
	s.mu.Lock()
	n := len(s.entries)
	s.byName = map[string]string{}
	s.entries = nil
	s.tlds = nil
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return 0, err
	}
	return n, nil
}

// persist rewrites the whole file: a temp file in the same directory then a
// rename, so a reader never sees a half written list and a failed write leaves
// the previous file untouched.
func (s *domainStore) persist() error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()

	s.mu.RLock()
	entries := make([]entry, len(s.entries))
	copy(entries, s.entries)
	s.mu.RUnlock()

	var b strings.Builder
	b.WriteString("# alias domain list: one \"[scheme://]domain\" per line, scheme defaults to ")
	b.WriteString(s.def)
	b.WriteString("\n")
	for _, e := range entries {
		if e.Scheme != "" && e.Scheme != s.def {
			b.WriteString(e.Scheme)
			b.WriteString("://")
		}
		b.WriteString(e.Name)
		b.WriteString("\n")
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".alias-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace %s: %w", s.path, err)
	}
	// Best effort: make the rename durable without failing the write that
	// already reached the file.
	if dirHandle, derr := os.Open(dir); derr == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}
