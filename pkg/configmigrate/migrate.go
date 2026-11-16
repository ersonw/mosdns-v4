// Package configmigrate rewrites a configuration written for an older release
// so that a newer binary accepts it.
//
// A release changes the YAML schema sometimes: a key is renamed, a value moves
// into a nested block, a section is split into two plugins. Without a rewrite
// the new binary refuses to start with "unused key" - which the updater would
// discover only after replacing the running binary. Migrations are therefore
// applied to a copy before the swap, and the result is checked by the very
// binary that is about to be installed.
//
// Migrations are ordered by the version they produce, and each one declares the
// version range it applies to, so a chain from any older release reaches any
// newer one without needing a migration for every pair.
package configmigrate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Migration is one schema change. Apply receives the parsed document and edits
// it in place; returning an error aborts the whole chain and leaves the file
// untouched.
type Migration struct {
	// From is the first version the migration applies to (inclusive).
	From string
	// To is the version the migration produces. A version below To is still
	// migrated when it is at or above From.
	To string
	// Describe is logged, so an operator can see which rewrites ran.
	Describe string
	Apply    func(root *yaml.Node) error
}

var registry []Migration

// Register adds a migration to the built-in chain. It is meant to be called
// from an init function next to the code that introduced the schema change.
func Register(m Migration) {
	registry = append(registry, m)
}

// Migrate rewrites data from version from to version to. It returns the new
// document and the descriptions of the migrations that ran. When from is
// already at or above to, the input is returned unchanged.
func Migrate(data []byte, from, to string) ([]byte, []string, error) {
	if len(data) == 0 {
		return data, nil, nil
	}
	if _, ok := parseVersion(from); !ok {
		return nil, nil, fmt.Errorf("cannot migrate config: %q is not a release version", from)
	}
	if _, ok := parseVersion(to); !ok {
		return nil, nil, fmt.Errorf("cannot migrate config: %q is not a release version", to)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("cannot parse config for migration, %w", err)
	}
	if root.Kind == 0 {
		return data, nil, nil
	}

	var applied []string
	cur, _ := parseVersion(from)
	toV, _ := parseVersion(to)
	// Walk the chain one producing version at a time instead of picking every
	// migration whose range happens to contain the starting version: a step
	// that starts at v4.0.5 only applies once an earlier step has reached it.
	for compare(cur, toV) < 0 {
		m, mv, ok := next(cur, toV)
		if !ok {
			break
		}
		if err := m.Apply(&root); err != nil {
			return nil, nil, fmt.Errorf("migration %q failed, %w", m.Describe, err)
		}
		applied = append(applied, m.Describe)
		cur = mv
	}
	if len(applied) == 0 {
		return data, nil, nil
	}

	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, nil, fmt.Errorf("cannot encode migrated config, %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, nil, fmt.Errorf("cannot finish migrated config, %w", err)
	}
	return []byte(buf.String()), applied, nil
}

// next returns the migration that moves a config at cur forward, preferring the
// smallest step so a chain with both fine and coarse migrations stays cheap.
func next(cur, to version) (Migration, version, bool) {
	var (
		best   Migration
		bestTo version
		found  bool
	)
	for _, m := range registry {
		fv, ok1 := parseVersion(m.From)
		mv, ok2 := parseVersion(m.To)
		if !ok1 || !ok2 {
			continue
		}
		if compare(cur, fv) < 0 || compare(cur, mv) >= 0 || compare(mv, to) > 0 {
			continue
		}
		if !found || compare(mv, bestTo) < 0 {
			best, bestTo, found = m, mv, true
		}
	}
	return best, bestTo, found
}

// chain returns the migrations needed to go from "from" to "to", oldest
// producing version first.
func chain(from, to string) []Migration {
	fromV, _ := parseVersion(from)
	toV, _ := parseVersion(to)

	var needed []Migration
	for _, m := range registry {
		mv, ok := parseVersion(m.To)
		if !ok {
			continue
		}
		if compare(mv, toV) > 0 {
			continue
		}
		fv, ok := parseVersion(m.From)
		if !ok {
			continue
		}
		// Applies when the config is older than what the migration produces.
		if compare(fromV, mv) < 0 && compare(fromV, fv) >= 0 {
			needed = append(needed, m)
		}
	}
	sort.SliceStable(needed, func(i, j int) bool {
		a, _ := parseVersion(needed[i].To)
		b, _ := parseVersion(needed[j].To)
		return compare(a, b) < 0
	})
	return needed
}

type version [3]int

func compare(a, b version) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// parseVersion accepts "v4.0.4" and the dev form "dev/v4.0.4-5-g8650ac5". The
// dev suffix describes local commits on top of a tag, which is why a dev build
// is never considered older than the tag it was built from.
func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "dev/")
	s = strings.TrimPrefix(s, "v")
	// Drop the "-5-g8650ac5" part: those are commits ahead of the tag.
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return version{}, false
	}
	var v version
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 {
			return version{}, false
		}
		v[i] = n
	}
	return v, true
}

// Versions exposes version comparison to callers that must decide whether an
// update is worth downloading, without duplicating the parsing rules.
func Versions(current, candidate string) (older bool) {
	c, ok1 := parseVersion(current)
	n, ok2 := parseVersion(candidate)
	if !ok1 || !ok2 {
		return false
	}
	return compare(n, c) > 0
}
