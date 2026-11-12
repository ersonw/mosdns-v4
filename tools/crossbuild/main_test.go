package main

import (
	"errors"
	"strings"
	"testing"
)

var errNoGit = errors.New("no git")

// An explicit version is used verbatim: it is what a release passes, and the
// git prefix would only make it wrong.
func TestResolveVersionPrefersTheExplicitOne(t *testing.T) {
	gitDescribe = func() (string, error) { return "v1.0.0-3-gabc123", nil }
	v, err := resolveVersion(" v4.0.1 ")
	if err != nil {
		t.Fatalf("resolveVersion: %v", err)
	}
	if v != "v4.0.1" {
		t.Fatalf("version = %q, want v4.0.1", v)
	}
}

// Without an explicit version the git answer is prefixed, so a local build still
// says which commit it came from.
func TestResolveVersionPrefixesTheGitAnswer(t *testing.T) {
	gitDescribe = func() (string, error) { return "v4.0.0-12-gabc123\n", nil }
	v, err := resolveVersion("")
	if err != nil {
		t.Fatalf("resolveVersion: %v", err)
	}
	if v != "dev/4.0-v4.0.0-12-gabc123" {
		t.Fatalf("version = %q", v)
	}
}

// A commit-only answer (no tags in the repository) is still a usable version.
func TestResolveVersionAcceptsTheCommitOnlyAnswer(t *testing.T) {
	gitDescribe = func() (string, error) { return "7d4d98a", nil }
	v, err := resolveVersion("")
	if err != nil {
		t.Fatalf("resolveVersion: %v", err)
	}
	if v != "dev/4.0-7d4d98a" {
		t.Fatalf("version = %q", v)
	}
}

// When git cannot answer, nothing is injected and main.version keeps its own
// default instead of becoming "dev/4.0-" with nothing behind it.
func TestResolveVersionWithoutGitInjectsNothing(t *testing.T) {
	gitDescribe = func() (string, error) { return "", errNoGit }
	v, err := resolveVersion("")
	if err != nil {
		t.Fatalf("resolveVersion: %v", err)
	}
	if v != "" {
		t.Fatalf("version = %q, want empty", v)
	}
	args := buildArgs("build/mosdns-linux-amd64", v)
	for _, a := range args {
		if strings.HasPrefix(a, "-ldflags") {
			t.Fatalf("args = %v, want no ldflags", args)
		}
	}
}

func TestBuildArgsCarryTheVersionInOneArgument(t *testing.T) {
	args := buildArgs("build/mosdns-linux-amd64", "dev/4.0-7d4d98a")
	want := "-ldflags=-X main.version=dev/4.0-7d4d98a"
	found := false
	for _, a := range args {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("args = %v, want %q as one argument", args, want)
	}
}

// A space would split the -X assignment and the build would fail with an error
// that does not mention the version.
func TestCheckVersionRejectsWhitespace(t *testing.T) {
	if _, err := checkVersion("dev/4.0 two"); err == nil {
		t.Fatalf("a version with a space must be rejected")
	}
}

func TestDropBlankKeepsRealArguments(t *testing.T) {
	if got := dropBlank([]string{" ", "linux/amd64", "\t"}); len(got) != 1 || got[0] != "linux/amd64" {
		t.Fatalf("dropBlank = %v", got)
	}
}
