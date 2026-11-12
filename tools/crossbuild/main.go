// Command crossbuild builds the whole module for every platform the release
// script targets, from a single machine, without cgo.
//
// It exists so the cross builds can be started from the IDE like any other run
// configuration. Targets that the sqlite driver cannot support are listed but
// reported as unsupported: modernc.org/libc has no mips / mips64 backend, so
// those fail on every host, not only on this one.
//
// The version the binary reports is injected through -ldflags. Passing it
// explicitly is optional: without -version the tool asks git for
// `describe --tags --long --always` and prefixes the answer with "dev/4.0-",
// which is how a local build still says which commit it came from. When git
// cannot answer either (no repository, no tags and no history), nothing is
// injected and main.version keeps its own "dev/4.0" default.
//
// Usage:
//
//	go run ./tools/crossbuild                      # every target, version from git
//	go run ./tools/crossbuild -version v4.0.1      # a fixed version
//	go run ./tools/crossbuild linux/amd64 ...      # only the named targets
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type target struct {
	name   string
	goos   string
	goarch string
	goarm  string
}

var targets = []target{
	{name: "darwin-arm64", goos: "darwin", goarch: "arm64"},
	{name: "darwin-amd64", goos: "darwin", goarch: "amd64"},
	{name: "linux-amd64", goos: "linux", goarch: "amd64"},
	{name: "linux-arm64", goos: "linux", goarch: "arm64"},
	{name: "linux-armv6", goos: "linux", goarch: "arm", goarm: "6"},
	{name: "linux-armv7", goos: "linux", goarch: "arm", goarm: "7"},
	{name: "linux-386", goos: "linux", goarch: "386"},
	{name: "linux-ppc64le", goos: "linux", goarch: "ppc64le"},
	{name: "freebsd-amd64", goos: "freebsd", goarch: "amd64"},
	{name: "windows-amd64", goos: "windows", goarch: "amd64"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\ncross build failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("crossbuild", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	explicit := fs.String("version", "", "version to inject into main.version; "+
		"default: \"dev/4.0-\" + git describe --tags --long --always")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	version, err := resolveVersion(*explicit)
	if err != nil {
		return err
	}
	// The IDE run configuration passes a single blank argument. It is a
	// positional one, so it survives parsing and is dropped here; a blank that
	// follows -version is the flag's value and must not be touched.
	selected, err := selectTargets(dropBlank(fs.Args()))
	if err != nil {
		return err
	}

	out := "build"
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if abs, err := filepath.Abs(out); err == nil {
		out = abs
	}

	goBin, _ := exec.LookPath("go")
	versionLine := "(none, main.version keeps its default)"
	if version != "" {
		versionLine = version
	}
	fmt.Printf("host: %s/%s\ngo: %s\nversion: %s\noutput: %s\n\n",
		runtime.GOOS, runtime.GOARCH, goBin, versionLine, out)

	var failed []string
	startAll := time.Now()
	for _, t := range selected {
		bin := filepath.Join(out, "mosdns-"+t.name)
		if t.goos == "windows" {
			bin += ".exe"
		}
		fmt.Printf("%-16s %s/%s%s ... ", t.name, t.goos, t.goarch, goarmLabel(t.goarm))

		start := time.Now()
		err := build(t, bin, version)
		if err != nil {
			fmt.Printf("FAIL\n    %v\n", indent(err.Error()))
			failed = append(failed, t.name)
			continue
		}
		var size string
		if st, statErr := os.Stat(bin); statErr == nil {
			size = humanSize(st.Size())
		}
		fmt.Printf("OK (%s, %s)\n", time.Since(start).Round(time.Second), size)
	}

	fmt.Printf("\ntotal %s\n", time.Since(startAll).Round(time.Second))
	if len(failed) > 0 {
		return fmt.Errorf("%d target(s) failed: %s", len(failed), strings.Join(failed, ", "))
	}
	fmt.Println("all targets built")
	return nil
}

func build(t target, bin, version string) error {
	cmd := exec.Command("go", buildArgs(bin, version)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+t.goos,
		"GOARCH="+t.goarch,
		"GOARM="+t.goarm,
	)
	if err := cmd.Run(); err != nil {
		_ = os.Remove(bin)
		return err
	}
	return nil
}

// buildArgs is the go command line for one target. The version travels through
// ldflags as a single argument: passing -ldflags=... keeps the go tool from
// re-splitting it, and an empty version adds no flag at all, so main.version
// stays at its default.
func buildArgs(bin, version string) []string {
	args := []string{"build", "-trimpath"}
	if version != "" {
		args = append(args, "-ldflags=-X main.version="+version)
	}
	return append(args, "-o", bin, ".")
}

// versionPrefix marks a version that came from git rather than from a release.
const versionPrefix = "dev/4.0-"

// gitDescribe answers with the nearest tag, the distance to it, and the short
// commit; with no tags at all it answers with the commit alone. It is a variable
// so a test can replace it without a git repository.
var gitDescribe = func() (string, error) {
	out, err := exec.Command("git", "describe", "--tags", "--long", "--always").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// resolveVersion returns the version to inject, or "" when there is none. An
// explicit version wins verbatim; otherwise the git answer is prefixed, and a
// git that cannot answer leaves nothing behind rather than a half made string.
func resolveVersion(explicit string) (string, error) {
	if v := strings.TrimSpace(explicit); v != "" {
		return checkVersion(v)
	}
	v, err := gitDescribe()
	if err != nil {
		return "", nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	return checkVersion(versionPrefix + v)
}

// checkVersion rejects a value the go tool cannot pass through ldflags in one
// piece: whitespace would split the -X assignment and fail the build with an
// error that does not mention the version at all.
func checkVersion(v string) (string, error) {
	if strings.ContainsAny(v, " \t\r\n\"'") {
		return "", fmt.Errorf("version %q contains a space or a quote", v)
	}
	return v, nil
}

func dropBlank(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.TrimSpace(a) == "" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// selectTargets accepts either the short name (linux-amd64) or the platform
// form (linux/amd64), and falls back to every target.
func selectTargets(args []string) ([]target, error) {
	if len(args) == 0 {
		return targets, nil
	}
	byName := make(map[string]target, len(targets))
	for _, t := range targets {
		byName[t.name] = t
		byName[t.goos+"/"+t.goarch] = t
	}

	var out []target
	var unknown []string
	for _, arg := range args {
		t, ok := byName[arg]
		if !ok {
			unknown = append(unknown, arg)
			continue
		}
		out = append(out, t)
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(targets))
		for _, t := range targets {
			known = append(known, t.name)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("unknown target(s) %s; known: %s",
			strings.Join(unknown, ", "), strings.Join(known, ", "))
	}
	return out, nil
}

func goarmLabel(goarm string) string {
	if goarm == "" {
		return ""
	}
	return "/GOARM=" + goarm
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines, "\n    ")
}
