// Command crossbuild builds the whole module for every platform the release
// script targets, from a single machine, without cgo.
//
// It exists so the cross builds can be started from the IDE like any other run
// configuration. Targets that the sqlite driver cannot support are listed but
// reported as unsupported: modernc.org/libc has no mips / mips64 backend, so
// those fail on every host, not only on this one.
//
// Usage:
//
//	go run ./tools/crossbuild                 # every target
//	go run ./tools/crossbuild linux/amd64 ... # only the named targets
package main

import (
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
	selected, err := selectTargets(os.Args[1:])
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
	fmt.Printf("host: %s/%s\ngo: %s\noutput: %s\n\n", runtime.GOOS, runtime.GOARCH, goBin, out)

	var failed []string
	startAll := time.Now()
	for _, t := range selected {
		bin := filepath.Join(out, "mosdns-"+t.name)
		if t.goos == "windows" {
			bin += ".exe"
		}
		fmt.Printf("%-16s %s/%s%s ... ", t.name, t.goos, t.goarch, goarmLabel(t.goarm))

		start := time.Now()
		err := build(t, bin)
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

func build(t target, bin string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
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
