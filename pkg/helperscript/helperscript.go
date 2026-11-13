// Package helperscript resolves plugin helper scripts under the config
// directory and downloads a missing script from the project's raw GitHub
// mirror.
package helperscript

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultDownloadBase is the directory that holds the scripts in the
	// project repository.
	DefaultDownloadBase = "https://raw.githubusercontent.com/ersonw/mosdns-v4/refs/heads/main/etc/mosdns/scripts"
	maxScriptBytes      = 4 << 20
)

// DownloadBaseURL is a variable so tests can substitute a local server.
var DownloadBaseURL = DefaultDownloadBase

// DefaultPath returns <configDir>/scripts/<name>.
func DefaultPath(configDir, name string) string {
	return filepath.Join(configDir, "scripts", name)
}

// ConfiguredPath resolves a configured script path. An empty value means the
// default path; a relative value is relative to the config directory.
func ConfiguredPath(configDir, raw, name string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultPath(configDir, name)
	}
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	return filepath.Join(configDir, raw)
}

// Resolve returns an existing script path. If neither the configured path nor
// the default config-directory path exists, it downloads the script into
// <configDir>/scripts and reports that it did so.
func Resolve(ctx context.Context, configDir, configured, name string) (path string, downloaded bool, err error) {
	configuredPath := ConfiguredPath(configDir, configured, name)
	fallback := DefaultPath(configDir, name)
	if regularFile(configuredPath) {
		return configuredPath, false, nil
	}
	if regularFile(fallback) {
		return fallback, false, nil
	}
	url := strings.TrimRight(DownloadBaseURL, "/") + "/" + name
	if err := Download(ctx, url, fallback); err != nil {
		return "", false, fmt.Errorf("download %s: %w", name, err)
	}
	return fallback, true, nil
}

func regularFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// Download fetches url and writes it atomically to dst.
func Download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mosdns-helper-script")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxScriptBytes {
		return fmt.Errorf("script exceeds %d bytes", maxScriptBytes)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return fmt.Errorf("empty script body")
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".script-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, dst)
}
