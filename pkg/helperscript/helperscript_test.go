package helperscript

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredPath(t *testing.T) {
	dir := "/etc/mosdns"
	if got := ConfiguredPath(dir, "", "a.py"); got != "/etc/mosdns/scripts/a.py" {
		t.Fatalf("default = %q", got)
	}
	if got := ConfiguredPath(dir, "scripts/a.py", "a.py"); got != "/etc/mosdns/scripts/a.py" {
		t.Fatalf("relative = %q", got)
	}
	if got := ConfiguredPath(dir, "/tmp/a.py", "a.py"); got != "/tmp/a.py" {
		t.Fatalf("absolute = %q", got)
	}
}

func TestResolveUsesPathRelativeToConfigDir(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "helpers", "test.py")
	if err := os.MkdirAll(filepath.Dir(custom), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, downloaded, err := Resolve(context.Background(), dir, "helpers/test.py", "test.py")
	if err != nil {
		t.Fatal(err)
	}
	if downloaded {
		t.Fatal("existing relative script must not be downloaded")
	}
	if path != custom {
		t.Fatalf("path = %q, want %q", path, custom)
	}
}

func TestResolveDownloadsMissingScript(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scripts/test.py" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("print('ok')\n"))
	}))
	defer server.Close()

	oldBase := DownloadBaseURL
	DownloadBaseURL = server.URL + "/scripts"
	defer func() { DownloadBaseURL = oldBase }()

	path, downloaded, err := Resolve(context.Background(), dir, "", "test.py")
	if err != nil {
		t.Fatal(err)
	}
	if !downloaded {
		t.Fatal("missing script should be downloaded")
	}
	if path != filepath.Join(dir, "scripts", "test.py") {
		t.Fatalf("path = %q", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "print('ok')\n" {
		t.Fatalf("body = %q", body)
	}

	_, downloaded, err = Resolve(context.Background(), dir, "", "test.py")
	if err != nil {
		t.Fatal(err)
	}
	if downloaded {
		t.Fatal("existing script must not be downloaded again")
	}
}
