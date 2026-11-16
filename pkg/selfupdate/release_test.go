package selfupdate

import "testing"

// The asset name is the build target, so a linux/amd64 router must ask for the
// linux/amd64 binary whatever the release is called.
func TestAssetFor(t *testing.T) {
	cases := []struct{ goos, goarch, want string }{
		{"linux", "amd64", "mosdns-linux-amd64"},
		{"linux", "arm64", "mosdns-linux-arm64"},
		{"darwin", "arm64", "mosdns-darwin-arm64"},
		{"windows", "amd64", "mosdns-windows-amd64.exe"},
	}
	for _, c := range cases {
		if got := AssetFor(c.goos, c.goarch); got != c.want {
			t.Errorf("AssetFor(%s,%s) = %q, want %q", c.goos, c.goarch, got, c.want)
		}
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		current, candidate string
		want               bool
	}{
		{"v4.0.4", "v4.0.5", true},
		{"dev/v4.0.4-5-g8650ac5", "v4.0.5", true},
		{"v4.0.4", "v4.0.4", false},
		{"dev/v4.0.4-5-g8650ac5", "v4.0.4", false},
		{"v4.0.5", "v4.0.4", false},
		{"dev", "v4.0.4", false},
	}
	for _, c := range cases {
		if got := Newer(c.current, c.candidate); got != c.want {
			t.Errorf("Newer(%q,%q) = %v, want %v", c.current, c.candidate, got, c.want)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	sums := []byte("abc123  mosdns-linux-amd64\ndef456  *mosdns-darwin-arm64\n")
	if got, ok := ChecksumFor(sums, "mosdns-linux-amd64"); !ok || got != "abc123" {
		t.Fatalf("got %q %v", got, ok)
	}
	// sha256sum marks binary mode with a star.
	if got, ok := ChecksumFor(sums, "mosdns-darwin-arm64"); !ok || got != "def456" {
		t.Fatalf("binary-mode line not parsed: %q %v", got, ok)
	}
	if _, ok := ChecksumFor(sums, "mosdns-linux-arm64"); ok {
		t.Fatal("reported a checksum for an asset that is not listed")
	}
}
