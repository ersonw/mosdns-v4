// Package selfupdate finds out whether a newer release exists and fetches it.
//
// It deliberately knows nothing about the local installation: it talks HTTP,
// parses the release, compares versions and verifies checksums. The caller
// decides what to do with the result, which keeps the network and the
// filesystem from being entangled in the same test.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

// maxAssetSize caps a download. A sent release binary is about 30MB; anything
// past this is not one, and refusing early avoids filling a router's /tmp.
const maxAssetSize = 200 << 20

// Release is the subset of the GitHub release payload this package needs.
type Release struct {
	TagName    string  `json:"tag_name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// LatestRelease asks GitHub for the newest published release of repo.
func LatestRelease(ctx context.Context, client *http.Client, repo string) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mosdns-selfupdate")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach GitHub, %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %s for %s", resp.Status, repo)
	}

	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("cannot parse the release payload, %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release payload has no tag name")
	}
	return &rel, nil
}

// AssetFor returns the asset name of this build target. The suffix after "mosdns-"
// is the GOOS/GOARCH pair the cross build used, so the updater follows the
// platform it is running on instead of installing a binary for another one.
func AssetFor(goos, goarch string) string {
	name := "mosdns-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// CurrentAsset is AssetFor for the running binary.
func CurrentAsset() string {
	return AssetFor(runtime.GOOS, runtime.GOARCH)
}

// AssetURL builds the stable download address of one asset. The repository
// publishes under a fixed asset name, so this needs no per-release bookkeeping.
func AssetURL(repo, tag, asset string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, asset)
}

// Download writes the asset to dst and returns its sha256, hex encoded.
func Download(ctx context.Context, client *http.Client, url string, dst io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mosdns-selfupdate")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot download %s, %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %s", resp.Status)
	}

	h := sha256.New()
	body := io.LimitReader(resp.Body, maxAssetSize+1)
	n, err := io.Copy(io.MultiWriter(dst, h), body)
	if err != nil {
		return "", fmt.Errorf("cannot write the download, %w", err)
	}
	if n > maxAssetSize {
		return "", fmt.Errorf("asset is larger than %d bytes, refusing it", maxAssetSize)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ChecksumFor reads a "sha256  name" file, the format sha256sum writes, and
// returns the hash recorded for name.
func ChecksumFor(sums []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// sha256sum prefixes a binary-mode marker, and some tools add "./".
		entry := strings.TrimPrefix(fields[1], "./")
		entry = strings.TrimPrefix(entry, "*")
		if entry == name {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

// Newer reports whether candidate is a newer release than current. A dev build
// carries the tag it was built from, so the tag itself is the floor: a release
// that matches the floor is not newer, because the dev binary already contains
// everything the tag has.
func Newer(current, candidate string) bool {
	return compareVersions(candidate, current) > 0
}

func compareVersions(a, b string) int {
	av, ok := semver(a)
	if !ok {
		return 0
	}
	bv, ok := semver(b)
	if !ok {
		return 0
	}
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// semver parses "v4.0.4" and the dev form "dev/v4.0.4-5-g8650ac5".
func semver(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "dev/")
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n := 0
		if p == "" {
			return v, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return v, false
			}
			n = n*10 + int(c-'0')
		}
		v[i] = n
	}
	return v, true
}

// Client returns the HTTP client the updater uses: bounded timeouts, because a
// stuck download on a router's uplink must not wedge the loop forever.
func Client(proxy string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 20 * time.Second
	transport.TLSHandshakeTimeout = 15 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil && u.Scheme != "" {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Minute}
}
