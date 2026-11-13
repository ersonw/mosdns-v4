package tools

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/matcher/v2data"
	"google.golang.org/protobuf/proto"
)

func writeGeoSiteTestFile(t *testing.T) string {
	t.Helper()
	list := &v2data.GeoSiteList{
		Entry: []*v2data.GeoSite{
			{
				CountryCode: "bytedance",
				Domain: []*v2data.Domain{
					{Type: v2data.Domain_Domain, Value: "tiktok.com"},
					{Type: v2data.Domain_Plain, Value: "tiktok"},
					{Type: v2data.Domain_Full, Value: "api.tiktok.com"},
					{Type: v2data.Domain_Regex, Value: `^ad\.tiktok\.com$`},
				},
			},
			{
				CountryCode: "google",
				Domain: []*v2data.Domain{
					{Type: v2data.Domain_Domain, Value: "google.com"},
				},
			},
		},
	}
	b, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestQueryDomainDAT(t *testing.T) {
	path := writeGeoSiteTestFile(t)
	var out, errOut bytes.Buffer
	if err := QueryDomainDAT(path+":bytedance", "tiktok", &out, &errOut, "", 0, false); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"bytedance\ttiktok.com",
		"bytedance\tkeyword:tiktok",
		"bytedance\tfull:api.tiktok.com",
		"bytedance\tregexp:^ad\\.tiktok\\.com$",
		"",
	}, "\n")
	if out.String() != want {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", out.String(), want)
	}
	if !strings.Contains(errOut.String(), "matched 4 entries in 1 tags") {
		t.Fatalf("unexpected summary: %q", errOut.String())
	}
}

func TestQueryDomainDATLimitAndRegex(t *testing.T) {
	path := writeGeoSiteTestFile(t)
	var out, errOut bytes.Buffer
	if err := QueryDomainDAT(path+":bytedance", `ad.*tiktok`, &out, &errOut, "", 1, true); err != nil {
		t.Fatal(err)
	}
	if out.String() != "bytedance\tregexp:^ad\\.tiktok\\.com$\n" {
		t.Fatalf("unexpected regex output: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "matched 1 entries in 1 tags") {
		t.Fatalf("unexpected summary: %q", errOut.String())
	}
}

func TestQueryDomainDATTagFilter(t *testing.T) {
	path := writeGeoSiteTestFile(t)
	var out, errOut bytes.Buffer
	if err := QueryDomainDAT(path, "tiktok", &out, &errOut, "google", 0, false); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no output, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "matched 0 entries in 0 tags") {
		t.Fatalf("unexpected summary: %q", errOut.String())
	}
}
