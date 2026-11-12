package telegram_bot

import (
	"context"
	"strings"
	"testing"
)

func TestDetectLang(t *testing.T) {
	cases := []struct {
		code string
		text string
		want lang
	}{
		{"zh", "", langZH},
		{"zh-Hans", "", langZH},
		{"zh-CN", "/help", langZH},
		{"en", "", langEN},
		{"ja", "こんにちは", langEN},
		{"", "你好", langZH},
		{"", "/help", langEN},
	}
	for _, c := range cases {
		if got := detectLang(c.code, c.text); got != c.want {
			t.Fatalf("detectLang(%q,%q)=%v want %v", c.code, c.text, got, c.want)
		}
	}
}

func TestChineseRepliesKeepEnglishCommands(t *testing.T) {
	p := newStubPlugin()

	reply, err := p.handleText(context.Background(), 123, "/help", langZH)
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(reply, "fakeip 映射") || !strings.Contains(reply, "/fip") {
		t.Fatalf("Chinese help should translate descriptions and keep commands: %q", reply)
	}
	if strings.Contains(reply, "configured targets") {
		t.Fatalf("Chinese help leaked English text: %q", reply)
	}

	reply, err = p.handleText(context.Background(), 123, "/stats", langZH)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if !strings.Contains(reply, "映射：") {
		t.Fatalf("Chinese stats = %q", reply)
	}

	reply, err = p.handleText(context.Background(), 123, "/stats")
	if err != nil {
		t.Fatalf("default stats: %v", err)
	}
	if !strings.Contains(reply, "mappings:") {
		t.Fatalf("default language should stay English: %q", reply)
	}
}
