package telegram_bot

import (
	"strings"
	"unicode"
)

// lang is the reply language for one Telegram message. It is selected from the
// sender's Telegram language_code, with a Han-character fallback for clients
// that do not publish one. Command names and permission identifiers stay in
// English; only explanatory text is localised.
type lang uint8

const (
	langEN lang = iota
	langZH
)

// detectLang maps a Telegram language_code to the reply language. Any non-empty
// non-Chinese code uses English, as requested. When the code is absent, the
// message itself is used so a Chinese-only client still gets Chinese replies.
func detectLang(code, text string) lang {
	code = strings.ToLower(strings.TrimSpace(code))
	if strings.HasPrefix(code, "zh") {
		return langZH
	}
	if code != "" {
		return langEN
	}
	for _, r := range text {
		if unicode.Is(unicode.Han, r) {
			return langZH
		}
	}
	return langEN
}

// replyLang returns the first explicit language, or English when a caller did
// not pass one. Keeping the parameter optional lets existing tests and internal
// calls keep their English expectations.
func replyLang(langs []lang) lang {
	if len(langs) == 0 {
		return langEN
	}
	return langs[0]
}

// t selects one of two already-formatted strings.
func (l lang) t(en, zh string) string {
	if l == langZH {
		return zh
	}
	return en
}

func (l lang) yesNo(v bool) string {
	if v {
		return l.t("on", "开")
	}
	return l.t("off", "关")
}
