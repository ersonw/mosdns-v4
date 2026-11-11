/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package telegram_bot

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// newHTTPClient builds the HTTP client handed to the Telegram library. Only
// the transport differs per proxy scheme; the idle timeout is sized so a
// long-poll request is never cut short by the client itself.
func newHTTPClient(proxyRaw string, timeout time.Duration) (*http.Client, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return &http.Client{Timeout: timeout}, nil
	}
	u, err := url.Parse(proxyRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy %q: %w", proxyRaw, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: http.ProxyURL(u)},
		}, nil
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pass}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy %q: %w", proxyRaw, err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 proxy %q does not support context dialing", proxyRaw)
		}
		return &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{DialContext: cd.DialContext},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https or socks5)", u.Scheme)
	}
}
