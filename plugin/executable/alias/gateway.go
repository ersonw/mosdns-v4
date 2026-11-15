package alias

// gateway.go is the HTTP face of the plugin. The client speaks plain HTTP to the
// virtual name; the gateway rewrites Host to the real domain and re-originates
// over the scheme the entry asks for (http by default, https when the entry says
// so). Terminating HTTP here is what removes the certificate problem: the client
// never opens a TLS session to the real site, the gateway does.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/base32"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	gatewayDialTimeout   = 15 * time.Second
	gatewayTLSHandshake  = 10 * time.Second
	gatewayMaxRequests   = 100              // per client connection
	gatewayHeaderTimeout = 90 * time.Second // a client that stalls after connecting
)

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// serveGateway reads requests from one terminated client connection until it
// closes. Every request is forwarded on its own upstream connection.
func (p *plugin) serveGateway(client net.Conn, domainName string) {
	br := bufio.NewReader(client)
	clientAlias := p.aliasName(domainName)

	for i := 0; i < gatewayMaxRequests; i++ {
		// A client that connects and never finishes its request must not hold
		// the terminated flow forever.
		_ = client.SetReadDeadline(time.Now().Add(gatewayHeaderTimeout))
		req, err := http.ReadRequest(br)
		_ = client.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		// The reverse mapping normally exists already; re-check it before any
		// redirect so a name reloaded while the flow was open still has its
		// virtual address.
		if p.alloc != nil {
			if _, err := p.alloc.Ensure(domainName); err != nil {
				p.log().Warn("alias: gateway mapping missing",
					zap.String("domain", domainName), zap.Error(err))
			}
		}
		// redirect_to_alias: a plain HTTP request that does not address the
		// alias host is sent to http://<alias host> with the same path and
		// query. This is what makes the real name converge on the alias name.
		if target := p.gatewayRedirectTarget(req, clientAlias); target != "" {
			writeGatewayRedirect(client, p.gatewayRedirectLocation(target, req))
			return
		}

		// A protocol upgrade (WebSocket) turns the rest of the connection
		// into a byte tunnel; nothing else can be parsed after it.
		if isUpgradeRequest(req) {
			if err := p.forwardUpgrade(client, br, req, domainName, clientAlias); err != nil {
				p.log().Debug("alias: gateway upgrade failed",
					zap.String("domain", domainName), zap.String("path", req.URL.Path), zap.Error(err))
			}
			return
		}
		keepAlive, ferr := p.forwardRequest(client, req, domainName, clientAlias)
		if ferr != nil {
			p.log().Debug("alias: gateway request failed",
				zap.String("domain", domainName), zap.String("path", req.URL.Path), zap.Error(ferr))
			return
		}
		if !keepAlive {
			return
		}
	}
}

// forwardRequest forwards one request and reports whether the client
// connection may carry another one.
func (p *plugin) forwardRequest(client net.Conn, req *http.Request, domainName, clientAlias string) (bool, error) {
	scheme, _ := p.store.matchName(domainName)
	if scheme == "" {
		scheme = p.defScheme
	}

	// The alias host is the address the client chose. If the upstream redirects
	// the real host to the same real host (typically http -> https or a path
	// canonicalisation), following it here keeps the alias host stable. Passing
	// that redirect back would rewrite Location to the alias, and the browser
	// would request the same alias URL again.
	var resp *http.Response
	var upstream net.Conn
	for attempt := 0; ; attempt++ {
		var tlsConn bool
		var err error
		upstream, tlsConn, err = p.dialUpstream(req.Context(), domainName, scheme)
		if err != nil {
			writeGatewayError(client, domainName, err)
			return false, err
		}

		// The client's Host and URI are about the alias name; the upstream only
		// accepts the real one.
		req.RequestURI = ""
		req.URL.Scheme = "http"
		if tlsConn {
			req.URL.Scheme = "https"
		}
		req.URL.Host = domainName
		req.Host = domainName
		rewriteOriginHeaders(req.Header, domainName, clientAlias, tlsConn)
		if err := p.rewriteRequest(req); err != nil {
			_ = upstream.Close()
			return false, fmt.Errorf("rewrite upstream request: %w", err)
		}
		stripHopByHop(req.Header)
		if req.Header.Get("Connection") == "" {
			req.Header.Set("Connection", "close")
		}
		// Keep the browser's compression offer but limit it to encodings the
		// gateway can decode before rewriting HTML. A bare client that did not
		// ask for compression must not be upgraded to one.
		if ae := req.Header.Get("Accept-Encoding"); ae != "" {
			if allowed := gatewayAcceptEncoding(ae); allowed != "" {
				req.Header.Set("Accept-Encoding", allowed)
			} else {
				req.Header.Del("Accept-Encoding")
			}
		}
		if p.forwarded {
			if ip, _, splitErr := net.SplitHostPort(client.RemoteAddr().String()); splitErr == nil {
				req.Header.Set("X-Forwarded-For", ip)
			}
			req.Header.Set("X-Forwarded-Host", clientAlias)
			proto := "http"
			if _, ok := client.(*tls.Conn); ok {
				proto = "https"
			}
			req.Header.Set("X-Forwarded-Proto", proto)
		}

		if err := req.Write(upstream); err != nil {
			_ = upstream.Close()
			return false, fmt.Errorf("write upstream request: %w", err)
		}

		resp, err = http.ReadResponse(bufio.NewReader(upstream), req)
		if err != nil {
			_ = upstream.Close()
			return false, fmt.Errorf("read upstream response: %w", err)
		}

		if attempt < gatewayMaxInternalRedirects {
			if location, ok := followableUpstreamRedirect(req, resp, domainName, tlsConn); ok {
				target, perr := url.Parse(location)
				if perr == nil {
					_ = resp.Body.Close()
					_ = upstream.Close()
					previousScheme := scheme
					scheme = strings.ToLower(target.Scheme)
					if scheme == "" {
						if tlsConn {
							scheme = schemeHTTPS
						} else {
							scheme = schemeHTTP
						}
					}
					if previousScheme == schemeHTTPSInsecure && scheme == schemeHTTPS {
						scheme = schemeHTTPSInsecure
					}
					req.URL.Path = target.Path
					req.URL.RawPath = target.RawPath
					req.URL.RawQuery = target.RawQuery
					continue
				}
			}
		}
		break
	}
	defer upstream.Close()
	defer resp.Body.Close()

	if err := p.rewriteResponse(resp, domainName, clientAlias); err != nil {
		return false, err
	}

	if err := resp.Write(client); err != nil {
		return false, fmt.Errorf("write client response: %w", err)
	}
	return !req.Close && !resp.Close, nil
}

// rewriteRequest restores alias URLs and hosts to the real upstream names.
// Responses are rewritten into the alias namespace; any alias name that the
// browser puts back into a request (Origin/Referer, Next.js router state, or a
// POST body) must be reversed before the request reaches the real server.
func (p *plugin) rewriteRequest(req *http.Request) error {
	if req == nil {
		return nil
	}
	for _, name := range []string{"Origin", "Referer", "Next-Router-State-Tree", "Next-Router-Prefetch", "RSC"} {
		values := req.Header.Values(name)
		if len(values) == 0 {
			continue
		}
		req.Header.Del(name)
		for _, value := range values {
			req.Header.Add(name, string(p.reverseAliasText([]byte(value))))
		}
	}
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if strings.TrimSpace(req.Header.Get("Content-Encoding")) != "" {
		// A compressed request body has to be decoded before it can be
		// reversed. The gateway does not accept request encodings it cannot
		// inspect; leave the original body for the upstream.
		return nil
	}
	if !isRewritableRequestType(req.Header.Get("Content-Type")) {
		return nil
	}
	const maxBody = 8 << 20
	if req.ContentLength > maxBody {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	_ = req.Body.Close()
	if int64(len(body)) > maxBody {
		req.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	rewritten := p.reverseAliasText(body)
	req.Body = io.NopCloser(bytes.NewReader(rewritten))
	req.ContentLength = int64(len(rewritten))
	req.TransferEncoding = nil
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	req.Header.Del("Transfer-Encoding")
	return nil
}

func isRewritableRequestType(ct string) bool {
	ct = strings.ToLower(ct)
	if strings.Contains(ct, "multipart/") {
		return false
	}
	return isRewritableBodyType(ct) || strings.Contains(ct, "application/x-www-form-urlencoded")
}

// reverseAliasText turns every alias URL and bare alias host back into the
// real upstream name. It covers escaped JSON/RSC forms and is deliberately
// host-scoped: arbitrary text is never replaced.
func (p *plugin) reverseAliasText(body []byte) []byte {
	body = sameSiteURLPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		if reversed, ok := p.reverseAliasURL(string(m)); ok {
			return []byte(reversed)
		}
		return m
	})
	return bareHostPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		host := strings.TrimSuffix(strings.ToLower(string(m)), ".")
		if real, ok := p.realFromAlias(host); ok {
			return []byte(real)
		}
		return m
	})
}

func (p *plugin) reverseAliasURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	real, ok := p.realFromAlias(host)
	if !ok {
		return raw, false
	}
	u.Host = real + u.Host[len(u.Hostname()):]
	return u.String(), true
}

func (p *plugin) realFromAlias(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	p.mu.RLock()
	suffix := strings.ToLower(p.suffix)
	p.mu.RUnlock()
	if host == "" || suffix == "" || !strings.HasSuffix(host, suffix) {
		return "", false
	}
	real, _, ok := p.lookup(host)
	return real, ok
}

// rewriteOriginHeaders rewrites the browser's Origin and Referer from the alias
// host to the real upstream host. The body of a page served through an alias
// origin sends these headers with the alias name; an upstream that validates
// CSRF or hotlink origins would reject that. Other browser headers (UA, Accept,
// Accept-Language, sec-ch-ua, Cookie, Sec-Fetch-*) pass through unchanged.
func rewriteOriginHeaders(h http.Header, domainName, clientAlias string, tlsUpstream bool) {
	if h == nil {
		return
	}
	scheme := schemeHTTP
	if tlsUpstream {
		scheme = schemeHTTPS
	}
	alias := strings.TrimSuffix(strings.ToLower(clientAlias), ".")
	for _, name := range []string{"Origin", "Referer"} {
		raw := h.Get(name)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host != alias && !strings.HasSuffix(host, "."+alias) {
			continue
		}
		u.Scheme = scheme
		u.Host = domainName + u.Host[len(u.Hostname()):]
		h.Set(name, u.String())
	}
}

// followableUpstreamRedirect reports a redirect the gateway should follow
// itself instead of handing it to the client. Only same-host HTTP(S) targets of
// a bodyless GET/HEAD are followed, so an upstream cannot steer the gateway to
// another host or make it replay a request body.
func followableUpstreamRedirect(req *http.Request, resp *http.Response, domainName string, tlsUpstream bool) (string, bool) {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return "", false
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return "", false
	}
	if req.Body != nil && req.Body != http.NoBody {
		return "", false
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", false
	}
	target, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	if target.Scheme != "" && target.Scheme != "http" && target.Scheme != "https" {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host != "" && host != strings.ToLower(domainName) {
		return "", false
	}
	scheme := strings.ToLower(target.Scheme)
	if scheme == "" {
		if tlsUpstream {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	path := target.Path
	if path == "" {
		path = "/"
	}
	if scheme == req.URL.Scheme && path == req.URL.Path && target.RawQuery == req.URL.RawQuery {
		return "", false
	}
	return location, true
}

// gatewayRedirectTarget returns the alias host when the request must be
// redirected, or "" when the request already addresses the alias host or the
// feature is off.
func (p *plugin) gatewayRedirectTarget(req *http.Request, clientAlias string) string {
	if !p.redirect {
		return ""
	}
	host := strings.TrimSpace(req.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == strings.ToLower(clientAlias) {
		return ""
	}
	// Only a real listed name redirects. An alias host is served in place, and
	// an unrelated Host is not turned into an open redirect.
	if p.store == nil {
		return ""
	}
	if _, known := p.store.matchName(host); !known {
		return ""
	}
	if p.alloc != nil {
		if _, err := p.alloc.Ensure(host); err != nil {
			p.log().Warn("alias: preallocate redirect host failed",
				zap.String("host", host), zap.Error(err))
			return ""
		}
	}
	return p.aliasName(host)
}

// gatewayRedirectLocation builds the absolute alias URL, keeping the path and
// query of the original request. With a TLS gateway the alias is reachable
// over https, so the redirect follows that scheme.
func (p *plugin) gatewayRedirectLocation(aliasHost string, req *http.Request) string {
	u := &url.URL{Scheme: p.redirectScheme(), Host: aliasHost, Path: "/"}
	if req.URL != nil {
		if req.URL.Path != "" && req.URL.Path != "*" {
			u.Path = req.URL.Path
			u.RawPath = req.URL.RawPath
		}
		u.RawQuery = req.URL.RawQuery
	}
	return u.String()
}

func writeGatewayRedirect(client net.Conn, location string) {
	body := "redirecting to " + location + "\n"
	_, _ = fmt.Fprintf(client,
		"HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n%s",
		location, len(body), body)
}

// redirectScheme is https when the gateway terminates TLS; the alias host is
// then reachable over TLS as well.
func (p *plugin) redirectScheme() string {
	if p.tlsConfig != nil {
		return "https"
	}
	return "http"
}

// isUpgradeRequest reports a protocol upgrade handshake (WebSocket and
// anything else that asks for one).
func isUpgradeRequest(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, field := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "upgrade") {
				return true
			}
		}
	}
	return false
}

// forwardUpgrade performs the upgrade handshake and then relays bytes in both
// directions until either side closes. The upstream connection is not reused.
func (p *plugin) forwardUpgrade(client net.Conn, br *bufio.Reader, req *http.Request, domainName, clientAlias string) error {
	scheme, _ := p.store.matchName(domainName)
	if scheme == "" {
		scheme = p.defScheme
	}
	upstream, tlsUpstream, err := p.dialUpstream(req.Context(), domainName, scheme)
	if err != nil {
		writeGatewayError(client, domainName, err)
		return err
	}
	defer upstream.Close()

	// Upgrade handshakes need Connection/Upgrade and the Sec-WebSocket-* fields,
	// so only the proxy-specific hop-by-hop headers are dropped here.
	req.RequestURI = ""
	req.URL.Scheme = "http"
	if tlsUpstream {
		req.URL.Scheme = "https"
	}
	req.URL.Host = domainName
	req.Host = domainName
	rewriteOriginHeaders(req.Header, domainName, clientAlias, tlsUpstream)
	req.Close = false
	for _, name := range []string{"Proxy-Connection", "Proxy-Authorization", "Keep-Alive", "Te", "Trailer"} {
		req.Header.Del(name)
	}
	if p.forwarded {
		if ip, _, splitErr := net.SplitHostPort(client.RemoteAddr().String()); splitErr == nil {
			req.Header.Set("X-Forwarded-For", ip)
		}
		req.Header.Set("X-Forwarded-Host", clientAlias)
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	return p.relayUpgrade(client, br, upstream, req, domainName, clientAlias)
}

// relayUpgrade speaks the upgrade handshake on an already dialled upstream and
// then relays bytes. It is split from dialling so the handshake can be tested
// without a real socket.
func (p *plugin) relayUpgrade(client net.Conn, br *bufio.Reader, upstream net.Conn, req *http.Request, domainName, clientAlias string) error {
	_ = upstream.SetDeadline(time.Now().Add(gatewayHeaderTimeout))
	upReader := bufio.NewReader(upstream)
	if err := req.Write(upstream); err != nil {
		return fmt.Errorf("write upgrade request: %w", err)
	}
	resp, err := http.ReadResponse(upReader, req)
	if err != nil {
		return fmt.Errorf("read upgrade response: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The server refused the upgrade: relay the normal response and stop.
		_ = upstream.SetDeadline(time.Time{})
		if err := p.rewriteResponse(resp, domainName, clientAlias); err != nil {
			return err
		}
		if err := resp.Write(client); err != nil {
			return fmt.Errorf("write upgrade rejection: %w", err)
		}
		return nil
	}

	// 101 must keep Connection/Upgrade and must not carry Connection: close.
	if _, err := fmt.Fprintf(client, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := resp.Header.Write(client); err != nil {
		return err
	}
	if _, err := client.Write([]byte("\r\n")); err != nil {
		return err
	}

	// The tunnel can stay idle for arbitrarily long; drop the handshake deadline
	// before relaying.
	_ = upstream.SetDeadline(time.Time{})

	p.log().Info("alias: websocket tunnel established", zap.String("domain", domainName))
	spliceUpgraded(client, br, upstream, upReader)
	return nil
}

// spliceUpgraded copies in both directions until one side ends, then half-closes
// the other connection so the peer sees a clean EOF.
func spliceUpgraded(client net.Conn, clientBuf *bufio.Reader, upstream net.Conn, upstreamBuf *bufio.Reader) {
	done := make(chan struct{})
	// Buffered readers may already hold bytes read during the handshake, so
	// relay from them rather than from the raw connections.
	go func() {
		_, _ = io.Copy(client, upstreamBuf)
		closeWrite(client)
		close(done)
	}()
	_, _ = io.Copy(upstream, clientBuf)
	closeWrite(upstream)
	<-done
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

// dialUpstream opens the upstream connection: proxy first when it is active,
// otherwise a direct dial through the pinned outlet.
func (p *plugin) dialUpstream(ctx context.Context, domainName, scheme string) (net.Conn, bool, error) {
	port := 80
	useTLS := scheme == schemeHTTPS || scheme == schemeHTTPSInsecure
	insecureTLS := scheme == schemeHTTPSInsecure
	if scheme == schemeAuto {
		// Try TLS first; a plain site answers a TLS handshake with a reset.
		conn, err := p.dialUpstreamOne(ctx, domainName, 443, true, false)
		if err == nil {
			return conn, true, nil
		}
		conn, err2 := p.dialUpstreamOne(ctx, domainName, 80, false, false)
		if err2 != nil {
			return nil, false, fmt.Errorf("auto: https: %v; http: %w", err, err2)
		}
		return conn, false, nil
	}
	if useTLS {
		port = 443
	}
	conn, err := p.dialUpstreamOne(ctx, domainName, port, useTLS, insecureTLS)
	return conn, useTLS, err
}

func (p *plugin) dialUpstreamOne(ctx context.Context, domainName string, port int, useTLS, insecureTLS bool) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, gatewayDialTimeout)
	defer cancel()
	target := dialHostPort(domainName, uint16(port))

	var conn net.Conn
	var err error
	if p.proxy != nil {
		conn, err = p.proxy.DialContext(dialCtx, "tcp", target)
	} else {
		addr, rerr := p.resolveForDial(dialCtx, domainName)
		if rerr != nil {
			return nil, rerr
		}
		conn, err = p.direct.DialContext(dialCtx, "tcp", net.JoinHostPort(addr.String(), fmt.Sprintf("%d", port)))
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	if !useTLS {
		return conn, nil
	}
	tlsConfig := &tls.Config{ServerName: domainName, MinVersion: tls.VersionTLS12}
	if insecureTLS {
		// Explicit per-entry opt-in for legacy origins whose certificate has
		// expired or is otherwise unverifiable. Never enabled globally.
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- explicit entry scheme
	}
	tlsConn := tls.Client(conn, tlsConfig)
	_ = tlsConn.SetDeadline(time.Now().Add(gatewayTLSHandshake))
	if herr := tlsConn.Handshake(); herr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", domainName, herr)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// aliasName renders the served name of a real domain, matching the plugin
// name form.
func (p *plugin) aliasName(domainName string) string {
	real := domainName
	p.mu.RLock()
	suffix, replace, dotRepl, opaque := p.suffix, p.replace, p.dotRepl, p.opaque
	p.mu.RUnlock()
	var alias string
	if opaque {
		if label := opaqueAliasLabel(domainName); label != "" {
			alias = label + suffix
		} else {
			alias = flattenDomain(domainName, dotRepl) + suffix
		}
	} else {
		if replace {
			domainName = stripLastLabel(domainName)
		}
		if dotRepl != "." && dotRepl != "" {
			domainName = flattenDomain(domainName, dotRepl)
		}
		alias = domainName + suffix
	}
	p.rememberAlias(alias, real)
	return alias
}

// opaqueAliasLabel encodes a domain into one case-insensitive base32 DNS
// label. The encoding is reversible, so the DNS path can recover the real
// domain without a runtime registry. Names longer than one label fall back to
// the readable form in aliasName.
func opaqueAliasLabel(domainName string) string {
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(domainName)))
	if len(label) > 63 {
		return ""
	}
	return label
}

// rewriteResponse keeps the client inside the alias namespace: absolute
// Location values point back at the alias name, and cookie domains follow.
func (p *plugin) rewriteResponse(resp *http.Response, domainName, clientAlias string) error {
	stripHopByHop(resp.Header)
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", p.rewriteLocation(loc, domainName, clientAlias))
	}
	if loc := resp.Header.Get("Content-Location"); loc != "" {
		if rewritten, ok := p.rewriteSameSiteURL(loc, domainName); ok {
			resp.Header.Set("Content-Location", rewritten)
		}
	}
	if refresh := resp.Header.Get("Refresh"); refresh != "" {
		resp.Header.Set("Refresh", p.rewriteRefresh(refresh, domainName))
	}
	if links := resp.Header.Values("Link"); len(links) > 0 {
		resp.Header.Del("Link")
		for _, link := range links {
			resp.Header.Add("Link", p.rewriteLinkHeader(link, domainName))
		}
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
		resp.Header.Del("Set-Cookie")
		for _, c := range cookies {
			if rewritten := p.rewriteCookie(c, domainName, clientAlias); rewritten != "" {
				resp.Header.Add("Set-Cookie", rewritten)
			}
		}
	}
	return p.rewriteHTMLBody(resp, domainName)
}

// rewriteHTMLBody keeps same-site subresources on the alias host. Without
// this, a page served over https://<alias> still references
// //cache.<real>/... in its HTML; the browser would open a TLS connection to
// the real subdomain, whose name the alias certificate cannot cover. The same
// applies to JS/CSS chunks: a Next.js chunk can contain
// "https://website-cdn.assets.example.com/x", and the browser would resolve
// that real name to the alias virtual IP before the TLS gateway can redirect
// it, producing ERR_CERT_COMMON_NAME_INVALID.
func (p *plugin) rewriteHTMLBody(resp *http.Response, domainName string) error {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || !isRewritableBodyType(ct) {
		return nil
	}
	if resp.Header.Get("Content-Range") != "" {
		return nil
	}
	const maxHTMLBody = 8 << 20
	if resp.ContentLength > maxHTMLBody {
		return nil
	}
	compressed, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read html body: %w", err)
	}
	if resp.ContentLength < 0 && int64(len(compressed)) > maxHTMLBody {
		// A chunked page has no declared length. It has already been consumed
		// here, so restore the bytes instead of truncating the client response.
		resp.Body = io.NopCloser(bytes.NewReader(compressed))
		return nil
	}
	_ = resp.Body.Close()
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	body := compressed
	if encoding == "gzip" || encoding == "deflate" {
		body, err = decodeHTMLBody(compressed, encoding, maxHTMLBody)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(compressed))
			return nil
		}
		if body == nil {
			resp.Body = io.NopCloser(bytes.NewReader(compressed))
			return nil
		}
	} else if encoding != "" {
		resp.Body = io.NopCloser(bytes.NewReader(compressed))
		return nil
	}
	rewritten := p.rewriteHTMLURLs(body, domainName)
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	// A rewritten chunked response now has a declared length. Clearing
	// Transfer-Encoding avoids sending both framing modes to the client.
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("ETag")
	resp.Header.Del("Last-Modified")
	resp.Header.Del("Content-MD5")
	resp.Header.Del("Accept-Ranges")
	return nil
}

// isRewritableBodyType selects text bodies whose URL-bearing strings are safe
// to rewrite. Binary assets and opaque encodings are never touched.
func isRewritableBodyType(ct string) bool {
	for _, typ := range []string{
		"text/html",
		"application/xhtml+xml",
		"text/javascript",
		"application/javascript",
		"application/x-javascript",
		"text/ecmascript",
		"application/ecmascript",
		"text/css",
		"application/json",
		"application/ld+json",
		"text/x-component",
	} {
		if strings.Contains(ct, typ) {
			return true
		}
	}
	return false
}

// decodeHTMLBody returns the decoded HTML, or nil when the decoded body is
// larger than max. The caller restores the original compressed bytes in that
// case so the page is still delivered intact, just without URL rewriting.
func decodeHTMLBody(body []byte, encoding string, max int64) ([]byte, error) {
	var reader io.ReadCloser
	var err error
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(body))
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", encoding)
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > max {
		return nil, nil
	}
	return out, nil
}

var (
	sameSiteURLPattern = regexp.MustCompile(`(?i)(?:https?:)?//([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]+)?`)
	// Bare hosts also occur inside Next.js RSC payloads and escaped JSON
	// (https:\/\/assets.example.com\/x). They have no "//" prefix, so the URL
	// pattern above would miss them and the browser would keep a real host.
	bareHostPattern = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?`)
)

func (p *plugin) rewriteHTMLURLs(body []byte, domainName string) []byte {
	body = sameSiteURLPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		if rewritten, ok := p.rewriteSameSiteURL(string(m), domainName); ok {
			return []byte(rewritten)
		}
		return m
	})
	return bareHostPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		host := strings.TrimSuffix(strings.ToLower(string(m)), ".")
		if !p.isServedHost(host, domainName) {
			return m
		}
		return []byte(p.aliasName(host))
	})
}

func (p *plugin) rewriteSameSiteURL(raw, domainName string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !p.isServedHost(host, domainName) {
		return raw, false
	}
	alias := p.aliasName(host)
	port := u.Port()
	if port == "80" || port == "443" {
		port = ""
	}
	u.Scheme = p.redirectScheme()
	if port != "" {
		u.Host = net.JoinHostPort(alias, port)
	} else {
		u.Host = alias
	}
	return u.String(), true
}

// isServedHost accepts the current real host, its subdomains, and any
// explicitly listed suffix. The store check is required for sibling
// subdomains: a page on www.example.com may reference assets.example.com,
// which is still inside the same served suffix.
func (p *plugin) isServedHost(host, domainName string) bool {
	if p.store != nil {
		_, ok := p.store.matchName(host)
		return ok
	}
	return host == domainName || strings.HasSuffix(host, "."+domainName)
}

func (p *plugin) rewriteRefresh(value, domainName string) string {
	parts := strings.Split(value, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < 4 || !strings.EqualFold(part[:4], "url=") {
			continue
		}
		target := strings.TrimSpace(part[4:])
		if rewritten, ok := p.rewriteSameSiteURL(target, domainName); ok {
			parts[i] = " url=" + rewritten
		} else {
			parts[i] = " " + part
		}
	}
	return strings.Join(parts, ";")
}

func (p *plugin) rewriteLinkHeader(value, domainName string) string {
	linkPattern := regexp.MustCompile(`<([^>]+)>`)
	return linkPattern.ReplaceAllStringFunc(value, func(m string) string {
		target := strings.TrimSuffix(strings.TrimPrefix(m, "<"), ">")
		if rewritten, ok := p.rewriteSameSiteURL(target, domainName); ok {
			return "<" + rewritten + ">"
		}
		return m
	})
}

func (p *plugin) rewriteLocation(loc, domainName, clientAlias string) string {
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		return loc
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if p.isServedHost(host, domainName) {
		alias := p.aliasName(host)
		port := u.Port()
		if port == "80" || port == "443" {
			port = ""
		}
		if port != "" {
			u.Host = net.JoinHostPort(alias, port)
		} else {
			u.Host = alias
		}
	}
	return u.String()
}

func (p *plugin) rewriteCookie(cookie, domainName, clientAlias string) string {
	lower := strings.ToLower(cookie)
	idx := strings.Index(lower, "domain=")
	if idx < 0 {
		return cookie
	}
	start := idx + len("domain=")
	end := start
	for end < len(cookie) && cookie[end] != ';' {
		end++
	}
	raw := strings.TrimSpace(cookie[start:end])
	leadingDot := strings.HasPrefix(raw, ".")
	value := strings.TrimSuffix(strings.TrimPrefix(raw, "."), ".")
	value = strings.ToLower(value)
	if value == "" || !p.isServedHost(value, domainName) {
		return cookie
	}
	// A response served through an alias must not set a Domain outside the
	// alias namespace. Rewrite the real domain to its alias form; this works
	// for every entry in alias.txt, not just the domain currently requested.
	// __Host- requires a host-only cookie, so its Domain is removed instead.
	cookieName := strings.ToLower(strings.TrimSpace(cookie[:idx]))
	if eq := strings.IndexByte(cookieName, '='); eq >= 0 {
		cookieName = cookieName[:eq]
	}
	alias := p.aliasName(value)
	newValue := alias
	if strings.HasPrefix(cookieName, "__host-") {
		newValue = ""
	} else if leadingDot {
		newValue = "." + alias
	}
	head := strings.TrimRight(cookie[:idx], "; ")
	tail := strings.TrimSpace(strings.TrimPrefix(cookie[end:], ";"))
	if newValue == "" {
		switch {
		case head == "" && tail == "":
			return ""
		case head == "":
			return tail
		case tail == "":
			return head
		default:
			return head + "; " + tail
		}
	}
	newAttr := "Domain=" + newValue
	switch {
	case head == "" && tail == "":
		return newAttr
	case head == "":
		return newAttr + "; " + tail
	case tail == "":
		return head + "; " + newAttr
	default:
		return head + "; " + newAttr + "; " + tail
	}
}

// gatewayAcceptEncoding narrows the browser's Accept-Encoding to the codings
// the gateway can decode before rewriting HTML. gzip and deflate are kept only
// when the client actually accepts them.
func gatewayAcceptEncoding(value string) string {
	var allowed []string
	for _, part := range strings.Split(value, ",") {
		fields := strings.Split(part, ";")
		token := strings.ToLower(strings.TrimSpace(fields[0]))
		if token != "gzip" && token != "deflate" {
			continue
		}
		qZero := false
		for _, f := range fields[1:] {
			f = strings.ToLower(strings.TrimSpace(f))
			if f == "q=0" || f == "q=0.0" || f == "q=0.00" || f == "q=0.000" {
				qZero = true
			}
		}
		if !qZero {
			allowed = append(allowed, token)
		}
	}
	return strings.Join(allowed, ", ")
}

func stripHopByHop(h http.Header) {
	// Connection tokens name further hop-by-hop fields, so read them before
	// Connection itself is removed.
	for _, v := range h.Values("Connection") {
		for _, field := range strings.Split(v, ",") {
			if f := strings.TrimSpace(field); f != "" {
				h.Del(f)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func writeGatewayError(client net.Conn, domainName string, err error) {
	body := "alias gateway: " + domainName + ": " + err.Error() + "\n"
	_, _ = fmt.Fprintf(client,
		"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}
