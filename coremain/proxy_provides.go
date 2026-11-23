package coremain

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProxyProvideConfig is one main-server entry. tag names the entry; an
// existing identity file's client_id wins over it, otherwise tag is used as
// the client_id when a new identity is issued. domain is the HTTPS API base,
// token is the optional HTTP bearer token, node_token is the optional CBP
// node AUTH token and identity_file is the optional Ed25519 identity path.
type ProxyProvideConfig struct {
	Tag string `yaml:"tag"`
	// Domain is the HTTPS API base, for example https://api.example.com.
	Domain string `yaml:"domain"`
	// Token is the non-desktop API key for the bootstrap endpoint, sent as
	// X-API-Key. For the built-in api.aa2.dev / api.aa3.dev hosts an empty
	// value falls back to the embedded bootstrap credential; other hosts keep
	// the no-authentication-header behavior.
	Token string `yaml:"token"`
	// NodeToken is the CBP node AUTH token. It is separate from the HTTP
	// token because a deployment may issue different tokens to the control
	// plane and to the CBP nodes. Empty falls back to the built-in credential
	// for api.aa2.dev / api.aa3.dev, then to Token.
	NodeToken string `yaml:"node_token"`
	// IdentityFile is the flat client identity. Empty defaults to
	// {config_dir}/proxy_provides/{tag}.json.
	IdentityFile string `yaml:"identity_file"`
	// ConfigDat optionally loads the CBP section from a CustomBrowser
	// config.proto ConfigDocument (.dat). Explicit YAML values win.
	ConfigDat string `yaml:"config_dat"`
	// Insecure is an explicit TLS override. When nil, a config_dat
	// insecure_skip_verify value is used.
	Insecure *bool `yaml:"insecure"`
	// ConfigKeyFile holds a base64/hex 32-byte CustomBrowser DB key for a
	// runtime CBCFG2 config_dat. Ignored for portable CBCFG1.
	ConfigKeyFile string `yaml:"config_key_file"`
	// GenerateDat is set internally when the resolved config_dat path does
	// not exist yet, whether it was explicit or defaulted. The first
	// successful main-server interaction writes it.
	GenerateDat bool `yaml:"-"`
	// ManageDat means this provider owns the .dat and may rewrite its node
	// table when NODE_LIST changes. The default path and files under
	// {config_dir}/proxy_provides are managed; an explicit .dat elsewhere is
	// read-only so a desktop client's own file is never overwritten.
	ManageDat bool `yaml:"-"`
}

// NodeTokenValue returns the CBP node AUTH token, falling back to the HTTP
// token for deployments that use one shared secret.
func (c ProxyProvideConfig) NodeTokenValue() string {
	if strings.TrimSpace(c.NodeToken) != "" {
		return c.NodeToken
	}
	return c.Token
}

var proxyProvideTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// prepareProxyProvides fills defaults, normalizes domains and validates every
// entry. It runs after includes are merged and before any plugin opens a
// listener, so check-config and a real start see the same values.
func (c *Config) prepareProxyProvides() error {
	tags := make(map[string]struct{}, len(c.ProxyProvides))
	for i := range c.ProxyProvides {
		cfg := &c.ProxyProvides[i]
		cfg.Tag = strings.TrimSpace(cfg.Tag)
		cfg.Token = strings.TrimSpace(cfg.Token)
		cfg.NodeToken = strings.TrimSpace(cfg.NodeToken)
		cfg.IdentityFile = strings.TrimSpace(cfg.IdentityFile)
		cfg.ConfigDat = strings.TrimSpace(cfg.ConfigDat)
		cfg.ConfigKeyFile = strings.TrimSpace(cfg.ConfigKeyFile)

		if !proxyProvideTagPattern.MatchString(cfg.Tag) {
			return fmt.Errorf("proxy_provides[%d]: tag %q must match %s", i, cfg.Tag, proxyProvideTagPattern)
		}
		if _, ok := tags[cfg.Tag]; ok {
			return fmt.Errorf("proxy_provides: duplicated tag %q", cfg.Tag)
		}
		tags[cfg.Tag] = struct{}{}

		defaultDat := cfg.ConfigDat == ""
		baseDir := proxyProvideBaseDir(c.configDir)
		if defaultDat {
			cfg.ConfigDat = filepath.Join(baseDir, "proxy_provides", cfg.Tag+".dat")
		}
		path, err := proxyProvideDatPath(cfg.ConfigDat)
		if err != nil {
			return fmt.Errorf("proxy_provides[%s]: %w", cfg.Tag, err)
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(proxyProvideBaseDir(c.configDir), path)
		}
		cfg.ConfigDat = path
		cfg.ManageDat = defaultDat || pathWithin(filepath.Join(baseDir, "proxy_provides"), path)
		keyFile := cfg.ConfigKeyFile
		if keyFile != "" && !filepath.IsAbs(keyFile) {
			keyFile = filepath.Join(proxyProvideBaseDir(c.configDir), keyFile)
		}
		if keyFile != "" {
			cfg.ConfigKeyFile = keyFile
		}
		if _, statErr := os.Stat(path); statErr != nil {
			if !os.IsNotExist(statErr) {
				return fmt.Errorf("proxy_provides[%s]: config_dat %s: %w", cfg.Tag, path, statErr)
			}
			cfg.GenerateDat = true
		} else {
			dat, err := loadProxyProvideDat(path, keyFile)
			if err != nil {
				return fmt.Errorf("proxy_provides[%s]: %w", cfg.Tag, err)
			}
			cfg.GenerateDat = false
			if cfg.Domain == "" {
				cfg.Domain = dat.IdentityServerURL
				if cfg.Domain == "" {
					cfg.Domain = dat.SecondaryIdentityServerURL
				}
			}
			if cfg.Token == "" {
				cfg.Token = dat.IdentityToken
			}
			if cfg.NodeToken == "" {
				cfg.NodeToken = dat.Token
			}
			if cfg.IdentityFile == "" {
				cfg.IdentityFile = dat.IdentityFile
			}
			if cfg.Insecure == nil {
				insecure := dat.InsecureSkipVerify
				cfg.Insecure = &insecure
			}
		}

		domain, err := normalizeProxyProvideDomain(cfg.Domain)
		if err != nil {
			return fmt.Errorf("proxy_provides[%s]: %w", cfg.Tag, err)
		}
		cfg.Domain = domain
		if auth, ok := builtinProxyProvideAuthFor(cfg.Domain); ok {
			if cfg.Token == "" {
				cfg.Token = auth.controlToken
			}
			if cfg.NodeToken == "" {
				cfg.NodeToken = auth.nodeToken
			}
		}

		if cfg.IdentityFile == "" {
			cfg.IdentityFile = filepath.Join(proxyProvideBaseDir(c.configDir), "proxy_provides", cfg.Tag+".json")
		}
	}
	return nil
}

func normalizeProxyProvideDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("domain is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", raw, err)
	}
	if strings.ToLower(u.Scheme) != "https" {
		return "", fmt.Errorf("domain %q must use https://", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("domain %q has no host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("domain %q must not contain userinfo", raw)

	}
	if u.Fragment != "" {
		return "", fmt.Errorf("domain %q must not contain a fragment", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	return u.Scheme + "://" + u.Host + u.Path, nil
}

// ProxyProvideBootstrapURL returns the HTTPS endpoint that lists main-server
// TCP candidates. A base domain gets /v1/edge/bootstrap appended.
func ProxyProvideBootstrapURL(domain string) string {
	domain = strings.TrimRight(strings.TrimSpace(domain), "/")
	if strings.HasSuffix(domain, "/v1/edge/bootstrap") {
		return domain
	}
	return domain + "/v1/edge/bootstrap"
}

// ProxyProvideIdentityURL returns the HTTPS base passed to the identity issuer.
// A domain configured as the full bootstrap URL is reduced to its origin path.
func ProxyProvideIdentityURL(domain string) string {
	domain = strings.TrimRight(strings.TrimSpace(domain), "/")
	domain = strings.TrimSuffix(domain, "/v1/edge/bootstrap")
	return domain
}

func pathWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func proxyProvideBaseDir(dir string) string {
	if dir == "" {
		dir = "."
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}
