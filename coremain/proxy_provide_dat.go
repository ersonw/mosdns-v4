package coremain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	proxyProvideDatSchema    = "custombrowser.config.proto/v1"
	proxyProvideDatPortable  = "CBCFG1"
	proxyProvideDatRuntime   = "CBCFG2"
	proxyProvideDatExtension = ".dat"
)

// builtinProxyProvideDatKey is the portable key used by CustomBrowser's
// default-config.dat / EncodeDat export. Runtime CBCFG2 files use a per-machine
// key and are intentionally rejected here.
var builtinProxyProvideDatKey = [32]byte{
	0x13, 0xd1, 0xcb, 0xd5, 0x9d, 0xb7, 0x36, 0x96,
	0x93, 0xa1, 0xa3, 0x18, 0xf4, 0xf6, 0x30, 0x2f,
	0xf6, 0xe9, 0x04, 0xac, 0xe0, 0x9c, 0xaf, 0x49,
	0x87, 0xd7, 0x50, 0xef, 0x16, 0x20, 0x14, 0x15,
}

type proxyProvideDatConfig struct {
	IdentityServerURL          string
	SecondaryIdentityServerURL string
	IdentityToken              string
	Token                      string
	IdentityFile               string
	InsecureSkipVerify         bool
}

func loadProxyProvideDat(path, keyFile string) (proxyProvideDatConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return proxyProvideDatConfig{}, fmt.Errorf("read config_dat %s: %w", path, err)
	}
	plain := raw
	switch {
	case bytes.HasPrefix(raw, []byte(proxyProvideDatRuntime)):
		if strings.TrimSpace(keyFile) == "" {
			return proxyProvideDatConfig{}, fmt.Errorf("config_dat %s is CBCFG2; config_key_file is required", path)
		}
		plain, err = decryptProxyProvideRuntimeDat(raw, keyFile)
		if err != nil {
			return proxyProvideDatConfig{}, fmt.Errorf("decrypt config_dat %s: %w", path, err)
		}
	case bytes.HasPrefix(raw, []byte(proxyProvideDatPortable)):
		plain, err = decryptProxyProvideDat(raw)
		if err != nil {
			return proxyProvideDatConfig{}, fmt.Errorf("decrypt config_dat %s: %w", path, err)
		}
	}
	return parseProxyProvideDat(plain)
}

func decryptProxyProvideRuntimeDat(raw []byte, keyFile string) ([]byte, error) {
	master, err := loadProxyProvideDatKey(keyFile)
	if err != nil {
		return nil, err
	}
	derived := deriveProxyProvideConfigKey(master)
	plain, err := decryptProxyProvideAESGCM(raw, proxyProvideDatRuntime, derived)
	if err == nil {
		return plain, nil
	}
	// Also accept a config-key file that already contains the derived key.
	return decryptProxyProvideAESGCM(raw, proxyProvideDatRuntime, master)
}

func loadProxyProvideDatKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config_key_file %s: %w", path, err)
	}
	value := strings.TrimSpace(string(raw))
	if key, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := base64.StdEncoding.DecodeString(value); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := hex.DecodeString(value); err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, errors.New("config_key_file must contain a base64 or hex 32-byte key")
}

func deriveProxyProvideConfigKey(master []byte) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("custombrowser/config-key/v1"))
	return mac.Sum(nil)
}

func decryptProxyProvideDat(raw []byte) ([]byte, error) {
	return decryptProxyProvideAESGCM(raw, proxyProvideDatPortable, builtinProxyProvideDatKey[:])
}

func decryptProxyProvideAESGCM(raw []byte, magic string, key []byte) ([]byte, error) {
	header := []byte(magic)
	if len(raw) < len(header)+12+16 {
		return nil, errors.New(".dat is truncated")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := raw[len(header) : len(header)+gcm.NonceSize()]
	ciphertext := raw[len(header)+gcm.NonceSize():]
	version := "v1"
	if magic == proxyProvideDatRuntime {
		version = "v2"
	}
	aad := append(append([]byte(nil), header...), []byte("custombrowser/config-dat/"+version)...)
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("config authentication failed")
	}
	return plain, nil
}

func parseProxyProvideDat(plain []byte) (proxyProvideDatConfig, error) {
	if len(plain) == 0 {
		return proxyProvideDatConfig{}, errors.New("config_dat is empty")
	}
	schema := ""
	var config []byte
	data := plain
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return proxyProvideDatConfig{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch num {
		case 1:
			value, n, err := consumeProxyProvideString(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			schema, data = value, data[n:]
		case 2:
			value, n, err := consumeProxyProvideBytes(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			config, data = value, data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return proxyProvideDatConfig{}, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	if schema != proxyProvideDatSchema {
		return proxyProvideDatConfig{}, fmt.Errorf("unsupported config_dat schema %q", schema)
	}
	if len(config) == 0 {
		return proxyProvideDatConfig{}, errors.New("config_dat has no config message")
	}

	var network []byte
	data = config
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return proxyProvideDatConfig{}, protowire.ParseError(n)
		}
		data = data[n:]
		if num == 6 {
			value, n, err := consumeProxyProvideBytes(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			network, data = value, data[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return proxyProvideDatConfig{}, protowire.ParseError(n)
		}
		data = data[n:]
	}
	if len(network) == 0 {
		return proxyProvideDatConfig{}, errors.New("config_dat has no network config")
	}

	var cbp []byte
	data = network
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return proxyProvideDatConfig{}, protowire.ParseError(n)
		}
		data = data[n:]
		if num == 4 {
			value, n, err := consumeProxyProvideBytes(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			cbp, data = value, data[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return proxyProvideDatConfig{}, protowire.ParseError(n)
		}
		data = data[n:]
	}
	if len(cbp) == 0 {
		return proxyProvideDatConfig{}, errors.New("config_dat has no network.cbp config")
	}

	var out proxyProvideDatConfig
	data = cbp
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return proxyProvideDatConfig{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch num {
		case 3:
			value, n, err := consumeProxyProvideString(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			out.Token, data = value, data[n:]
		case 4:
			value, n, err := consumeProxyProvideString(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			out.IdentityFile, data = value, data[n:]
		case 5:
			value, n, err := consumeProxyProvideString(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			out.IdentityServerURL, data = value, data[n:]
		case 6:
			value, n, err := consumeProxyProvideString(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			out.IdentityToken, data = value, data[n:]
		case 14:
			if typ != protowire.VarintType {
				return proxyProvideDatConfig{}, fmt.Errorf("protobuf field 14 has wire type %d, want varint", typ)
			}
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return proxyProvideDatConfig{}, protowire.ParseError(n)
			}
			out.InsecureSkipVerify, data = value != 0, data[n:]
		case 15:
			value, n, err := consumeProxyProvideString(typ, data)
			if err != nil {
				return proxyProvideDatConfig{}, err
			}
			out.SecondaryIdentityServerURL, data = value, data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return proxyProvideDatConfig{}, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return out, nil
}

func consumeProxyProvideString(typ protowire.Type, data []byte) (string, int, error) {
	value, n, err := consumeProxyProvideBytes(typ, data)
	if err != nil {
		return "", 0, err
	}
	return string(value), n, nil
}

func consumeProxyProvideBytes(typ protowire.Type, data []byte) ([]byte, int, error) {
	if typ != protowire.BytesType {
		return nil, 0, fmt.Errorf("protobuf field has wire type %d, want bytes", typ)
	}
	value, n := protowire.ConsumeBytes(data)
	if n < 0 {
		return nil, 0, protowire.ParseError(n)
	}
	return value, n, nil
}

func proxyProvideDatPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if !strings.EqualFold(filepath.Ext(path), proxyProvideDatExtension) {
		return "", fmt.Errorf("config_dat %q must use %s", path, proxyProvideDatExtension)
	}
	return path, nil
}

// ProxyProvideDatNode is the subset of a NODE_LIST node written into a generated
// CustomBrowser ConfigDocument.
type ProxyProvideDatNode struct {
	ID          string
	Label       string
	Region      string
	ControlAddr string
	PublicHost  string
	PublicAddr  string
	LANAddr     string
}

// WriteProxyProvideDat writes a portable CustomBrowser config.proto
// ConfigDocument containing this provider's network.cbp section. It is used
// only when the root config did not point at an existing .dat: the first
// successful main-server interaction generates the file so later starts can
// read the server-issued values back.
func WriteProxyProvideDat(path string, cfg ProxyProvideConfig, insecure bool, nodes []ProxyProvideDatNode) error {
	plain, err := encodeProxyProvideDat(cfg, insecure, nodes)
	if err != nil {
		return err
	}
	sealed, err := sealProxyProvideDat(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".proxy-provide-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func encodeProxyProvideDat(cfg ProxyProvideConfig, insecure bool, nodes []ProxyProvideDatNode) ([]byte, error) {
	var cbp []byte
	cbp = proxyProvidePBBool(cbp, 1, true)
	if len(nodes) > 0 && nodes[0].ControlAddr != "" {
		cbp = proxyProvidePBString(cbp, 2, nodes[0].ControlAddr)
	}
	cbp = proxyProvidePBString(cbp, 3, cfg.NodeTokenValue())
	cbp = proxyProvidePBString(cbp, 4, cfg.IdentityFile)
	cbp = proxyProvidePBString(cbp, 5, cfg.Domain)
	cbp = proxyProvidePBString(cbp, 6, cfg.Token)
	for _, node := range nodes {
		var encoded []byte
		label := strings.TrimSpace(node.Label)
		if label == "" {
			label = node.ID
		}
		encoded = proxyProvidePBString(encoded, 1, node.ID)
		encoded = proxyProvidePBString(encoded, 2, label)
		encoded = proxyProvidePBString(encoded, 3, node.ControlAddr)
		encoded = proxyProvidePBString(encoded, 4, node.PublicHost)
		encoded = proxyProvidePBString(encoded, 5, node.PublicAddr)
		encoded = proxyProvidePBString(encoded, 6, node.LANAddr)
		encoded = proxyProvidePBString(encoded, 7, node.Region)
		cbp = proxyProvidePBBytes(cbp, 11, encoded)
	}
	cbp = proxyProvidePBBool(cbp, 14, insecure)

	var network []byte
	network = proxyProvidePBBytes(network, 4, cbp)

	var config []byte
	config = proxyProvidePBBytes(config, 6, network)

	var doc []byte
	doc = proxyProvidePBString(doc, 1, proxyProvideDatSchema)
	doc = proxyProvidePBBytes(doc, 2, config)
	return doc, nil
}

func sealProxyProvideDat(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(builtinProxyProvideDatKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	header := []byte(proxyProvideDatPortable)
	aad := append(append([]byte(nil), header...), []byte("custombrowser/config-dat/v1")...)
	sealed := gcm.Seal(nil, nonce, plain, aad)
	out := append(append([]byte(nil), header...), nonce...)
	return append(out, sealed...), nil
}

func proxyProvidePBString(dst []byte, num protowire.Number, value string) []byte {
	if value == "" {
		return dst
	}
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	return protowire.AppendString(dst, value)
}

func proxyProvidePBBytes(dst []byte, num protowire.Number, value []byte) []byte {
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	return protowire.AppendBytes(dst, value)
}

func proxyProvidePBBool(dst []byte, num protowire.Number, value bool) []byte {
	dst = protowire.AppendTag(dst, num, protowire.VarintType)
	if value {
		return protowire.AppendVarint(dst, 1)
	}
	return protowire.AppendVarint(dst, 0)
}
