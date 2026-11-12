package radius

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeOcservConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ocserv.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write ocserv.conf: %v", err)
	}
	return path
}

func TestParseIPPool(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		first  string
		last   string
		server string
	}{
		{"cidr", "10.9.0.0/24", "10.9.0.1", "10.9.0.254", "10.9.0.1"},
		{"range", "10.9.0.2-10.9.0.4", "10.9.0.2", "10.9.0.4", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := parseIPPool(tc.value)
			if err != nil {
				t.Fatalf("parseIPPool(%q): %v", tc.value, err)
			}
			if got := ipv4String(pool.first); got != tc.first {
				t.Fatalf("first = %s, want %s", got, tc.first)
			}
			if got := ipv4String(pool.last); got != tc.last {
				t.Fatalf("last = %s, want %s", got, tc.last)
			}
			server := ""
			if pool.server != 0 {
				server = ipv4String(pool.server)
			}
			if server != tc.server {
				t.Fatalf("server = %s, want %s", server, tc.server)
			}
		})
	}
}

func TestParseIPPoolInvalid(t *testing.T) {
	for _, value := range []string{
		"10.9.0.0/31",
		"10.9.0.0/32",
		"fd00::/64",
		"10.9.0.300",
		"10.9.0.5-10.9.0.2",
		"10.9.0.2-",
	} {
		if _, err := parseIPPool(value); err == nil {
			t.Fatalf("parseIPPool(%q) accepted an invalid pool", value)
		}
	}
	if pool, err := parseIPPool(""); err != nil || pool != nil {
		t.Fatalf("empty pool = %v, %v; want nil, nil", pool, err)
	}
}

func TestLoadPoolFromOcserv(t *testing.T) {
	cases := []struct {
		name    string
		content string
		first   string
		last    string
		server  string
	}{
		{
			name:    "network base reserves first host",
			content: "ipv4-network = 10.9.0.0/24\nipv6-network = fd00:10:9::/48\n",
			first:   "10.9.0.1",
			last:    "10.9.0.254",
			server:  "10.9.0.1",
		},
		{
			name:    "host address is the machine ip",
			content: "ipv4-network = 10.9.0.254/24\n",
			first:   "10.9.0.1",
			last:    "10.9.0.254",
			server:  "10.9.0.254",
		},
		{
			name:    "legacy netmask form",
			content: "ipv4-network = 10.9.0.1\nipv4-netmask = 255.255.255.0\n",
			first:   "10.9.0.1",
			last:    "10.9.0.254",
			server:  "10.9.0.1",
		},
		{
			name:    "explicit server-ip",
			content: "ipv4-network = 10.9.0.0/24\nserver-ip = 10.9.0.10\n",
			first:   "10.9.0.1",
			last:    "10.9.0.254",
			server:  "10.9.0.10",
		},
		{
			name:    "top level key without equals",
			content: "ipv4-network 10.9.0.0/24\n",
			first:   "10.9.0.1",
			last:    "10.9.0.254",
			server:  "10.9.0.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := loadPoolFromOcserv(writeOcservConf(t, tc.content))
			if err != nil {
				t.Fatalf("loadPoolFromOcserv: %v", err)
			}
			if got := ipv4String(pool.first); got != tc.first {
				t.Fatalf("first = %s, want %s", got, tc.first)
			}
			if got := ipv4String(pool.last); got != tc.last {
				t.Fatalf("last = %s, want %s", got, tc.last)
			}
			if got := ipv4String(pool.server); got != tc.server {
				t.Fatalf("server = %s, want %s", got, tc.server)
			}
		})
	}
}

func TestLoadPoolFromOcservErrors(t *testing.T) {
	if _, err := loadPoolFromOcserv(filepath.Join(t.TempDir(), "missing.conf")); err == nil {
		t.Fatal("missing config accepted")
	}
	if _, err := loadPoolFromOcserv(writeOcservConf(t, "ipv6-network = fd00::/48\n")); err == nil {
		t.Fatal("config without ipv4-network accepted")
	}
}

func TestAllocateDescendingAndSkipsUsed(t *testing.T) {
	st := testStore(t)
	pool, err := parseIPPool("10.9.0.0/30")
	if err != nil {
		t.Fatalf("parseIPPool: %v", err)
	}
	// 10.9.0.0/30: server .1, leases .2 only.
	if err := st.addUserWithIP("alice", "pw-alice", "users", "10.9.0.2"); err != nil {
		t.Fatalf("addUserWithIP: %v", err)
	}
	if _, err := st.allocate(pool); !errors.Is(err, errPoolExhausted) {
		t.Fatalf("allocate = %v, want errPoolExhausted", err)
	}

	pool, err = parseIPPool("10.9.0.0/29")
	if err != nil {
		t.Fatalf("parseIPPool: %v", err)
	}
	// /29: server .1, leases .2-.6; the top free address is .6.
	ip, err := st.allocate(pool)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if ip != "10.9.0.6" {
		t.Fatalf("allocate = %s, want 10.9.0.6", ip)
	}
}
