package fakeipnat

// This file parses the host default route. The two command shapes differ:
// iproute2 prints one line ("default via 192.168.1.1 dev eth0"), BSD route
// prints a "gateway:" / "interface:" listing. Parsing is kept separate from
// running the command so it can be tested on any host.

import "strings"

func parseIPRouteDefault(out string) (hop, dev string) {
	line := strings.SplitN(out, "\n", 2)[0]
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			hop = fields[i+1]
		case "dev":
			dev = fields[i+1]
		}
	}
	return hop, dev
}

func parseBSDDefaultRoute(out string) (hop, dev string) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "gateway":
			hop = strings.TrimSpace(value)
		case "interface":
			dev = strings.TrimSpace(value)
		}
	}
	return hop, dev
}
