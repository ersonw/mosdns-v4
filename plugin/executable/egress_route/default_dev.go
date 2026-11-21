package egress_route

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const defaultDevProbeTimeout = 5 * time.Second

// systemDefaultRouteDev returns the device of the host's IPv4 default route.
// An exit that names no next_hop_dev follows whatever WAN the system is using
// instead of a hard-coded interface name.
func systemDefaultRouteDev(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultDevProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route show default: %w: %s", err, strings.TrimSpace(string(out)))
	}
	dev := parseDefaultRouteDev(string(out))
	if dev == "" {
		return "", fmt.Errorf("system has no IPv4 default route: %q", strings.TrimSpace(string(out)))
	}
	return dev, nil
}

// parseDefaultRouteDev returns the device of the first IPv4 default route.
// Example line: "default nhid 20 via 192.168.1.1 dev eth0 proto static".
func parseDefaultRouteDev(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" && strings.TrimSpace(fields[i+1]) != "" {
				return fields[i+1]
			}
		}
	}
	return ""
}
