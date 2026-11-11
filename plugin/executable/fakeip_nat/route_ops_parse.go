package fakeipnat

import (
	"fmt"
	"net/netip"
	"strings"
)

// netmaskString renders a CIDR prefix length as the dotted netmask that
// BSD route(8) and Windows route.exe expect.
func netmaskString(bits int) string {
	mask := ^uint32(0) << uint(32-bits)
	return fmt.Sprintf("%d.%d.%d.%d", mask>>24, (mask>>16)&0xff, (mask>>8)&0xff, mask&0xff)
}

// prefixMask converts a dotted netmask back to a prefix length.
func prefixMask(mask string) (int, bool) {
	v, err := netip.ParseAddr(mask)
	if err != nil || !v.Is4() {
		return 0, false
	}
	// Count the leading ones with a strict check: a netmask with a hole is
	// invalid and must not silently become a wider route.
	b := v.As4()
	bits := 0
	seenZero := false
	for _, by := range b {
		for i := 7; i >= 0; i-- {
			if by&(1<<uint(i)) != 0 {
				if seenZero {
					return 0, false
				}
				bits++
			} else {
				seenZero = true
			}
		}
	}
	return bits, true
}

// splitPrefix splits "1.2.3.4/32" into its address and prefix length.
func splitPrefix(prefix string) (string, int, bool) {
	addr, bits, ok := strings.Cut(prefix, "/")
	if !ok {
		if _, err := netip.ParseAddr(prefix); err != nil {
			return "", 0, false
		}
		return prefix, 32, true
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return "", 0, false
	}
	n := 0
	if _, err := fmt.Sscanf(bits, "%d", &n); err != nil || n < 0 || n > 32 {
		return "", 0, false
	}
	return addr, n, true
}

// parseBSDManagedRoutes reads the output of "netstat -rn -f inet" and returns
// the prefixes that point at the configured gateway or device.
func parseBSDManagedRoutes(out, hop, dev string) []string {
	var routes []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dest, gateway, netif := fields[0], fields[1], fields[3]
		if dest == "Destination" || dest == "default" {
			continue
		}
		// A device route (link#12) is the interface's own subnet; it is not a
		// route the plugin wrote and must never be removed.
		if strings.HasPrefix(gateway, "link#") {
			continue
		}
		if strings.Contains(dest, ":") {
			continue
		}
		prefix, ok := bsdDestination(dest)
		if !ok {
			continue
		}
		if hop != "" && gateway != hop {
			continue
		}
		if dev != "" && netif != dev {
			continue
		}
		routes = append(routes, prefix)
	}
	return routes
}

// bsdDestination normalises a netstat destination column: "1.2.3.4" becomes
// "1.2.3.4/32", "10.0.0.0/8" is kept as is.
func bsdDestination(dest string) (string, bool) {
	if strings.Contains(dest, "/") {
		addr, bits, ok := splitPrefix(dest)
		if !ok {
			return "", false
		}
		return fmt.Sprintf("%s/%d", addr, bits), true
	}
	if _, err := netip.ParseAddr(dest); err != nil {
		return "", false
	}
	return dest + "/32", true
}

// parseWindowsDefaultRoute finds the "0.0.0.0/0" row of "route print -4". The
// interface column is an address, not a name, so dev stays empty.
func parseWindowsDefaultRoute(out string) (hop, dev string) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		if fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		if _, err := netip.ParseAddr(fields[2]); err != nil {
			continue
		}
		return fields[2], ""
	}
	return "", ""
}

// parseWindowsManagedRoutes reads "route print -4" and returns the prefixes
// whose next hop is the configured gateway. Windows has no device-name column
// in that output (the interface is listed by address), so dev only filters
// when it happens to be an address.
func parseWindowsManagedRoutes(out, hop, dev string) []string {
	var routes []string
	inActive := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Active Routes") {
			inActive = true
			continue
		}
		if !inActive {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 5 {
			continue
		}
		dest, mask, gateway := fields[0], fields[1], fields[2]
		if dest == "Network" || dest == "0.0.0.0" {
			continue
		}
		if _, err := netip.ParseAddr(dest); err != nil {
			continue
		}
		bits, ok := prefixMask(mask)
		if !ok {
			continue
		}
		if hop != "" && gateway != hop {
			continue
		}
		if dev != "" && dev != gateway && fields[3] != dev {
			continue
		}
		routes = append(routes, fmt.Sprintf("%s/%d", dest, bits))
	}
	return routes
}
