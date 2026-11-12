package fakeipnat

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
)

// AdminPlane reports what the data plane has installed right now, together with
// the state a later run would use to clean it up. The values come from the
// plugin's own fields and from the kernel, read back through the same runner the
// install path uses: "installed" is not the same as "there".
func (p *FakeIPNatPlugin) AdminPlane(ctx context.Context) (fakeipadmin.Plane, error) {
	plane := fakeipadmin.Plane{
		Range:       p.cidr,
		ProxyActive: p.proxyActive,
		MarkEnabled: p.markRoutingEnabled(),
		RouteMark:   p.routeMark,
		RouteTable:  p.routeTable,
		OutletTable: p.tunRouteTable,
		DataPlane:   "nft",
		Recorded:    make(map[string]string),
	}
	if p.useTun {
		plane.DataPlane = "tun"
		plane.Device = p.tunDev
	}

	// One listing answers both "does the mark set exist" and "how many addresses
	// does it hold", which is the number that explains a burst of mark warns.
	plane.RealIPs = p.verifyMarkRouting(ctx).SetSize

	if p.policyRuleSupported {
		if out, err := p.runner.Run(ctx, "ip", "rule", "show"); err == nil {
			plane.Rules = ownRuleLines(out, p.cidr, p.routeTable, p.tunRouteTable, p.routeMark)
		}
		for _, table := range []string{p.routeTable, p.tunRouteTable} {
			if table == "" || table == "main" {
				continue
			}
			if out, err := p.runner.Run(ctx, "ip", "route", "show", "table", table); err == nil {
				for _, line := range strings.Split(out, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "default") {
						plane.Routes = append(plane.Routes, "table "+table+": "+line)
					}
				}
			}
		}
	}

	fakeRule, egress := p.loadTunState(ctx)
	if fakeRule != "" {
		plane.Recorded[stateKeyFakeRule] = fakeRule
	}
	if egress != "" {
		plane.Recorded[stateKeyTunEgress] = egress
	}
	if mark, table := p.loadMarkState(ctx); mark != 0 {
		plane.Recorded[stateKeyMark] = strconv.FormatUint(uint64(mark), 10)
		plane.Recorded[stateKeyTable] = table
	}
	return plane, nil
}

// ownRuleLines keeps the lines of `ip rule show` that belong to this plugin:
// the fake range pin, the outlet rule, and the mark rule. VyOS keeps its own
// rules in the same list, so matching on the whole table is not an option.
func ownRuleLines(out, cidr, routeTable, outletTable string, mark uint32) []string {
	hexMark := "0x" + strconv.FormatUint(uint64(mark), 16)
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case cidr != "" && strings.Contains(line, "to "+cidr+" lookup main"):
			lines = append(lines, line)
		case cidr != "" && strings.Contains(line, "from "+cidr) && strings.Contains(line, "lookup"):
			lines = append(lines, line)
		case mark != 0 && strings.Contains(line, "fwmark "+hexMark):
			lines = append(lines, line)
		case routeTable != "" && routeTable != "main" && strings.HasSuffix(line, "lookup "+routeTable):
			lines = append(lines, line)
		}
	}
	return lines
}

// AdminDiagnose answers what happens to one domain end to end: the mapping that
// was handed out, the real addresses the plane learned for it, and which way the
// stack would dial them.
func (p *FakeIPNatPlugin) AdminDiagnose(ctx context.Context, domain string) (fakeipadmin.Diagnosis, error) {
	out := fakeipadmin.Diagnosis{
		Domain:      domain,
		ProxyActive: p.proxyActive,
		Marked:      p.markRoutingEnabled(),
	}
	entry, ok, err := p.AdminLookupDomain(ctx, domain)
	if err != nil {
		return out, err
	}
	if ok {
		out.FakeIP = entry.FakeIP
		out.CreatedAt = entry.CreatedAt
	}
	if p.db != nil {
		rows, err := p.db.QueryContext(ctx,
			`SELECT ip FROM `+p.ipTable+` WHERE domain = ? LIMIT 8`, domain)
		if err != nil {
			return out, fmt.Errorf("read real ips: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				return out, fmt.Errorf("scan real ip: %w", err)
			}
			out.RealIPs = append(out.RealIPs, ip)
		}
		if err := rows.Err(); err != nil {
			return out, fmt.Errorf("read real ips: %w", err)
		}
		out.RealIPKnown = len(out.RealIPs) > 0
	}
	switch {
	case p.proxyActive:
		out.Outlet = "proxy"
	case p.useTun && p.nextHop != "" && p.nextHopDev != "":
		out.Outlet = "tun via " + p.nextHop + " dev " + p.nextHopDev + " (table " + p.tunRouteTable + ")"
	case p.useTun:
		out.Outlet = "tun through the host default route"
	default:
		out.Outlet = "nft dnat, host routes"
	}
	return out, nil
}

// AdminSweep removes the objects a previous run recorded and this run does not
// own. It is the same sweep the startup performs, so calling it by hand cannot
// remove anything the running configuration depends on.
func (p *FakeIPNatPlugin) AdminSweep(ctx context.Context) ([]string, error) {
	keepFake := ""
	if p.useTun && p.policyRuleSupported {
		keepFake = fakeRangeRuleState(p.cidr, tunFakeRulePriority)
	}
	keepEgress := ""
	if p.useTun && !p.proxyActive {
		keepEgress = tunEgressState(p.tunRouteTable, p.cidr)
	}
	return p.sweepRecordedTunState(ctx, keepFake, keepEgress), nil
}
