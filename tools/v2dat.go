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

package tools

import (
	"fmt"
	"github.com/ersonw/mosdns-v4/mlog"
	"github.com/ersonw/mosdns-v4/pkg/matcher/domain"
	"github.com/ersonw/mosdns-v4/pkg/matcher/netlist"
	"github.com/ersonw/mosdns-v4/pkg/matcher/v2data"
	"github.com/spf13/cobra"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func newUnpackDomainCmd() *cobra.Command {
	var ourDir string
	c := &cobra.Command{
		Use:   "unpack-domain [-o output_dir] geosite.dat[:tag1[,tag2]...]",
		Args:  cobra.ExactArgs(1),
		Short: "Unpack v2ray domain data file to text files.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := UnpackDomainDAT(args[0], ourDir); err != nil {
				mlog.S().Fatal(err)
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVarP(&ourDir, "out", "o", "", "output dir")
	return c
}

func newUnpackIPCmd() *cobra.Command {
	var ourDir string
	c := &cobra.Command{
		Use:   "unpack-ip [-o output_dir] geoip.dat[:tag1[,tag2]...]",
		Args:  cobra.ExactArgs(1),
		Short: "Unpack v2ray ip data file to text files.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := UnpackIPDAT(args[0], ourDir); err != nil {
				mlog.S().Fatal(err)
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVarP(&ourDir, "out", "o", "", "output dir")
	return c
}

func newQueryDomainCmd() *cobra.Command {
	var (
		tagFilter string
		limit     int
		regexMode bool
	)
	c := &cobra.Command{
		Use:     "query-domain <geosite.dat[:tag1[,tag2]...]> <query>",
		Aliases: []string{"search-domain"},
		Args:    cobra.ExactArgs(2),
		Short:   "Search domain entries in a v2ray domain data file without unpacking it.",
		Long: "Search domain entries in a geosite.dat without writing every tag to disk. " +
			"The default mode is a case-insensitive substring match on the domain value. " +
			"Output is one match per line: tag<TAB>rule. Use a tag suffix or --tag to limit the search.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 0 {
				return fmt.Errorf("limit must be >= 0")
			}
			return QueryDomainDAT(
				args[0], args[1], cmd.OutOrStdout(), cmd.ErrOrStderr(),
				tagFilter, limit, regexMode,
			)
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVarP(&tagFilter, "tag", "t", "", "only search these tags (comma separated)")
	c.Flags().IntVarP(&limit, "limit", "l", 0, "stop after N matches (0 = no limit)")
	c.Flags().BoolVarP(&regexMode, "regex", "r", false, "treat query as a Go regular expression")
	return c
}

// QueryDomainDAT searches a geosite.dat without unpacking all tags.
func QueryDomainDAT(in, query string, out, errOut io.Writer, tagFilter string, limit int, regexMode bool) error {
	filePath, wantTags := splitTags(in)
	b, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	geoSiteList, err := domain.LoadGeoSiteList(b)
	if err != nil {
		return err
	}

	entries := make(map[string]*v2data.GeoSite)
	for _, geoSite := range geoSiteList.GetEntry() {
		entries[strings.ToLower(geoSite.GetCountryCode())] = geoSite
	}

	selected := make(map[string]struct{})
	if len(wantTags) > 0 {
		for _, tag := range wantTags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			if _, ok := entries[tag]; !ok {
				return fmt.Errorf("cannot find entry %s", tag)
			}
			selected[tag] = struct{}{}
		}
	} else {
		for tag := range entries {
			selected[tag] = struct{}{}
		}
	}

	if tagFilter != "" {
		allowed := make(map[string]struct{})
		for _, tag := range strings.Split(tagFilter, ",") {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			if _, ok := entries[tag]; !ok {
				return fmt.Errorf("cannot find entry %s", tag)
			}
			allowed[tag] = struct{}{}
		}
		for tag := range selected {
			if _, ok := allowed[tag]; !ok {
				delete(selected, tag)
			}
		}
	}

	tags := make([]string, 0, len(selected))
	for tag := range selected {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	query = strings.TrimSpace(query)
	if query == "" {
		return fmt.Errorf("query is empty")
	}
	var match func(string) bool
	if regexMode {
		re, err := regexp.Compile("(?i)" + query)
		if err != nil {
			return fmt.Errorf("invalid query regexp: %w", err)
		}
		match = re.MatchString
	} else {
		query = strings.ToLower(query)
		match = func(value string) bool {
			return strings.Contains(strings.ToLower(value), query)
		}
	}

	matches := 0
	matchedTags := 0
outer:
	for _, tag := range tags {
		geoSite := entries[tag]
		printed := false
		for _, domainEntry := range geoSite.GetDomain() {
			if !match(domainEntry.GetValue()) {
				continue
			}
			rule, err := formatV2Domain(domainEntry)
			if err != nil {
				return fmt.Errorf("tag %s: %w", tag, err)
			}
			if !printed {
				printed = true
				matchedTags++
			}
			fmt.Fprintf(out, "%s\t%s\n", tag, rule)
			matches++
			if limit > 0 && matches >= limit {
				break outer
			}
		}
	}
	fmt.Fprintf(errOut, "matched %d entries in %d tags\n", matches, matchedTags)
	return nil
}

func splitTags(s string) (string, []string) {
	file, tags, ok := strings.Cut(s, ":")
	if ok {
		t := strings.FieldsFunc(tags, func(r rune) bool {
			return r == ','
		})
		return file, t
	}
	return s, nil
}

func UnpackDomainDAT(in, outDir string) error {
	filePath, wantTags := splitTags(in)
	b, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	geoSiteList, err := domain.LoadGeoSiteList(b)
	if err != nil {
		return err
	}

	entries := make(map[string]*v2data.GeoSite)
	var wantEntries map[string]*v2data.GeoSite
	for _, geoSite := range geoSiteList.GetEntry() {
		tag := strings.ToLower(geoSite.GetCountryCode())
		entries[tag] = geoSite
	}

	if len(wantTags) > 0 {
		wantEntries = make(map[string]*v2data.GeoSite)
		for _, tag := range wantTags {
			entry, ok := entries[tag]
			if !ok {
				return fmt.Errorf("cannot find entry %s", tag)
			}
			wantEntries[tag] = entry
		}
	} else {
		wantEntries = entries
	}

	for tag, geoSite := range wantEntries {
		file := fmt.Sprintf("%s_%s.txt", fileName(in), tag)
		if len(outDir) > 0 {
			file = filepath.Join(outDir, file)
		}
		mlog.S().Infof("saving %s domain to %s", tag, file)
		err := convertV2DomainToTextFile(geoSite.GetDomain(), file)
		if err != nil {
			return err
		}
	}
	return nil
}

func fileName(f string) string {
	f = filepath.Base(f)
	if i := strings.LastIndexByte(f, '.'); i == -1 {
		return f
	} else {
		return f[:i]
	}
}

func convertV2DomainToTextFile(domain []*v2data.Domain, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	return convertV2DomainToText(domain, f)
}

func formatV2Domain(r *v2data.Domain) (string, error) {
	var prefix string
	switch r.Type {
	case v2data.Domain_Plain:
		prefix = "keyword:"
	case v2data.Domain_Regex:
		prefix = "regexp:"
	case v2data.Domain_Domain:
		prefix = ""
	case v2data.Domain_Full:
		prefix = "full:"
	default:
		return "", fmt.Errorf("invalid domain type %d", r.Type)
	}
	return prefix + r.Value, nil
}

func convertV2DomainToText(domain []*v2data.Domain, w io.Writer) error {
	for _, r := range domain {
		rule, err := formatV2Domain(r)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(rule + "\n"))
		if err != nil {
			return err
		}
	}
	return nil
}

func UnpackIPDAT(in, ourDir string) error {
	filePath, wantTags := splitTags(in)
	b, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	geoIPList, err := netlist.LoadGeoIPListFromDAT(b)
	if err != nil {
		return err
	}

	entries := make(map[string]*v2data.GeoIP)
	var wantEntries map[string]*v2data.GeoIP
	for _, geoSite := range geoIPList.GetEntry() {
		tag := strings.ToLower(geoSite.GetCountryCode())
		entries[tag] = geoSite
	}

	if len(wantTags) > 0 {
		wantEntries = make(map[string]*v2data.GeoIP)
		for _, tag := range wantTags {
			entry, ok := entries[tag]
			if !ok {
				return fmt.Errorf("cannot find entry %s", tag)
			}
			wantEntries[tag] = entry
		}
	} else {
		wantEntries = entries
	}

	for tag, ipList := range wantEntries {
		file := fmt.Sprintf("%s_%s.txt", fileName(in), tag)
		if len(ourDir) > 0 {
			file = filepath.Join(ourDir, file)
		}
		mlog.S().Infof("saving %s ip to %s", tag, file)
		err := convertV2CidrToTextFile(ipList.GetCidr(), file)
		if err != nil {
			return err
		}
	}

	return nil
}

func convertV2CidrToTextFile(cidr []*v2data.CIDR, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	return convertV2CidrToText(cidr, f)
}

func convertV2CidrToText(cidr []*v2data.CIDR, w io.Writer) error {
	for _, record := range cidr {
		n := net.IPNet{
			IP: record.Ip,
		}
		switch len(record.Ip) {
		case 4:
			n.Mask = net.CIDRMask(int(record.Prefix), 32)
		case 16:
			n.Mask = net.CIDRMask(int(record.Prefix), 128)
		}
		_, err := w.Write([]byte(n.String() + "\n"))
		if err != nil {
			return err
		}
	}
	return nil
}
