package cbp_proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const probeTimeout = 1200 * time.Millisecond

// SelectedMain is one reachable main-server TCP entry. Address is the host:port
// the coordinator dials; ServerName is the TLS name that belongs to it.
type SelectedMain struct {
	ID         string
	Role       string
	Address    string
	ServerName string
	RTT        time.Duration
}

type probeResult struct {
	candidate MainCandidate
	address   string
	rtt       time.Duration
	err       error
}

// SelectMainCandidate probes every address of every main-server TCP candidate
// and returns the lowest RTT that answered. ICMP is tried first, TCP connect
// is the fallback. Candidates are never treated as CBP nodes.
func SelectMainCandidate(ctx context.Context, candidates []MainCandidate) (SelectedMain, error) {
	if len(candidates) == 0 {
		return SelectedMain{}, errors.New("cbp_proxy: no main-server candidates")
	}
	results := make(chan probeResult, len(candidates)*2)
	var wg sync.WaitGroup
	for _, candidate := range candidates {
		for _, address := range candidate.Addresses {
			wg.Add(1)
			go func(candidate MainCandidate, address string) {
				defer wg.Done()
				rtt, err := probeAddress(ctx, address)
				results <- probeResult{candidate: candidate, address: address, rtt: rtt, err: err}
			}(candidate, address)
		}
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var reachable []probeResult
	for result := range results {
		if result.err == nil && result.rtt > 0 {
			reachable = append(reachable, result)
		}
	}
	if len(reachable) == 0 {
		return SelectedMain{}, errors.New("cbp_proxy: all main-server candidates are unreachable")
	}
	sort.SliceStable(reachable, func(i, j int) bool {
		a, b := reachable[i], reachable[j]
		if a.rtt != b.rtt {
			return a.rtt < b.rtt
		}
		// A stable tie-break: main before relay, then public before LAN.
		if roleRank(a.candidate.Role) != roleRank(b.candidate.Role) {
			return roleRank(a.candidate.Role) < roleRank(b.candidate.Role)
		}
		return a.address < b.address
	})
	best := reachable[0]
	serverName := strings.TrimSpace(best.candidate.PublicIP)
	if serverName == "" {
		host, _, err := net.SplitHostPort(best.address)
		if err == nil {
			serverName = strings.Trim(host, "[]")
		}
	}
	return SelectedMain{
		ID:         best.candidate.ID,
		Role:       best.candidate.Role,
		Address:    best.address,
		ServerName: serverName,
		RTT:        best.rtt,
	}, nil
}

func roleRank(role string) int {
	if strings.EqualFold(strings.TrimSpace(role), "main") {
		return 0
	}
	return 1
}

func probeAddress(ctx context.Context, address string) (time.Duration, error) {
	if rtt, err := probeICMP(ctx, address); err == nil {
		return rtt, nil
	}
	return probeTCP(ctx, address)
}

func probeICMP(ctx context.Context, address string) (time.Duration, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return 0, fmt.Errorf("invalid probe address %q", address)
	}
	network := "udp4"
	protocol := 1
	if ip.To4() == nil {
		network = "udp6"
		protocol = 58
	}
	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		if ip.To4() == nil {
			network = "ip6:ipv6-icmp"
			conn, err = icmp.ListenPacket(network, "::")
		} else {
			network = "ip4:icmp"
			conn, err = icmp.ListenPacket(network, "0.0.0.0")
		}
	}
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	deadline := time.Now().Add(probeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	id := int(time.Now().UnixNano() & 0xffff)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("mosdns-cbp")},
	}
	if ip.To4() == nil {
		msg.Type = ipv6.ICMPTypeEchoRequest
	}
	payload, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	var dst net.Addr = &net.UDPAddr{IP: ip}
	if strings.HasPrefix(network, "ip") {
		dst = &net.IPAddr{IP: ip}
	}
	_, writeErr := conn.WriteTo(payload, dst)
	if writeErr != nil {
		return 0, writeErr
	}
	start := time.Now()
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		parsed, err := icmp.ParseMessage(protocol, buf[:n])
		if err != nil {
			continue
		}
		switch body := parsed.Body.(type) {
		case *icmp.Echo:
			if body.Seq == 1 && body.ID == id {
				return time.Since(start), nil
			}
		case *icmp.RawBody:
			_ = body
		}
	}
}

func probeTCP(ctx context.Context, address string) (time.Duration, error) {
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	start := time.Now()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}
