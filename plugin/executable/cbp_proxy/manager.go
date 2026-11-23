package cbp_proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/cbpcoord"
	"github.com/ersonw/mosdns-v4/pkg/cbpstream"
	"github.com/ersonw/mosdns-v4/pkg/egress"
	"go.uber.org/zap"
)

const (
	nodeRefreshTTL           = 5 * time.Minute
	nodeRefreshCheckInterval = time.Minute
	dialTimeout              = 10 * time.Second
)

// Manager owns one state per proxy_provides tag. A state caches the current
// CBP node list from NODE_LIST and the selected main-server TCP candidate.
type Manager struct {
	logger *zap.Logger
	byTag  map[string]*tagState
}

type tagState struct {
	cfg coremain.ProxyProvideConfig
	log *zap.Logger

	mu                   sync.RWMutex
	nodes                map[string]cbpcoord.Node
	coordinator          SelectedMain
	coordinatorFallbacks []SelectedMain
	refreshedAt          time.Time
	lastErr              error

	refreshMu      sync.Mutex
	datFingerprint string
}

func NewManager(configs []coremain.ProxyProvideConfig, logger *zap.Logger) (*Manager, error) {
	if len(configs) == 0 {
		return nil, errors.New("cbp_proxy: proxy_provides is empty")
	}
	m := &Manager{logger: logger, byTag: make(map[string]*tagState, len(configs))}
	for _, cfg := range configs {
		if _, ok := m.byTag[cfg.Tag]; ok {
			return nil, fmt.Errorf("cbp_proxy: duplicated proxy_provides tag %q", cfg.Tag)
		}
		m.byTag[cfg.Tag] = &tagState{
			cfg:   cfg,
			log:   logger.With(zap.String("proxy_provide", cfg.Tag)),
			nodes: make(map[string]cbpcoord.Node),
		}
	}
	return m, nil
}

// NewProxyDialer parses "<tag>:<node>", ensures the NODE_LIST cache is fresh,
// resolves <node> by node ID first and then by node label, and opens its stream
// session. The selected coordinator relay is tried first; legacy direct node
// control endpoints are only a fallback for older standalone nodes.
// RunRefreshLoop keeps the NODE_LIST cache current. Without it the table
// would only be refreshed when egress_route asks for a dialer at startup.
func (m *Manager) RunRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(nodeRefreshCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refreshStale(ctx)
		}
	}
}

func (m *Manager) refreshStale(ctx context.Context) {
	tags := make([]string, 0, len(m.byTag))
	for tag := range m.byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		if ctx.Err() != nil {
			return
		}
		s := m.byTag[tag]
		s.mu.RLock()
		fresh := len(s.nodes) > 0 && time.Since(s.refreshedAt) < nodeRefreshTTL
		s.mu.RUnlock()
		if fresh {
			continue
		}
		if !s.refreshMu.TryLock() {
			continue
		}
		s.mu.RLock()
		fresh = len(s.nodes) > 0 && time.Since(s.refreshedAt) < nodeRefreshTTL
		s.mu.RUnlock()
		if fresh {
			s.refreshMu.Unlock()
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := s.refresh(rctx, s.cfgInsecure())
		cancel()
		if err != nil {
			s.mu.Lock()
			s.lastErr = err
			s.mu.Unlock()
			s.log.Warn("cbp_proxy: background node refresh failed, keeping the previous table", zap.Error(err))
		}
		s.refreshMu.Unlock()
	}
}

func (s *tagState) cfgInsecure() bool {
	return s.cfg.Insecure != nil && *s.cfg.Insecure
}

func (m *Manager) NewProxyDialer(params string, insecure bool) (egress.Dialer, string, error) {
	tag, nodeName, ok := strings.Cut(strings.TrimSpace(params), ":")
	if !ok || strings.TrimSpace(tag) == "" || strings.TrimSpace(nodeName) == "" {
		return nil, "", fmt.Errorf("cbp_proxy: want <tag>:<node_id_or_label>, got %q", params)
	}
	tag = strings.TrimSpace(tag)
	nodeName = strings.TrimSpace(nodeName)
	state, ok := m.byTag[tag]
	if !ok {
		return nil, "", fmt.Errorf("cbp_proxy: proxy_provides tag %q is not configured", tag)
	}
	if state.cfg.Insecure != nil && *state.cfg.Insecure {
		insecure = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := state.ensure(ctx, insecure); err != nil {
		return nil, "", err
	}

	state.mu.RLock()
	node, found, lookupErr := findNode(state.nodes, nodeName)
	coordinator := state.coordinator
	fallbacks := append([]SelectedMain(nil), state.coordinatorFallbacks...)
	state.mu.RUnlock()
	if lookupErr != nil {
		return nil, "", fmt.Errorf("cbp_proxy: tag %q: %w", tag, lookupErr)
	}
	if !found {
		return nil, "", fmt.Errorf("cbp_proxy: tag %q has no CBP node %q (available: %s)", tag, nodeName, state.nodeNames())
	}
	nodeID := node.ID
	addresses := nodeControlAddresses(node)
	// The current server advertises node TCP ports as coordinator relay
	// candidates. The node forwards those bytes to the main server without
	// terminating TLS, so they are not CBP control endpoints: dialing them
	// with cbp-control/2 fails ALPN. Prefer the selected coordinator relay
	// whenever one exists, and keep the legacy direct path only as a fallback
	// for an older standalone node that is not registered at the coordinator.
	var relayErrs []string
	for _, relay := range relayChoices(coordinator, fallbacks) {
		dialer, host, err := m.dialNode(ctx, state, node, "", relay, true, insecure)
		if err == nil {
			return dialer, host, nil
		}
		relayErrs = append(relayErrs, fmt.Sprintf("%s (%s): %v", relay.Address, relay.Role, err))
		m.logger.Warn("cbp_proxy: coordinator relay candidate failed",
			zap.String("tag", tag), zap.String("node", nodeID),
			zap.String("address", relay.Address), zap.String("role", relay.Role), zap.Error(err))
	}

	if len(addresses) == 0 {
		return nil, "", fmt.Errorf("cbp_proxy: node %q has no direct control endpoint; relay failed: %s", nodeID, strings.Join(relayErrs, "; "))
	}

	// Legacy path: an older standalone node still exposes direct control
	// endpoints. Try them only after every relay candidate failed.
	probes, probeErr := selectNodeAddresses(ctx, addresses)
	var directErrs []string
	if probeErr != nil {
		directErrs = append(directErrs, probeErr.Error())
	} else {
		for _, candidate := range probes {
			dialer, host, err := m.dialNode(ctx, state, node, candidate.Address, coordinator, false, insecure)
			if err == nil {
				return dialer, host, nil
			}
			directErrs = append(directErrs, fmt.Sprintf("%s (%v)", candidate.Address, err))
			m.logger.Warn("cbp_proxy: legacy direct CBP node candidate failed",
				zap.String("tag", tag), zap.String("node", nodeID),
				zap.String("address", candidate.Address), zap.Duration("rtt", candidate.RTT), zap.Error(err))
		}
	}
	return nil, "", fmt.Errorf("cbp_proxy: node %q relay: %s; direct: %s", nodeID, strings.Join(relayErrs, "; "), strings.Join(directErrs, "; "))
}

// relayChoices orders the relay attempts. The lowest-RTT coordinator is
// first; when it is a node relay and fails, the main coordinator is tried
// before the remaining candidates so a stale node forwarder cannot take the
// egress offline.
func relayChoices(primary SelectedMain, fallbacks []SelectedMain) []SelectedMain {
	out := make([]SelectedMain, 0, len(fallbacks)+1)
	seen := make(map[string]struct{}, len(fallbacks)+1)
	add := func(candidate SelectedMain) {
		if candidate.Address == "" {
			return
		}
		if _, ok := seen[candidate.Address]; ok {
			return
		}
		seen[candidate.Address] = struct{}{}
		out = append(out, candidate)
	}
	add(primary)
	if !strings.EqualFold(strings.TrimSpace(primary.Role), "main") {
		for _, candidate := range fallbacks {
			if strings.EqualFold(strings.TrimSpace(candidate.Role), "main") {
				add(candidate)
				break
			}
		}
	}
	for _, candidate := range fallbacks {
		add(candidate)
	}
	return out
}

func (m *Manager) dialNode(ctx context.Context, state *tagState, node cbpcoord.Node, address string, coordinator SelectedMain, relay bool, insecure bool) (egress.Dialer, string, error) {
	serverName := nodeServerName(node, address)
	relayAddr := ""
	if relay {
		if coordinator.Address == "" {
			return nil, "", errors.New("cbp_proxy: no main-server coordinator selected for relay")
		}
		relayAddr = coordinator.Address
		serverName = coordinator.ServerName
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}
	streamCfg := cbpstream.Config{
		ControlAddr:                address,
		TLSConfig:                  tlsConfig,
		Token:                      state.cfg.NodeTokenValue(),
		DeviceID:                   state.cfg.Tag,
		DialTimeout:                dialTimeout,
		IdentityFile:               state.cfg.IdentityFile,
		IdentityServerURL:          coremain.ProxyProvideIdentityURL(state.cfg.Domain),
		IdentityToken:              state.cfg.Token,
		IdentityInsecureSkipVerify: insecure,
		ClientID:                   state.clientID(),
		RelayAddr:                  relayAddr,
		RelayNodeID:                node.ID,
	}
	if relay {
		streamCfg.RelayTLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         coordinator.ServerName,
			InsecureSkipVerify: insecure,
		}
	}
	client, err := cbpstream.Dial(ctx, streamCfg)
	if err != nil {
		return nil, "", err
	}
	host := address
	if relay {
		host = relayAddr
	}
	host = hostOnly(host)
	state.log.Info("cbp_proxy: CBP stream session ready",
		zap.String("node", node.ID), zap.String("control", address),
		zap.Bool("relay", relay), zap.String("relay_addr", relayAddr))
	return &cbpDialer{client: client, cfg: streamCfg, host: host, node: node.ID}, host, nil
}

func hostOnly(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return strings.Trim(host, "[]")
}

func (s *tagState) ensure(ctx context.Context, insecure bool) error {
	s.mu.RLock()
	fresh := len(s.nodes) > 0 && time.Since(s.refreshedAt) < nodeRefreshTTL
	nodes := len(s.nodes)
	lastErr := s.lastErr
	s.mu.RUnlock()
	if fresh {
		return nil
	}

	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	s.mu.RLock()
	fresh = len(s.nodes) > 0 && time.Since(s.refreshedAt) < nodeRefreshTTL
	s.mu.RUnlock()
	if fresh {
		return nil
	}
	if err := s.refresh(ctx, insecure); err != nil {
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		if nodes > 0 {
			s.log.Warn("cbp_proxy: node refresh failed, keeping the previous CBP node list", zap.Error(err))
			return nil
		}
		if lastErr != nil {
			return fmt.Errorf("cbp_proxy: refresh %s: %v (previous: %v)", s.cfg.Tag, err, lastErr)
		}
		return fmt.Errorf("cbp_proxy: refresh %s: %w", s.cfg.Tag, err)
	}
	return nil
}

func (s *tagState) refresh(ctx context.Context, insecure bool) error {
	candidates, err := FetchMainCandidates(ctx, s.cfg, insecure)
	if err != nil {
		return err
	}
	ranked, err := RankMainCandidates(ctx, candidates)
	if err != nil {
		return err
	}

	// A node relay candidate is only useful when the node actually forwards
	// TCP to the coordinator. Probe the ranked candidates with NODE_LIST and
	// keep the first that authenticates; a stale relay entry must not take the
	// whole egress offline when the main path is healthy.
	var selected SelectedMain
	var nodes []cbpcoord.Node
	var fetchErrs []string
	for _, candidate := range relayChoices(ranked[0], ranked[1:]) {
		nodes, err = cbpcoord.FetchNodes(ctx, cbpcoord.Config{
			Address:                    candidate.Address,
			ServerName:                 candidate.ServerName,
			InsecureSkipVerify:         insecure,
			ClientID:                   s.clientID(),
			IdentityFile:               s.cfg.IdentityFile,
			IdentityServerURL:          coremain.ProxyProvideIdentityURL(s.cfg.Domain),
			IdentityToken:              s.cfg.Token,
			IdentityInsecureSkipVerify: insecure,
			Timeout:                    dialTimeout,
		})
		if err == nil {
			selected = candidate
			break
		}
		fetchErrs = append(fetchErrs, fmt.Sprintf("%s (%s): %v", candidate.Address, candidate.Role, err))
	}
	if selected.Address == "" {
		return fmt.Errorf("cbp_proxy: NODE_LIST failed on every main-server candidate: %s", strings.Join(fetchErrs, "; "))
	}
	if len(fetchErrs) > 0 {
		s.log.Warn("cbp_proxy: NODE_LIST candidate fallback used",
			zap.String("tag", s.cfg.Tag), zap.String("selected", selected.Address),
			zap.String("role", selected.Role), zap.String("failed", strings.Join(fetchErrs, "; ")))
	}

	table := make(map[string]cbpcoord.Node, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.ID) == "" {
			continue
		}
		table[node.ID] = node
	}
	if len(table) == 0 {
		return errors.New("cbp_proxy: NODE_LIST contained no usable CBP node ID")
	}

	fallbacks := make([]SelectedMain, 0, len(ranked)-1)
	for _, candidate := range ranked {
		if candidate.Address == selected.Address {
			continue
		}
		fallbacks = append(fallbacks, candidate)
	}

	s.mu.Lock()
	s.nodes = table
	s.coordinator = selected
	s.coordinatorFallbacks = fallbacks
	s.refreshedAt = time.Now()
	s.lastErr = nil
	s.mu.Unlock()
	s.log.Info("cbp_proxy: CBP node list refreshed",
		zap.Int("nodes", len(table)), zap.String("main", selected.Address),
		zap.String("role", selected.Role), zap.Duration("rtt", selected.RTT))
	if s.cfg.ManageDat || s.cfg.GenerateDat {
		s.writeDatIfChanged(nodes, insecure)
	}
	return nil
}

func (s *tagState) writeDatIfChanged(nodes []cbpcoord.Node, insecure bool) {
	fingerprint := nodeTableFingerprint(nodes)
	if fingerprint == s.datFingerprint && !s.cfg.GenerateDat {
		return
	}
	if s.writeGeneratedDat(nodes, insecure) {
		s.datFingerprint = fingerprint
	}
}

func nodeTableFingerprint(nodes []cbpcoord.Node) string {
	ordered := append([]cbpcoord.Node(nil), nodes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	var b strings.Builder
	for _, node := range ordered {
		b.WriteString(node.ID)
		b.WriteByte('|')
		b.WriteString(node.Label)
		b.WriteByte('|')
		b.WriteString(node.Region)
		b.WriteByte('|')
		b.WriteString(strings.Join(nodeControlAddresses(node), ","))
		b.WriteByte('|')
		b.WriteString(node.PublicAddr)
		b.WriteByte('|')
		b.WriteString(node.LANEndpoint)
		b.WriteByte('|')
		b.WriteString(node.LANTCPEndpoint)
		b.WriteByte('\n')
	}
	return b.String()
}

func (s *tagState) writeGeneratedDat(nodes []cbpcoord.Node, insecure bool) bool {
	ordered := append([]cbpcoord.Node(nil), nodes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	out := make([]coremain.ProxyProvideDatNode, 0, len(ordered))
	for _, node := range ordered {
		control := ""
		publicAddr := ""
		if addresses := nodeControlAddresses(node); len(addresses) > 0 {
			control = addresses[0]
			publicAddr = addresses[0]
		}
		lanAddr := endpointWithPort(node.LANTCPEndpoint, "")
		if lanAddr == "" {
			lanAddr = endpointWithPort(node.LANEndpoint, endpointPort(publicAddr))
		}
		out = append(out, coremain.ProxyProvideDatNode{
			ID:          node.ID,
			Label:       node.Label,
			Region:      node.Region,
			ControlAddr: control,
			PublicHost:  endpointHost(publicAddr),
			PublicAddr:  publicAddr,
			LANAddr:     lanAddr,
		})
	}
	if err := coremain.WriteProxyProvideDat(s.cfg.ConfigDat, s.cfg, insecure, out); err != nil {
		s.log.Warn("cbp_proxy: write config.dat failed", zap.String("path", s.cfg.ConfigDat), zap.Error(err))
		return false
	}
	s.cfg.GenerateDat = false
	s.log.Info("cbp_proxy: config.dat updated", zap.String("path", s.cfg.ConfigDat), zap.Int("nodes", len(out)))
	return true
}

func endpointWithPort(raw, port string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Host
		}
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	if port == "" {
		return ""
	}
	return net.JoinHostPort(strings.Trim(raw, "[]"), port)
}

func endpointHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return strings.Trim(u.Hostname(), "[]")
		}
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(raw, "[]")
}

// clientID returns the client identity registered with the main server.
// An existing flat identity file is authoritative: customBrowser and its
// server register the key under the file's client_id, while the root tag only
// names this proxy_provides entry. Without a file, the tag doubles as the ID
// used for the first identity request.
func (s *tagState) clientID() string {
	raw, err := os.ReadFile(s.cfg.IdentityFile)
	if err == nil {
		var identity struct {
			ClientID string `json:"client_id"`
		}
		if json.Unmarshal(raw, &identity) == nil && strings.TrimSpace(identity.ClientID) != "" {
			return strings.TrimSpace(identity.ClientID)
		}
	}
	return s.cfg.Tag
}

// findNode resolves an egress node selector. ID is authoritative and checked
// first; label is only a fallback alias. Duplicate labels are rejected rather
// than resolved arbitrarily. The caller must hold the node-table lock.
func findNode(nodes map[string]cbpcoord.Node, name string) (cbpcoord.Node, bool, error) {
	if node, ok := nodes[name]; ok {
		return node, true, nil
	}
	var matches []cbpcoord.Node
	for _, node := range nodes {
		if strings.TrimSpace(node.Label) != "" && node.Label == name {
			matches = append(matches, node)
		}
	}
	switch len(matches) {
	case 0:
		return cbpcoord.Node{}, false, nil
	case 1:
		return matches[0], true, nil
	default:
		ids := make([]string, 0, len(matches))
		for _, node := range matches {
			ids = append(ids, node.ID)
		}
		sort.Strings(ids)
		return cbpcoord.Node{}, false, fmt.Errorf("node label %q is ambiguous, matches node IDs: %s", name, strings.Join(ids, ", "))
	}
}

func (s *tagState) nodeNames() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.nodes))
	for id := range s.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		label := strings.TrimSpace(s.nodes[id].Label)
		if label == "" || label == id {
			names = append(names, id)
			continue
		}
		names = append(names, fmt.Sprintf("%s (%s)", id, label))
	}
	return strings.Join(names, ", ")
}

// cbpDialer is the data entry returned to egress_route. TCP opens one CBP
// stream per target; UDP opens one association and wraps it as a connected
// net.Conn.
type cbpDialer struct {
	mu     sync.Mutex
	client *cbpstream.Client
	cfg    cbpstream.Config
	host   string
	node   string
	closed bool
}

// ensureClient returns a live control session, replacing one that was closed
// by the node (session TTL, node restart, relay switch) with a fresh AUTH
// handshake. This mirrors the desktop cbpclient.Ensure path instead of
// routing new streams into a dead socket.
func (d *cbpDialer) ensureClient(ctx context.Context) (*cbpstream.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errors.New("cbp_proxy: dialer is closed")
	}
	if d.client != nil && d.client.Healthy() {
		return d.client, nil
	}
	if d.client != nil {
		_ = d.client.Close()
		d.client = nil
	}
	client, err := cbpstream.Dial(ctx, d.cfg)
	if err != nil {
		return nil, fmt.Errorf("cbp_proxy: reconnect node %s: %w", d.node, err)
	}
	if d.closed {
		_ = client.Close()
		return nil, errors.New("cbp_proxy: dialer is closed")
	}
	d.client = client
	return client, nil
}

func (d *cbpDialer) invalidate(client *cbpstream.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client == client {
		_ = d.client.Close()
		d.client = nil
	}
}

func isClientClosed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "client closed")
}

func (d *cbpDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	for attempt := 0; attempt < 2; attempt++ {
		client, err := d.ensureClient(ctx)
		if err != nil {
			return nil, err
		}
		var conn net.Conn
		switch {
		case network == "" || network == "tcp":
			conn, err = client.OpenStream(ctx, "tcp", addr)
		case strings.HasPrefix(network, "udp"):
			var udp *cbpstream.UDPConn
			udp, err = client.OpenUDP(ctx)
			if err == nil {
				var target *net.UDPAddr
				target, err = net.ResolveUDPAddr("udp", addr)
				if err != nil {
					_ = udp.Close()
					return nil, err
				}
				conn = &connectedUDP{UDPConn: udp, target: target}
			}
		default:
			return nil, fmt.Errorf("cbp_proxy: unsupported network %q", network)
		}
		if err == nil {
			return conn, nil
		}
		if attempt == 1 || !isClientClosed(err) {
			return nil, err
		}
		d.invalidate(client)
	}
	return nil, errors.New("cbp_proxy: CBP stream session is not available")
}

func (d *cbpDialer) Probe(ctx context.Context) error {
	_, err := d.ensureClient(ctx)
	return err
}

func (d *cbpDialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	client := d.client
	d.client = nil
	d.mu.Unlock()
	if client == nil {
		return nil
	}
	return client.Close()
}

// connectedUDP adapts cbpstream.UDPConn (a net.PacketConn) to net.Conn for
// callers that already know the single destination.
type connectedUDP struct {
	*cbpstream.UDPConn
	target *net.UDPAddr
}

func (c *connectedUDP) Read(p []byte) (int, error) {
	n, _, err := c.UDPConn.ReadFrom(p)
	return n, err
}

func (c *connectedUDP) Write(p []byte) (int, error) {
	return c.UDPConn.WriteTo(p, c.target)
}

func (c *connectedUDP) RemoteAddr() net.Addr { return c.target }
