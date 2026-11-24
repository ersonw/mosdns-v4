// Package cbpstream carries TCP streams over an authenticated CBP control
// session. It is the app-internal proxy path used when a packet tunnel
// Network Extension is not installed. TCP can optionally use the node's QUIC
// data-stream API; raw IP packets still use the control-stream mirror in this
// package when the node's QUIC data port is unreachable.
package cbpstream

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
	"github.com/ersonw/mosdns-v4/pkg/cbpidentity"
)

type Config struct {
	ControlAddr                string
	TLSConfig                  *tls.Config
	Token                      string
	DeviceID                   string
	PrivateKey                 ed25519.PrivateKey
	DialTimeout                time.Duration
	IdentityFile               string
	IdentityServerURL          string
	IdentityToken              string
	IdentityInsecureSkipVerify bool
	ClientID                   string
	Regions                    []string

	// RelayAddr routes the CBP control stream through the main server on 9443
	// instead of dialing the node's TCP control port directly. RelayNodeID
	// selects the destination node.
	RelayAddr      string
	RelayNodeID    string
	RelayTLSConfig *tls.Config

	// UseDataStreams opts into logical TCP streams over the node's QUIC data
	// connection. It is false by default, so the stable control stream remains
	// the default even when a node advertises the capability.
	UseDataStreams bool
	// DataAddrs is the main server's node data-address list, used when the
	// SESSION_READY relay response omits data_addr. Entries are host:port.
	DataAddrs []string
	// DataDialTimeout bounds one QUIC data-endpoint handshake. It is separate
	// from DialTimeout so a blocked UDP port does not delay control login.
	DataDialTimeout time.Duration
}

type flushControlConn struct {
	*tls.Conn
	buf *cbp.BufferedConn
}

func (c *flushControlConn) Flush() error { return c.buf.Flush() }

type Client struct {
	cfg       Config
	control   net.Conn
	ready     cbp.SessionReady
	controlMu sync.Mutex
	binary    bool

	pendingMu sync.Mutex
	pending   map[uint64]chan openAck

	streamsMu sync.Mutex
	streams   map[uint64]*Conn
	// UDP associations are kept separately because their frames carry one
	// address-prefixed datagram and must not be merged into the TCP byte queue.
	udpStreams map[uint64]*UDPConn

	pingMu      sync.Mutex
	pingStateMu sync.Mutex
	pingPending map[uint64]chan struct{}
	pingSeq     uint64

	resolveMu      sync.Mutex
	resolvePending map[uint64]chan cbp.ResolveResponse

	// rawControl carries complete IPv4/IPv6 packets over the authenticated
	// control stream. It is the fallback when the node's QUIC data port is
	// unreachable from the client (for example when an upstream NAT forwards
	// only TCP 8443), and it can traverse the main-server relay unchanged.
	rawMu         sync.Mutex
	rawReady      chan struct{}
	rawOnce       sync.Once
	rawPackets    chan []byte
	rawErr        error
	rawTunnelIPv4 netip.Addr
	rawTunnelIPv6 netip.Addr

	dataMu            sync.RWMutex
	data              *dataPlane
	dataErr           error
	dataStreamsBroken bool

	nextID    uint64
	closed    chan struct{}
	closeOnce sync.Once
}

type openRequest struct {
	StreamID      uint64 `json:"stream_id"`
	Network       string `json:"network"`
	Address       string `json:"address"`
	ReceiveWindow int    `json:"receive_window,omitempty"`
}

type openAck struct {
	StreamID      uint64 `json:"stream_id"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	ReceiveWindow int    `json:"receive_window,omitempty"`
}

type pingRequest struct {
	ID uint64 `json:"id"`
}

// rawPacketFrame is the JSON envelope for RAW_PACKET control frames. The IP
// packet itself is base64 encoded so the control stream stays a sequence of
// ordinary framed JSON documents and the relay needs no special case.
type rawPacketFrame struct {
	Data string `json:"data"`
}

const (
	streamCreditBatch = 256 << 10
	// sessionHeartbeatInterval keeps the server-side control-session read
	// deadline alive. The CBP node closes a session after SessionTTL without
	// any control frame; desktop clients keep traffic flowing, while an idle
	// mosdns egress can sit silent for minutes. PING is acknowledged by the
	// node and refreshes the same expiry as stream traffic.
	sessionHeartbeatInterval = 20 * time.Second
	// sessionHeartbeatPingID is outside the PingProxy sequence. PONG with a
	// nonzero ID only matches a pending probe; zero is treated as a legacy
	// empty PONG and would steal the in-flight PingProxy result.
	sessionHeartbeatPingID uint64 = ^uint64(0)
)

type relayAuth struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type relayOpen struct {
	NodeID string `json:"node_id"`
}

func relayPreamble(conn net.Conn, cfg Config) (string, error) {
	env, err := cbp.ReadControlFrame(conn)
	if err != nil {
		return "", fmt.Errorf("cbpstream: relay hello: %w", err)
	}
	if env.Type != "HELLO" {
		return "", fmt.Errorf("cbpstream: relay expected HELLO, got %s", env.Type)
	}
	var hello struct {
		Protocol string `json:"protocol"`
		Nonce    string `json:"nonce"`
	}
	if err := cbp.UnmarshalPayload(env.Payload, &hello); err != nil {
		return "", err
	}
	if hello.Protocol != "cbp-relay/1" {
		return "", fmt.Errorf("cbpstream: relay unexpected protocol %q", hello.Protocol)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(hello.Nonce)
	if err != nil {
		return "", fmt.Errorf("cbpstream: relay bad nonce: %w", err)
	}
	clientID := cfg.ClientID
	if clientID == "" {
		clientID = cfg.DeviceID
	}
	pub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	auth := relayAuth{
		ClientID:  clientID,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(cfg.PrivateKey, nonce)),
	}
	raw, err := cbp.MarshalPayload(auth)
	if err != nil {
		return "", err
	}
	if err := cbp.WriteControlFrame(conn, cbp.Envelope{Type: "CLIENT_AUTH", Payload: raw}); err != nil {
		return "", err
	}
	env, err = cbp.ReadControlFrame(conn)
	if err != nil {
		return "", fmt.Errorf("cbpstream: relay auth result: %w", err)
	}
	if env.Type == "ERROR" {
		var em cbp.ErrorMessage
		_ = cbp.UnmarshalPayload(env.Payload, &em)
		return "", fmt.Errorf("cbpstream: relay auth failed: %s: %s", em.Code, em.Message)
	}
	if env.Type != "RELAY_READY" {
		return "", fmt.Errorf("cbpstream: relay expected RELAY_READY, got %s", env.Type)
	}
	open := relayOpen{NodeID: cfg.RelayNodeID}
	raw, err = cbp.MarshalPayload(open)
	if err != nil {
		return "", err
	}
	if err := cbp.WriteControlFrame(conn, cbp.Envelope{Type: "RELAY_OPEN", Payload: raw}); err != nil {
		return "", err
	}
	env, err = cbp.ReadControlFrame(conn)
	if err != nil {
		return "", fmt.Errorf("cbpstream: relay open result: %w", err)
	}
	if env.Type == "RELAY_ERROR" || env.Type == "ERROR" {
		var em cbp.ErrorMessage
		_ = cbp.UnmarshalPayload(env.Payload, &em)
		return "", fmt.Errorf("cbpstream: relay open failed: %s: %s", em.Code, em.Message)
	}
	if env.Type != "RELAY_OPENED" {
		return "", fmt.Errorf("cbpstream: relay expected RELAY_OPENED, got %s", env.Type)
	}
	var opened struct {
		NodeID         string `json:"node_id"`
		StreamProtocol string `json:"stream_protocol,omitempty"`
	}
	if err := cbp.UnmarshalPayload(env.Payload, &opened); err != nil {
		return "", err
	}
	return opened.StreamProtocol, nil
}

type dataFrame struct {
	StreamID uint64 `json:"stream_id"`
	Data     []byte `json:"data,omitempty"`
	FIN      bool   `json:"fin,omitempty"`
}

type closeFrame struct {
	StreamID uint64 `json:"stream_id"`
}

func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.RelayAddr == "" && cfg.ControlAddr == "" {
		return nil, errors.New("cbpstream: control or relay address is required")
	}
	if cfg.RelayAddr != "" && cfg.RelayNodeID == "" {
		return nil, errors.New("cbpstream: relay node id is required")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if len(cfg.PrivateKey) == 0 && cfg.IdentityFile != "" {
		id, err := identity.LoadOrIssueClient(ctx, identity.ClientIdentityConfig{
			FilePath:           cfg.IdentityFile,
			ServerURL:          cfg.IdentityServerURL,
			Token:              cfg.IdentityToken,
			ClientID:           cfg.ClientID,
			InsecureSkipVerify: cfg.IdentityInsecureSkipVerify,
			Regions:            cfg.Regions,
		})
		if err != nil {
			return nil, err
		}
		seed, err := base64.RawURLEncoding.DecodeString(id.PrivateKey)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("cbpstream: invalid client identity seed")
		}
		cfg.PrivateKey = ed25519.NewKeyFromSeed(seed)
		if cfg.DeviceID == "" {
			cfg.DeviceID = id.ClientID
		}
	}
	if len(cfg.PrivateKey) == 0 {
		return nil, errors.New("cbpstream: private key or identity file is required")
	}
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	relayMode := cfg.RelayAddr != ""
	baseTLS := cfg.TLSConfig
	if relayMode && cfg.RelayTLSConfig != nil {
		baseTLS = cfg.RelayTLSConfig
	}
	controlTLS := baseTLS.Clone()
	if relayMode {
		controlTLS.NextProtos = []string{"cbp-relay/1"}
	} else {
		controlTLS.NextProtos = []string{cbp.ALPNControlV2, cbp.ALPNControl}
	}
	dialAddr := cfg.ControlAddr
	if relayMode {
		dialAddr = cfg.RelayAddr
	}
	if controlTLS.ServerName == "" && !controlTLS.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(dialAddr)
		if err == nil {
			controlTLS.ServerName = host
		}
	}
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, fmt.Errorf("cbpstream: dial control: %w", err)
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetReadBuffer(4 << 20)
		_ = tcp.SetWriteBuffer(4 << 20)
	}
	buf := cbp.NewBufferedConn(raw, 256<<10)
	conn := tls.Client(buf, controlTLS)
	hctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	err = conn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("cbpstream: control TLS: %w", err)
	}
	// The node can queue a new session behind its admission pool for up to
	// five minutes. The control handshake must honor the caller's deadline so
	// a saturated node cannot pin a mosdns egress goroutine indefinitely.
	setHandshakeDeadline := func() error {
		deadline := time.Now().Add(cfg.DialTimeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		return conn.SetDeadline(deadline)
	}
	if err := setHandshakeDeadline(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	relayProtocol := ""
	if relayMode {
		relayProtocol, err = relayPreamble(conn, cfg)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err := setHandshakeDeadline(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	env, err := cbp.ReadControlFrame(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: read HELLO_ACK: %w", err)
	}
	if env.Type == "ERROR" {
		var em cbp.ErrorMessage
		_ = cbp.UnmarshalPayload(env.Payload, &em)
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: pre-auth error: %s: %s", em.Code, em.Message)
	}
	if env.Type != "HELLO_ACK" {
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: expected HELLO_ACK, got %s", env.Type)
	}
	var hello cbp.HelloAck
	if err := cbp.UnmarshalPayload(env.Payload, &hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(hello.Nonce)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: bad nonce: %w", err)
	}
	pub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	auth := cbp.AuthRequest{
		Token:     cfg.Token,
		DeviceID:  cfg.DeviceID,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(cfg.PrivateKey, nonce)),
	}
	rawPayload, err := cbp.MarshalPayload(auth)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := cbp.WriteControlFrame(conn, cbp.Envelope{Type: "AUTH", Payload: rawPayload}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	env, err = cbp.ReadControlFrame(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: read AUTH result: %w", err)
	}
	if env.Type == "ERROR" {
		var em cbp.ErrorMessage
		_ = cbp.UnmarshalPayload(env.Payload, &em)
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: auth failed: %s: %s", em.Code, em.Message)
	}
	if env.Type != "SESSION_READY" {
		_ = conn.Close()
		return nil, fmt.Errorf("cbpstream: expected SESSION_READY, got %s", env.Type)
	}
	var ready cbp.SessionReady
	if err := cbp.UnmarshalPayload(env.Payload, &ready); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	control := &flushControlConn{Conn: conn, buf: buf}
	streamV2 := conn.ConnectionState().NegotiatedProtocol == cbp.ALPNControlV2
	if relayMode {
		// The outer relay TLS only speaks cbp-relay/1. The node's inner control
		// protocol is reported by RELAY_OPENED; without this, a v2 node waits
		// forever for STREAM_CREDIT after its initial 2 MiB window.
		streamV2 = relayProtocol == cbp.ALPNControlV2
	}
	client := &Client{
		cfg:            cfg,
		control:        control,
		ready:          ready,
		pending:        make(map[uint64]chan openAck),
		streams:        make(map[uint64]*Conn),
		udpStreams:     make(map[uint64]*UDPConn),
		pingPending:    make(map[uint64]chan struct{}),
		resolvePending: make(map[uint64]chan cbp.ResolveResponse),
		closed:         make(chan struct{}),
		binary:         streamV2,
		rawReady:       make(chan struct{}),
		rawPackets:     make(chan []byte, 64),
	}
	go client.readLoop()
	go client.heartbeatLoop()
	if cfg.UseDataStreams && ready.DataStreams {
		if err := client.attachData(ctx); err != nil {
			client.dataMu.Lock()
			client.dataErr = err
			client.dataMu.Unlock()
		}
	}
	return client, nil
}

func (c *Client) Ready() cbp.SessionReady { return c.ready }

// Healthy reports whether the control session is still open. The read loop
// closes it on EOF or protocol failure, so callers can discard a cached client
// after a proxy-node restart instead of routing new streams into a dead socket.
func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(sessionHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			if !c.Healthy() {
				return
			}
			if err := c.send("PING", pingRequest{ID: sessionHeartbeatPingID}); err != nil {
				c.close()
				return
			}
		}
	}
}

func (c *Client) Healthy() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

func (c *Client) flush() error {
	if f, ok := c.control.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func (c *Client) send(typ string, payload any) error {
	raw, err := cbp.MarshalPayload(payload)
	if err != nil {
		return err
	}
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	if err := cbp.WriteControlFrame(c.control, cbp.Envelope{Type: typ, Payload: raw}); err != nil {
		return err
	}
	return c.flush()
}

func (c *Client) sendStreamData(id uint64, data []byte) error {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	if err := cbp.WriteStreamFrame(c.control, cbp.StreamFrame{
		Kind:     cbp.StreamFrameData,
		StreamID: id,
		Data:     data,
	}); err != nil {
		return err
	}
	return c.flush()
}

func (c *Client) sendStreamCredit(id uint64, credit int) error {
	if credit <= 0 {
		return nil
	}
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	if err := cbp.WriteStreamFrame(c.control, cbp.StreamFrame{
		Kind:     cbp.StreamFrameCredit,
		StreamID: id,
		Credit:   uint32(credit),
	}); err != nil {
		return err
	}
	return c.flush()
}

// EnableRawControl asks the node to mirror its tunnel packets onto the already
// authenticated control stream. The node acknowledges with RAW_READY only
// after it has switched its egress path, so a caller cannot race a packet into
// a channel the peer is not reading.
func (c *Client) EnableRawControl(ctx context.Context) error {
	c.rawMu.Lock()
	select {
	case <-c.rawReady:
		c.rawMu.Unlock()
		return nil
	default:
	}
	if c.rawErr != nil {
		err := c.rawErr
		c.rawMu.Unlock()
		return err
	}
	c.rawMu.Unlock()

	if err := c.send("RAW_OPEN", struct{}{}); err != nil {
		c.setRawError(err)
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		c.rawMu.Lock()
		err := c.rawErr
		c.rawMu.Unlock()
		if err == nil {
			err = errors.New("cbpstream: client closed while enabling raw control")
		}
		return err
	case <-c.rawReady:
		return nil
	}
}

// applyRawReady records the tunnel addresses the node assigns to this session.
// The reader closes rawReady only after the fields are stored, so a caller that
// returns from EnableRawControl always sees the address it must use as the raw
// packet source.
func (c *Client) applyRawReady(payload []byte) {
	var ready struct {
		TunnelIPv4 string `json:"tunnel_ipv4"`
		TunnelIPv6 string `json:"tunnel_ipv6"`
	}
	if json.Unmarshal(payload, &ready) == nil {
		v4, _ := netip.ParseAddr(strings.TrimSpace(ready.TunnelIPv4))
		v6, _ := netip.ParseAddr(strings.TrimSpace(ready.TunnelIPv6))
		c.rawMu.Lock()
		if v4.IsValid() {
			c.rawTunnelIPv4 = v4.Unmap()
		}
		if v6.IsValid() {
			c.rawTunnelIPv6 = v6.Unmap()
		}
		c.rawMu.Unlock()
	}
	c.rawOnce.Do(func() { close(c.rawReady) })
}

// RawTunnelIPv4 is the source address the node accepts on RAW_PACKET frames.
// It is valid only after EnableRawControl has returned successfully.
func (c *Client) RawTunnelIPv4() netip.Addr {
	c.rawMu.Lock()
	defer c.rawMu.Unlock()
	return c.rawTunnelIPv4
}

func (c *Client) setRawError(err error) {
	c.rawMu.Lock()
	c.rawErr = err
	c.rawMu.Unlock()
}

// WriteRawPacket sends one complete IPv4/IPv6 packet to the node tunnel. The
// frame is intentionally limited to the CBP MTU; callers must not hand it a
// reassembled packet larger than the tunnel can carry.
func (c *Client) WriteRawPacket(packet []byte) error {
	if len(packet) == 0 || len(packet) > 1500 {
		return fmt.Errorf("cbpstream: raw packet length %d outside 1..1500", len(packet))
	}
	select {
	case <-c.rawReady:
	default:
		return errors.New("cbpstream: raw control is not enabled")
	}
	return c.send("RAW_PACKET", rawPacketFrame{Data: base64.RawStdEncoding.EncodeToString(packet)})
}

// ReadRawPacket waits for the next packet the node emitted for this session.
// A slow packet-tunnel consumer drops the oldest queued packet instead of
// stalling the shared control reader.
func (c *Client) ReadRawPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("cbpstream: client closed")
	case packet := <-c.rawPackets:
		return packet, nil
	}
}

func (c *Client) deliverRawPacket(packet []byte) {
	if len(packet) == 0 {
		return
	}
	select {
	case c.rawPackets <- packet:
	default:
		// The control stream must keep draining ACKs and stream frames even
		// when the packet tunnel is temporarily behind.
	}
}

func (c *Client) nextStreamID() uint64 {
	c.streamsMu.Lock()
	c.nextID++
	id := c.nextID
	c.streamsMu.Unlock()
	return id
}

// openStreamID performs STREAM_OPEN for an ID whose local stream object has
// already been registered. Registering first matters: a fast upstream can
// send the first response frame immediately after STREAM_ACK.
func (c *Client) openStreamID(ctx context.Context, id uint64, network, address string) (openAck, error) {
	ackCh := make(chan openAck, 1)
	c.pendingMu.Lock()
	c.pending[id] = ackCh
	c.pendingMu.Unlock()
	if err := c.send("STREAM_OPEN", openRequest{
		StreamID:      id,
		Network:       network,
		Address:       address,
		ReceiveWindow: cbp.DefaultStreamWindow,
	}); err != nil {
		c.removePending(id)
		return openAck{}, err
	}
	select {
	case <-ctx.Done():
		c.removePending(id)
		// The node's stream pool may have queued this STREAM_OPEN. Close it
		// instead of leaving a stream that the caller has already abandoned.
		if c.Healthy() {
			_ = c.send("STREAM_CLOSE", closeFrame{StreamID: id})
		}
		return openAck{}, ctx.Err()
	case <-c.closed:
		c.removePending(id)
		return openAck{}, errors.New("cbpstream: client closed")
	case ack := <-ackCh:
		c.removePending(id)
		if !ack.OK {
			return ack, fmt.Errorf("cbpstream: open %s: %s", address, ack.Error)
		}
		return ack, nil
	}
}

// ResolveHost asks the node to resolve host at the exit point. The local
// process never calls getaddrinfo for this name.
func (c *Client) ResolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, errors.New("cbpstream: empty hostname")
	}
	select {
	case <-c.closed:
		return nil, errors.New("cbpstream: client closed")
	default:
	}
	id := c.nextStreamID()
	ch := make(chan cbp.ResolveResponse, 1)
	c.resolveMu.Lock()
	c.resolvePending[id] = ch
	c.resolveMu.Unlock()
	defer func() {
		c.resolveMu.Lock()
		delete(c.resolvePending, id)
		c.resolveMu.Unlock()
	}()
	if err := c.send("RESOLVE", cbp.ResolveRequest{ID: id, Host: host}); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("cbpstream: client closed")
	case resp := <-ch:
		if resp.Error != "" {
			return nil, fmt.Errorf("cbpstream: resolve %s: %s", host, resp.Error)
		}
		ips := make([]net.IP, 0, len(resp.Addresses))
		for _, raw := range resp.Addresses {
			if ip := net.ParseIP(raw); ip != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("cbpstream: resolve %s: no addresses", host)
		}
		return ips, nil
	}
}

func (c *Client) OpenStream(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" {
		return nil, fmt.Errorf("cbpstream: unsupported network %q", network)
	}
	select {
	case <-c.closed:
		return nil, errors.New("cbpstream: client closed")
	default:
	}
	id := c.nextStreamID()
	conn := newConn(c, id, cbp.DefaultStreamWindow)
	c.streamsMu.Lock()
	c.streams[id] = conn
	c.streamsMu.Unlock()
	ack, err := c.openStreamID(ctx, id, "tcp", address)
	if err != nil {
		c.removeConn(id)
		return nil, err
	}
	if c.binary {
		conn.setSendWindow(normalizeWindow(ack.ReceiveWindow))
	}
	return conn, nil
}

// OpenUDP opens one unconnected UDP association over the CBP control session.
// Each CBP STREAM_DATA frame carries exactly one address-prefixed datagram.
func (c *Client) OpenUDP(ctx context.Context) (*UDPConn, error) {
	select {
	case <-c.closed:
		return nil, errors.New("cbpstream: client closed")
	default:
	}
	id := c.nextStreamID()
	conn := newUDPConn(c, id)
	c.streamsMu.Lock()
	if c.udpStreams == nil {
		c.udpStreams = make(map[uint64]*UDPConn)
	}
	c.udpStreams[id] = conn
	c.streamsMu.Unlock()
	if _, err := c.openStreamID(ctx, id, "udp", "0.0.0.0:0"); err != nil {
		c.removeUDPConn(id)
		return nil, err
	}
	return conn, nil
}

// PingProxy measures the desktop-to-node control-path RTT and packet loss
// through the already authenticated CBP session. It is used when the raw-IP
// QUIC data plane is unavailable, as with relay-only public connections.
// It never probes the node's public address with the system ICMP stack.
func (c *Client) PingProxy(ctx context.Context, count int) (cbp.LatencyResult, error) {
	c.pingMu.Lock()
	defer c.pingMu.Unlock()

	if count <= 0 {
		count = 5
	}
	select {
	case <-c.closed:
		return cbp.LatencyResult{}, errors.New("cbpstream: client closed")
	default:
	}
	result := cbp.LatencyResult{Count: count}
	var total time.Duration
	for seq := 0; seq < count; seq++ {
		id, ch := c.registerPing()
		start := time.Now()
		if err := c.send("PING", pingRequest{ID: id}); err != nil {
			c.unregisterPing(id)
			return result, err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.unregisterPing(id)
			result.LossPercent = float64(count-result.Received) * 100 / float64(count)
			return result, ctx.Err()
		case <-c.closed:
			timer.Stop()
			c.unregisterPing(id)
			result.LossPercent = float64(count-result.Received) * 100 / float64(count)
			return result, errors.New("cbpstream: client closed")
		case <-timer.C:
			c.unregisterPing(id)
			continue
		case <-ch:
			rtt := time.Since(start)
			result.Received++
			result.Last = rtt
			total += rtt
			if result.Min == 0 || rtt < result.Min {
				result.Min = rtt
			}
			if rtt > result.Max {
				result.Max = rtt
			}
		}
	}
	if result.Received > 0 {
		result.Avg = total / time.Duration(result.Received)
	}
	result.LossPercent = float64(count-result.Received) * 100 / float64(count)
	return result, nil
}

func (c *Client) registerPing() (uint64, chan struct{}) {
	c.pingStateMu.Lock()
	defer c.pingStateMu.Unlock()
	c.pingSeq++
	id := c.pingSeq
	ch := make(chan struct{}, 1)
	c.pingPending[id] = ch
	return id, ch
}

func (c *Client) unregisterPing(id uint64) {
	c.pingStateMu.Lock()
	delete(c.pingPending, id)
	c.pingStateMu.Unlock()
}

func (c *Client) deliverPong(payload []byte) {
	var reply pingRequest
	hasID := false
	if err := json.Unmarshal(payload, &reply); err == nil && reply.ID != 0 {
		hasID = true
	}

	c.pingStateMu.Lock()
	defer c.pingStateMu.Unlock()
	if hasID {
		if ch := c.pingPending[reply.ID]; ch != nil {
			delete(c.pingPending, reply.ID)
			close(ch)
		}
		return
	}
	// Older nodes reply with an empty PONG. Only one probe is in flight at a
	// time, so it can be safely matched to the single pending entry.
	for id, ch := range c.pingPending {
		delete(c.pingPending, id)
		close(ch)
		break
	}
}

func normalizeWindow(window int) int {
	if window <= 0 {
		return cbp.DefaultStreamWindow
	}
	return window
}

func (c *Client) deliverStream(id uint64, data []byte, fin bool) {
	c.streamsMu.Lock()
	stream := c.streams[id]
	udp := c.udpStreams[id]
	c.streamsMu.Unlock()
	if stream != nil {
		stream.deliver(data, fin)
		return
	}
	if udp != nil {
		udp.deliver(data, fin)
	}
}

func (c *Client) removeConn(id uint64) {
	c.streamsMu.Lock()
	stream := c.streams[id]
	delete(c.streams, id)
	c.streamsMu.Unlock()
	if stream != nil {
		stream.markRemoteClosed()
	}
}

func (c *Client) removeUDPConn(id uint64) {
	c.streamsMu.Lock()
	stream := c.udpStreams[id]
	delete(c.udpStreams, id)
	c.streamsMu.Unlock()
	if stream != nil {
		stream.markRemoteClosed()
	}
}

func (c *Client) removePending(id uint64) {
	c.pendingMu.Lock()
	delete(c.pending, id)
	c.pendingMu.Unlock()
}

func (c *Client) readLoop() {
	defer c.close()
	for {
		env, err := cbp.ReadControlFrame(c.control)
		if err != nil {
			return
		}
		switch env.Type {
		case "STREAM_ACK":
			var ack openAck
			if json.Unmarshal(env.Payload, &ack) == nil {
				c.pendingMu.Lock()
				ch := c.pending[ack.StreamID]
				c.pendingMu.Unlock()
				if ch != nil {
					select {
					case ch <- ack:
					default:
					}
				}
			}
		case "STREAM_DATA":
			var frame dataFrame
			if json.Unmarshal(env.Payload, &frame) != nil {
				continue
			}
			c.deliverStream(frame.StreamID, frame.Data, frame.FIN)
		case "STREAM_BINARY":
			if env.Stream == nil {
				continue
			}
			frame := *env.Stream
			switch frame.Kind {
			case cbp.StreamFrameData:
				c.deliverStream(frame.StreamID, frame.Data, false)
			case cbp.StreamFrameCredit:
				c.streamsMu.Lock()
				stream := c.streams[frame.StreamID]
				c.streamsMu.Unlock()
				if stream != nil {
					stream.addSendCredit(int(frame.Credit))
				}
			case cbp.StreamFrameFIN:
				c.deliverStream(frame.StreamID, nil, true)
			}
		case "STREAM_CLOSE":
			var frame closeFrame
			if json.Unmarshal(env.Payload, &frame) == nil {
				c.closeStream(frame.StreamID)
			}
		case "RESOLVE_RESULT":
			var resp cbp.ResolveResponse
			if json.Unmarshal(env.Payload, &resp) == nil {
				c.resolveMu.Lock()
				ch := c.resolvePending[resp.ID]
				delete(c.resolvePending, resp.ID)
				c.resolveMu.Unlock()
				if ch != nil {
					select {
					case ch <- resp:
					default:
					}
				}
			}
		case "RAW_READY":
			c.applyRawReady(env.Payload)
		case "RAW_PACKET":
			var frame rawPacketFrame
			if json.Unmarshal(env.Payload, &frame) != nil || frame.Data == "" {
				continue
			}
			packet, err := base64.RawStdEncoding.DecodeString(frame.Data)
			if err != nil || len(packet) == 0 {
				continue
			}
			c.deliverRawPacket(packet)
		case "PONG":
			c.deliverPong(env.Payload)
		case "CLOSE", "ERROR":
			return
		}
	}
}

func (c *Client) closeStream(id uint64) {
	c.streamsMu.Lock()
	stream := c.streams[id]
	udp := c.udpStreams[id]
	delete(c.streams, id)
	delete(c.udpStreams, id)
	c.streamsMu.Unlock()
	if stream != nil {
		stream.markRemoteClosed()
	}
	if udp != nil {
		udp.markRemoteClosed()
	}
}

func (c *Client) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.closeData()
		_ = c.control.Close()
		c.streamsMu.Lock()
		streams := c.streams
		udpStreams := c.udpStreams
		c.streams = make(map[uint64]*Conn)
		c.udpStreams = make(map[uint64]*UDPConn)
		c.streamsMu.Unlock()
		for _, stream := range streams {
			stream.markRemoteClosed()
		}
		for _, stream := range udpStreams {
			stream.markRemoteClosed()
		}
	})
}

func (c *Client) Close() error {
	c.close()
	return nil
}

// Conn is a net.Conn backed by CBP STREAM frames. Deadline methods are
// accepted but not enforced because the underlying control session owns I/O
// timeouts.
type Conn struct {
	client *Client
	id     uint64

	mu            sync.Mutex
	cond          *sync.Cond
	chunks        [][]byte
	consumed      int
	fin           bool
	closed        bool
	sendCredit    int
	creditPending int
}

func newConn(client *Client, id uint64, receiveWindow int) *Conn {
	conn := &Conn{client: client, id: id, creditPending: 0}
	conn.cond = sync.NewCond(&conn.mu)
	return conn
}

func (c *Conn) setSendWindow(window int) {
	c.mu.Lock()
	c.sendCredit = window
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *Conn) addSendCredit(credit int) {
	if credit <= 0 {
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.sendCredit += credit
		c.cond.Broadcast()
	}
	c.mu.Unlock()
}

func (c *Conn) deliver(data []byte, fin bool) {
	c.mu.Lock()
	if !c.closed && len(data) > 0 {
		// Keep each frame as its own chunk. A single growing buffer copies the
		// whole response on every append, which is the dominant cost for large
		// page bodies over CBP.
		c.chunks = append(c.chunks, data)
	}
	if fin {
		c.fin = true
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *Conn) markRemoteClosed() {
	c.mu.Lock()
	c.fin = true
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	for len(c.chunks) == 0 && !c.fin && !c.closed {
		c.cond.Wait()
	}
	if len(c.chunks) > 0 {
		chunk := c.chunks[0]
		n := copy(p, chunk[c.consumed:])
		c.consumed += n
		if c.consumed >= len(chunk) {
			c.chunks[0] = nil
			c.chunks = c.chunks[1:]
			c.consumed = 0
		}
		credit := 0
		if c.client.binary {
			c.creditPending += n
			if c.creditPending >= streamCreditBatch {
				credit = c.creditPending
				c.creditPending = 0
			}
		}
		c.mu.Unlock()
		if credit > 0 {
			_ = c.client.sendStreamCredit(c.id, credit)
		}
		return n, nil
	}
	fin, closed := c.fin, c.closed
	c.mu.Unlock()
	if fin {
		return 0, io.EOF
	}
	if closed {
		return 0, net.ErrClosed
	}
	return 0, errors.New("cbpstream: stream closed")
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.client.binary {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		for offset := 0; offset < len(p); offset += cbp.PreferredStreamChunk {
			end := offset + cbp.PreferredStreamChunk
			if end > len(p) {
				end = len(p)
			}
			if err := c.client.send("STREAM_DATA", dataFrame{StreamID: c.id, Data: p[offset:end]}); err != nil {
				return offset, err
			}
		}
		return len(p), nil
	}
	written := 0
	for written < len(p) {
		c.mu.Lock()
		for c.sendCredit <= 0 && !c.closed {
			c.cond.Wait()
		}
		if c.closed {
			c.mu.Unlock()
			return written, net.ErrClosed
		}
		n := len(p) - written
		if n > cbp.PreferredStreamChunk {
			n = cbp.PreferredStreamChunk
		}
		if n > c.sendCredit {
			n = c.sendCredit
		}
		c.sendCredit -= n
		c.mu.Unlock()
		if err := c.client.sendStreamData(c.id, p[written:written+n]); err != nil {
			c.mu.Lock()
			c.closed = true
			c.cond.Broadcast()
			c.mu.Unlock()
			return written, err
		}
		written += n
	}
	return written, nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	_ = c.client.send("STREAM_CLOSE", closeFrame{StreamID: c.id})
	c.client.streamsMu.Lock()
	delete(c.client.streams, c.id)
	c.client.streamsMu.Unlock()
	return nil
}

func (c *Conn) LocalAddr() net.Addr              { return dummyAddr("cbp-local") }
func (c *Conn) RemoteAddr() net.Addr             { return dummyAddr(fmt.Sprintf("cbp-stream-%d", c.id)) }
func (c *Conn) SetDeadline(time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "cbp" }
func (a dummyAddr) String() string  { return string(a) }
