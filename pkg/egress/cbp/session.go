package cbp

// Session is a live CBP/1 session: one TLS control connection, one QUIC
// datagram connection, and the reliability state for both directions.

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Config describes one CBP session.
type Config struct {
	// ControlAddr is the edge control endpoint, host:port.
	ControlAddr string
	// Token is the deployment token (the server's auth_token). A standalone
	// identity bundle supplies it when this field is empty.
	Token string
	// IdentityFile holds either a flat server-issued key pair or a portable
	// bundle written by a standalone node's `cbpserver keygen`.
	IdentityFile string
	// IdentityServerURL issues a key pair on first use for a central node.
	// A standalone bundle never contacts it.
	IdentityServerURL string
	// IdentityToken authenticates the issue request.
	IdentityToken string
	// ClientID labels the key pair on the server. A bundle fills it.
	ClientID string
	// DeviceID is the device label sent with AUTH. A bundle defaults it to the
	// client id, matching the lease the standalone node stores.
	DeviceID string
	// Regions selects the proxy permission set at issue time.
	Regions []string
	// ServerName overrides the TLS name; empty uses the control host.
	ServerName string
	// InsecureSkipVerify accepts any certificate.
	InsecureSkipVerify bool
	// CACertFile pins a private CA bundle.
	CACertFile string
	// DialTimeout bounds each dial step.
	DialTimeout time.Duration
}

// Session is the live connection.
type Session struct {
	cfg     Config
	control net.Conn
	data    quic.Connection
	ready   SessionReady
	readyMu sync.RWMutex

	sessionID uint64

	recvBlocks *AckTracker
	reasm      *Reassembler
	sendWindow *SendWindow

	sendMu       sync.Mutex
	nextPacketID uint64
	nextBlockID  uint64

	dataMu sync.Mutex

	repairMu   sync.Mutex
	lastRepair time.Time

	incoming  chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	statsMu sync.Mutex
	stats   localStats
}

type localStats struct {
	sentPackets    uint64
	sentBlocks     uint64
	receivedBlocks uint64
	reassembled    uint64
	drops          uint64
}

// Dial opens the control session, authenticates it with the issued key, and
// binds the QUIC datagram plane.
func Dial(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}

	key, meta, err := resolveIdentity(ctx, &cfg)
	if err != nil {
		return nil, err
	}
	if cfg.ControlAddr == "" {
		cfg.ControlAddr = endpointAddress(meta.ControlEndpoint)
	}
	if cfg.ControlAddr == "" {
		return nil, errors.New("cbp: control address is required")
	}

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.ControlAddr)
	if err != nil {
		return nil, fmt.Errorf("cbp: dial control: %w", err)
	}
	if tcpConn, ok := raw.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(1 << 20)
		_ = tcpConn.SetWriteBuffer(1 << 20)
	}
	controlTLS := tlsConfig.Clone()
	controlTLS.NextProtos = []string{ALPNControl}
	conn := tls.Client(raw, controlTLS)
	hctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	err = conn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("cbp: control TLS: %w", err)
	}

	ready, err := authenticate(conn, cfg.Token, cfg.DeviceID, key)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	dataTLS := tlsConfig.Clone()
	dataTLS.NextProtos = []string{ALPNData}
	qconn, err := dialDataCandidates(ctx, ready, dataTLS, cfg.DialTimeout)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cbp: dial data: %w", err)
	}
	if !qconn.ConnectionState().SupportsDatagrams {
		_ = qconn.CloseWithError(1, "server does not support datagrams")
		_ = conn.Close()
		return nil, errors.New("cbp: server does not support QUIC datagrams")
	}

	bindToken, err := decodeBindToken(ready.DataToken)
	if err != nil {
		_ = qconn.CloseWithError(1, "bad data token")
		_ = conn.Close()
		return nil, err
	}
	bind := DataPacket{Type: DataTypeBind, SessionID: ready.SessionID, FragCount: 1, Payload: bindToken}
	buf, err := bind.Encode()
	if err != nil {
		_ = qconn.CloseWithError(1, "bad bind")
		_ = conn.Close()
		return nil, err
	}
	if err := qconn.SendMessage(buf); err != nil {
		_ = qconn.CloseWithError(1, "bind send failed")
		_ = conn.Close()
		return nil, fmt.Errorf("cbp: send bind: %w", err)
	}

	s := &Session{
		cfg:        cfg,
		control:    conn,
		data:       qconn,
		ready:      ready,
		sessionID:  ready.SessionID,
		recvBlocks: NewAckTracker(),
		reasm:      NewReassembler(DefaultMaxPacketsInFlight, DefaultReassemblyTimeout),
		incoming:   make(chan []byte, 256),
		closed:     make(chan struct{}),
	}
	s.sendWindow = NewSendWindow(SendWindowConfig{
		Write:       s.writeData,
		ACKSnapshot: s.recvBlocks.Snapshot,
	})
	s.sendWindow.Start()
	go s.controlLoop()
	go s.dataLoop()
	return s, nil
}

// resolveIdentity loads or issues the client key pair. A standalone bundle
// fills the session's token, CA, client id and device id; no identity server or
// token in the proxy URL is needed. A missing file still uses the central issue
// path when identity_server is configured.
func resolveIdentity(ctx context.Context, cfg *Config) (ed25519.PrivateKey, IdentityMetadata, error) {
	if stringsTrim(cfg.IdentityFile) == "" {
		return nil, IdentityMetadata{}, errors.New("cbp: identity file is required (standalone bundle or server-issued cache)")
	}

	identity, meta, found, err := LoadClientIdentity(cfg.IdentityFile)
	if err != nil {
		return nil, IdentityMetadata{}, err
	}
	if !found {
		if stringsTrim(cfg.IdentityServerURL) == "" {
			return nil, IdentityMetadata{}, fmt.Errorf("cbp: no identity file %s and no identity server to issue one", cfg.IdentityFile)
		}
		identity, err = LoadOrIssueClient(ctx, IdentityConfig{
			FilePath:  cfg.IdentityFile,
			ServerURL: cfg.IdentityServerURL,
			Token:     cfg.IdentityToken,
			ClientID:  cfg.ClientID,
			Regions:   cfg.Regions,
		})
		if err != nil {
			return nil, IdentityMetadata{}, err
		}
	}

	if stringsTrim(cfg.ClientID) == "" {
		cfg.ClientID = identity.ClientID
	}
	if stringsTrim(cfg.DeviceID) == "" {
		cfg.DeviceID = identity.ClientID
	}
	if stringsTrim(cfg.Token) == "" {
		cfg.Token = meta.AuthToken
	}
	if stringsTrim(cfg.CACertFile) == "" {
		cfg.CACertFile = meta.TLSCAFile
	}
	if stringsTrim(cfg.Token) == "" {
		return nil, IdentityMetadata{}, errors.New("cbp: auth token is required; put it in the URL or the identity bundle")
	}

	key, err := identity.IdentityKey()
	if err != nil {
		return nil, IdentityMetadata{}, err
	}
	return key, meta, nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.CACertFile != "" && !cfg.InsecureSkipVerify {
		pool, err := loadCertPool(cfg.CACertFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	if tlsConfig.ServerName == "" && !tlsConfig.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(cfg.ControlAddr)
		if err == nil {
			tlsConfig.ServerName = host
		}
	}
	return tlsConfig, nil
}

// authenticate performs the HELLO_ACK / AUTH / SESSION_READY exchange.
func authenticate(conn net.Conn, token, deviceID string, key ed25519.PrivateKey) (SessionReady, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := ReadControlFrame(conn)
	if err != nil || env.Type != "HELLO_ACK" {
		return SessionReady{}, fmt.Errorf("cbp: read HELLO_ACK: %v", err)
	}
	var hello HelloAck
	if err := UnmarshalPayload(env.Payload, &hello); err != nil {
		return SessionReady{}, err
	}
	nonce, err := decodeBase64(hello.Nonce)
	if err != nil {
		return SessionReady{}, fmt.Errorf("cbp: bad nonce: %w", err)
	}
	pub := key.Public().(ed25519.PublicKey)
	auth := AuthRequest{
		Token:     token,
		DeviceID:  deviceID,
		PublicKey: encodeBase64(pub),
		Signature: encodeBase64(ed25519.Sign(key, nonce)),
	}
	rawPayload, err := MarshalPayload(auth)
	if err != nil {
		return SessionReady{}, err
	}
	if err := WriteControlFrame(conn, Envelope{Type: "AUTH", Payload: rawPayload}); err != nil {
		return SessionReady{}, err
	}
	env, err = ReadControlFrame(conn)
	if err != nil {
		return SessionReady{}, fmt.Errorf("cbp: read AUTH result: %w", err)
	}
	if env.Type == "ERROR" {
		var em ErrorMessage
		_ = UnmarshalPayload(env.Payload, &em)
		return SessionReady{}, fmt.Errorf("cbp: auth failed: %s: %s", em.Code, em.Message)
	}
	if env.Type != "SESSION_READY" {
		return SessionReady{}, fmt.Errorf("cbp: expected SESSION_READY, got %s", env.Type)
	}
	var ready SessionReady
	if err := UnmarshalPayload(env.Payload, &ready); err != nil {
		return SessionReady{}, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return ready, nil
}

// dialDataCandidates prefers the LAN data address, then the public one.
func dialDataCandidates(ctx context.Context, ready SessionReady, baseTLS *tls.Config, timeout time.Duration) (quic.Connection, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	candidates := make([]string, 0, 2)
	lanFirst := ready.LANDataAddr != "" && ready.LANDataAddr != ready.DataAddr
	if lanFirst {
		candidates = append(candidates, ready.LANDataAddr)
	}
	if ready.DataAddr != "" {
		candidates = append(candidates, ready.DataAddr)
	}
	var lastErr error
	for _, addr := range candidates {
		tlsCfg := baseTLS.Clone()
		if tlsCfg.ServerName == "" && !tlsCfg.InsecureSkipVerify {
			if host, _, err := net.SplitHostPort(addr); err == nil {
				tlsCfg.ServerName = host
			}
		}
		dialTimeout := timeout
		if lanFirst && addr == ready.LANDataAddr {
			dialTimeout = 3 * time.Second
		}
		qctx, cancel := context.WithTimeout(ctx, dialTimeout)
		qconn, err := quic.DialAddr(qctx, addr, tlsCfg, &quic.Config{
			EnableDatagrams:       true,
			MaxIdleTimeout:        60 * time.Second,
			KeepAlivePeriod:       20 * time.Second,
			MaxIncomingStreams:    -1,
			MaxIncomingUniStreams: -1,
		})
		cancel()
		if err == nil {
			return qconn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("cbp: no data address available")
	}
	return nil, lastErr
}

// Ready returns the session parameters.
func (s *Session) Ready() SessionReady {
	s.readyMu.RLock()
	defer s.readyMu.RUnlock()
	return s.ready
}

// SessionID is the server-assigned id.
func (s *Session) SessionID() uint64 { return s.sessionID }

// Healthy reports whether both planes are still open.
func (s *Session) Healthy() bool {
	select {
	case <-s.closed:
		return false
	default:
		return true
	}
}

// SendPacket hands one raw IP packet to the sender window.
func (s *Session) SendPacket(packet []byte) error {
	wirePacket, compressed := CompressIP(packet)
	frags := FragmentIP(wirePacket)
	if len(frags) == 0 {
		return errors.New("cbp: empty packet")
	}
	s.sendMu.Lock()
	packetID := s.nextPacketID
	s.nextPacketID++
	blockIDs := make([]uint64, len(frags))
	for i := range blockIDs {
		blockIDs[i] = s.nextBlockID
		s.nextBlockID++
	}
	s.sendMu.Unlock()

	baseFlags := uint8(0)
	if len(packet) >= 1 && packet[0]>>4 == 4 {
		baseFlags |= FlagIPv4
	} else if len(packet) >= 1 && packet[0]>>4 == 6 {
		baseFlags |= FlagIPv6
	}
	if compressed {
		baseFlags |= FlagCompressed
	}
	flags := make([]uint8, len(frags))
	for i := range flags {
		flags[i] = baseFlags
		if i == len(frags)-1 {
			flags[i] |= FlagLastFragment
		}
	}
	s.sendWindow.Push(s.sessionID, packetID, blockIDs, flags, frags)
	s.statsMu.Lock()
	s.stats.sentPackets++
	s.stats.sentBlocks += uint64(len(frags))
	s.statsMu.Unlock()
	return nil
}

// ReceivePacket blocks until one whole IP packet arrives.
func (s *Session) ReceivePacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, errors.New("cbp: session closed")
	case p := <-s.incoming:
		return p, nil
	}
}

func (s *Session) dataLoop() {
	for {
		msg, err := s.data.ReceiveMessage()
		if err != nil {
			s.close()
			return
		}
		pkt, err := DecodeDataPacket(msg)
		if err != nil {
			continue
		}
		if pkt.SessionID != s.sessionID {
			continue
		}
		switch pkt.Type {
		case DataTypeData:
			s.handleData(pkt)
		case DataTypeACK:
			s.sendWindow.Ack(pkt.AckBase, pkt.AckBitmap)
		case DataTypeRepair:
			s.sendWindow.Repair(pkt.AckBase, pkt.AckBitmap)
		case DataTypePing:
			_ = s.sendACK()
		}
	}
}

func (s *Session) handleData(pkt DataPacket) {
	if s.recvBlocks.Observe(pkt.BlockID) {
		s.statsMu.Lock()
		s.stats.receivedBlocks++
		s.statsMu.Unlock()
	}
	ip, complete := s.reasm.Add(pkt)
	if !complete {
		if pkt.FragCount > 1 {
			s.requestRepair()
		}
		return
	}
	if pkt.Flags&FlagCompressed != 0 {
		decoded, err := DecompressIP(ip)
		if err != nil {
			s.statsMu.Lock()
			s.stats.drops++
			s.statsMu.Unlock()
			return
		}
		ip = decoded
	}
	s.statsMu.Lock()
	s.stats.reassembled++
	s.statsMu.Unlock()
	select {
	case s.incoming <- ip:
	case <-s.closed:
	default:
		s.statsMu.Lock()
		s.stats.drops++
		s.statsMu.Unlock()
	}
	_ = s.sendACK()
}

func (s *Session) requestRepair() {
	now := time.Now()
	s.repairMu.Lock()
	if !s.lastRepair.IsZero() && now.Sub(s.lastRepair) < 50*time.Millisecond {
		s.repairMu.Unlock()
		return
	}
	s.lastRepair = now
	s.repairMu.Unlock()
	base, bitmap := s.recvBlocks.Snapshot()
	_ = s.writeData(DataPacket{
		Type:         DataTypeRepair,
		SessionID:    s.sessionID,
		FragCount:    1,
		AckBase:      base,
		AckBitmap:    bitmap,
		SendTSMillis: UnixMillis(now),
	})
}

func (s *Session) sendACK() error {
	base, bitmap := s.recvBlocks.Snapshot()
	return s.writeData(DataPacket{
		Type:         DataTypeACK,
		SessionID:    s.sessionID,
		FragCount:    1,
		AckBase:      base,
		AckBitmap:    bitmap,
		SendTSMillis: UnixMillis(time.Now()),
	})
}

func (s *Session) writeData(pkt DataPacket) error {
	buf, err := pkt.Encode()
	if err != nil {
		return err
	}
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	return s.data.SendMessage(buf)
}

func (s *Session) controlLoop() {
	for {
		env, err := ReadControlFrame(s.control)
		if err != nil {
			s.close()
			return
		}
		switch env.Type {
		case "SESSION_REFRESH":
			var refresh SessionRefresh
			if err := UnmarshalPayload(env.Payload, &refresh); err == nil && refresh.ExpiresAt != "" {
				s.readyMu.Lock()
				s.ready.ExpiresAt = refresh.ExpiresAt
				s.readyMu.Unlock()
			}
		case "CLOSE", "ERROR":
			s.close()
			return
		default:
			// STATS / PONG / STREAM_BINARY need no action in this client.
		}
	}
}

// Stats returns local counters.
func (s *Session) Stats() (sent, blocks, received, reassembled, drops uint64) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	return s.stats.sentPackets, s.stats.sentBlocks, s.stats.receivedBlocks, s.stats.reassembled, s.stats.drops
}

// Close tears down both planes.
func (s *Session) Close() error {
	s.close()
	return nil
}

func (s *Session) close() {
	s.closeOnce.Do(func() {
		if s.sendWindow != nil {
			s.sendWindow.Close()
		}
		close(s.closed)
		_ = s.control.Close()
		s.dataMu.Lock()
		_ = s.data.CloseWithError(0, "client closed")
		s.dataMu.Unlock()
	})
}
